"""
secchat_testlib.py — shared helpers for SecChat integration tests.

Owns ALL WebSocket/TLS/handshake/auth boilerplate plus the ChatClient
context-manager and a db_reset() helper that TRUNCATEs every table in
chatdb via `docker exec`.

See tests/RULES.md for the rules every test file must follow.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import uuid
import sys
from typing import Any, Callable, Iterable, Optional
from urllib.error import URLError
from urllib.request import urlopen

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from client.crypto_engine.openmls_bridge import PQ_HYBRID_CIPHERSUITE
from client.utils import identity_keygen, identity_sign

# ─── Constants ────────────────────────────────────────────────────────────────

HOST = os.environ.get("CHAT_HOST", "localhost")
WS_PORT = int(os.environ.get("CHAT_PORT", os.environ.get("CHAT_WS_PORT", "18888")))
HTTP_PORT = int(os.environ.get("CHAT_HTTP_PORT", "18889"))

CERT_PATH = os.path.join(tempfile.gettempdir(), "secchat_chat.crt")
DB_CONTAINER = os.environ.get("CHAT_DB_CONTAINER", "chat-db")
SERVER_CONTAINER = os.environ.get("CHAT_SERVER_CONTAINER", "chat-server")
DB_NAME = os.environ.get("CHAT_DB_NAME", "chatdb")


def _load_dotenv() -> dict[str, str]:
    """Best-effort .env loader from the project root. Never raises."""
    out: dict[str, str] = {}
    here = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(here)
    env_path = os.path.join(project_root, ".env")
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


_DOTENV = _load_dotenv()

# Reset uses root: it has the broadest privileges (FK toggling, TRUNCATE on
# every table) and is the only credential guaranteed to exist by the compose
# config. Chatuser is what the *server* uses for normal operation.
DB_ROOT_USER = "root"
DB_ROOT_PASS = (
    os.environ.get("MYSQL_ROOT_PASSWORD")
    or _DOTENV.get("MYSQL_ROOT_PASSWORD")
    or "rootpass"
)

DEFAULT_TIMEOUT = 5.0


def _is_rate_limit_error(msg: Optional[dict]) -> bool:
    return (
        bool(msg)
        and msg.get("type") == "error"
        and "rate" in str(msg.get("msg", "")).lower()
    )


# ─── Bootstrapping ────────────────────────────────────────────────────────────

_cert_lock = threading.Lock()
_cert_cached = False


def ensure_cert() -> str:
    """One-shot copy of the server's pinned cert from the container.

    Cached for the lifetime of the test process. Returns the cert path.
    Tests do NOT need to call this — ws_connect calls it automatically.
    """
    global _cert_cached
    with _cert_lock:
        if _cert_cached and os.path.exists(CERT_PATH):
            return CERT_PATH
        try:
            out = subprocess.run(
                ["docker", "exec", "chat-server", "cat", "/certs/chat.crt"],
                check=True, capture_output=True, timeout=5,
            ).stdout
            with open(CERT_PATH, "wb") as f:
                f.write(out)
            _cert_cached = True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            # docker may be unreachable on this host or container not running.
            # Tests that require pinning will fail later with a clear error;
            # tests that use CERT_NONE (the default in this lib) don't care.
            pass
        return CERT_PATH


def wait_ready(timeout: float = 30.0) -> None:
    """Block until http://localhost:HTTP_PORT/readyz returns 200, or raise."""
    deadline = time.time() + timeout
    last_err: Optional[Exception] = None
    while time.time() < deadline:
        try:
            with urlopen(f"http://{HOST}:{HTTP_PORT}/readyz", timeout=2.0) as r:
                if r.status == 200:
                    return
        except (URLError, ConnectionError, OSError) as e:
            last_err = e
        time.sleep(0.5)
    raise RuntimeError(
        f"server not ready on {HOST}:{HTTP_PORT} after {timeout}s "
        f"(last error: {last_err!r})"
    )


def _mysql(sql: str, batch: bool = True, timeout: float = 10.0) -> str:
    """Run SQL in chatdb as root via docker exec. Returns stdout text.

    `batch=True` uses `-BN` for tab-separated, header-less output suitable
    for shell parsing. Set `batch=False` for human-readable output.
    """
    args = ["docker", "exec", DB_CONTAINER, "mysql",
            f"-u{DB_ROOT_USER}", f"-p{DB_ROOT_PASS}"]
    if batch:
        args.append("-BN")
    args += [DB_NAME, "-e", sql]
    out = subprocess.run(args, check=True, capture_output=True, timeout=timeout)
    return out.stdout.decode("utf-8", errors="replace")


def db_reset(skip_tables: Iterable[str] = ("schema_migrations",)) -> None:
    """TRUNCATE every table in chatdb (except schema_migrations) via docker exec.

    Runs in ~200ms. Survives schema changes — enumerates tables from
    information_schema. Does NOT drop the schema, only truncates rows.
    schema_migrations is preserved so the server doesn't re-run migrations.
    Full-suite runs may set SECCHAT_DB_RESET_SETTLE_SECONDS so in-memory
    server token buckets can refill after user ids are reused.
    """
    skip_set = set(skip_tables)
    tables_sql = (
        "SELECT table_name FROM information_schema.tables "
        f"WHERE table_schema='{DB_NAME}'"
    )
    raw = _mysql(tables_sql, batch=True, timeout=5.0)
    tables = [t.strip() for t in raw.splitlines() if t.strip() and t.strip() not in skip_set]
    if not tables:
        return
    truncates = ";".join(f"TRUNCATE TABLE `{t}`" for t in tables)
    reset_sql = (
        "SET FOREIGN_KEY_CHECKS=0;"
        f"{truncates};"
        "SET FOREIGN_KEY_CHECKS=1;"
    )
    _mysql(reset_sql, batch=False, timeout=90.0)
    try:
        settle = float(os.environ.get("SECCHAT_DB_RESET_SETTLE_SECONDS", "0") or "0")
    except ValueError:
        settle = 0.0
    if settle > 0:
        time.sleep(settle)


# ─── Naming ───────────────────────────────────────────────────────────────────

def unique(prefix: str = "u") -> str:
    """Collision-resistant test identifier. Use for usernames, group names, etc."""
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


# ─── Hashing ──────────────────────────────────────────────────────────────────

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


# ─── Raw WebSocket layer ──────────────────────────────────────────────────────

def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _ws_handshake(sock: ssl.SSLSocket) -> None:
    key = _b64(os.urandom(16))
    req = (
        "GET / HTTP/1.1\r\n"
        f"Host: {HOST}:{WS_PORT}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    sock.sendall(req.encode())
    resp = b""
    deadline = time.time() + 5.0
    while b"\r\n\r\n" not in resp and time.time() < deadline:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp += chunk
    if b"101" not in resp.split(b"\r\n", 1)[0]:
        raise RuntimeError(f"WebSocket handshake failed: {resp!r}")


def ws_connect(host: str = HOST, port: int = WS_PORT) -> ssl.SSLSocket:
    """Open a TLS+WS connection. Cert is NOT verified (matches existing tests).

    Returns the wrapped socket with handshake completed.
    """
    last_exc: Optional[BaseException] = None
    for attempt in range(4):
        raw: Optional[socket.socket] = None
        sock: Optional[ssl.SSLSocket] = None
        try:
            raw = socket.create_connection((host, port), timeout=10)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=host)
            _ws_handshake(sock)
            return sock
        except (OSError, ssl.SSLError, socket.timeout, TimeoutError, RuntimeError) as exc:
            last_exc = exc
            if sock is not None:
                ws_close(sock)
            elif raw is not None:
                try:
                    raw.close()
                except OSError:
                    pass
            if attempt < 3:
                time.sleep(0.25 * (attempt + 1))
                continue
            raise
    raise RuntimeError(f"WebSocket connect failed: {last_exc!r}")


def ws_close(sock: ssl.SSLSocket) -> None:
    try:
        sock.close()
    except Exception:
        pass


def ws_send(sock: ssl.SSLSocket, obj: dict) -> None:
    """Send a JSON message as a single masked client→server text frame."""
    data = json.dumps(obj).encode("utf-8")
    length = len(data)
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    if length < 126:
        header = struct.pack("!BB", 0x81, 0x80 | length) + mask
    elif length < 65536:
        header = struct.pack("!BBH", 0x81, 0x80 | 126, length) + mask
    else:
        header = struct.pack("!BBQ", 0x81, 0x80 | 127, length) + mask
    sock.sendall(header + masked)


def _recv_exact(sock: ssl.SSLSocket, n: int) -> Optional[bytes]:
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            raise
        if not chunk:
            return None
        buf += chunk
    return buf


def ws_recv(sock: ssl.SSLSocket, timeout: float = DEFAULT_TIMEOUT) -> Optional[dict]:
    """Receive one full WebSocket text frame and return its JSON-parsed body.

    Returns None on close, ping (auto-pong then re-recv), or timeout.
    Raises only on protocol violations.
    """
    sock.settimeout(timeout)
    try:
        header = _recv_exact(sock, 2)
        if header is None:
            return None
        opcode = header[0] & 0x0F
        length = header[1] & 0x7F
        if opcode == 0x9:                       # ping → pong, then continue
            sock.sendall(struct.pack("!BB", 0x8A, 0))
            return ws_recv(sock, timeout)
        if opcode == 0x8:                       # close
            return None
        if length == 126:
            ext = _recv_exact(sock, 2)
            if ext is None:
                return None
            length = struct.unpack("!H", ext)[0]
        elif length == 127:
            ext = _recv_exact(sock, 8)
            if ext is None:
                return None
            length = struct.unpack("!Q", ext)[0]
        data = _recv_exact(sock, length)
        if data is None:
            return None
        text = data.decode("utf-8", errors="replace")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"__raw__": text}
    except socket.timeout:
        return None


# ─── Frame-safe receive ───────────────────────────────────────────────────────

def recv_until(
    sock: ssl.SSLSocket,
    predicate: Callable[[dict], bool],
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[dict]:
    """Receive frames until predicate(msg) is True or timeout elapses.

    NEVER use this after a blind drain() — partial frames will already
    have corrupted the buffer. Use this for the ENTIRE receive sequence.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        remaining = max(0.1, deadline - time.time())
        msg = ws_recv(sock, timeout=remaining)
        if msg is None:
            continue
        if predicate(msg):
            return msg
    return None


def recv_type(
    sock: ssl.SSLSocket,
    type_: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[dict]:
    """recv_until specialized to message["type"] == type_."""
    return recv_until(sock, lambda m: m.get("type") == type_, timeout=timeout)


def collect(
    sock: ssl.SSLSocket,
    count: int,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[dict]:
    """Collect up to `count` frames in `timeout` seconds total. Stops early."""
    deadline = time.time() + timeout
    out: list[dict] = []
    while len(out) < count and time.time() < deadline:
        remaining = max(0.1, deadline - time.time())
        msg = ws_recv(sock, timeout=remaining)
        if msg is None:
            continue
        out.append(msg)
    return out


# ─── Auth fixtures ────────────────────────────────────────────────────────────

def register_user(
    sock: ssl.SSLSocket,
    username: str,
    password: str = "Pw!12345",
    email: Optional[str] = None,
) -> Optional[dict]:
    """Send a register request on `sock` and wait for the response."""
    if email is None:
        email = f"{username}@test.local"
    resp: Optional[dict] = None
    for _ in range(8):
        ws_send(sock, {
            "type": "register",
            "username": username,
            "email": email,
            "password": sha256_hex(password),
        })
        resp = ws_recv(sock, timeout=DEFAULT_TIMEOUT)
        if _is_rate_limit_error(resp):
            time.sleep(1.2)
            continue
        return resp
    return resp


def login(
    sock: ssl.SSLSocket,
    username: str,
    password: str = "Pw!12345",
) -> Optional[dict]:
    """Send an auth request on `sock` and wait for the response."""
    resp: Optional[dict] = None
    for _ in range(8):
        ws_send(sock, {
            "type": "auth",
            "username": username,
            "password": sha256_hex(password),
        })
        # The server may emit presence broadcasts before/after the auth response;
        # match by presence of user_id, NOT by arrival order.
        resp = recv_until(
            sock,
            lambda m: m.get("user_id") is not None or m.get("type") == "error",
            timeout=DEFAULT_TIMEOUT,
        )
        if _is_rate_limit_error(resp):
            time.sleep(1.2)
            continue
        return resp
    return resp


def make_friends(
    sa: ssl.SSLSocket, uid_a: int,
    sb: ssl.SSLSocket, uid_b: int,
    timeout: float = 4.0,
) -> None:
    """Send + accept friend request between two logged-in sockets.

    Uses recv_until for the async notifications — never drain().
    Caller is responsible for any further recv on sa/sb afterwards.
    """
    ws_send(sa, {"type": "friend_request", "target_id": uid_b})
    # Wait for sb to actually see the notification — that's the cue
    # that the server has finished writing the friendship row.
    recv_until(
        sb,
        lambda m: m.get("type") == "friend_request_received",
        timeout=timeout,
    )
    ws_send(sb, {"type": "friend_accept", "requester_id": uid_a})
    recv_until(
        sa,
        lambda m: m.get("type") == "friend_accepted",
        timeout=timeout,
    )


# Global counter for E2R message prefixes — incremented per send so each
# test message gets a unique counter and the replay window never triggers.
_S3DR_counter = 0


def fake_S3DR(body: str) -> str:
    global _S3DR_counter
    _S3DR_counter += 1
    raw = json.dumps({
        "v": 2,
        "dh": "test",
        "pn": 0,
        "n": _S3DR_counter,
        "ct": body,
    }, separators=(",", ":")).encode("utf-8")
    token = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"S3DR:{token}"


def fake_mls_b64(label: str) -> str:
    raw = json.dumps({
        "label": label,
        "nonce": uuid.uuid4().hex,
    }, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class DockerMlsBridge:
    """Stateful test wrapper around the bridge binary inside the server container."""

    def __init__(self) -> None:
        self.proc: subprocess.Popen[str] | None = None

    def start(self) -> None:
        if self.proc and self.proc.poll() is None:
            return
        self.proc = subprocess.Popen(
            ["docker", "exec", "-i", SERVER_CONTAINER, "secchat_mls_bridge", "serve"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def command(self, cmd: str, **kwargs: Any) -> dict:
        self.start()
        if not self.proc or not self.proc.stdin or not self.proc.stdout:
            raise RuntimeError("MLS bridge test process is unavailable")
        self.proc.stdin.write(json.dumps({"cmd": cmd, **kwargs}, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()
        raw = self.proc.stdout.readline()
        if not raw:
            err = ""
            try:
                err = self.proc.stderr.read() if self.proc.stderr else ""
            except Exception:
                pass
            raise RuntimeError(f"MLS bridge test process stopped: {err}")
        payload = json.loads(raw)
        if not payload.get("ok"):
            raise RuntimeError(str(payload.get("error") or raw))
        return payload

    def init_identity(self, *, user_id: int, email: str,
                      secchat_identity_pk: str,
                      secchat_identity_version: int) -> dict:
        return self.command(
            "init_identity",
            user_id=int(user_id),
            email=email,
            secchat_identity_pk=secchat_identity_pk,
            secchat_identity_version=int(secchat_identity_version),
        )

    def top_up_key_packages(self, count: int = 4) -> list[dict]:
        return list(self.command("top_up_key_packages", count=int(count)).get("key_packages") or [])

    def create_group(self, conversation_id: int) -> dict:
        return self.command("create_group", conversation_id=int(conversation_id))

    def add_members(self, conversation_id: int, key_packages: list[str]) -> dict:
        return self.command(
            "add_members",
            conversation_id=int(conversation_id),
            key_packages=list(key_packages),
        )

    def remove_members(self, conversation_id: int, user_ids: list[int]) -> dict:
        return self.command(
            "remove_members",
            conversation_id=int(conversation_id),
            user_ids=[int(uid) for uid in user_ids],
        )

    def close(self) -> None:
        proc = self.proc
        self.proc = None
        if not proc:
            return
        try:
            if proc.stdin:
                proc.stdin.close()
        except Exception:
            pass
        try:
            proc.terminate()
            proc.wait(timeout=2.0)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        for stream in (proc.stdout, proc.stderr):
            try:
                if stream:
                    stream.close()
            except Exception:
                pass


def _mls_key_package_sig_msg(pkg: dict) -> bytes:
    return (
        b"SecChatMLSKeyPackage\x00"
        + str(pkg.get("key_package_ref", "") or "").encode("utf-8")
        + b"\x00"
        + str(pkg.get("key_package_b64", "") or "").encode("utf-8")
        + b"\x00"
        + str(pkg.get("ciphersuite", "") or "").encode("utf-8")
    )


def ensure_mls_ready(client: "ChatClient", *, publish: bool = True) -> None:
    if not client.user_id:
        raise AssertionError("ChatClient must be logged in before MLS setup")
    if client.identity_pk is None or client.identity_sk is None:
        client.identity_pk, client.identity_sk = identity_keygen()
        id_pk_b64 = _b64e(client.identity_pk)
        ws_send(client.sock, {
            "type": "upload_keys",
            "identity_pk": id_pk_b64,
            "identity_sig": _b64e(identity_sign(client.identity_sk, b"test-identity")),
            "identity_sk_enc": f"test-id-sk-{client.user_id}",
        })
        got = recv_until(client.sock, lambda m: m.get("type") in ("ok", "error"), timeout=4.0)
        if not got or got.get("type") == "error":
            raise AssertionError(f"upload_keys for MLS identity failed: {got}")
    if client.mls is None:
        client.mls = DockerMlsBridge()
        result = client.mls.init_identity(
            user_id=int(client.user_id),
            email=f"{client.username or client.user_id}@test.local",
            secchat_identity_pk=_b64e(client.identity_pk),
            secchat_identity_version=0,
        )
        client.mls_credential_identity_b64 = str(
            result.get("credential_identity_b64", "") or "")
    if publish:
        packages = client.mls.top_up_key_packages(count=4)
        for pkg in packages:
            pkg["credential_identity_b64"] = client.mls_credential_identity_b64
            pkg["secchat_signature"] = _b64e(
                identity_sign(client.identity_sk, _mls_key_package_sig_msg(pkg)))
        ws_send(client.sock, {
            "type": "upload_mls_key_packages",
            "key_packages": packages,
        })
        got = recv_until(
            client.sock,
            lambda m: m.get("type") in ("mls_key_packages_uploaded", "error"),
            timeout=6.0,
        )
        if (not got or got.get("type") == "error" or
                int(got.get("stored", 0) or 0) <= 0):
            raise AssertionError(f"upload_mls_key_packages failed: {got}")


def claim_mls_key_package(client: "ChatClient", target_uid: int) -> str:
    ws_send(client.sock, {"type": "claim_mls_key_package", "user_id": int(target_uid)})
    got = recv_until(
        client.sock,
        lambda m: m.get("type") in ("mls_key_package", "error"),
        timeout=6.0,
    )
    if not got or got.get("type") == "error" or not got.get("found"):
        raise AssertionError(f"claim_mls_key_package failed for {target_uid}: {got}")
    if got.get("ciphersuite") != PQ_HYBRID_CIPHERSUITE:
        raise AssertionError(f"claimed non-X-Wing KeyPackage: {got}")
    return str(got.get("key_package_b64", "") or "")


def _mls_group_id_b64(conv_id: int) -> str:
    return _b64e(f"secchat-group:{int(conv_id)}".encode("utf-8"))


def prepare_group_change(client: "ChatClient", operation: str, **payload: Any) -> dict:
    ws_send(client.sock, {
        "type": "prepare_group_change",
        "operation": operation,
        **payload,
    })
    msg = recv_until(
        client.sock,
        lambda m: m.get("type") in ("group_change_prepared", "error"),
        timeout=6.0,
    )
    if msg is None:
        raise AssertionError(f"prepare_group_change timed out for {operation}")
    return msg


def apply_group_change(
    client: "ChatClient",
    prepared: dict,
    *,
    target_user_ids: Iterable[int] = (),
    control: bool = False,
    mls_result: Optional[dict] = None,
) -> None:
    operation_id = prepared.get("operation_id")
    conv_id = int(prepared.get("conversation_id", 0) or 0)
    operation = str(prepared.get("operation", "group"))
    if not operation_id or conv_id <= 0:
        raise AssertionError(f"invalid prepared group operation: {prepared}")
    payload: dict[str, Any] = {
        "type": "apply_group_change",
        "operation_id": operation_id,
        "conversation_id": conv_id,
        "epoch": int(time.time()),
    }
    if mls_result and mls_result.get("epoch") is not None:
        payload["epoch"] = int(mls_result.get("epoch", 0) or 0)
    if control:
        payload["control_b64"] = fake_mls_b64(f"{operation}:control:{operation_id}")
    elif mls_result:
        for key in ("commit_b64", "group_info_b64", "group_id_b64", "ratchet_tree_b64"):
            if mls_result.get(key):
                payload[key] = mls_result[key]
        welcome = str(mls_result.get("welcome_b64", "") or "")
        if welcome:
            payload["welcomes"] = [
                {
                    "user_id": int(uid),
                    "welcome_b64": welcome,
                }
                for uid in target_user_ids
            ]
    else:
        payload.update({
            "commit_b64": fake_mls_b64(f"{operation}:commit:{operation_id}"),
            "group_info_b64": fake_mls_b64(f"{operation}:group-info:{operation_id}"),
            "group_id_b64": fake_mls_b64(f"group:{conv_id}"),
            "ratchet_tree_b64": fake_mls_b64(f"{operation}:ratchet-tree:{operation_id}"),
            "welcomes": [
                {
                    "user_id": int(uid),
                    "welcome_b64": fake_mls_b64(f"{operation}:welcome:{uid}:{operation_id}"),
                }
                for uid in target_user_ids
            ],
        })
    ws_send(client.sock, payload)


def consume_group_applied(client: "ChatClient", operation_id: str, timeout: float = 1.0) -> None:
    recv_until(
        client.sock,
        lambda m: m.get("type") == "group_change_applied"
        and m.get("operation_id") == operation_id,
        timeout=timeout,
    )


def create_group_mls(client: "ChatClient", name: str, members: Iterable["ChatClient"]) -> int:
    member_ids = [int(m.user_id) for m in members if m.user_id is not None]
    ensure_mls_ready(client, publish=False)
    for member in members:
        ensure_mls_ready(member, publish=True)
    prepared = prepare_group_change(
        client,
        "create_group",
        name=name,
        members=member_ids,
    )
    if prepared.get("type") == "error":
        raise AssertionError(f"prepare create_group failed: {prepared}")
    conv_id = int(prepared.get("conversation_id", 0) or 0)
    if not client.mls:
        raise AssertionError("creator MLS bridge is not initialized")
    created_local = client.mls.create_group(conv_id)
    packages = [claim_mls_key_package(client, uid) for uid in member_ids]
    mls_result = client.mls.add_members(conv_id, packages)
    mls_result["group_id_b64"] = str(
        created_local.get("group_id_b64") or _mls_group_id_b64(conv_id))
    apply_group_change(
        client, prepared, target_user_ids=member_ids, mls_result=mls_result)
    created = recv_until(
        client.sock,
        lambda m: m.get("type") in ("group_created", "error"),
        timeout=6.0,
    )
    if created is None or created.get("type") != "group_created":
        raise AssertionError(f"group_created not received: {created}")
    consume_group_applied(client, str(prepared["operation_id"]))
    return int(created["conversation_id"])


def add_member_mls(client: "ChatClient", group_id: int, member: "ChatClient") -> dict:
    ensure_mls_ready(client, publish=False)
    ensure_mls_ready(member, publish=True)
    prepared = prepare_group_change(
        client,
        "add_member",
        group_id=int(group_id),
        user_id=int(member.user_id),
    )
    if prepared.get("type") == "error":
        raise AssertionError(f"prepare add_member failed: {prepared}")
    if not client.mls:
        raise AssertionError("actor MLS bridge is not initialized")
    package = claim_mls_key_package(client, int(member.user_id))
    mls_result = client.mls.add_members(int(group_id), [package])
    mls_result["group_id_b64"] = _mls_group_id_b64(int(group_id))
    apply_group_change(
        client, prepared, target_user_ids=[int(member.user_id)], mls_result=mls_result)
    added = recv_until(
        client.sock,
        lambda m: m.get("type") in ("member_added", "error")
        and (m.get("type") == "error" or int(m.get("group_id", 0) or 0) == int(group_id)),
        timeout=6.0,
    )
    if added is None or added.get("type") != "member_added":
        raise AssertionError(f"member_added not received: {added}")
    consume_group_applied(client, str(prepared["operation_id"]))
    return added


def remove_member_mls(client: "ChatClient", group_id: int, member: "ChatClient") -> dict:
    ensure_mls_ready(client, publish=False)
    prepared = prepare_group_change(
        client,
        "remove_member",
        group_id=int(group_id),
        user_id=int(member.user_id),
    )
    if prepared.get("type") == "error":
        raise AssertionError(f"prepare remove_member failed: {prepared}")
    if not client.mls:
        raise AssertionError("actor MLS bridge is not initialized")
    mls_result = client.mls.remove_members(int(group_id), [int(member.user_id)])
    mls_result["group_id_b64"] = _mls_group_id_b64(int(group_id))
    apply_group_change(client, prepared, target_user_ids=[], mls_result=mls_result)
    removed = recv_until(
        client.sock,
        lambda m: m.get("type") in ("member_removed", "error")
        and (m.get("type") == "error" or int(m.get("group_id", 0) or 0) == int(group_id)),
        timeout=6.0,
    )
    if removed is None or removed.get("type") != "member_removed":
        raise AssertionError(f"member_removed not received: {removed}")
    consume_group_applied(client, str(prepared["operation_id"]))
    return removed


def set_member_role_mls(
    client: "ChatClient",
    group_id: int,
    member: "ChatClient",
    role: str,
) -> dict:
    prepared = prepare_group_change(
        client,
        "set_member_role",
        group_id=int(group_id),
        user_id=int(member.user_id),
        role=role,
    )
    if prepared.get("type") == "error":
        raise AssertionError(f"prepare set_member_role failed: {prepared}")
    apply_group_change(client, prepared, control=True)
    changed = recv_until(
        client.sock,
        lambda m: m.get("type") in ("member_role_changed", "error")
        and (m.get("type") == "error" or int(m.get("group_id", 0) or 0) == int(group_id)),
        timeout=6.0,
    )
    if changed is None or changed.get("type") != "member_role_changed":
        raise AssertionError(f"member_role_changed not received: {changed}")
    consume_group_applied(client, str(prepared["operation_id"]))
    return changed


def ws_send_msg(sock: ssl.SSLSocket, conv_id: int, body: str, **extra) -> str:
    """Send a message with the required SecChat end-to-end prefix.

    Server-side ciphertext enforcement rejects plaintext.  All integration tests that
    send a 'message' type must use this helper instead of bare ws_send so the
    body carries a valid S3DR:<payload> prefix.

    Returns the full prefixed body string so callers can use it in recv_until
    predicates:  ``sent = ws_send_msg(...); recv_until(sock, lambda m: m.get("body") == sent)``

    Extra keyword args (e.g. ``mentions=[uid]``) are forwarded to ws_send.
    """
    prefixed = fake_S3DR(body)
    ws_send(sock, {"type": "message", "conversation_id": conv_id,
                   "body": prefixed, **extra})
    return prefixed


def open_dm(sock: ssl.SSLSocket, peer_uid: int, timeout: float = 4.0) -> Optional[int]:
    """Send start_dm and return the conversation_id from dm_ready."""
    ws_send(sock, {"type": "start_dm", "user_id": peer_uid})
    msg = recv_until(
        sock,
        lambda m: m.get("type") in ("dm_ready", "error")
                  or m.get("conversation_id") is not None,
        timeout=timeout,
    )
    if msg is None:
        return None
    return msg.get("conversation_id")


# ─── HTTP control plane ───────────────────────────────────────────────────────

def http_get(path: str, timeout: float = 3.0) -> tuple[int, str]:
    """GET http://localhost:HTTP_PORT/<path>. Returns (status, body)."""
    if not path.startswith("/"):
        path = "/" + path
    url = f"http://{HOST}:{HTTP_PORT}{path}"
    last_exc: Optional[BaseException] = None
    for attempt in range(3):
        try:
            with urlopen(url, timeout=timeout) as r:
                body = r.read().decode("utf-8", errors="replace")
                return r.status, body
        except URLError as e:
            # urllib raises HTTPError (subclass) for non-2xx; surface its status.
            if hasattr(e, "code") and hasattr(e, "read"):
                return int(e.code), e.read().decode("utf-8", errors="replace")  # type: ignore[attr-defined]
            last_exc = e
        except (TimeoutError, socket.timeout, OSError) as e:
            last_exc = e
        if attempt < 2:
            time.sleep(0.25 * (attempt + 1))
    if last_exc:
        raise last_exc
    raise RuntimeError(f"HTTP GET failed for {url}")


def get_metrics() -> dict:
    """Fetch /metrics and parse the JSON body."""
    status, body = http_get("/metrics")
    if status != 200:
        raise RuntimeError(f"/metrics returned {status}: {body[:200]}")
    return json.loads(body)


# ─── High-level client ────────────────────────────────────────────────────────

class ChatClient:
    """Thin synchronous WebSocket client for tests.

    Use as a context manager so the socket closes on assertion failure:

        with ChatClient() as c:
            c.register("alice")
            c.login("alice")
            ...
    """

    sock: ssl.SSLSocket
    username: Optional[str]
    user_id: Optional[int]

    def __init__(self, username: Optional[str] = None,
                 password: str = "Pw!12345"):
        self.sock = ws_connect()
        self.username = username
        self.password = password
        self.user_id = None
        self.identity_pk = None
        self.identity_sk = None
        self.mls: DockerMlsBridge | None = None
        self.mls_credential_identity_b64 = ""

    # --- context manager ---
    def __enter__(self) -> "ChatClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # --- core WS ---
    def send(self, type_: str, **kwargs) -> None:
        msg = {"type": type_, **kwargs}
        ws_send(self.sock, msg)

    def recv(self, timeout: float = DEFAULT_TIMEOUT) -> Optional[dict]:
        return ws_recv(self.sock, timeout=timeout)

    def expect(
        self,
        predicate_or_type: Any,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> Optional[dict]:
        """Receive frames until match. `predicate_or_type` is either a
        callable(msg)->bool or a string (matched against msg['type'])."""
        if callable(predicate_or_type):
            return recv_until(self.sock, predicate_or_type, timeout=timeout)
        return recv_type(self.sock, str(predicate_or_type), timeout=timeout)

    def close(self) -> None:
        if self.mls:
            self.mls.close()
            self.mls = None
        ws_close(self.sock)

    # --- account ---
    def register(self, username: Optional[str] = None,
                 password: Optional[str] = None,
                 email: Optional[str] = None) -> Optional[dict]:
        username = username or self.username or unique("u")
        password = password or self.password
        self.username = username
        self.password = password
        return register_user(self.sock, username, password, email)

    def login(self, username: Optional[str] = None,
              password: Optional[str] = None) -> Optional[dict]:
        username = username or self.username
        password = password or self.password
        if not username:
            raise RuntimeError("ChatClient.login: no username set")
        resp = login(self.sock, username, password)
        if resp and resp.get("user_id"):
            self.user_id = resp["user_id"]
            self.username = resp.get("username", username)
        return resp

    def register_and_login(self, username: Optional[str] = None,
                           password: Optional[str] = None) -> "ChatClient":
        """Register on a temp connection, then login on this connection."""
        username = username or self.username or unique("u")
        password = password or self.password
        with ChatClient() as tmp:
            register_user(tmp.sock, username, password)
        self.username = username
        self.password = password
        resp = self.login(username, password)
        if not self.user_id:
            raise AssertionError(f"login failed for {username}: {resp}")
        return self


__all__ = [
    "HOST", "WS_PORT", "HTTP_PORT", "CERT_PATH", "DEFAULT_TIMEOUT",
    "ensure_cert", "wait_ready", "db_reset",
    "unique", "sha256_hex",
    "ws_connect", "ws_close", "ws_send", "ws_recv",
    "recv_until", "recv_type", "collect",
    "register_user", "login", "make_friends", "open_dm",
    "fake_mls_b64", "prepare_group_change", "apply_group_change",
    "create_group_mls", "add_member_mls", "remove_member_mls",
    "set_member_role_mls",
    "http_get", "get_metrics",
    "ChatClient",
]
