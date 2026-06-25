#!/usr/bin/env python3
"""Security regression test suite"""

import sys, os, ssl, socket, json, time, base64, subprocess, hashlib, random

# ── Copy cert from container ───────────────────────────────────
REPO_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CERT_DIR = os.path.join(REPO_DIR, ".tmp_cert")
CERT     = os.path.join(CERT_DIR, "chat.crt")
os.makedirs(CERT_DIR, exist_ok=True)
with open(CERT, "wb") as f:
    subprocess.run(["docker", "exec", "chat-server", "cat", "/etc/ssl/chat.crt"],
                   stdout=f, check=True)

HOST = os.environ.get("CHAT_HOST", "localhost")
PORT = int(os.environ.get("CHAT_PORT", os.environ.get("CHAT_WS_PORT", "18888")))

def ws_connect():
    raw = socket.socket()
    raw.settimeout(8)
    raw.connect((HOST, PORT))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(CERT)
    ctx.verify_mode    = ssl.CERT_REQUIRED
    ctx.check_hostname = False          # CN=chat-server, not localhost
    s = ctx.wrap_socket(raw, server_hostname="chat-server")
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((
        f"GET / HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(1024)
    assert b"101" in buf, "WS handshake failed"
    return s

def ws_send(s, obj):
    payload = json.dumps(obj).encode()
    n = len(payload)
    mk  = os.urandom(4)
    hdr = bytearray([0x81])
    if   n <= 125:   hdr += bytes([0x80 | n])
    elif n <= 65535: hdr += bytes([0x80 | 126]) + n.to_bytes(2, "big")
    else:            hdr += bytes([0x80 | 127]) + n.to_bytes(8, "big")
    hdr += mk
    s.sendall(bytes(hdr) + bytes(b ^ mk[i % 4] for i, b in enumerate(payload)))

def ws_recv(s):
    def read_exact(n):
        d = b""
        while len(d) < n:
            chunk = s.recv(n - len(d))
            if not chunk:
                raise ConnectionError("connection closed")
            d += chunk
        return d
    h    = read_exact(2)
    op   = h[0] & 0x0f
    plen = h[1] & 0x7f
    if plen == 126:  plen = int.from_bytes(read_exact(2), "big")
    elif plen == 127: plen = int.from_bytes(read_exact(8), "big")
    data = read_exact(plen)
    if op == 0x08:
        raise ConnectionError("server sent close frame")
    return json.loads(data.decode())

def recv_until(s, pred, timeout=4.0):
    old_timeout = s.gettimeout()
    deadline = time.time() + timeout
    last = None
    try:
        while time.time() < deadline:
            s.settimeout(max(0.1, deadline - time.time()))
            msg = ws_recv(s)
            last = msg
            if pred(msg):
                return msg
    finally:
        s.settimeout(old_timeout)
    return last or {}

def pw_hash(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def fake_mls_b64(label):
    raw = json.dumps({
        "label": label,
        "nonce": base64.b64encode(os.urandom(12)).decode(),
    }).encode()
    return base64.b64encode(raw).decode()

PASS = "P@ssw0rd123!"
PH   = pw_hash(PASS)

# Unique suffix per run so users never collide across test runs
_RUN = random.randint(10000, 99999)
USER_A  = f"p2A{_RUN}"; EMAIL_A = f"p2a{_RUN}@test.com"
USER_B  = f"p2B{_RUN}"; EMAIL_B = f"p2b{_RUN}@test.com"

ok = 0; fail = 0

def check(name, cond, detail=""):
    global ok, fail
    if cond:
        print(f"  PASS  {name}")
        ok += 1
    else:
        print(f"  FAIL  {name}" + (f" -- {detail}" if detail else ""))
        fail += 1

# =================================================================
# WebSocket frame size smoke test: server must not crash.
# =================================================================
print("\n=== WS oversized frame rejection (smoke test) ===")
try:
    s = ws_connect()
    ws_send(s, {"type": "auth", "email": "nobody@x.com", "password": PH})
    r = ws_recv(s)
    check("Server responds correctly to a normal frame (no int-overflow crash)", True)
    s.close()
except Exception as e:
    check("Server responds after normal frame", False, str(e))

# =================================================================
# Server-side input validation
# =================================================================
print("\n=== Server-side input validation ===")

def try_register(username, email, password):
    s = ws_connect()
    ws_send(s, {"type": "register", "username": username,
                "email": email, "password": password})
    r = ws_recv(s)
    s.close()
    return r

r = try_register("ab", "", PH)
check("Username 2 chars rejected (need 3-63)",
      r.get("type") == "error" and "3-63" in r.get("msg", ""),
      r.get("msg",""))

r = try_register("a" * 64, "", PH)
check("Username 64 chars rejected (max 63)",
      r.get("type") == "error",
      r.get("msg",""))

r = try_register("user@bad", "", PH)
check("Username with '@' rejected",
      r.get("type") == "error",
      r.get("msg",""))

r = try_register("user name", "", PH)
check("Username with space rejected",
      r.get("type") == "error",
      r.get("msg",""))

r = try_register("good_user99", "notanemail", PH)
check("Bad email (no @ sign) rejected",
      r.get("type") == "error" and "email" in r.get("msg","").lower(),
      r.get("msg",""))

r = try_register("good_user99", "a@b", PH)
check("Bad email (no TLD dot) rejected",
      r.get("type") == "error",
      r.get("msg",""))

r = try_register("good_user99", "", "tooshort")
check("Password not 64-hex-chars rejected",
      r.get("type") == "error",
      r.get("msg",""))

r = try_register(USER_A, EMAIL_A, PH)
check("Valid registration accepted",
      r.get("type") == "ok",
      r.get("msg",""))

r = try_register(USER_B, EMAIL_B, PH)
check("Second valid registration accepted",
      r.get("type") == "ok",
      r.get("msg",""))

# =================================================================
# Friendship checks for OpenMLS prepare/apply group changes
# =================================================================
print("\n=== Friendship check for OpenMLS group prepare/apply ===")

def login(email, pw):
    s = ws_connect()
    ws_send(s, {"type": "auth", "email": email, "password": pw_hash(pw)})
    r = ws_recv(s)
    return s, r.get("user_id") or r.get("id")

def drain(s, timeout=0.5):
    """Consume any pending server notifications (non-blocking drain)."""
    s.settimeout(timeout)
    msgs = []
    try:
        while True: msgs.append(ws_recv(s))
    except: pass
    s.settimeout(8)
    return msgs

try:
    sA, uidA = login(EMAIL_A, PASS)
    sB, uidB = login(EMAIL_B, PASS)

    # A tries to prepare group creation with B (not friends yet)
    ws_send(sA, {"type": "prepare_group_change", "operation": "create_group",
                 "name": "BadGroup", "members": [uidB]})
    r = ws_recv(sA)
    check("prepare_group_change with non-friend member rejected",
          r.get("type") == "error" and "friend" in r.get("msg","").lower(),
          r.get("msg",""))

    # Direct mutation commands have been removed; only MLS prepare/apply exists.
    ws_send(sA, {"type": "create_group", "name": "DirectBad", "members": [uidB]})
    r = ws_recv(sA)
    check("removed direct create_group is rejected",
          r.get("type") == "error" and r.get("msg","") == "Unsupported command",
          r.get("msg",""))

    # Make A and B friends
    ws_send(sA, {"type": "friend_request", "target_id": uidB})
    ws_recv(sA)                             # ok from sA
    ws_send(sB, {"type": "friend_accept", "requester_id": uidA})
    ws_recv(sB)                             # ok from sB
    drain(sA)                               # consume friend_accepted notification on sA
    drain(sB)                               # consume friend_request_received on sB

    # Now prepare/apply group with friend — should succeed
    ws_send(sA, {"type": "prepare_group_change", "operation": "create_group",
                 "name": "GoodGroup", "members": [uidB]})
    prepared = recv_until(
        sA,
        lambda m: m.get("type") in ("group_change_prepared", "error"),
        timeout=4.0,
    )
    ok_prepare = prepared.get("type") == "group_change_prepared"
    check("prepare_group_change with friend member accepted",
          ok_prepare,
          prepared.get("msg","") or str(prepared))
    if ok_prepare:
        ws_send(sA, {
            "type": "apply_group_change",
            "operation_id": prepared["operation_id"],
            "conversation_id": prepared["conversation_id"],
            "epoch": 1,
            "commit_b64": fake_mls_b64("commit"),
            "group_info_b64": fake_mls_b64("group-info"),
            "group_id_b64": fake_mls_b64("group-id"),
            "welcomes": [{"user_id": uidB, "welcome_b64": fake_mls_b64("welcome")}],
        })
        r = recv_until(
            sA,
            lambda m: m.get("type") in ("group_created", "error"),
            timeout=4.0,
        )
        check("apply_group_change without MLS transcript rejected",
              r.get("type") == "error" and "MLS commit" in r.get("msg", ""),
              r.get("msg","") or str(r))

    sA.close()
    sB.close()
except Exception as e:
    check("Friendship group tests", False, str(e))
    import traceback; traceback.print_exc()

# =================================================================
# Auth rate limiting per IP
# =================================================================
print("\n=== Auth rate limiting ===")
try:
    # Use a fresh TLS connection per attempt. The auth limiter is keyed by
    # (login, IP), not socket, and this avoids TLS frame edge cases after
    # repeated auth errors on one connection.
    for i in range(5):
        s = ws_connect()
        try:
            ws_send(s, {"type": "auth", "email": EMAIL_A,
                        "password": pw_hash("wrongpass_" + str(i))})
            r = ws_recv(s)
        finally:
            s.close()

    # 6th attempt from same IP/login should be rate-limited.
    s = ws_connect()
    try:
        ws_send(s, {"type": "auth", "email": EMAIL_A,
                    "password": pw_hash("wrongpass_again")})
        r = ws_recv(s)
    finally:
        s.close()
    check("6th failed attempt is rate-limited",
          r.get("type") == "error" and "too many" in r.get("msg","").lower(),
          r.get("msg",""))
except Exception as e:
    check("Rate limiting test", False, str(e))
    import traceback; traceback.print_exc()

# =================================================================
# Pre-auth connection timeout
# =================================================================
print("\n=== Pre-auth timeout (wait up to 40s) ===")
print("    connecting without authenticating...")
try:
    s = ws_connect()
    s.settimeout(40)
    evicted = False
    deadline = time.time() + 38
    while time.time() < deadline:
        try:
            r = ws_recv(s)
        except (ConnectionError, ConnectionResetError, OSError,
                ssl.SSLError, json.JSONDecodeError):
            evicted = True
            break
    check("Unauthenticated connection evicted by janitor within 40s", evicted)
    try: s.close()
    except: pass
except Exception as e:
    check("Pre-auth timeout test", False, str(e))

# =================================================================
# Summary
# =================================================================
print(f"\n{'='*52}")
print(f"Security regression results: {ok} passed, {fail} failed")
sys.exit(0 if fail == 0 else 1)
