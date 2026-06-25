"""
Blocking, advanced messaging, and change-password integration tests.

Blocking:
  Blocking-1      block / unblock returns ok
  Blocking-2      blocked user cannot start DM
  Blocking-3      blocked user cannot send message in existing DM
  Blocking-4      get_blocked_list
  Blocking-5      removed moderation commands are unsupported
  Blocking-6      rate limit (send >10 messages rapidly, get throttled)
  Blocking-7      offline notification delivered on reconnect
  Blocking-8      blocking self is rejected

Advanced messaging:
  Messaging-1..4   pin_message / unpin / get_pinned_messages / empty list
  Messaging-7..8   set_disappearing (set / clear)
  Messaging-9..10  mute_conversation (mute / unmute)
  Messaging-11     archive_conversation (toggle)
  Messaging-12     pin_conversation (toggle)
  Messaging-13     mark_unread
  Messaging-14     non-member pin rejected

Change password:
  CP-1      change_password success
  CP-2      change_password fails with wrong old_password
  CP-3      login with new password succeeds
  CP-4      old password no longer works
  CP-5      change_password without auth returns error
"""

import ssl
import json
import time
import struct
import hashlib
import socket
import threading
import unittest
import os
import sys

REPO_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_DIR, "tests"))
from secchat_testlib import db_reset, wait_ready  # noqa: E402

HOST = os.environ.get("CHAT_HOST", "localhost")
PORT = int(os.environ.get("CHAT_PORT", os.environ.get("CHAT_WS_PORT", "18888")))


def setUpModule():
    wait_ready()
    db_reset()
    # Full-suite runs can leave per-user token buckets partially depleted in
    # server memory. DB reset alone does not clear that state, and TRUNCATE can
    # reuse ids, so wait for a full refill before this file starts.
    time.sleep(11.0)

# ─── WebSocket helpers ────────────────────────────────────────────────────────

def _b64(data: bytes) -> str:
    import base64
    return base64.b64encode(data).decode()


def _ws_handshake(sock):
    key = _b64(os.urandom(16))
    req = (
        "GET / HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    sock.sendall(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        resp += sock.recv(4096)
    return resp


def _ws_send(sock, payload: str):
    data = payload.encode()
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


def _ws_recv(sock, timeout=5):
    sock.settimeout(timeout)
    try:
        header = b""
        while len(header) < 2:
            chunk = sock.recv(2 - len(header))
            if not chunk:
                return None
            header += chunk
        opcode = header[0] & 0x0F
        length = header[1] & 0x7F
        if opcode == 0x9:                       # ping → pong
            sock.sendall(struct.pack("!BB", 0x8A, 0))
            return _ws_recv(sock, timeout)
        if opcode == 0x8:                       # close
            return None
        if length == 126:
            ext = b""
            while len(ext) < 2:
                ext += sock.recv(2 - len(ext))
            length = struct.unpack("!H", ext)[0]
        elif length == 127:
            ext = b""
            while len(ext) < 8:
                ext += sock.recv(8 - len(ext))
            length = struct.unpack("!Q", ext)[0]
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return data.decode("utf-8", errors="replace")
    except socket.timeout:
        return None


def _sha256(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


class ChatClient:
    """Thin synchronous WebSocket client for testing."""

    def __init__(self):
        raw = socket.create_connection((HOST, PORT), timeout=10)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.sock = ctx.wrap_socket(raw, server_hostname=HOST)
        _ws_handshake(self.sock)
        self.uid = None
        self.username = None

    def send(self, obj: dict):
        _ws_send(self.sock, json.dumps(obj))

    def recv(self, timeout=5):
        raw = _ws_recv(self.sock, timeout)
        if raw is None:
            return None
        return json.loads(raw)

    def recv_until(self, type_filter, timeout=8):
        """Receive messages, skipping ones that don't match type_filter."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = max(0.3, deadline - time.time())
            msg = self.recv(timeout=remaining)
            if msg is None:
                continue   # timeout — no data yet, keep waiting
            if msg.get("type") == type_filter:
                return msg
        return None

    def drain(self, n=5, timeout=0.4):
        """Drain up to n pending messages with a short timeout each."""
        for _ in range(n):
            if self.recv(timeout=timeout) is None:
                break

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

    def register(self, username: str, password: str = "password123"):
        for _ in range(8):
            self.send({"type": "register", "username": username,
                       "email": f"{username}@test.local",
                       "password": _sha256(password)})
            resp = self.recv(timeout=8)
            if (resp and resp.get("type") == "error"
                    and "rate" in resp.get("msg", "").lower()):
                time.sleep(1.2)
                continue
            return resp
        return resp

    def login(self, username: str, password: str = "password123"):
        deadline = time.time() + 18
        resp = None
        while time.time() < deadline:
            self.send({"type": "auth", "username": username,
                       "password": _sha256(password)})
            msg = self.recv(timeout=max(0.3, deadline - time.time()))
            if msg is None:
                continue
            if (msg.get("type") == "error"
                    and "rate" in msg.get("msg", "").lower()):
                time.sleep(1.2)
                continue
            if msg.get("user_id") is not None or msg.get("type") == "error":
                resp = msg
                break
        if resp and resp.get("user_id"):
            self.uid = resp["user_id"]
            self.username = resp.get("username", username)
        return resp

    def register_and_login(self, username: str, password: str = "password123"):
        """Register on a temp connection, then login on this connection."""
        tmp = ChatClient()
        tmp.register(username, password)
        tmp.close()
        resp = self.login(username, password)
        if not self.uid:
            raise AssertionError(f"login failed for {username}: {resp}")
        return self


_counter = 0
_counter_lock = threading.Lock()
_msg_counter = 0
_msg_counter_lock = threading.Lock()


def _unique(prefix="u"):
    global _counter
    with _counter_lock:
        _counter += 1
        return f"{prefix}{_counter}_{int(time.time() * 1000) % 100000}"


def _e2e_body(body: str) -> str:
    """Return a server-accepted SecChat S3 test payload."""
    global _msg_counter
    with _msg_counter_lock:
        _msg_counter += 1
        import base64
        raw = json.dumps({
            "v": 3,
            "dh": "test",
            "pn": 0,
            "n": _msg_counter,
            "ct": body,
        }, separators=(",", ":")).encode("utf-8")
        return "S3DR:" + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _make_friends(c1: ChatClient, c2: ChatClient):
    """Send + accept friend request, then drain async notifications on both sides."""
    c1.send({"type": "friend_request", "target_id": c2.uid})
    c1.recv()                          # "ok" from send
    c2.send({"type": "friend_accept", "requester_id": c1.uid})
    c2.recv()                          # "ok" from accept
    # Drain async notifications: c1 gets friend_accepted, both may get presence
    c1.drain(n=5, timeout=0.4)
    c2.drain(n=5, timeout=0.4)


# ─── Blocking tests ─────────────────────────────────────────────────────────────────────────

class TestBlockingRules(unittest.TestCase):

    def test_block_and_unblock(self):
        """Blocking-1: block_user returns ok; unblock_user returns ok."""
        a = ChatClient(); a.register_and_login(_unique("a71"))
        b = ChatClient(); b.register_and_login(_unique("b71"))
        _make_friends(a, b)

        a.send({"type": "block_user", "user_id": b.uid})
        r = a.recv_until("ok")
        self.assertIsNotNone(r)
        self.assertIn("blocked", r.get("msg", "").lower())

        a.send({"type": "unblock_user", "user_id": b.uid})
        unblock_reply = a.recv_until("ok")
        self.assertIsNotNone(unblock_reply)
        self.assertIn("unblocked", unblock_reply.get("msg", "").lower())
        a.close(); b.close()

    def test_block_prevents_dm_start(self):
        """Blocking-2: after A blocks B, B cannot start_dm with A."""
        a = ChatClient(); a.register_and_login(_unique("a72"))
        b = ChatClient(); b.register_and_login(_unique("b72"))
        _make_friends(a, b)

        a.send({"type": "block_user", "user_id": b.uid})
        a.recv_until("ok")

        b.send({"type": "start_dm", "user_id": a.uid})
        r = b.recv_until("error")
        self.assertIsNotNone(r)
        self.assertIn("blocked", r.get("msg", "").lower())
        a.close(); b.close()

    def test_block_prevents_message_in_dm(self):
        """Blocking-3: message is rejected after B blocks A, even in existing DM."""
        a = ChatClient(); a.register_and_login(_unique("a73"))
        b = ChatClient(); b.register_and_login(_unique("b73"))
        _make_friends(a, b)

        # Create DM first
        a.send({"type": "start_dm", "user_id": b.uid})
        dm = a.recv_until("dm_ready")
        cid = dm["conversation_id"]

        # B blocks A
        b.send({"type": "block_user", "user_id": a.uid})
        b.recv_until("ok")

        # A tries to send
        a.send({"type": "message", "conversation_id": cid,
                "body": _e2e_body("hello!")})
        r = a.recv_until("error")
        self.assertIsNotNone(r)
        self.assertIn("blocked", r.get("msg", "").lower())
        a.close(); b.close()

    def test_get_blocked_list(self):
        """Blocking-4: get_blocked_list returns UIDs that I blocked."""
        a = ChatClient(); a.register_and_login(_unique("a74"))
        b = ChatClient(); b.register_and_login(_unique("b74"))
        c = ChatClient(); c.register_and_login(_unique("c74"))
        _make_friends(a, b)
        _make_friends(a, c)

        a.send({"type": "block_user", "user_id": b.uid})
        a.recv_until("ok")
        a.send({"type": "block_user", "user_id": c.uid})
        a.recv_until("ok")

        a.send({"type": "get_blocked_list"})
        r = a.recv_until("blocked_list")
        self.assertIsNotNone(r)
        self.assertIn(b.uid, r.get("users", []))
        self.assertIn(c.uid, r.get("users", []))
        a.close(); b.close(); c.close()

    def test_removed_moderation_commands_are_unsupported(self):
        """Blocking-5: removed moderation commands return unsupported command."""
        a = ChatClient(); a.register_and_login(_unique("a75"))
        b = ChatClient(); b.register_and_login(_unique("b75"))

        a.send({"type": "report_user", "user_id": b.uid, "reason": "spam"})
        r = a.recv_until("error")
        self.assertIsNotNone(r)
        self.assertIn("unsupported", r.get("msg", "").lower())

        a.send({"type": "report_message", "message_id": 1, "reason": "spam"})
        r = a.recv_until("error")
        self.assertIsNotNone(r)
        self.assertIn("unsupported", r.get("msg", "").lower())
        a.close(); b.close()

    def test_send_rate_limit(self):
        """Blocking-6: sending > 10 messages very rapidly triggers throttling."""
        a = ChatClient(); a.register_and_login(_unique("a77"))
        b = ChatClient(); b.register_and_login(_unique("b77"))
        _make_friends(a, b)

        a.send({"type": "start_dm", "user_id": b.uid})
        dm = a.recv_until("dm_ready")
        cid = dm["conversation_id"]

        # Send 20 messages back-to-back without waiting
        for i in range(20):
            a.send({"type": "message", "conversation_id": cid,
                    "body": _e2e_body(f"msg {i}")})

        # Collect responses — count rate-limit errors
        errors = 0
        for _ in range(25):
            r = a.recv(timeout=3)
            if r is None:
                break
            if r.get("type") == "error" and "rate" in r.get("msg", "").lower():
                errors += 1

        self.assertGreater(errors, 0, "Expected at least one rate-limit error")
        a.close(); b.close()

    def test_friend_accept_notification(self):
        """Blocking-7: accept friend request → requester gets notification."""
        a = ChatClient(); a.register_and_login(_unique("a78"))
        b = ChatClient(); b.register_and_login(_unique("b78"))

        a.send({"type": "friend_request", "target_id": b.uid})
        a.recv()  # ok

        b.send({"type": "friend_accept", "requester_id": a.uid})
        b.recv()  # ok

        # A should receive friend_accepted notification
        notif = a.recv_until("friend_accepted", timeout=5)
        self.assertIsNotNone(notif,
            "A should receive friend_accepted when B accepts the request")
        a.close(); b.close()

    def test_block_self_rejected(self):
        """Blocking-8: blocking yourself returns error."""
        a = ChatClient(); a.register_and_login(_unique("a79"))
        a.send({"type": "block_user", "user_id": a.uid})
        r = a.recv_until("error")
        self.assertIsNotNone(r)
        a.close()

    def test_unblock_nonexistent_noop(self):
        """Blocking-9: unblocking someone you never blocked returns ok (no-op)."""
        a = ChatClient(); a.register_and_login(_unique("a710"))
        b = ChatClient(); b.register_and_login(_unique("b710"))

        a.send({"type": "unblock_user", "user_id": b.uid})
        r = a.recv_until("ok")
        self.assertIsNotNone(r)
        a.close(); b.close()


# ─── Advanced messaging tests ───────────────────────────────────────────────────────────

class TestAdvancedMessaging(unittest.TestCase):

    def _setup_dm(self, prefix="x8"):
        """Helper: two friends with an open DM. Returns (a, b, cid)."""
        a = ChatClient(); a.register_and_login(_unique(f"a{prefix}"))
        b = ChatClient(); b.register_and_login(_unique(f"b{prefix}"))
        _make_friends(a, b)
        a.send({"type": "start_dm", "user_id": b.uid})
        dm = a.recv_until("dm_ready")
        cid = dm["conversation_id"]
        return a, b, cid

    def _send_and_get_id(self, sender: ChatClient, cid: int, body: str):
        """Send a message and return its id from the broadcast."""
        sender.send({"type": "message", "conversation_id": cid,
                     "body": _e2e_body(body)})
        msg = sender.recv_until("message")
        self.assertIsNotNone(msg, f"Expected message broadcast after send: {body}")
        return msg["id"]

    def test_pin_message(self):
        """Messaging-1: pin_message broadcasts message_pinned to both members."""
        a, b, cid = self._setup_dm("81")
        mid = self._send_and_get_id(a, cid, "pin me")
        b.drain(n=3, timeout=0.3)  # drain broadcast on b's side

        a.send({"type": "pin_message", "message_id": mid})
        got_a = a.recv_until("message_pinned")
        got_b = b.recv_until("message_pinned")
        self.assertIsNotNone(got_a)
        self.assertIsNotNone(got_b)
        self.assertEqual(got_a.get("message_id"), mid)
        self.assertEqual(got_b.get("message_id"), mid)
        a.close(); b.close()

    def test_unpin_message(self):
        """Messaging-2: unpin_message broadcasts message_unpinned."""
        a, b, cid = self._setup_dm("82")
        mid = self._send_and_get_id(a, cid, "unpin me")
        b.drain(n=3, timeout=0.3)

        a.send({"type": "pin_message", "message_id": mid})
        a.recv_until("message_pinned"); b.recv_until("message_pinned")

        a.send({"type": "unpin_message", "message_id": mid})
        got = a.recv_until("message_unpinned")
        self.assertIsNotNone(got)
        self.assertEqual(got.get("message_id"), mid)
        a.close(); b.close()

    def test_get_pinned_messages(self):
        """Messaging-3: get_pinned_messages returns the pinned list."""
        a, b, cid = self._setup_dm("83")
        mid = self._send_and_get_id(a, cid, "pin this")
        b.drain(n=3, timeout=0.3)

        a.send({"type": "pin_message", "message_id": mid})
        a.recv_until("message_pinned")

        a.send({"type": "get_pinned_messages", "conversation_id": cid})
        r = a.recv_until("pinned_messages")
        self.assertIsNotNone(r)
        msgs = r.get("messages", [])
        self.assertTrue(any(m.get("message_id") == mid for m in msgs),
                        f"mid={mid} not in pinned list: {msgs}")
        a.close(); b.close()

    def test_get_pinned_messages_empty(self):
        """Messaging-4: get_pinned_messages on conv with no pins returns empty list."""
        a, b, cid = self._setup_dm("84")
        a.send({"type": "get_pinned_messages", "conversation_id": cid})
        r = a.recv_until("pinned_messages")
        self.assertIsNotNone(r)
        self.assertEqual(r.get("messages", []), [])
        a.close(); b.close()

    # Forwarding is now a client-side operation: the client decrypts the
    # plaintext and re-encrypts it as a normal message (wrapped in an SCMSG
    # envelope). The server-side `forward_message` command was removed,
    # so its integration tests were dropped as well.

    def test_set_disappearing_timer(self):
        """Messaging-7: set_disappearing broadcasts disappearing_updated."""
        a, b, cid = self._setup_dm("87")
        a.send({"type": "set_disappearing",
                "conversation_id": cid,
                "disappear_after_secs": 3600})
        got_a = a.recv_until("disappearing_updated")
        got_b = b.recv_until("disappearing_updated")
        self.assertIsNotNone(got_a)
        self.assertIsNotNone(got_b)
        self.assertEqual(got_a.get("disappear_after_secs"), 3600)
        a.close(); b.close()

    def test_clear_disappearing_timer(self):
        """Messaging-8: set_disappearing with secs=0 broadcasts null timer."""
        a, b, cid = self._setup_dm("88")
        a.send({"type": "set_disappearing",
                "conversation_id": cid, "disappear_after_secs": 3600})
        a.recv_until("disappearing_updated")
        b.drain(n=2, timeout=0.3)

        a.send({"type": "set_disappearing",
                "conversation_id": cid, "disappear_after_secs": 0})
        got = a.recv_until("disappearing_updated")
        self.assertIsNotNone(got)
        self.assertIsNone(got.get("disappear_after_secs"))
        a.close(); b.close()

    def test_mute_conversation(self):
        """Messaging-9: mute_conversation returns ok."""
        a, b, cid = self._setup_dm("89")
        a.send({"type": "mute_conversation",
                "conversation_id": cid, "mute_secs": 3600})
        r = a.recv_until("ok")
        self.assertIsNotNone(r)
        a.close(); b.close()

    def test_unmute_conversation(self):
        """Messaging-10: mute_conversation with secs=0 unmutes."""
        a, b, cid = self._setup_dm("810")
        a.send({"type": "mute_conversation",
                "conversation_id": cid, "mute_secs": 3600})
        a.recv_until("ok")
        a.send({"type": "mute_conversation",
                "conversation_id": cid, "mute_secs": 0})
        r = a.recv_until("ok")
        self.assertIsNotNone(r)
        a.close(); b.close()

    def test_archive_conversation_toggle(self):
        """Messaging-11: archive_conversation toggles archive state."""
        a, b, cid = self._setup_dm("811")
        a.send({"type": "archive_conversation", "conversation_id": cid})
        r = a.recv_until("ok")
        self.assertIsNotNone(r)
        # Unarchive
        a.send({"type": "archive_conversation", "conversation_id": cid})
        unarchive_reply = a.recv_until("ok")
        self.assertIsNotNone(unarchive_reply)
        a.close(); b.close()

    def test_pin_conversation_toggle(self):
        """Messaging-12: pin_conversation toggles pin state."""
        a, b, cid = self._setup_dm("812")
        a.send({"type": "pin_conversation", "conversation_id": cid})
        r = a.recv_until("ok")
        self.assertIsNotNone(r)
        # Unpin
        a.send({"type": "pin_conversation", "conversation_id": cid})
        unpin_reply = a.recv_until("ok")
        self.assertIsNotNone(unpin_reply)
        a.close(); b.close()

    def test_mark_unread(self):
        """Messaging-13: mark_unread returns ok."""
        a, b, cid = self._setup_dm("813")
        a.send({"type": "mark_unread", "conversation_id": cid})
        r = a.recv_until("ok")
        self.assertIsNotNone(r)
        a.close(); b.close()

    def test_nonmember_pin_rejected(self):
        """Messaging-14: non-member cannot pin a message."""
        a = ChatClient(); a.register_and_login(_unique("a814"))
        b = ChatClient(); b.register_and_login(_unique("b814"))
        c = ChatClient(); c.register_and_login(_unique("c814"))
        _make_friends(a, b)

        a.send({"type": "start_dm", "user_id": b.uid})
        dm = a.recv_until("dm_ready")
        cid = dm["conversation_id"]

        mid = self._send_and_get_id(a, cid, "secret")
        b.drain(n=3, timeout=0.3)

        # c is not a member of this DM — pin should fail
        c.send({"type": "pin_message", "message_id": mid})
        r = c.recv_until("error")
        self.assertIsNotNone(r)
        a.close(); b.close(); c.close()



# ─── Change password tests ────────────────────────────────────────────────────

class TestChangePassword(unittest.TestCase):

    def test_CP_1_change_password_success(self):
        """CP-1: change_password with correct old_password returns ok."""
        uname = _unique("cp1")
        a = ChatClient(); a.register_and_login(uname, "oldpass123")
        a.send({"type": "change_password",
                "old_password": _sha256("oldpass123"),
                "new_password": _sha256("newpass456")})
        r = a.recv_until("ok")
        self.assertIsNotNone(r)
        self.assertIn("changed", r.get("msg", "").lower())
        a.close()

    def test_CP_2_change_password_wrong_old(self):
        """CP-2: change_password with wrong old_password returns error."""
        uname = _unique("cp2")
        a = ChatClient(); a.register_and_login(uname, "mypassword")
        a.send({"type": "change_password",
                "old_password": _sha256("wrongpassword"),
                "new_password": _sha256("newpass456")})
        r = a.recv_until("error")
        self.assertIsNotNone(r)
        self.assertIn("incorrect", r.get("msg", "").lower())
        a.close()

    def test_CP_3_login_with_new_password(self):
        """CP-3: after change_password, login with new password succeeds."""
        uname = _unique("cp3")
        a = ChatClient(); a.register_and_login(uname, "oldpass123")
        a.send({"type": "change_password",
                "old_password": _sha256("oldpass123"),
                "new_password": _sha256("newpass789")})
        a.recv_until("ok")
        a.close()

        b = ChatClient()
        r = b.login(uname, "newpass789")
        self.assertIsNotNone(r.get("user_id"),
                             "Login with new password should succeed")
        b.close()

    def test_CP_4_old_password_no_longer_works(self):
        """CP-4: after change_password, old password is rejected."""
        uname = _unique("cp4")
        a = ChatClient(); a.register_and_login(uname, "oldpass123")
        a.send({"type": "change_password",
                "old_password": _sha256("oldpass123"),
                "new_password": _sha256("newpass789")})
        a.recv_until("ok")
        a.close()

        b = ChatClient()
        r = b.login(uname, "oldpass123")
        self.assertIsNone(r.get("user_id"),
                          "Old password should no longer work after change")
        b.close()

    def test_CP_5_change_password_requires_auth(self):
        """CP-5: change_password without prior login returns error."""
        uname = _unique("cp5")
        # Register on a temp connection
        tmp = ChatClient()
        tmp.send({"type": "register", "username": uname,
                  "email": f"{uname}@test.local",
                  "password": _sha256("mypass")})
        tmp.recv()
        tmp.close()

        # New connection — NOT logged in
        a = ChatClient()
        a.send({"type": "change_password",
                "old_password": _sha256("mypass"),
                "new_password": _sha256("newpass")})
        r = a.recv_until("error")
        self.assertIsNotNone(r, "Should get error when not authenticated")
        a.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
