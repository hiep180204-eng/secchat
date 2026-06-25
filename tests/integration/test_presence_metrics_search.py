#!/usr/bin/env python3
"""Security and metrics regression test suite"""

import sys, os, ssl, socket, json, time, base64, subprocess, hashlib

# ── Copy cert from container ─────────────────────────────────────
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
    raw = socket.socket(); raw.settimeout(8); raw.connect((HOST, PORT))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(CERT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = False
    s = ctx.wrap_socket(raw, server_hostname="chat-server")
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET / HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
               f"Sec-WebSocket-Version: 13\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf: buf += s.recv(1024)
    assert b"101" in buf
    return s

def ws_send(s, obj):
    payload = json.dumps(obj).encode()
    n = len(payload); mk = os.urandom(4); hdr = bytearray([0x81])
    if   n <= 125:   hdr += bytes([0x80 | n])
    elif n <= 65535: hdr += bytes([0x80 | 126]) + n.to_bytes(2, "big")
    else:            hdr += bytes([0x80 | 127]) + n.to_bytes(8, "big")
    hdr += mk
    s.sendall(bytes(hdr) + bytes(b ^ mk[i % 4] for i, b in enumerate(payload)))

def ws_recv(s):
    def read(n):
        d = b""
        while len(d) < n:
            c = s.recv(n - len(d))
            if not c: raise ConnectionError("closed")
            d += c
        return d
    h = read(2); op = h[0] & 0xf; plen = h[1] & 0x7f
    if plen == 126: plen = int.from_bytes(read(2), "big")
    elif plen == 127: plen = int.from_bytes(read(8), "big")
    data = read(plen)
    if op == 0x08: raise ConnectionError("server closed")
    return json.loads(data.decode())

def drain(s, t=0.5):
    s.settimeout(t); msgs = []
    try:
        while True: msgs.append(ws_recv(s))
    except: pass
    s.settimeout(8); return msgs

def pw_hash(pw): return hashlib.sha256(pw.encode()).hexdigest()
PASS = "P@ssw0rd123!"; PH = pw_hash(PASS)

ok = 0; fail = 0

def check(name, cond, detail=""):
    global ok, fail
    if cond:
        print(f"  PASS  {name}"); ok += 1
    else:
        print(f"  FAIL  {name}" + (f" -- {detail}" if detail else "")); fail += 1

# Register two test users
def try_reg(u, e):
    s = ws_connect()
    ws_send(s, {"type": "register", "username": u, "email": e, "password": PH})
    r = ws_recv(s); s.close(); return r

try_reg("p34A", "p34a@t.com")
try_reg("p34B", "p34b@t.com")

def login(email):
    s = ws_connect()
    ws_send(s, {"type": "auth", "email": email, "password": PH})
    r = ws_recv(s)
    return s, r.get("user_id")

# ================================================================
# Email is not written to server logs.
# ================================================================
print("\n=== Email redacted from server logs ===")
logs = subprocess.run(["docker", "logs", "chat-server"], capture_output=True, text=True)
all_logs = logs.stdout + logs.stderr
check("Email 'p34a@t.com' NOT in server logs",
      "p34a@t.com" not in all_logs,
      "found email in logs!")
check("Email 'p34b@t.com' NOT in server logs",
      "p34b@t.com" not in all_logs)

# ================================================================
# VNC password is intentionally fixed for the local demo container.
# ================================================================
print("\n=== VNC password is fixed for local demo ===")
check("VNC password line printed in logs",
      "VNC password:" in all_logs)
check("VNC password 'docker' present in logs",
      "VNC password: docker" in all_logs)

# ================================================================
# MAX_CLIENTS is set to 200.
# ================================================================
print("\n=== MAX_CLIENTS = 200 ===")
# The server log should say max 200 clients
check("Server log shows 200 max clients",
      "max 200 clients" in all_logs,
      all_logs[:500] if "max" not in all_logs else "")

# ================================================================
# Search rate limiting
# ================================================================
print("\n=== Search rate limiting ===")
try:
    sA, uidA = login("p34a@t.com")
    # A short burst should be rate-limited. The server may allow more than one
    # immediate query, so do not assume the second frame is the throttled one.
    ws_send(sA, {"type": "search_user", "query": "p34"})
    search_hit = ws_recv(sA)
    blocked = None
    burst = []
    for _ in range(5):
        ws_send(sA, {"type": "search_user", "query": "p34"})
        got = ws_recv(sA)
        burst.append(got)
        if (got.get("type") == "search_result" and len(got.get("users", [])) == 0) \
                or got.get("type") == "error":
            blocked = got
            break
    check("First search returns results",
          search_hit.get("type") == "search_result"
          and len(search_hit.get("users", [])) > 0,
          str(search_hit))
    check("Rapid search burst is rate-limited",
          blocked is not None,
          str(burst))
    # Wait 1 second, search should work again
    time.sleep(1.1)
    ws_send(sA, {"type": "search_user", "query": "p34"})
    search_after_cooldown = ws_recv(sA)
    check("Search works again after 1s cooldown",
          search_after_cooldown.get("type") == "search_result"
          and len(search_after_cooldown.get("users", [])) > 0,
          str(search_after_cooldown))
    sA.close()
except Exception as e:
    check("Search rate limit tests", False, str(e))
    import traceback; traceback.print_exc()

# ================================================================
# Server-side message body size limit
# ================================================================
print("\n=== Server-side body size limit ===")
try:
    sA, uidA = login("p34a@t.com")
    sB, uidB = login("p34b@t.com")
    # Make them friends first
    ws_send(sA, {"type": "friend_request", "target_id": uidB}); drain(sA)
    ws_send(sB, {"type": "friend_accept", "requester_id": uidA}); drain(sB)
    drain(sA); drain(sB)
    # Start DM
    ws_send(sA, {"type": "start_dm", "user_id": uidB})
    r = ws_recv(sA)
    conv_id = r.get("conversation_id", 0)
    drain(sA); drain(sB)
    # Send oversized body (> 22 MB)
    huge = "X" * (23 * 1024 * 1024)
    ws_send(sA, {"type": "message", "conversation_id": conv_id, "body": huge})
    r = ws_recv(sA)
    check("Oversized message body rejected by server",
          r.get("type") == "error",
          r.get("msg","") or str(r)[:100])
    sA.close(); sB.close()
except Exception as e:
    check("Body size limit test", False, str(e))

# ================================================================
# Profile visibility: authenticated users can view basic profile/avatar.
# ================================================================
print("\n=== Profile visible to authenticated users ===")
try:
    sA, uidA = login("p34a@t.com")

    # Register a stranger that is NOT friends with A
    try_reg("stranger99", "s99@t.com")
    sS, uidS = login("s99@t.com")

    # Stranger can view basic profile/avatar. Status and last-seen are still
    # filtered by the profile privacy flags, but the avatar must be available
    # in shared group contexts without noisy "friends only" popups.
    ws_send(sS, {"type": "get_profile", "user_id": uidA})
    r = ws_recv(sS)
    check("Authenticated user can view basic profile",
          r.get("type") == "profile" and r.get("user_id") == uidA and r.get("is_own") == False,
          str(r)[:100])

    # A views own profile — always allowed
    ws_send(sA, {"type": "get_profile", "user_id": 0})
    r = ws_recv(sA)
    check("Own profile always visible",
          r.get("type") == "profile" and r.get("is_own") == True,
          str(r)[:100])

    sA.close(); sS.close()
except Exception as e:
    check("Profile privacy tests", False, str(e))
    import traceback; traceback.print_exc()

# ================================================================
# Avatar MIME / magic byte validation
# ================================================================
print("\n=== Avatar MIME magic byte validation ===")
try:
    sA, uidA = login("p34a@t.com")

    # Send fake JPEG (just random bytes, not a real JPEG)
    fake_data = base64.b64encode(b"\x00\x01\x02\x03" * 100).decode()
    ws_send(sA, {"type": "upload_avatar", "data": fake_data, "mime": "image/jpeg"})
    r = ws_recv(sA)
    check("Fake JPEG (wrong magic bytes) rejected",
          r.get("type") == "error",
          r.get("msg",""))

    # Send valid PNG magic bytes (89 50 4E 47 0D 0A 1A 0A) — even if truncated
    valid_png_magic = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100
    good_data = base64.b64encode(valid_png_magic).decode()
    ws_send(sA, {"type": "upload_avatar", "data": good_data, "mime": "image/png"})
    r = ws_recv(sA)
    # May fail with MySQL decode error on a truncated PNG, but should not say "Invalid image"
    check("Valid PNG magic bytes NOT rejected by MIME check",
          "Invalid image" not in r.get("msg", ""),
          r.get("msg",""))

    sA.close()
except Exception as e:
    check("Avatar MIME tests", False, str(e))

# ================================================================
# M-10: Replay protection in E2E layer
# ================================================================
print("\n=== M-10: E2E replay protection ===")
import sys
sys.path.insert(0, REPO_DIR)
try:
    from client.utils import encrypt_with_key, decrypt_with_key
    key = os.urandom(32)

    # Normal encrypt/decrypt should work
    ct = encrypt_with_key(key, "hello world")
    pt = decrypt_with_key(key, ct)
    check("Normal encrypt/decrypt round-trip works", pt == "hello world", pt)

    # Simulate a 6-minute-old message by patching the timestamp
    import json as _json
    raw = base64.b64decode(ct.encode())
    nonce, ciphertext = raw[:12], raw[12:]
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(key)
    inner = _json.loads(aesgcm.decrypt(nonce, ciphertext, None).decode())
    inner["ts"] = inner["ts"] - (6 * 60 * 1000)   # 6 minutes ago
    old_inner = _json.dumps(inner).encode()
    old_ct_bytes = nonce + aesgcm.encrypt(nonce, old_inner, None)
    old_token = base64.b64encode(old_ct_bytes).decode()

    try:
        pt2 = decrypt_with_key(key, old_token)
        check("6-minute-old message rejected as replay", False, f"got: {pt2!r}")
    except ValueError as e:
        check("6-minute-old message rejected as replay", True)
    except Exception as e:
        check("6-minute-old message rejected as replay", False, str(e))

    # Recent message (1 second old) must NOT be rejected
    inner2 = {"ts": int(time.time() * 1000) - 1000, "body": "recent"}
    nonce2 = os.urandom(12)
    ct2_bytes = nonce2 + aesgcm.encrypt(nonce2, _json.dumps(inner2).encode(), None)
    token2 = base64.b64encode(ct2_bytes).decode()
    pt3 = decrypt_with_key(key, token2)
    check("1-second-old message accepted", pt3 == "recent", pt3)

except Exception as e:
    check("Replay protection tests", False, str(e))
    import traceback; traceback.print_exc()

# ================================================================
# L-1: Thread-safe localtime (log format sanity check)
# ================================================================
print("\n=== L-1: localtime_r / log timestamp sanity ===")
check("Server log lines have valid HH:MM:SS timestamps",
      any(line[1:9].count(":") == 2
          for line in all_logs.splitlines()
          if line.startswith("[")),
      "no timestamp lines found")

# ================================================================
# Summary
# ================================================================
print(f"\n{'='*54}")
print(f"Security and metrics results: {ok} passed, {fail} failed")
sys.exit(0 if fail == 0 else 1)
