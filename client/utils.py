"""Các tiện ích mật mã cấp thấp của SecChat.

Module này gom các primitive dùng chung: băm mật khẩu (PBKDF2), dẫn xuất master
key, mã hóa/giải mã AES-256-GCM tại chỗ và sinh khóa định danh Ed25519. Tầng
giao thức (secure_protocol.py, session.py) gọi các hàm ở đây để dựng bundle và
mã hóa state cục bộ.

Ghi chú về xóa khóa khỏi bộ nhớ:
  Python không đảm bảo secret (bytes/str) bị xóa khỏi RAM khi ra khỏi scope — GC
  có thể giữ bản sao trong heap. Muốn xóa chắc chắn phải dùng native extension
  (vd ctypes.memset). Đây là giới hạn được ghi nhận, không khắc phục, vì threat
  model của đồ án không bao gồm forensics bộ nhớ vật lý.

Ghi chú về chống replay:
  AES-256-GCM với nonce ngẫu nhiên 96-bit đã chống *giả mạo* tin mới. Nhưng kẻ
  địch bắt được ciphertext hợp lệ rồi gửi lại vẫn khiến server phát lại (replay).
  Để giảm thiểu, ta nhúng timestamp (mili-giây) vào payload đã mã hóa; bên nhận
  từ chối tin có timestamp cũ hơn REPLAY_WINDOW_MS. Dedup ở tầng server là biện
  pháp bổ sung (tương lai).
"""

import os
import base64
import json
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives            import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption)
from cryptography.exceptions import InvalidSignature

# Từ chối tin có timestamp nhúng cũ hơn cửa sổ này (chống replay).
REPLAY_WINDOW_MS = 5 * 60 * 1000   # 5 phút, tính bằng mili-giây

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Băm mật khẩu phía client (PBKDF2)
# ----------------------------------------------------------------------
#
# Hash gửi lên server là PBKDF2-HMAC-SHA256 trên mật khẩu thô, salt là email
# (viết thường) của người dùng, 100 000 vòng lặp. Việc này khiến tấn công từ
# điển offline trên credential bị nghe lén khó hơn nhiều so với SHA-256 trần.
#
# Mô hình hai tầng:
#   Client -> PBKDF2(pw, email, 100k)                      <- hàm này
#   Server -> PBKDF2(client_hash, salt_ngẫu_nhiên, 600k)   <- tầng server phía trên
#
# Vì sao salt = email:
#  - Email có sẵn ở cả trang đăng ký lẫn đăng nhập nên hai bên ra cùng hash mà
#    không cần thêm round-trip.
#  - Salt = email (giá trị biết trước) nên không tốn chỗ lưu thêm; phần ngẫu
#    nhiên nằm ở tầng 600k vòng của server phía trên.
#
# LƯU Ý: nếu người dùng đăng nhập bằng *username* (server hỗ trợ), client băm với
# salt = username thay vì email. Vẫn nhất quán miễn là dùng cùng một giá trị ở cả
# lúc đăng ký và đăng nhập.

_CLIENT_PBKDF2_ITERS = 100_000


def hash_password(password: str, salt: str) -> str:
    """Băm mật khẩu phía client bằng PBKDF2-HMAC-SHA256.

    Tham số:
        password: Mật khẩu thô người dùng nhập.
        salt:     Salt theo từng người — dùng email (viết thường) ở cả trang
                  đăng ký lẫn đăng nhập để hai bên ra cùng một hash.

    Trả về:
        Chuỗi hex 32 byte PBKDF2 — chính là ``pw_hash`` client gửi lên server
        (server còn băm thêm 600k vòng nữa với salt ngẫu nhiên trước khi lưu).
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.lower().encode(),
        iterations=_CLIENT_PBKDF2_ITERS,
    )
    return kdf.derive(password.encode()).hex()


def ts_short(ts: str) -> str:
    """Rút gọn timestamp '2024-01-01 14:35:22' thành '14:35' để hiển thị."""
    if not ts:
        return ""
    parts = ts.split(" ")
    if len(parts) > 1:
        return parts[1][:5]
    return ts[:5]

def derive_master_key(password: str, username: str) -> bytes:
    """Dẫn xuất master key 32 byte từ mật khẩu + username (làm salt).

    Tất định: cùng input → cùng output, nên thiết bị nào cũng tính lại được để mở
    state cục bộ. TUYỆT ĐỐI không gửi key này lên server; nó chỉ dùng để mã hóa
    tại chỗ các file nhạy cảm (identity sk, prekey, state DR/MLS, cache tin).
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=username.lower().encode(),   # salt = username, cố định và biết trước
        iterations=600_000,               # NIST recommend 2023
    )
    return kdf.derive(password.encode())


def encrypt_with_key(key: bytes, plaintext: str) -> str:
    """Mã hóa plaintext bằng AES-256-GCM, có bọc timestamp chống replay.

    Nhúng timestamp (mili-giây) vào envelope JSON để bên nhận từ chối frame bị
    phát lại cũ hơn REPLAY_WINDOW_MS.
    Định dạng wire: base64( nonce[12] || AES-GCM( JSON({ts, body}) ) ).
    """
    nonce  = os.urandom(12)   # nonce ngẫu nhiên 96-bit, mỗi tin một nonce khác nhau
    ts_ms  = int(time.time() * 1000)
    inner  = json.dumps({"ts": ts_ms, "body": plaintext}, ensure_ascii=False)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, inner.encode(), None)
    return base64.b64encode(nonce + ciphertext).decode()


def decrypt_with_key(key: bytes, token: str, check_replay: bool = True) -> str:
    """Giải mã token (base64) bằng AES-256-GCM và kiểm timestamp chống replay.

    Mọi dữ liệu do SecChat mã hóa đều ở dạng envelope ``{ts, body}``; nếu giải ra
    không phải JSON hợp lệ thì lỗi sẽ được ném ra cho handler chung phía trên xử
    lý (hiển thị "[Cannot decrypt]") — không nhận định dạng đã gỡ bỏ.

    check_replay=False: bỏ kiểm timestamp. Dùng cho dữ liệu LƯU TRỮ (file state
    Double Ratchet / MLS, identity sk, cache tin...) vốn có thể cũ hơn cửa sổ
    REPLAY_WINDOW_MS một cách hợp lệ.
    """
    raw = base64.b64decode(token.encode())
    nonce, ciphertext = raw[:12], raw[12:]
    aesgcm  = AESGCM(key)
    plainbytes = aesgcm.decrypt(nonce, ciphertext, None)   # ném lỗi nếu bị sửa / sai key
    envelope = json.loads(plainbytes.decode())             # luôn là envelope {ts, body}
    if check_replay:
        ts_ms = envelope.get("ts", 0)
        now_ms = int(time.time() * 1000)
        if ts_ms and (now_ms - ts_ms) > REPLAY_WINDOW_MS:
            raise ValueError(
                f"Replay detected: message timestamp is {(now_ms - ts_ms) // 1000}s old"
            )
    return envelope.get("body", "")


def encrypt_key_with_master(master_key: bytes, conv_key: bytes) -> str:
    """Wrap một conversation key bằng master key để lưu lên server."""
    return encrypt_with_key(master_key, base64.b64encode(conv_key).decode())


def decrypt_key_with_master(master_key: bytes, token: str) -> bytes:
    """Unwrap conversation key từ server. AT-REST: no replay window check."""
    return base64.b64decode(
        decrypt_with_key(master_key, token, check_replay=False).encode())


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Khóa định danh Ed25519  (gốc của Safety Number)
# ----------------------------------------------------------------------
#
# Khóa định danh sống lâu dài (không tự rotate) và dùng để KÝ mọi prekey (PQXDH,
# MLS KeyPackage) cùng self-certification chính nó trước khi upload lên server.
# Bất kỳ peer nào nhận key material đều kiểm được nó do đúng chủ tạo ra, không bị
# server tráo (chống MITM).
#
# Safety Number tính từ khóa định danh nên fingerprint giữ nguyên qua các lần
# xoay prekey.

IDENTITY_ALG = "Ed25519"


def identity_keygen() -> tuple[bytes, bytes]:
    """Sinh cặp khóa định danh Ed25519.

    Trả về ``(public_key, secret_key)`` — mỗi cái 32 byte (raw). Secret key phải
    lưu mã hóa trên đĩa; public key chia sẻ thoải mái. Đây là gốc của safety
    number và là khóa ký mọi prekey.
    """
    sk = Ed25519PrivateKey.generate()
    pk_bytes = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sk_bytes = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return pk_bytes, sk_bytes


def identity_pk_from_sk(sk_bytes: bytes) -> bytes:
    """Khôi phục public key Ed25519 từ seed private 32 byte."""
    sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def identity_sign(sk_bytes: bytes, message: bytes) -> bytes:
    """Ký *message* bằng seed private Ed25519 32 byte. Trả về chữ ký 64 byte."""
    sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)
    return sk.sign(message)


def identity_verify(pk_bytes: bytes, message: bytes, signature: bytes) -> None:
    """Kiểm *signature* trên *message* bằng public key Ed25519 32 byte.

    Ném ``ValueError`` nếu chữ ký sai. Người gọi BẮT BUỘC kiểm hàm này trước khi
    dùng bất kỳ key material nào từ nguồn không tin cậy (chống MITM tráo khóa).
    """
    pk = Ed25519PublicKey.from_public_bytes(pk_bytes)
    try:
        pk.verify(signature, message)
    except InvalidSignature as exc:
        raise ValueError(f"Identity signature invalid: {exc}") from exc


def initials_pixmap(username: str, size: int = 32):
    """
    Generate a circular avatar pixmap with the user's initial.
    Returns a QPixmap of `size x size` pixels.
    """
    from PyQt5.QtGui import QPixmap, QPainter, QColor, QFont
    from PyQt5.QtCore import Qt
    _COLORS = [
        "#5865f2", "#57f287", "#fee75c", "#eb459e", "#ed4245",
        "#3ba55d", "#faa61a", "#00b0f4", "#7289da", "#9b84ee",
    ]
    color   = _COLORS[hash(username) % len(_COLORS)]
    initial = (username[0].upper()) if username else "?"
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setBrush(QColor(color))
    p.setPen(Qt.NoPen)
    p.drawEllipse(0, 0, size, size)
    p.setPen(QColor("#ffffff"))
    font = QFont()
    font.setBold(True)
    font.setPixelSize(max(1, int(size * 0.45)))
    p.setFont(font)
    p.drawText(0, 0, size, size, Qt.AlignCenter, initial)
    p.end()
    return pm


def make_circular_pixmap(pm, size: int):
    """
    Scale and clip a QPixmap to a circle of `size × size` with transparent background.
    """
    from PyQt5.QtGui import QPixmap, QPainter, QBrush
    from PyQt5.QtCore import Qt
    scaled = pm.scaled(size, size, Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation)
    if scaled.width() > size:
        scaled = scaled.copy((scaled.width() - size) // 2, 0, size, size)
    if scaled.height() > size:
        scaled = scaled.copy(0, (scaled.height() - size) // 2, size, size)
    result = QPixmap(size, size)
    result.fill(Qt.transparent)
    p = QPainter(result)
    p.setRenderHint(QPainter.Antialiasing)
    p.setBrush(QBrush(scaled))
    p.setPen(Qt.NoPen)
    p.drawEllipse(0, 0, size, size)
    p.end()
    return result


def avatar_from_b64(b64_str: str, size: int = 48):
    """
    Decode a base64 avatar string and return a circular QPixmap.
    Returns None if the image data is invalid.
    """
    from PyQt5.QtGui import QPixmap, QImage
    try:
        raw = base64.b64decode(b64_str)
    except Exception:
        return None
    img = QImage()
    img.loadFromData(raw)
    if img.isNull():
        return None
    return make_circular_pixmap(QPixmap.fromImage(img), size)
