"""CÃ¡c primitive giao thá»©c SecChat.

File nÃ y cá»‘ tÃ¬nh Ä‘á»©ng Ä‘á»™c láº­p vá»›i PyQt. UI chá»‰ nÃªn yÃªu cáº§u "mÃ£ hÃ³a", "giáº£i
mÃ£" hoáº·c "táº¡o Welcome", cÃ²n cÃ¡c bÆ°á»›c chuyá»ƒn tráº¡ng thÃ¡i giao thá»©c pháº£i náº±m á»Ÿ
Ä‘Ã¢y. CÃ¡ch tÃ¡ch nÃ y giÃºp Ä‘á»c vÃ  kiá»ƒm tra crypto dá»… hÆ¡n, vÃ¬ controller giao diá»‡n
khÃ´ng pháº£i biáº¿t chi tiáº¿t wire format.

SecChat láº¥y Ã½ tÆ°á»Ÿng tá»« Signal PQXDH, Double Ratchet vÃ  MLS, nhÆ°ng khÃ´ng
tÆ°Æ¡ng thÃ­ch wire format vá»›i Signal hay MLS RFC 9420. VÃ¬ váº­y cÃ¡c prefix
``S3PQI:``, ``S3DR:`` vÃ  ``S3MLS:`` lÃ  format riÃªng cá»§a SecChat.
"""

from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

try:
    import oqs as _oqs
except Exception:  # pragma: no cover - exercised only on hosts without liboqs.
    _oqs = None


SECCHAT_SCHEMA = 3

# Prefix cá»§a body message Ä‘Æ°á»£c lÆ°u trong database vÃ  chuyá»ƒn qua WebSocket.
# Server chá»‰ cáº§n kiá»ƒm tra prefix Ä‘á»ƒ tá»« chá»‘i plaintext hoáº·c format cÅ©; server
# khÃ´ng giáº£i mÃ£ Ä‘Æ°á»£c payload phÃ­a sau prefix.
PREFIX_PQ_INIT = "S3PQI:"
PREFIX_DR = "S3DR:"
PREFIX_MLS = "S3MLS:"

# ML-KEM-1024 lÃ  lá»±a chá»n máº·c Ä‘á»‹nh khi thÆ° viá»‡n OQS há»— trá»£. CÃ¡c biáº¿n thá»ƒ Kyber
# Ä‘Æ°á»£c giá»¯ Ä‘á»ƒ mÃ´i trÆ°á»ng phÃ¡t triá»ƒn cÅ© váº«n cháº¡y Ä‘Æ°á»£c, nhÆ°ng thuáº­t toÃ¡n Ä‘Ã£ chá»n
# luÃ´n Ä‘Æ°á»£c ghi vÃ o bundle Ä‘á»ƒ hai phÃ­a khÃ´ng hiá»ƒu nháº§m khi báº¯t tay khÃ³a.
DEFAULT_KEM = "ML-KEM-1024"
ALLOWED_KEMS = ("ML-KEM-1024", "Kyber1024", "ML-KEM-768", "Kyber768")
MAX_SKIP_KEYS = 1000


def b64e(raw: bytes) -> str:
    """Base64 url-safe khÃ´ng padding Ä‘á»ƒ wire message ngáº¯n vÃ  dá»… nhÃºng JSON."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    """Giáº£i mÃ£ cáº£ chuá»—i url-safe thiáº¿u padding do ``b64e`` táº¡o ra."""
    return base64.urlsafe_b64decode((text + ("=" * (-len(text) % 4))).encode("ascii"))


def json_b64(obj: dict[str, Any]) -> str:
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return b64e(raw)


def json_unb64(token: str) -> dict[str, Any]:
    return json.loads(b64d(token).decode("utf-8"))


def hkdf(ikm: bytes, info: bytes, *, salt: bytes | None = None, length: int = 32) -> bytes:
    """HKDF-SHA256: nghiền một bí mật thô (ikm) + nhãn (info) thành khóa sạch.

    Dùng khắp giao thức để tách khóa độc lập (root, chain, header...) từ cùng một
    nguồn bí mật; ``info`` đóng vai trò domain separation giữa các mục đích.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def _aead_encrypt(key: bytes, obj: dict[str, Any], aad: bytes = b"") -> str:
    """Mã hóa AEAD (AES-256-GCM) một object JSON → base64(nonce 12B || ciphertext).

    AAD được xác thực nhưng không mã hóa — đổi AAD sẽ làm giải mã thất bại.
    """
    nonce = os.urandom(12)
    plain = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ct = AESGCM(key).encrypt(nonce, plain, aad)
    return b64e(nonce + ct)


def _aead_decrypt(key: bytes, token: str, aad: bytes = b"") -> dict[str, Any]:
    """Giải mã AEAD; raise nếu key/nonce/AAD/ciphertext không khớp (toàn vẹn hỏng)."""
    raw = b64d(token)
    plain = AESGCM(key).decrypt(raw[:12], raw[12:], aad)
    return json.loads(plain.decode("utf-8"))


def available_kems() -> tuple[str, ...]:
    if _oqs is None:
        return ()
    try:
        enabled = set(_oqs.get_enabled_kem_mechanisms())
    except AttributeError:
        enabled = set(ALLOWED_KEMS)
    return tuple(name for name in ALLOWED_KEMS if name in enabled)


def select_kem(preferred: str | None = None) -> str:
    """Chá»n thuáº­t toÃ¡n KEM kháº£ dá»¥ng trÃªn mÃ¡y hiá»‡n táº¡i.

    Má»—i mÃ¡y cÃ³ thá»ƒ cÃ i phiÃªn báº£n liboqs khÃ¡c nhau. HÃ m nÃ y Æ°u tiÃªn thuáº­t toÃ¡n
    Ä‘Æ°á»£c yÃªu cáº§u náº¿u há»£p lá»‡, sau Ä‘Ã³ dÃ¹ng máº·c Ä‘á»‹nh, rá»“i má»›i fallback sang cÃ¡c
    biáº¿n thá»ƒ khÃ¡c. Viá»‡c chá»n luÃ´n náº±m á»Ÿ client vÃ¬ server chá»‰ lÆ°u public material
    vÃ  khÃ´ng cháº¡y KEM cho ná»™i dung tin nháº¯n.
    """
    enabled = available_kems()
    if preferred and preferred in ALLOWED_KEMS and (not enabled or preferred in enabled):
        return preferred
    if DEFAULT_KEM in enabled:
        return DEFAULT_KEM
    for name in ALLOWED_KEMS:
        if not enabled or name in enabled:
            return name
    raise RuntimeError("No supported ML-KEM/Kyber mechanism is enabled")


def kem_keygen(alg: str) -> tuple[bytes, bytes]:
    """Sinh cặp khóa KEM hậu lượng tử (ML-KEM/Kyber) → (public, secret)."""
    if _oqs is None:
        raise RuntimeError("liboqs is not available")
    with _oqs.KeyEncapsulation(alg) as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
    return pk, sk


def kem_encapsulate(alg: str, public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate: từ public key sinh (ciphertext, shared_secret) ngẫu nhiên.

    Phía gửi gọi hàm này; ciphertext gửi cho bên kia, shared_secret giữ lại để
    trộn vào root. Đây là bước thay thế Diffie-Hellman bằng KEM hậu lượng tử.
    """
    if _oqs is None:
        raise RuntimeError("liboqs is not available")
    with _oqs.KeyEncapsulation(alg) as kem:
        ct, ss = kem.encap_secret(public_key)
    return ct, ss


def kem_decapsulate(alg: str, secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate: từ secret key + ciphertext khôi phục đúng shared_secret."""
    if _oqs is None:
        raise RuntimeError("liboqs is not available")
    with _oqs.KeyEncapsulation(alg, secret_key=secret_key) as kem:
        return kem.decap_secret(ciphertext)


def x25519_keygen() -> tuple[bytes, bytes]:
    """Sinh cặp khóa X25519 (Diffie-Hellman cổ điển) → (public, secret) dạng raw."""
    sk = X25519PrivateKey.generate()
    return (
        sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
    )


def x25519_dh(sk_bytes: bytes, peer_pk_bytes: bytes) -> bytes:
    """DH X25519: tính bí mật chung 32 byte từ secret của mình + public của peer."""
    sk = X25519PrivateKey.from_private_bytes(sk_bytes)
    pk = X25519PublicKey.from_public_bytes(peer_pk_bytes)
    return sk.exchange(pk)


def _ed_priv(sk_bytes: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(sk_bytes)


def _ed_pub(pk_bytes: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(pk_bytes)


def _sig_msg(kind: str, key_id: int, alg: str, public_key: bytes) -> bytes:
    return (
        b"SecChatPreKey\x00"
        + kind.encode("ascii")
        + b"\x00"
        + str(int(key_id)).encode("ascii")
        + b"\x00"
        + alg.encode("ascii")
        + b"\x00"
        + public_key
    )


def sign_prekey(identity_sk: bytes, kind: str, key_id: int, alg: str,
                public_key: bytes) -> bytes:
    """Identity key Ed25519 ký một prekey → chứng minh prekey thuộc identity này."""
    return _ed_priv(identity_sk).sign(_sig_msg(kind, key_id, alg, public_key))


def verify_prekey(identity_pk: bytes, kind: str, key_id: int, alg: str,
                  public_key: bytes, sig: bytes) -> None:
    """Kiểm chữ ký prekey; raise nếu sai → phát hiện server tráo prekey không khớp identity."""
    _ed_pub(identity_pk).verify(sig, _sig_msg(kind, key_id, alg, public_key))


def _new_key_id() -> int:
    return int(time.time() * 1000) & 0x7fffffff


def generate_local_bundle(identity_pk: bytes, identity_sk: bytes,
                          *, kem_alg: str | None = None,
                          otk_count: int = 8) -> tuple[dict[str, Any], dict[str, Any]]:
    """Táº¡o prekey bundle vÃ  pháº§n secret tÆ°Æ¡ng á»©ng Ä‘á»ƒ lÆ°u cá»¥c bá»™.

    GiÃ¡ trá»‹ tráº£ vá» gá»“m hai pháº§n:

    * ``upload``: chá»‰ chá»©a public key vÃ  chá»¯ kÃ½, Ä‘Æ°á»£c gá»­i lÃªn server.
    * ``local``: chá»©a secret key cá»§a signed prekey vÃ  one-time prekey, pháº£i Ä‘Æ°á»£c
      mÃ£ hÃ³a báº±ng master key trÆ°á»›c khi ghi xuá»‘ng Ä‘Ä©a.

    Identity key Ed25519 kÃ½ cáº£ prekey X25519 vÃ  prekey KEM. Nhá» váº­y khi má»™t
    client khÃ¡c láº¥y bundle tá»« server, há» cÃ³ thá»ƒ phÃ¡t hiá»‡n server thay prekey
    khÃ´ng khá»›p vá»›i identity key Ä‘Ã£ cÃ´ng bá»‘.
    """
    alg = select_kem(kem_alg)
    base = _new_key_id()
    curve_pk, curve_sk = x25519_keygen()
    pq_pk, pq_sk = kem_keygen(alg)
    curve_sig = sign_prekey(identity_sk, "curve-signed", base, "X25519", curve_pk)
    pq_sig = sign_prekey(identity_sk, "pq-signed", base, alg, pq_pk)

    local: dict[str, Any] = {
        "identity_pk": b64e(identity_pk),
        "curve_signed": {"key_id": base, "pk": b64e(curve_pk), "sk": b64e(curve_sk)},
        "pq_signed": {"key_id": base, "alg": alg, "pk": b64e(pq_pk), "sk": b64e(pq_sk)},
        "curve_one_time": {},
        "pq_one_time": {},
    }
    upload: dict[str, Any] = {
        "type": "upload_pqxdh_bundle",
        "identity_pk": b64e(identity_pk),
        "curve_spk_id": base,
        "curve_spk": b64e(curve_pk),
        "curve_spk_sig": b64e(curve_sig),
        "pq_spk_id": base,
        "pq_kem_alg": alg,
        "pq_spk": b64e(pq_pk),
        "pq_spk_sig": b64e(pq_sig),
        "curve_one_time_prekeys": [],
        "pq_one_time_prekeys": [],
    }

    for i in range(otk_count):
        kid = base + i + 1
        cpk, csk = x25519_keygen()
        csig = sign_prekey(identity_sk, "curve-otk", kid, "X25519", cpk)
        local["curve_one_time"][str(kid)] = {"pk": b64e(cpk), "sk": b64e(csk)}
        upload["curve_one_time_prekeys"].append({
            "key_id": kid,
            "public_key": b64e(cpk),
            "signature": b64e(csig),
        })

        qpk, qsk = kem_keygen(alg)
        qsig = sign_prekey(identity_sk, "pq-otk", kid, alg, qpk)
        local["pq_one_time"][str(kid)] = {"alg": alg, "pk": b64e(qpk), "sk": b64e(qsk)}
        upload["pq_one_time_prekeys"].append({
            "key_id": kid,
            "alg": alg,
            "public_key": b64e(qpk),
            "signature": b64e(qsig),
        })
    return upload, local


def verify_bundle(bundle: dict[str, Any]) -> None:
    """Kiá»ƒm tra chá»¯ kÃ½ trong bundle trÆ°á»›c khi dÃ¹ng Ä‘á»ƒ báº¯t tay khÃ³a.

    HÃ m nÃ y khÃ´ng kiá»ƒm tra ngÆ°á»i dÃ¹ng cÃ³ "Ä‘Ãºng ngÆ°á»i" hay chÆ°a. Viá»‡c Ä‘Ã³ thuá»™c
    safety number vÃ  identity transparency. á»ž Ä‘Ã¢y chá»‰ Ä‘áº£m báº£o public prekey
    trong bundle tháº­t sá»± Ä‘Æ°á»£c identity key cá»§a bundle kÃ½.
    """
    identity_pk = b64d(bundle["identity_pk"])
    verify_prekey(
        identity_pk, "curve-signed", int(bundle["curve_spk_id"]), "X25519",
        b64d(bundle["curve_spk"]), b64d(bundle["curve_spk_sig"]),
    )
    verify_prekey(
        identity_pk, "pq-signed", int(bundle["pq_spk_id"]), bundle["pq_kem_alg"],
        b64d(bundle["pq_spk"]), b64d(bundle["pq_spk_sig"]),
    )
    if int(bundle.get("curve_otk_id", -1)) > 0 and bundle.get("curve_otk"):
        verify_prekey(
            identity_pk, "curve-otk", int(bundle["curve_otk_id"]), "X25519",
            b64d(bundle["curve_otk"]), b64d(bundle["curve_otk_sig"]),
        )
    if int(bundle.get("pq_otk_id", -1)) > 0 and bundle.get("pq_otk"):
        verify_prekey(
            identity_pk, "pq-otk", int(bundle["pq_otk_id"]), bundle["pq_otk_alg"],
            b64d(bundle["pq_otk"]), b64d(bundle["pq_otk_sig"]),
        )


def _initial_chains(root_key: bytes, initiator: bool) -> tuple[bytes, bytes]:
    """Dẫn xuất cặp chain key khởi tạo (gửi, nhận) từ root key.

    Hai phía cùng root nhưng phải gán chain ngược nhau: chain GỬI của initiator
    chính là chain NHẬN của bên kia. Dùng hai nhãn HKDF "left"/"right" rồi tráo
    thứ tự theo vai trò để hai bên khớp nhau.
    """
    left = hkdf(root_key, b"SecChat-DR-init-left")
    right = hkdf(root_key, b"SecChat-DR-init-right")
    return (left, right) if initiator else (right, left)


def _kdf_rk(root_key: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """Bánh cóc ROOT (KDF_RK): trộn DH output mới vào root → (root mới, chain key mới).

    HKDF với salt = root cũ, ikm = DH output, lấy 64 byte rồi tách đôi. Đây là
    bước tạo post-compromise security: mỗi DH tươi làm "mới" toàn bộ root.
    """
    out = hkdf(dh_out, b"SecChat-DR-rk", salt=root_key, length=64)
    return out[:32], out[32:]


def _kdf_ck(chain_key: bytes) -> tuple[bytes, bytes]:
    """Bánh cóc CHAIN (KDF_CK): chain key → (message key, chain key kế tiếp).

    Một chiều: từ chain key mới không suy ngược được chain/message key cũ →
    forward secrecy. Mỗi tin tiêu thụ đúng một message key rồi vứt đi.
    """
    out = hkdf(chain_key, b"SecChat-DR-ck", length=64)
    return out[:32], out[32:]


@dataclass
class DoubleRatchet:
    """Trạng thái Double Ratchet (kiểu Signal) cho MỘT phiên DM.

    Double Ratchet là cơ chế khóa quay vòng cho tin nhắn 1-1, lồng hai "bánh
    cóc" (ratchet) vào nhau:

    * Bánh cóc đối xứng (symmetric ratchet): mỗi tin lấy ra một message key mới
      từ chain key rồi vứt key cũ đi (KDF_CK). Cho *forward secrecy* — lộ khóa
      hiện tại không giải lại được tin cũ.
    * Bánh cóc DH (DH ratchet): mỗi khi hội thoại đổi chiều, trộn một X25519 DH
      tươi vào root key (KDF_RK). Cho *post-compromise security* — sau một lượt
      trao đổi, hệ thống tự lành nếu state từng bị lộ.

    Mỗi wire message mang một header định tuyến nhìn thấy được CỘNG một bản sao
    header đã mã hóa (header encryption). AAD của ciphertext là header canonical,
    nên sửa conversation_id, người gửi/nhận, session id, số thứ tự hay ratchet
    public key đều làm giải mã thất bại — chống tráo/giả mạo metadata.

    Lưu ý hậu lượng tử: root key ban đầu do PQXDH gieo (đã trộn ML-KEM); bản
    thân ratchet về sau chỉ chạy X25519 cổ điển.
    """
    root_key: bytes              # root secret hiện tại; gốc dẫn xuất mọi chain key
    dh_pk: bytes                 # public key X25519 ratchet của mình (gửi trong header)
    dh_sk: bytes                 # secret key X25519 ratchet của mình
    remote_dh: bytes = b""       # public key ratchet mới nhất của đối phương
    ck_send: bytes = b""         # chain key chiều gửi
    ck_recv: bytes = b""         # chain key chiều nhận
    hk_send: bytes = b""         # header key chiều gửi (để mã hóa header)
    hk_recv: bytes = b""         # header key chiều nhận (để giải mã header)
    n_send: int = 0              # số thứ tự tin trong chain gửi hiện tại
    n_recv: int = 0              # số thứ tự tin mong đợi tiếp theo trong chain nhận
    pn: int = 0                  # độ dài chain gửi trước (previous N), giúp bên kia skip đúng
    skipped: dict[str, str] = field(default_factory=dict)  # khóa nhảy cóc "remote_dh:n" -> message key
    needs_send_ratchet: bool = False  # cờ: lần gửi tới phải xoay DH ratchet trước
    session_id: str = ""         # định danh phiên, chống trộn tin giữa hai phiên cùng conv
    conversation_id: int = 0     # gắn state vào đúng hội thoại
    my_uid: int = 0              # uid của mình (vào header để chống tráo người nhận)
    peer_uid: int = 0            # uid đối phương
    sender_identity_version: int = 0  # version identity key của người gửi lúc bắt tay
    seen: set[str] = field(default_factory=set)  # message id đã xử lý, chống nhận lặp/replay

    @classmethod
    def new(cls, root_key: bytes, *, initiator: bool,
            remote_dh: bytes = b"", session_id: str = "") -> "DoubleRatchet":
        pk, sk = x25519_keygen()
        ck_send, ck_recv = _initial_chains(root_key, initiator)
        hk_left = hkdf(root_key, b"SecChat-DR-header-init-left")
        hk_right = hkdf(root_key, b"SecChat-DR-header-init-right")
        hk_send, hk_recv = (hk_left, hk_right) if initiator else (hk_right, hk_left)
        return cls(
            root_key=root_key,
            dh_pk=pk,
            dh_sk=sk,
            remote_dh=remote_dh,
            ck_send=ck_send,
            ck_recv=ck_recv,
            hk_send=hk_send,
            hk_recv=hk_recv,
            needs_send_ratchet=(not initiator and bool(remote_dh)),
            session_id=session_id or b64e(os.urandom(16)),
        )

    def set_context(self, *, conversation_id: int = 0, my_uid: int = 0,
                    peer_uid: int = 0,
                    sender_identity_version: int | None = None) -> "DoubleRatchet":
        self.conversation_id = int(conversation_id or self.conversation_id or 0)
        self.my_uid = int(my_uid or self.my_uid or 0)
        self.peer_uid = int(peer_uid or self.peer_uid or 0)
        if sender_identity_version is not None:
            self.sender_identity_version = int(sender_identity_version)
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": SECCHAT_SCHEMA,
            "root_key": b64e(self.root_key),
            "dh_pk": b64e(self.dh_pk),
            "dh_sk": b64e(self.dh_sk),
            "remote_dh": b64e(self.remote_dh) if self.remote_dh else "",
            "ck_send": b64e(self.ck_send),
            "ck_recv": b64e(self.ck_recv),
            "hk_send": b64e(self.hk_send),
            "hk_recv": b64e(self.hk_recv),
            "n_send": self.n_send,
            "n_recv": self.n_recv,
            "pn": self.pn,
            "skipped": self.skipped,
            "needs_send_ratchet": self.needs_send_ratchet,
            "session_id": self.session_id,
            "conversation_id": self.conversation_id,
            "my_uid": self.my_uid,
            "peer_uid": self.peer_uid,
            "sender_identity_version": self.sender_identity_version,
            "seen": sorted(self.seen)[-2048:],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "DoubleRatchet":
        return cls(
            root_key=b64d(d["root_key"]),
            dh_pk=b64d(d["dh_pk"]),
            dh_sk=b64d(d["dh_sk"]),
            remote_dh=b64d(d["remote_dh"]) if d.get("remote_dh") else b"",
            ck_send=b64d(d["ck_send"]),
            ck_recv=b64d(d["ck_recv"]),
            hk_send=b64d(d["hk_send"]) if d.get("hk_send") else b"",
            hk_recv=b64d(d["hk_recv"]) if d.get("hk_recv") else b"",
            n_send=int(d.get("n_send", 0)),
            n_recv=int(d.get("n_recv", 0)),
            pn=int(d.get("pn", 0)),
            skipped=dict(d.get("skipped", {})),
            needs_send_ratchet=bool(d.get("needs_send_ratchet", False)),
            session_id=str(d.get("session_id", "") or ""),
            conversation_id=int(d.get("conversation_id", 0) or 0),
            my_uid=int(d.get("my_uid", 0) or 0),
            peer_uid=int(d.get("peer_uid", 0) or 0),
            sender_identity_version=int(d.get("sender_identity_version", 0) or 0),
            seen=set(str(x) for x in d.get("seen", []) if x),
        )

    @staticmethod
    def _canonical(obj: dict[str, Any]) -> bytes:
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    @staticmethod
    def _header_key(root_key: bytes, chain_key: bytes) -> bytes:
        return hkdf(root_key + chain_key, b"SecChat-DR-header-chain")

    def _header(self, n: int) -> dict[str, Any]:
        return {
            "v": SECCHAT_SCHEMA,
            "sid": self.session_id,
            "conversation_id": int(self.conversation_id or 0),
            "sender_uid": int(self.my_uid or 0),
            "recipient_uid": int(self.peer_uid or 0),
            "sender_identity_version": int(self.sender_identity_version or 0),
            "dh": b64e(self.dh_pk),
            "pn": int(self.pn),
            "n": int(n),
        }

    def _message_id(self, header: dict[str, Any]) -> str:
        return f"{header.get('sid', '')}:{header.get('dh', '')}:{int(header.get('n', 0))}"

    def _remember_seen(self, message_id: str) -> None:
        self.seen.add(message_id)
        if len(self.seen) > 4096:
            self.seen = set(sorted(self.seen)[-2048:])

    def _maybe_send_ratchet(self) -> None:
        """Xoay DH ratchet chiều GỬI nếu đang nợ (vừa nhận khóa mới của đối phương).

        Sinh cặp X25519 mới, trộn DH(sk mới, remote_dh) vào root để mở chain gửi
        mới, ghi lại pn (độ dài chain cũ) rồi reset n_send. Gọi ngay trước khi mã
        hóa tin đầu tiên của một lượt gửi mới.
        """
        if not self.needs_send_ratchet or not self.remote_dh:
            return
        self.pn = self.n_send
        self.dh_pk, self.dh_sk = x25519_keygen()
        self.root_key, self.ck_send = _kdf_rk(
            self.root_key, x25519_dh(self.dh_sk, self.remote_dh)
        )
        self.hk_send = self._header_key(self.root_key, self.ck_send)
        self.n_send = 0
        self.needs_send_ratchet = False

    def encrypt(self, plaintext: str) -> str:
        """Mã hóa một tin, đẩy bánh cóc đối xứng một nấc, trả về wire ``S3DR:``.

        Trình tự: (1) xoay DH ratchet nếu cần; (2) KDF_CK lấy message key mới +
        tiến chain gửi; (3) gói plaintext (kèm timestamp) bằng AES-GCM với AAD là
        header canonical; (4) mã hóa thêm một bản sao header bằng header key. Mỗi
        message key chỉ dùng đúng một lần rồi bị bỏ.
        """
        self._maybe_send_ratchet()
        mk, self.ck_send = _kdf_ck(self.ck_send)  # message key mới + chain key kế tiếp
        n = self.n_send
        self.n_send += 1
        header = self._header(n)
        aad = self._canonical(header)  # ràng ciphertext vào đúng metadata trong header
        ct = _aead_encrypt(mk, {"ts": int(time.time() * 1000), "body": plaintext}, aad)
        encrypted_header = _aead_encrypt(
            self.hk_send, header, b"SecChat-DR-encrypted-header"
        )
        return PREFIX_DR + json_b64({
            "v": SECCHAT_SCHEMA,
            "sid": self.session_id,
            "h": header,
            "eh": encrypted_header,
            "ct": ct,
        })

    def _skip_until(self, until_n: int) -> None:
        """Dẫn trước chain nhận tới ``until_n``, cất lại các message key bị bỏ qua.

        Khi tin đến không liên tục (n nhảy vọt do offline/lệch thứ tự), phải sinh
        và CẤT các message key ở giữa vào ``skipped`` để tin đến sau vẫn giải
        được. Giới hạn MAX_SKIP_KEYS = 1000 để chống bơm n cực lớn gây cạn bộ nhớ.
        """
        gap = until_n - self.n_recv
        if gap < 0:
            return
        if gap > MAX_SKIP_KEYS or len(self.skipped) + gap > MAX_SKIP_KEYS:
            raise ValueError("Too many skipped message keys")
        while self.n_recv < until_n:
            mk, self.ck_recv = _kdf_ck(self.ck_recv)
            self.skipped[f"{b64e(self.remote_dh)}:{self.n_recv}"] = b64e(mk)
            self.n_recv += 1

    def _dh_ratchet(self, new_remote_dh: bytes) -> None:
        """Xoay DH ratchet khi thấy ratchet public key MỚI của đối phương.

        Hai nửa: (1) trộn DH(sk cũ, remote mới) → mở chain NHẬN mới; (2) sinh cặp
        X25519 mới của mình rồi trộn tiếp → mở chain GỬI mới. Đây là bước "ping-
        pong" làm khóa DH luân phiên mỗi lần đổi chiều — nguồn của post-compromise
        security.
        """
        self.pn = self.n_send
        self.n_send = 0
        self.n_recv = 0
        self.remote_dh = new_remote_dh
        self.root_key, self.ck_recv = _kdf_rk(
            self.root_key, x25519_dh(self.dh_sk, self.remote_dh)
        )
        self.hk_recv = self._header_key(self.root_key, self.ck_recv)
        self.dh_pk, self.dh_sk = x25519_keygen()
        self.root_key, self.ck_send = _kdf_rk(
            self.root_key, x25519_dh(self.dh_sk, self.remote_dh)
        )
        self.hk_send = self._header_key(self.root_key, self.ck_send)

    def _read_header(self, obj: dict[str, Any]) -> dict[str, Any]:
        visible = obj.get("h") if isinstance(obj.get("h"), dict) else None
        encrypted = obj.get("eh")
        if encrypted and self.hk_recv:
            try:
                header = _aead_decrypt(
                    self.hk_recv, encrypted, b"SecChat-DR-encrypted-header"
                )
                if visible and header != visible:
                    raise ValueError("Double Ratchet header copy mismatch")
                return header
            except Exception:
                if not visible:
                    raise
        if visible:
            return visible
        # In-memory unit helpers may construct a raw object. Valid SecChat
        # traffic uses the canonical ``h`` field.
        return {
            "v": int(obj.get("v", SECCHAT_SCHEMA)),
            "sid": str(obj.get("sid", self.session_id) or self.session_id),
            "conversation_id": int(obj.get("conversation_id", self.conversation_id) or 0),
            "sender_uid": int(obj.get("sender_uid", self.peer_uid) or 0),
            "recipient_uid": int(obj.get("recipient_uid", self.my_uid) or 0),
            "sender_identity_version": int(
                obj.get("sender_identity_version", 0) or 0),
            "dh": obj["dh"],
            "pn": int(obj.get("pn", 0)),
            "n": int(obj["n"]),
        }

    def decrypt(self, wire: str) -> str:
        """Giải mã một wire ``S3DR:`` và đẩy bánh cóc nhận tương ứng.

        Trình tự: đọc + kiểm header (sid/conv/recipient phải khớp state; chống
        replay qua tập ``seen``); nếu key đã nằm sẵn trong ``skipped`` thì dùng
        luôn; nếu thấy ratchet key mới thì xoay DH ratchet; skip các key trung
        gian; cuối cùng KDF_CK lấy message key và mở AES-GCM với AAD = header.
        """
        obj = json_unb64(wire[len(PREFIX_DR):] if wire.startswith(PREFIX_DR) else wire)
        header = self._read_header(obj)
        if self.session_id and header.get("sid") != self.session_id:
            raise ValueError("Double Ratchet session mismatch")
        if int(self.conversation_id or 0) and int(header.get("conversation_id", 0) or 0) != int(self.conversation_id):
            raise ValueError("Double Ratchet conversation mismatch")
        if int(self.my_uid or 0) and int(header.get("recipient_uid", 0) or 0) != int(self.my_uid):
            raise ValueError("Double Ratchet recipient mismatch")
        remote = b64d(str(header["dh"]))
        n = int(header["n"])
        message_id = self._message_id(header)
        if message_id in self.seen:
            raise ValueError("Duplicate/replayed Double Ratchet message")
        key_id = f"{b64e(remote)}:{n}"
        aad = self._canonical(header)
        if key_id in self.skipped:
            mk = b64d(self.skipped.pop(key_id))
            plain = str(_aead_decrypt(mk, obj["ct"], aad).get("body", ""))
            self._remember_seen(message_id)
            return plain
        if not self.remote_dh or remote != self.remote_dh:
            self._dh_ratchet(remote)
        self._skip_until(n)
        mk, self.ck_recv = _kdf_ck(self.ck_recv)
        self.n_recv += 1
        plain = str(_aead_decrypt(mk, obj["ct"], aad).get("body", ""))
        self._remember_seen(message_id)
        return plain

def pqxdh_initiate(bundle: dict[str, Any], local_store: dict[str, Any],
                   identity_pk: bytes, identity_sk: bytes, my_uid: int,
                   peer_uid: int, initial_body: str = "__S3_INIT__",
                   sender_identity_version: int | None = None,
                   conversation_id: int = 0
                   ) -> tuple[str, DoubleRatchet, str]:
    """PhÃ­a gá»­i táº¡o tin DM Ä‘áº§u tiÃªn báº±ng transcript kiá»ƒu PQXDH.

    CÃ¡c secret Ä‘áº§u vÃ o gá»“m X25519 DH vÃ  shared secret tá»« ML-KEM/Kyber. ChÃºng
    Ä‘Æ°á»£c trá»™n báº±ng HKDF Ä‘á»ƒ táº¡o root secret cho Double Ratchet. Tin Ä‘áº§u tiÃªn
    mang prefix ``S3PQI:`` Ä‘á»ƒ phÃ­a nháº­n biáº¿t Ä‘Ã¢y lÃ  initial message, khÃ´ng pháº£i
    message ratchet bÃ¬nh thÆ°á»ng.
    """
    verify_bundle(bundle)
    alg = bundle.get("pq_otk_alg") if int(bundle.get("pq_otk_id", -1)) > 0 else bundle["pq_kem_alg"]
    pq_pk = b64d(bundle.get("pq_otk") or bundle["pq_spk"])
    pq_ct, pq_ss = kem_encapsulate(alg, pq_pk)

    eph_pk, eph_sk = x25519_keygen()
    local_curve = local_store["curve_signed"]
    local_curve_pk = b64d(local_curve["pk"])
    local_curve_sk = b64d(local_curve["sk"])
    peer_curve_spk = b64d(bundle["curve_spk"])
    peer_curve_otk = b64d(bundle["curve_otk"]) if int(bundle.get("curve_otk_id", -1)) > 0 else b""

    dh_parts = [
        x25519_dh(local_curve_sk, peer_curve_spk),
        x25519_dh(eph_sk, peer_curve_spk),
    ]
    if peer_curve_otk:
        dh_parts.append(x25519_dh(eph_sk, peer_curve_otk))
    root = hkdf(b"".join(dh_parts) + pq_ss, b"SecChat-PQXDH")
    session_id = b64e(os.urandom(16))
    state = DoubleRatchet.new(
        root, initiator=True, session_id=session_id
    ).set_context(
        conversation_id=int(conversation_id or 0),
        my_uid=int(my_uid),
        peer_uid=int(peer_uid),
        sender_identity_version=sender_identity_version,
    )
    mk, state.ck_send = _kdf_ck(state.ck_send)
    state.n_send += 1

    curve_key_id = int(local_curve["key_id"])
    curve_sig = sign_prekey(identity_sk, "curve-signed", curve_key_id, "X25519", local_curve_pk)
    payload = {
        "v": SECCHAT_SCHEMA,
        "sid": session_id,
        "conversation_id": int(conversation_id or 0),
        "sender_uid": my_uid,
        "recipient_uid": peer_uid,
        "identity_pk": b64e(identity_pk),
        "sender_curve_spk_id": curve_key_id,
        "sender_curve_spk": b64e(local_curve_pk),
        "sender_curve_spk_sig": b64e(curve_sig),
        "eph_curve_pk": b64e(eph_pk),
        "curve_spk_id": int(bundle["curve_spk_id"]),
        "curve_otk_id": int(bundle.get("curve_otk_id", -1)),
        "pq_spk_id": int(bundle["pq_spk_id"]),
        "pq_otk_id": int(bundle.get("pq_otk_id", -1)),
        "pq_kem_alg": alg,
        "pq_ct": b64e(pq_ct),
        "dr_pub": b64e(state.dh_pk),
    }
    if sender_identity_version is not None:
        payload["sender_identity_version"] = int(sender_identity_version)
    ct = _aead_encrypt(
        mk,
        {"ts": int(time.time() * 1000), "body": initial_body},
        DoubleRatchet._canonical(payload),
    )
    payload["ct"] = ct
    token = PREFIX_PQ_INIT + json_b64(payload)
    fingerprint = safety_fingerprint(identity_pk, b64d(bundle["identity_pk"]))
    return token, state, fingerprint


def pqxdh_respond(wire: str, local_store: dict[str, Any],
                  expected_uid: int | None = None) -> tuple[str, DoubleRatchet, str, int]:
    """PhÃ­a nháº­n má»Ÿ ``S3PQI`` vÃ  táº¡o cÃ¹ng root secret vá»›i phÃ­a gá»­i.

    HÃ m nÃ y láº¥y secret prekey cá»¥c bá»™ theo key id trong transcript. Náº¿u transcript
    dÃ¹ng one-time prekey thÃ¬ key Ä‘Ã³ bá»‹ pop khá»i local store Ä‘á»ƒ trÃ¡nh tÃ¡i sá»­ dá»¥ng.
    Káº¿t quáº£ tráº£ vá» gá»“m plaintext tin Ä‘áº§u tiÃªn, tráº¡ng thÃ¡i Double Ratchet má»›i,
    safety fingerprint vÃ  version identity cá»§a sender náº¿u wire cÃ³ gá»­i kÃ¨m.
    """
    obj = json_unb64(wire[len(PREFIX_PQ_INIT):] if wire.startswith(PREFIX_PQ_INIT) else wire)
    sender_uid = int(obj["sender_uid"])
    if expected_uid is not None and int(obj["recipient_uid"]) != expected_uid:
        raise ValueError("PQXDH recipient mismatch")
    sender_identity = b64d(obj["identity_pk"])
    sender_curve = b64d(obj["sender_curve_spk"])
    verify_prekey(
        sender_identity, "curve-signed", int(obj["sender_curve_spk_id"]),
        "X25519", sender_curve, b64d(obj["sender_curve_spk_sig"]),
    )

    curve_otk_id = int(obj.get("curve_otk_id", -1))
    pq_otk_id = int(obj.get("pq_otk_id", -1))
    local_curve_signed = local_store["curve_signed"]
    local_curve_sk = b64d(local_curve_signed["sk"])
    local_curve_otk_sk = b""
    if curve_otk_id > 0:
        hit = local_store.get("curve_one_time", {}).pop(str(curve_otk_id), None)
        if hit:
            local_curve_otk_sk = b64d(hit["sk"])
    alg = obj["pq_kem_alg"]
    if pq_otk_id > 0:
        phit = local_store.get("pq_one_time", {}).pop(str(pq_otk_id), None)
        pq_sk = b64d(phit["sk"]) if phit else b64d(local_store["pq_signed"]["sk"])
    else:
        pq_sk = b64d(local_store["pq_signed"]["sk"])

    eph_pk = b64d(obj["eph_curve_pk"])
    dh_parts = [
        x25519_dh(local_curve_sk, sender_curve),
        x25519_dh(local_curve_sk, eph_pk),
    ]
    if local_curve_otk_sk:
        dh_parts.append(x25519_dh(local_curve_otk_sk, eph_pk))
    pq_ss = kem_decapsulate(alg, pq_sk, b64d(obj["pq_ct"]))
    root = hkdf(b"".join(dh_parts) + pq_ss, b"SecChat-PQXDH")
    state = DoubleRatchet.new(
        root,
        initiator=False,
        remote_dh=b64d(obj["dr_pub"]),
        session_id=str(obj.get("sid", "") or ""),
    ).set_context(
        conversation_id=int(obj.get("conversation_id", 0) or 0),
        my_uid=int(obj.get("recipient_uid", 0) or 0),
        peer_uid=sender_uid,
        sender_identity_version=obj.get("sender_identity_version"),
    )
    mk, state.ck_recv = _kdf_ck(state.ck_recv)
    state.n_recv += 1
    aad_obj = dict(obj)
    aad_obj.pop("ct", None)
    plain = str(_aead_decrypt(mk, obj["ct"], DoubleRatchet._canonical(aad_obj)).get("body", ""))
    fingerprint = safety_fingerprint(b64d(local_store["identity_pk"]), sender_identity)
    return plain, state, fingerprint, sender_uid


def safety_fingerprint(a: bytes, b: bytes) -> str:
    """Tính safety number (fingerprint) từ hai identity key Ed25519.

    Sắp xếp hai key để hai phía luôn ra cùng chuỗi mà không cần thỏa thuận thứ
    tự, rồi SHA-256 và format thành các nhóm 4 hex. Người dùng so chuỗi này ngoài
    luồng (gọi điện/gặp mặt) để chắc chắn không bị MITM tráo khóa.
    """
    left, right = sorted([a, b])
    digest = hashes.Hash(hashes.SHA256())
    digest.update(b"SecChatSafety\x00" + left + right)
    h = digest.finalize().hex().upper()
    return " ".join(h[i:i + 4] for i in range(0, 32, 4))


