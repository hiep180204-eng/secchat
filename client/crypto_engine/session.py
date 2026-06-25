"""Quáº£n lÃ½ tráº¡ng thÃ¡i mÃ£ hÃ³a phÃ­a client vÃ  lÆ°u cá»¥c bá»™ cÃ³ mÃ£ hÃ³a.

File nÃ y lÃ  lá»›p trung gian giá»¯a UI vÃ  cÃ¡c primitive máº­t mÃ£. UI/controller khÃ´ng
nÃªn tá»± Ä‘á»c ghi file khÃ³a, file ratchet, cache plaintext hoáº·c quyáº¿t Ä‘á»‹nh chuyá»ƒn
tráº¡ng thÃ¡i giao thá»©c. Táº¥t cáº£ tráº¡ng thÃ¡i nháº¡y cáº£m Ä‘Æ°á»£c gom vÃ o ``CryptoSession``
Ä‘á»ƒ pháº§n cÃ²n láº¡i cá»§a á»©ng dá»¥ng chá»‰ cáº§n gá»i cÃ¡c thao tÃ¡c cáº¥p cao nhÆ° táº¡o bundle
PQXDH, mÃ£ hÃ³a tin nháº¯n, giáº£i mÃ£ history, táº¡o Welcome cho group hoáº·c export
backup.

CÃ¡c file trong thÆ° má»¥c ``~/.secchat/<username>`` Ä‘á»u Ä‘Æ°á»£c bá»c báº±ng master key
dáº«n xuáº¥t tá»« máº­t kháº©u Ä‘Äƒng nháº­p. VÃ¬ váº­y server khÃ´ng Ä‘á»c Ä‘Æ°á»£c state cá»¥c bá»™, cÃ²n
khi Ä‘á»•i máº­t kháº©u client pháº£i re-wrap láº¡i cÃ¡c file nÃ y báº±ng master key má»›i.
"""

from __future__ import annotations

import base64
import fnmatch
import glob
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from client.crypto_engine.secure_protocol import (
    DoubleRatchet,
    PREFIX_DR,
    PREFIX_MLS,
    PREFIX_PQ_INIT,
    b64d as protocol_b64d,
    b64e as protocol_b64e,
    generate_local_bundle,
    json_b64,
    json_unb64,
    pqxdh_initiate,
    pqxdh_respond,
    sign_prekey,
)
from client.crypto_engine.openmls_bridge import (
    MlsBridge,
    PQ_HYBRID_CIPHERSUITE,
)
from client.utils import (
    ts_short,
    decrypt_with_key,
    decrypt_key_with_master,
    encrypt_key_with_master,
    encrypt_with_key,
    identity_keygen,
    identity_pk_from_sk,
    identity_sign,
    identity_verify,
)


class CryptoStateError(RuntimeError):
    """Lá»—i nghiá»‡p vá»¥ khi thao tÃ¡c cáº§n state mÃ£ hÃ³a nhÆ°ng state chÆ°a sáºµn sÃ ng."""


def _same_identity_key(a: str, b: str) -> bool:
    """So sÃ¡nh identity key theo bytes tháº­t, khÃ´ng so sÃ¡nh chuá»—i base64.

    Má»™t public key cÃ³ thá»ƒ Ä‘Æ°á»£c biá»ƒu diá»…n báº±ng base64 chuáº©n hoáº·c url-safe,
    cÃ³ padding hoáº·c khÃ´ng padding. Náº¿u so sÃ¡nh chuá»—i trá»±c tiáº¿p, client/server
    cÃ³ thá»ƒ hiá»ƒu nháº§m lÃ  ngÆ°á»i dÃ¹ng Ä‘á»•i identity key dÃ¹ bytes khÃ³a khÃ´ng Ä‘á»•i.
    """
    try:
        return protocol_b64d(str(a or "")) == protocol_b64d(str(b or ""))
    except Exception:
        return str(a or "") == str(b or "")


@dataclass
class CryptoSession:
    """ToÃ n bá»™ state E2EE cá»§a má»™t phiÃªn Ä‘Äƒng nháº­p.

    CÃ¡c nhÃ³m field chÃ­nh:

    * ``identity_*``: khÃ³a Ä‘á»‹nh danh dÃ i háº¡n vÃ 
      khÃ³a/prekey dÃ¹ng cho báº¯t tay hybrid háº­u lÆ°á»£ng tá»­.
    * ``pqxdh_prekeys``, ``double_ratchet_states``: bundle PQXDH local vÃ  tráº¡ng thÃ¡i
      Double Ratchet cho DM SecChat.
    * ``mls_bridge`` vÃ  ``mls_group_ready``: state group MLS RFC 9420 do OpenMLS
      quáº£n lÃ½ qua bridge Rust.
    * ``conv_verified`` vÃ  ``identity_audit_states``: tráº¡ng thÃ¡i ngÆ°á»i dÃ¹ng Ä‘Ã£
      xÃ¡c minh safety number hay chÆ°a vÃ  káº¿t quáº£ kiá»ƒm tra transparency log.
    * ``msgs_*.bin`` cache: plaintext Ä‘Ã£ giáº£i mÃ£, Ä‘Æ°á»£c mÃ£ hÃ³a láº¡i báº±ng
      master key Ä‘á»ƒ cÃ³ preview/history sau khi ratchet Ä‘Ã£ xÃ³a message key cÅ©.

    LÆ°u Ã½ quan trá»ng: cache plaintext lÃ  Ä‘Ã¡nh Ä‘á»•i cÃ³ chá»§ Ä‘Ã­ch giá»¯a usability vÃ 
    báº£o vá»‡ dá»¯ liá»‡u cá»¥c bá»™. NÃ³ giÃºp Ä‘á»c láº¡i tin cÅ© sau relogin, nhÆ°ng váº«n lÃ  dá»¯
    liá»‡u nháº¡y cáº£m trÃªn mÃ¡y ngÆ°á»i dÃ¹ng nÃªn cÃ³ policy báº­t/táº¯t, TTL vÃ  xÃ³a thá»§ cÃ´ng.
    """
    master_key: bytes | None = None
    secchat_dir: str = ""
    my_uid: int = 0

    identity_pk: bytes = b""
    identity_sk: bytes = b""

    conv_peer_uids: dict[int, int] = field(default_factory=dict)
    conv_fingerprints: dict[int, str] = field(default_factory=dict)
    conv_verified: dict[int, bool] = field(default_factory=dict)
    identity_audit_states: dict[int, dict] = field(default_factory=dict)
    auditor_state: dict = field(default_factory=dict)
    group_conv_ids: set[int] = field(default_factory=set)
    group_epochs: dict[int, int] = field(default_factory=dict)

    pqxdh_prekeys: dict | None = None
    double_ratchet_states: dict[int, DoubleRatchet] = field(default_factory=dict)
    double_ratchet_session_states: dict[int, dict[str, DoubleRatchet]] = field(default_factory=dict)
    mls_bridge: MlsBridge | None = field(default=None, repr=False)
    mls_identity_ready: bool = False
    mls_credential_identity_b64: str = ""
    mls_group_ready: set[int] = field(default_factory=set)
    mls_handshake_seen: set[str] = field(default_factory=set)
    cache_enabled: bool = True
    cache_ttl_days: int = 30
    cache_clear_on_logout: bool = False
    cache_disabled_convs: set[int] = field(default_factory=set)
    control_warnings: dict[int, list[str]] = field(default_factory=dict)

    logger: logging.Logger = field(
        default_factory=lambda: logging.getLogger(__name__), repr=False)

    def reset(self) -> None:
        """XÃ³a toÃ n bá»™ state trong RAM khi logout hoáº·c báº¯t Ä‘áº§u phiÃªn má»›i."""
        logger = self.logger
        bridge = getattr(self, "mls_bridge", None)
        if bridge:
            try:
                bridge.close()
            except Exception:
                pass
        self.__dict__.clear()
        self.__init__(logger=logger)

    def configure(self, *, master_key: bytes | None, secchat_dir: str,
                  my_uid: int) -> None:
        """Gáº¯n context Ä‘Äƒng nháº­p hiá»‡n táº¡i cho session crypto.

        ``master_key`` dÃ¹ng Ä‘á»ƒ giáº£i mÃ£/mÃ£ hÃ³a cÃ¡c file local state. ``secchat_dir``
        lÃ  thÆ° má»¥c riÃªng cá»§a account Ä‘ang Ä‘Äƒng nháº­p. ``my_uid`` dÃ¹ng khi táº¡o
        transcript, group commit vÃ  kiá»ƒm tra cache/identity.
        """
        self.master_key = master_key
        self.secchat_dir = secchat_dir
        self.my_uid = int(my_uid or 0)

    # CÃ¡c helper path giá»¯ viá»‡c Ä‘áº·t tÃªn file local á»Ÿ má»™t chá»— duy nháº¥t. Äiá»u nÃ y
    # lÃ m backup/restore vÃ  re-wrap password Ã­t lá»—i hÆ¡n vÃ¬ khÃ´ng pháº£i ráº£i tÃªn
    # file state á»Ÿ nhiá»u module khÃ¡c nhau.

    def identity_key_path(self) -> str:
        return os.path.join(self.secchat_dir, "identity_sk.bin")

    def msg_cache_path(self, conv_id: int) -> str:
        return os.path.join(self.secchat_dir, f"msgs_{int(conv_id)}.bin")

    def cache_policy_path(self) -> str:
        return os.path.join(self.secchat_dir, "cache_policy.bin")

    def backup_state_path(self) -> str:
        return os.path.join(self.secchat_dir, "backup_state.bin")

    def transcript_path(self, conv_id: int) -> str:
        return os.path.join(self.secchat_dir, f"transcript_{int(conv_id)}.bin")

    @staticmethod
    def wire_cache_key(wire: str) -> str:
        digest = hashlib.sha256((wire or "").encode("utf-8")).hexdigest()
        return f"wire:{digest}"

    def _add_control_warning(self, conv_id: int, warning: str) -> None:
        warning = str(warning or "").strip()
        if warning:
            self.control_warnings.setdefault(int(conv_id), []).append(warning)

    def pop_control_warnings(self, conv_id: int) -> list[str]:
        return self.control_warnings.pop(int(conv_id), [])

    def pqxdh_prekeys_path(self) -> str:
        return os.path.join(self.secchat_dir, "pqxdh_prekeys.bin")

    def double_ratchet_path(self, conv_id: int) -> str:
        return os.path.join(self.secchat_dir, f"dr_{int(conv_id)}.bin")

    def double_ratchet_sessions_path(self, conv_id: int) -> str:
        return os.path.join(self.secchat_dir, f"dr_sessions_{int(conv_id)}.bin")

    def mls_state_path(self) -> str:
        return os.path.join(self.secchat_dir, "mls_state.bin")

    def verified_path(self, conv_id: int) -> str:
        return os.path.join(self.secchat_dir, f"verified_{int(conv_id)}.bin")

    def identity_audit_path(self, user_id: int) -> str:
        return os.path.join(self.secchat_dir, f"identity_audit_{int(user_id)}.bin")

    def auditor_state_path(self) -> str:
        return os.path.join(self.secchat_dir, "auditor_state.bin")

    # Local plaintext cache
    #
    # Double Ratchet cÃ³ tÃ­nh forward secrecy: sau khi giáº£i mÃ£ xong, message key
    # cÅ© khÃ´ng nÃªn giá»¯ láº¡i. Há»‡ quáº£ lÃ  khi reload history tá»« server, tin cÅ© cÃ³
    # thá»ƒ khÃ´ng giáº£i mÃ£ láº¡i Ä‘Æ°á»£c tá»« ciphertext. Cache dÆ°á»›i Ä‘Ã¢y lÆ°u plaintext Ä‘Ã£
    # tá»«ng Ä‘á»c, nhÆ°ng mÃ£ hÃ³a file cache báº±ng master key Ä‘á»ƒ UI váº«n hiá»ƒn thá»‹ Ä‘Æ°á»£c
    # preview/history trÃªn cÃ¹ng thiáº¿t bá»‹ mÃ  khÃ´ng Ä‘Æ°a plaintext lÃªn server.

    def get_cache_policy(self) -> dict:
        """Trả về policy cache hiện tại dưới dạng dict (cho UI hiển thị/đồng bộ)."""
        return {
            "enabled": bool(self.cache_enabled),
            "ttl_days": int(self.cache_ttl_days),
            "clear_on_logout": bool(self.cache_clear_on_logout),
            "disabled_conversation_ids": sorted(
                int(cid) for cid in self.cache_disabled_convs),
        }

    def load_cache_policy(self) -> dict:
        """Nạp policy cache từ file đã mã hóa; fallback về mặc định nếu chưa có file."""
        if not self.secchat_dir or not self.master_key:
            return self.get_cache_policy()
        path = self.cache_policy_path()
        if not os.path.exists(path):
            return self.get_cache_policy()
        try:
            with open(path, "r", encoding="utf-8") as fh:
                token = fh.read().strip()
            raw = decrypt_with_key(self.master_key, token, check_replay=False)
            policy = json.loads(raw)
            self.cache_enabled = bool(policy.get("enabled", True))
            self.cache_ttl_days = int(policy.get("ttl_days", 30))
            self.cache_clear_on_logout = bool(policy.get("clear_on_logout", False))
            disabled = policy.get("disabled_conversation_ids", [])
            if not disabled:
                disabled = policy.get("no_cache_conversation_ids", [])
            self.cache_disabled_convs = {
                int(cid) for cid in disabled
                if str(cid).lstrip("-").isdigit() and int(cid) > 0
            }
        except Exception as exc:
            self.logger.warning("Cache policy load failed: %s", exc)
        return self.get_cache_policy()

    def save_cache_policy(self) -> None:
        """Ghi policy cache xuống đĩa (mã hóa bằng master key)."""
        if not self.secchat_dir or not self.master_key:
            return
        try:
            os.makedirs(self.secchat_dir, exist_ok=True)
            token = encrypt_with_key(
                self.master_key,
                json.dumps(self.get_cache_policy(), ensure_ascii=False),
            )
            with open(self.cache_policy_path(), "w", encoding="utf-8") as fh:
                fh.write(token)
        except Exception as exc:
            self.logger.warning("Cache policy save failed: %s", exc)

    def set_cache_policy(self, *, enabled: bool | None = None,
                         ttl_days: int | None = None,
                         clear_on_logout: bool | None = None,
                         disabled_conversation_ids: list[int] | None = None) -> dict:
        """Cập nhật policy cache (bật/tắt, TTL, danh sách conv tắt cache) rồi áp dụng ngay.

        Tắt cache → xóa toàn bộ cache; bật → siết lại theo TTL mới (enforce).
        """
        if enabled is not None:
            self.cache_enabled = bool(enabled)
        if ttl_days is not None:
            self.cache_ttl_days = int(ttl_days)
        if clear_on_logout is not None:
            self.cache_clear_on_logout = bool(clear_on_logout)
        if disabled_conversation_ids is not None:
            disabled: set[int] = set()
            for cid in disabled_conversation_ids:
                try:
                    cid_i = int(cid)
                except Exception:
                    continue
                if cid_i > 0:
                    disabled.add(cid_i)
            self.cache_disabled_convs = disabled
        self.save_cache_policy()
        if not self.cache_enabled:
            self.clear_message_cache()
        else:
            self.enforce_cache_policy()
        return self.get_cache_policy()

    def is_conversation_cache_enabled(self, conv_id: int) -> bool:
        """True nếu được phép cache cho hội thoại này (cache bật và conv không bị tắt riêng)."""
        return (
            bool(self.cache_enabled)
            and int(conv_id or 0) > 0
            and int(conv_id) not in self.cache_disabled_convs
        )

    def set_conversation_cache_enabled(self, conv_id: int,
                                       enabled: bool) -> dict:
        """Bật/tắt cache cho riêng một hội thoại; tắt thì xóa luôn cache hiện có của nó."""
        conv_id = int(conv_id or 0)
        if conv_id <= 0:
            return self.get_cache_policy()
        if enabled:
            self.cache_disabled_convs.discard(conv_id)
        else:
            self.cache_disabled_convs.add(conv_id)
            self.clear_message_cache(conv_id)
        self.save_cache_policy()
        return self.get_cache_policy()

    def _cache_entry_is_fresh(self, entry: dict) -> bool:
        """True nếu entry cache còn trong hạn TTL (ttl < 0 nghĩa là không hết hạn)."""
        ttl = int(self.cache_ttl_days)
        if ttl < 0:
            return True
        cached_at = float(entry.get("cached_at") or time.time())
        return cached_at >= time.time() - (ttl * 86400)

    def cache_message(self, conv_id: int, msg_id: int, sender_id: int,
                      plaintext: str, ts: str) -> None:
        """LÆ°u plaintext Ä‘Ã£ giáº£i mÃ£ vÃ o cache cá»¥c bá»™ Ä‘Ã£ mÃ£ hÃ³a.

        Cache chá»‰ ghi khi policy cho phÃ©p vÃ  conversation khÃ´ng bá»‹ táº¯t cache
        riÃªng. Má»—i entry lÃ  má»™t dÃ²ng Ä‘á»™c láº­p Ä‘á»ƒ khi má»™t dÃ²ng lá»—i váº«n cÃ³ thá»ƒ bá»
        qua mÃ  khÃ´ng lÃ m há»ng toÃ n bá»™ cache cá»§a conversation.
        """
        if (not self.is_conversation_cache_enabled(conv_id) or not self.secchat_dir
                or not self.master_key or not msg_id):
            return
        try:
            os.makedirs(self.secchat_dir, exist_ok=True)
            entry = {
                "id": msg_id,
                "from": sender_id,
                "body": plaintext,
                "ts": ts,
                "cached_at": time.time(),
            }
            token = encrypt_with_key(
                self.master_key, json.dumps(entry, ensure_ascii=False))
            with open(self.msg_cache_path(conv_id), "a", encoding="utf-8") as fh:
                fh.write(token + "\n")
        except Exception as exc:
            self.logger.warning(
                "Message cache save failed conv=%d id=%d: %s",
                conv_id, msg_id, exc)

    def cache_outgoing_wire(self, conv_id: int, wire: str, sender_id: int,
                            plaintext: str, ts: str = "") -> None:
        """Cache plaintext cá»§a tin vá»«a gá»­i trÆ°á»›c khi server echo láº¡i.

        Vá»›i tin tá»± gá»­i, client khÃ´ng Ä‘Æ°á»£c dÃ¹ng receive ratchet Ä‘á»ƒ giáº£i mÃ£ echo
        cá»§a chÃ­nh mÃ¬nh vÃ¬ sáº½ lÃ m lá»‡ch chain. VÃ¬ váº­y plaintext Ä‘Æ°á»£c map theo hash
        cá»§a wire ciphertext, rá»“i dÃ¹ng láº¡i khi server tráº£ vá» message tháº­t.
        """
        if (not self.is_conversation_cache_enabled(conv_id) or not self.secchat_dir
                or not self.master_key or not wire):
            return
        try:
            os.makedirs(self.secchat_dir, exist_ok=True)
            entry = {
                "id": 0,
                "from": sender_id,
                "body": plaintext,
                "ts": ts,
                "cached_at": time.time(),
                "wire_hash": self.wire_cache_key(wire)[len("wire:"):],
            }
            token = encrypt_with_key(
                self.master_key, json.dumps(entry, ensure_ascii=False))
            with open(self.msg_cache_path(conv_id), "a", encoding="utf-8") as fh:
                fh.write(token + "\n")
        except Exception as exc:
            self.logger.warning(
                "Outgoing message cache save failed conv=%d: %s", conv_id, exc)

    def load_cached_messages(self, conv_id: int) -> dict:
        """Äá»c cache plaintext Ä‘Ã£ mÃ£ hÃ³a vÃ  tá»± dá»n entry háº¿t háº¡n/lá»—i.

        Káº¿t quáº£ Ä‘Æ°á»£c index theo cáº£ ``message_id`` vÃ  ``wire:<hash>``. Index theo
        ``message_id`` dÃ¹ng cho history/inbox; index theo wire dÃ¹ng cho echo cá»§a
        tin vá»«a gá»­i trÆ°á»›c khi server gÃ¡n id tháº­t.
        """
        out = {}
        if (not self.is_conversation_cache_enabled(conv_id)
                or not self.secchat_dir or not self.master_key):
            return out
        path = self.msg_cache_path(conv_id)
        if not os.path.exists(path):
            return out
        kept_tokens = []
        changed = False
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw = decrypt_with_key(
                            self.master_key, line, check_replay=False)
                        entry = json.loads(raw)
                        if not self._cache_entry_is_fresh(entry):
                            changed = True
                            continue
                        kept_tokens.append(line)
                        mid = int(entry.get("id", 0))
                        if mid:
                            out[mid] = entry
                        wire_hash = str(entry.get("wire_hash", "") or "")
                        if wire_hash:
                            out[f"wire:{wire_hash}"] = entry
                    except Exception:
                        changed = True
                        continue
            if changed:
                tmp = path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    if kept_tokens:
                        fh.write("\n".join(kept_tokens) + "\n")
                os.replace(tmp, path)
        except Exception as exc:
            self.logger.warning(
                "Message cache load failed conv=%d: %s", conv_id, exc)
        return out

    def enforce_cache_policy(self) -> int:
        """Ãp dá»¥ng policy cache hiá»‡n táº¡i cho cÃ¡c file ``msgs_*.bin``.

        HÃ m nÃ y Ä‘Æ°á»£c gá»i sau login vÃ  sau khi ngÆ°á»i dÃ¹ng Ä‘á»•i policy Ä‘á»ƒ xÃ³a cache
        bá»‹ táº¯t, xÃ³a entry háº¿t TTL, hoáº·c xÃ³a toÃ n bá»™ náº¿u cache global bá»‹ táº¯t.
        """
        if not self.cache_enabled:
            return self.clear_message_cache()
        touched = 0
        if not self.secchat_dir or not self.master_key:
            return touched
        for path in glob.glob(os.path.join(self.secchat_dir, "msgs_*.bin")):
            try:
                before = os.path.getsize(path)
                conv_id = int(os.path.basename(path)[5:-4])
                if not self.is_conversation_cache_enabled(conv_id):
                    os.remove(path)
                    touched += 1
                    continue
                self.load_cached_messages(conv_id)
                after = os.path.getsize(path) if os.path.exists(path) else 0
                if after != before:
                    touched += 1
            except Exception:
                continue
        return touched

    def clear_message_cache(self, conv_id: int | None = None) -> int:
        """XÃ³a chá»‰ cÃ¡c file cache plaintext cá»¥c bá»™, khÃ´ng xÃ³a khÃ³a hay ratchet."""
        removed = 0
        if not self.secchat_dir:
            return removed
        if conv_id is None:
            pattern = "msgs_*.bin"
        else:
            pattern = f"msgs_{int(conv_id)}.bin"
        for path in glob.glob(os.path.join(self.secchat_dir, pattern)):
            try:
                os.remove(path)
                removed += 1
            except OSError:
                pass
        return removed

    # Encrypted local E2EE backup
    #
    # Backup E2EE lÃ  file ngÆ°á»i dÃ¹ng tá»± giá»¯. BÃªn trong backup lÃ  cÃ¡c entry state
    # Ä‘Ã£ Ä‘Æ°á»£c giáº£i mÃ£ khá»i master key hiá»‡n táº¡i, sau Ä‘Ã³ mÃ£ hÃ³a láº¡i báº±ng passphrase
    # backup riÃªng. Khi restore, entry Ä‘Æ°á»£c bá»c láº¡i báº±ng master key cá»§a láº§n Ä‘Äƒng
    # nháº­p hiá»‡n táº¡i. CÃ¡ch nÃ y giÃºp backup váº«n dÃ¹ng Ä‘Æ°á»£c sau khi ngÆ°á»i dÃ¹ng Ä‘á»•i
    # máº­t kháº©u tÃ i khoáº£n, miá»…n lÃ  há» cÃ²n passphrase backup.

    _BACKUP_FORMAT = "secchat-e2ee-state-backup"
    _BACKUP_VERSION = 3
    _BACKUP_MIN_VERSION = 1
    _BACKUP_KDF_ITERS = 600_000
    _BACKUP_PATTERNS = (
        "identity_sk.bin",
        "pqxdh_prekeys.bin",
        "dr_*.bin",
        "mls_*.bin",
        "verified_*.bin",
        "identity_audit_*.bin",
        "auditor_state.bin",
        "cache_policy.bin",
        "transcript_*.bin",
        "msgs_*.bin",
    )

    @classmethod
    def _backup_name_allowed(cls, name: str) -> bool:
        """Chỉ cho phép backup/restore các file state trong allowlist (chống path traversal)."""
        base = os.path.basename(str(name or ""))
        if base != name or not base:
            return False
        return any(fnmatch.fnmatchcase(base, pat) for pat in cls._BACKUP_PATTERNS)

    @classmethod
    def _backup_key(cls, passphrase: str, salt: bytes, iterations: int) -> bytes:
        """Dẫn xuất khóa AES backup từ passphrase bằng PBKDF2 (salt + iterations lưu trong file)."""
        if not passphrase:
            raise CryptoStateError("Backup passphrase is required.")
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=int(iterations),
        ).derive(passphrase.encode("utf-8"))

    @staticmethod
    def backup_passphrase_report(passphrase: str) -> dict:
        """Chấm độ mạnh passphrase backup (độ dài + đa dạng nhóm ký tự) cho UI cảnh báo."""
        value = passphrase or ""
        classes = sum([
            any(ch.islower() for ch in value),
            any(ch.isupper() for ch in value),
            any(ch.isdigit() for ch in value),
            any(not ch.isalnum() for ch in value),
        ])
        length_bonus = (1 if len(value) >= 16 else 0) + (1 if len(value) >= 24 else 0)
        score = classes + length_bonus
        ok = len(value) >= 12 and score >= 3
        if len(value) < 12:
            msg = "Use at least 12 characters for the backup passphrase."
        elif score < 3:
            msg = (
                "Use a longer passphrase or mix words with numbers or symbols."
            )
        else:
            msg = "Backup passphrase strength is acceptable."
        return {"ok": ok, "score": score, "message": msg}

    def _load_backup_state(self) -> dict:
        """Đọc metadata backup cục bộ (id, generation, danh sách revoke) đã mã hóa."""
        if not self.secchat_dir or not self.master_key:
            return {}
        path = self.backup_state_path()
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as fh:
                token = fh.read().strip()
            raw = decrypt_with_key(self.master_key, token, check_replay=False)
            data = json.loads(raw)
            return data if isinstance(data, dict) else {}
        except Exception as exc:
            self.logger.warning("Backup state load failed: %s", exc)
            return {}

    def _save_backup_state(self, state: dict) -> None:
        """Ghi metadata backup cục bộ xuống đĩa (mã hóa bằng master key)."""
        if not self.secchat_dir or not self.master_key:
            return
        try:
            os.makedirs(self.secchat_dir, exist_ok=True)
            token = encrypt_with_key(
                self.master_key,
                json.dumps(state, ensure_ascii=False, separators=(",", ":")),
            )
            with open(self.backup_state_path(), "w", encoding="utf-8") as fh:
                fh.write(token)
        except Exception as exc:
            self.logger.warning("Backup state save failed: %s", exc)

    def get_backup_status(self) -> dict:
        """Tóm tắt trạng thái backup gần nhất cho UI (id, thời điểm, generation, đã revoke...)."""
        state = self._load_backup_state()
        return {
            "latest_backup_id": str(state.get("latest_backup_id", "") or ""),
            "latest_created_at": int(state.get("latest_created_at", 0) or 0),
            "latest_generation": int(state.get("latest_generation", 0) or 0),
            "latest_device_label": str(state.get("latest_device_label", "") or ""),
            "latest_include_cache": bool(state.get("latest_include_cache", False)),
            "restored_from_backup_id": str(
                state.get("restored_from_backup_id", "") or ""),
            "restored_at": int(state.get("restored_at", 0) or 0),
            "revoked_before_generation": int(
                state.get("revoked_before_generation", 0) or 0),
            "revoked_count": len(list(state.get("revoked_backup_ids") or [])),
        }

    def revoke_local_backups(self) -> dict:
        """ÄÃ¡nh dáº¥u cÃ¡c backup mÃ  thiáº¿t bá»‹ nÃ y biáº¿t lÃ  khÃ´ng cÃ²n tin cáº­y.

        ÄÃ¢y khÃ´ng pháº£i revoke toÃ n cáº§u. Náº¿u ngÆ°á»i dÃ¹ng Ä‘Ã£ copy file backup ra
        nÆ¡i khÃ¡c, app khÃ´ng thá»ƒ xÃ³a hoáº·c vÃ´ hiá»‡u hÃ³a báº£n copy Ä‘Ã³. CÆ¡ cháº¿ nÃ y chá»‰
        lÃ m client hiá»‡n táº¡i tá»« chá»‘i restore cÃ¡c backup cÃ³ metadata khá»›p danh
        sÃ¡ch revoke cá»¥c bá»™.
        """
        state = self._load_backup_state()
        latest_id = str(state.get("latest_backup_id", "") or "")
        latest_generation = int(state.get("latest_generation", 0) or 0)
        revoked = set(str(x) for x in state.get("revoked_backup_ids", []) if x)
        if latest_id:
            revoked.add(latest_id)
        state["revoked_backup_ids"] = sorted(revoked)
        state["revoked_before_generation"] = max(
            int(state.get("revoked_before_generation", 0) or 0),
            latest_generation,
        )
        state["revoked_at"] = int(time.time())
        self._save_backup_state(state)
        return self.get_backup_status()

    def inspect_e2ee_backup(self, path: str) -> dict:
        """Đọc header/manifest file backup mà CHƯA cần passphrase (kiểm format + metadata)."""
        with open(path, "r", encoding="utf-8") as fh:
            outer = json.load(fh)
        if outer.get("format") != self._BACKUP_FORMAT:
            raise CryptoStateError("This is not a SecChat E2EE backup file.")
        manifest = outer.get("manifest") or {}
        return {
            "format": outer.get("format"),
            "version": int(outer.get("version", 1) or 1),
            "backup_id": str(outer.get("backup_id", "")
                             or manifest.get("backup_id", "") or ""),
            "generation": int(outer.get("generation", 0)
                              or manifest.get("generation", 0) or 0),
            "created_at": int(outer.get("created_at", 0)
                              or manifest.get("created_at", 0) or 0),
            "account_username": str(manifest.get("account_username", "") or ""),
            "user_id": int(manifest.get("user_id", 0) or 0),
            "device_label": str(manifest.get("device_label", "") or ""),
            "include_cache": bool(manifest.get("include_cache", False)),
            "identity_fingerprint": str(
                manifest.get("identity_fingerprint", "") or ""),
            "file_count": int(manifest.get("file_count", 0) or 0),
            "entry_count": int(manifest.get("entry_count", 0) or 0),
        }

    @staticmethod
    def _canonical_backup_manifest(manifest: dict) -> bytes:
        """Serialize manifest dạng canonical (sort_keys) để dùng làm AAD ký nhất quán."""
        return json.dumps(
            manifest, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")

    @staticmethod
    def _new_backup_id() -> str:
        return base64.urlsafe_b64encode(os.urandom(18)).decode("ascii").rstrip("=")

    def _identity_backup_fingerprint(self) -> str:
        """Fingerprint ngắn của identity key, gắn vào manifest để nhận diện chủ backup."""
        pk = self.identity_pk or b""
        if not pk and self.identity_sk:
            pk = identity_pk_from_sk(self.identity_sk)
        return hashlib.sha256(pk).hexdigest()[:24] if pk else ""

    @staticmethod
    def _b64(raw: bytes) -> str:
        return base64.b64encode(raw).decode("ascii")

    @staticmethod
    def _unb64(text: str) -> bytes:
        return base64.b64decode(str(text).encode("ascii"))

    def _state_files_for_backup(self, *, include_cache: bool) -> list[tuple[str, bool]]:
        """Liệt kê các file state cần đưa vào backup theo allowlist (tùy chọn kèm cache tin)."""
        if not self.secchat_dir:
            return []
        out: list[tuple[str, bool]] = []
        seen: set[str] = set()
        for pattern in self._BACKUP_PATTERNS:
            if not include_cache and pattern == "msgs_*.bin":
                continue
            for path in glob.glob(os.path.join(self.secchat_dir, pattern)):
                name = os.path.basename(path)
                if name in seen or not self._backup_name_allowed(name):
                    continue
                seen.add(name)
                out.append((path, name.startswith("msgs_")))
        out.sort(key=lambda item: os.path.basename(item[0]))
        return out

    def export_e2ee_backup(self, path: str, passphrase: str, *,
                           account_username: str = "",
                           include_cache: bool = True) -> dict:
        """Xuáº¥t state E2EE cá»¥c bá»™ thÃ nh má»™t file backup mÃ£ hÃ³a báº±ng passphrase.

        Payload backup chá»©a cÃ¡c entry state sau khi Ä‘Ã£ thÃ¡o lá»›p mÃ£ hÃ³a báº±ng
        master key hiá»‡n táº¡i. ToÃ n bá»™ payload sau Ä‘Ã³ Ä‘Æ°á»£c mÃ£ hÃ³a báº±ng passphrase
        backup riÃªng. Khi restore, tá»«ng entry Ä‘Æ°á»£c mÃ£ hÃ³a láº¡i báº±ng master key
        cá»§a phiÃªn Ä‘Äƒng nháº­p hiá»‡n táº¡i, nÃªn Ä‘á»•i máº­t kháº©u tÃ i khoáº£n sau khi export
        khÃ´ng lÃ m file backup cÅ© máº¥t tÃ¡c dá»¥ng.
        """
        if not self.master_key or not self.secchat_dir:
            raise CryptoStateError("Login is required before exporting backup.")
        report = self.backup_passphrase_report(passphrase)
        if not report.get("ok"):
            raise CryptoStateError(
                str(report.get("message") or "Backup passphrase is too weak.")
            )
        self._save_mls_state()
        files = []
        for src, line_mode in self._state_files_for_backup(include_cache=include_cache):
            entries = []
            with open(src, "r", encoding="utf-8") as fh:
                raw_lines = fh.read().splitlines() if line_mode else [fh.read().strip()]
            for token in raw_lines:
                token = token.strip()
                if not token:
                    continue
                entries.append(decrypt_with_key(self.master_key, token, check_replay=False))
            if entries:
                files.append({
                    "name": os.path.basename(src),
                    "line_mode": bool(line_mode),
                    "entries": entries,
                })

        state = self._load_backup_state()
        generation = int(state.get("latest_generation", 0) or 0) + 1
        created_at = int(time.time())
        backup_id = self._new_backup_id()
        entry_count = sum(len(f["entries"]) for f in files)
        manifest = {
            "format": self._BACKUP_FORMAT,
            "version": self._BACKUP_VERSION,
            "backup_id": backup_id,
            "generation": generation,
            "created_at": created_at,
            "account_username": account_username or "",
            "user_id": int(self.my_uid or 0),
            "include_cache": bool(include_cache),
            "device_label": str(state.get("device_label", "") or "primary device"),
            "identity_fingerprint": self._identity_backup_fingerprint(),
            "file_count": len(files),
            "entry_count": entry_count,
        }
        payload = {
            "format": self._BACKUP_FORMAT,
            "version": self._BACKUP_VERSION,
            "manifest": manifest,
            "backup_id": backup_id,
            "generation": generation,
            "created_at": created_at,
            "account_username": account_username or "",
            "user_id": int(self.my_uid or 0),
            "include_cache": bool(include_cache),
            "files": files,
        }
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._backup_key(passphrase, salt, self._BACKUP_KDF_ITERS)
        plain = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        aad = self._canonical_backup_manifest(manifest)
        ct = AESGCM(key).encrypt(nonce, plain, aad)
        outer = {
            "format": self._BACKUP_FORMAT,
            "version": self._BACKUP_VERSION,
            "backup_id": backup_id,
            "generation": generation,
            "created_at": created_at,
            "include_cache": bool(include_cache),
            "manifest": manifest,
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": self._BACKUP_KDF_ITERS,
            "salt": self._b64(salt),
            "nonce": self._b64(nonce),
            "ciphertext": self._b64(ct),
        }
        dst_dir = os.path.dirname(os.path.abspath(path))
        if dst_dir:
            os.makedirs(dst_dir, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(outer, fh, ensure_ascii=False, separators=(",", ":"))
        state.update({
            "latest_backup_id": backup_id,
            "latest_generation": generation,
            "latest_created_at": created_at,
            "latest_device_label": manifest["device_label"],
            "latest_include_cache": bool(include_cache),
        })
        self._save_backup_state(state)
        return {
            "files": len(files),
            "entries": entry_count,
            "backup_id": backup_id,
            "backup_generation": generation,
            "created_at": created_at,
            "include_cache": bool(include_cache),
        }

    def restore_e2ee_backup(self, path: str, passphrase: str, *,
                            overwrite: bool = True,
                            preserve_current_identity: bool = False) -> dict:
        """KhÃ´i phá»¥c backup E2EE vÃ  re-wrap state báº±ng master key hiá»‡n táº¡i.

        Sau khi ghi láº¡i file state, cÃ¡c cache trong RAM bá»‹ xÃ³a Ä‘á»ƒ láº§n Ä‘á»c tiáº¿p
        theo náº¡p láº¡i tá»« Ä‘Ä©a. Restore cÃ³ thá»ƒ thay Ä‘á»•i identity key hoáº·c ratchet
        state cá»¥c bá»™, nÃªn UI luÃ´n nÃªn yÃªu cáº§u ngÆ°á»i dÃ¹ng review láº¡i identity.
        """
        if not self.master_key or not self.secchat_dir:
            raise CryptoStateError("Login is required before restoring backup.")
        with open(path, "r", encoding="utf-8") as fh:
            outer = json.load(fh)
        if outer.get("format") != self._BACKUP_FORMAT:
            raise CryptoStateError("This is not a SecChat E2EE backup file.")
        manifest = outer.get("manifest") or {}
        backup_id = str(outer.get("backup_id", "")
                        or manifest.get("backup_id", "") or "")
        generation = int(outer.get("generation", 0)
                         or manifest.get("generation", 0) or 0)
        state = self._load_backup_state()
        revoked_ids = {str(x) for x in state.get("revoked_backup_ids", []) if x}
        revoked_before = int(state.get("revoked_before_generation", 0) or 0)
        if backup_id and backup_id in revoked_ids:
            raise CryptoStateError(
                "This backup was revoked on this device and will not be restored."
            )
        if generation and revoked_before and generation <= revoked_before:
            raise CryptoStateError(
                "This backup generation was revoked on this device and will not be restored."
            )
        key = self._backup_key(
            passphrase,
            self._unb64(outer["salt"]),
            int(outer.get("iterations", self._BACKUP_KDF_ITERS)),
        )
        aad = self._canonical_backup_manifest(manifest) if manifest else None
        plain = AESGCM(key).decrypt(
            self._unb64(outer["nonce"]),
            self._unb64(outer["ciphertext"]),
            aad,
        )
        payload = json.loads(plain.decode("utf-8"))
        version = int(payload.get("version", 0) or 0)
        if (payload.get("format") != self._BACKUP_FORMAT
                or version < self._BACKUP_MIN_VERSION
                or version > self._BACKUP_VERSION):
            raise CryptoStateError("Unsupported SecChat backup version.")
        payload_manifest = payload.get("manifest") or {}
        if manifest and payload_manifest != manifest:
            raise CryptoStateError("Backup manifest does not match encrypted payload.")

        os.makedirs(self.secchat_dir, exist_ok=True)
        restored = 0
        entries = 0
        skipped = 0
        for item in payload.get("files", []):
            name = os.path.basename(str(item.get("name", "")))
            if not self._backup_name_allowed(name):
                continue
            dst = os.path.join(self.secchat_dir, name)
            line_mode = bool(item.get("line_mode", False))
            if preserve_current_identity and self._restore_should_skip_for_merge(name):
                skipped += 1
                continue
            if os.path.exists(dst) and not overwrite and not (
                    preserve_current_identity and name.startswith("msgs_") and line_mode):
                skipped += 1
                continue
            raw_entries = [str(entry) for entry in item.get("entries", [])]
            if preserve_current_identity and name.startswith("msgs_") and line_mode:
                raw_entries = self._merge_cache_entries(dst, raw_entries)
            elif preserve_current_identity and os.path.exists(dst):
                skipped += 1
                continue
            encrypted = [encrypt_with_key(self.master_key, entry) for entry in raw_entries]
            tmp = dst + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                if line_mode:
                    if encrypted:
                        fh.write("\n".join(encrypted) + "\n")
                else:
                    fh.write(encrypted[0] if encrypted else "")
            os.replace(tmp, dst)
            restored += 1
            entries += len(encrypted)

        if not preserve_current_identity:
            self.conv_verified.clear()
            self.conv_fingerprints.clear()
            self.identity_audit_states.clear()
            self.auditor_state.clear()
            self.pqxdh_prekeys = None
            self.double_ratchet_states.clear()
            self.double_ratchet_session_states.clear()
            self.group_epochs.clear()
            self.group_conv_ids.clear()
            self.mls_group_ready.clear()
            self.mls_handshake_seen.clear()
            if self.mls_bridge:
                try:
                    self.mls_bridge.close()
                except Exception:
                    pass
                self.mls_bridge = None
            self.mls_identity_ready = False
            self.mls_credential_identity_b64 = ""
        self.load_cache_policy()
        self.load_or_create_identity_key()
        if not preserve_current_identity:
            self._load_mls_state_into_bridge()
        state = self._load_backup_state()
        state.update({
            "restored_from_backup_id": backup_id,
            "restored_generation": generation,
            "restored_at": int(time.time()),
            "latest_backup_id": state.get("latest_backup_id", "") or backup_id,
            "latest_generation": max(
                int(state.get("latest_generation", 0) or 0), generation),
            "latest_created_at": int(
                state.get("latest_created_at", 0) or 0)
                or int(manifest.get("created_at", payload.get("created_at", 0)) or 0),
            "latest_device_label": state.get("latest_device_label", "")
                or str(manifest.get("device_label", "") or ""),
            "latest_include_cache": bool(
                state.get("latest_include_cache", False)
                or payload.get("include_cache", False)),
        })
        self._save_backup_state(state)
        return {
            "files": restored,
            "entries": entries,
            "skipped": skipped,
            "account_username": payload.get("account_username", ""),
            "user_id": int(payload.get("user_id", 0) or 0),
            "include_cache": bool(payload.get("include_cache", False)),
            "backup_id": backup_id,
            "backup_generation": generation,
            "created_at": int(payload.get("created_at", 0) or 0),
            "identity_review_recommended": True,
            "preserved_current_identity": bool(preserve_current_identity),
        }

    @staticmethod
    def _restore_should_skip_for_merge(name: str) -> bool:
        if name in {
                "identity_sk.bin",
                "pqxdh_prekeys.bin",
                "auditor_state.bin",
                "cache_policy.bin",
        }:
            return True
        return (
            name.startswith("dr_")
            or name.startswith("mls_")
            or name.startswith("verified_")
            or name.startswith("identity_audit_")
            or name.startswith("transcript_")
        )

    def _merge_cache_entries(self, dst: str, incoming: list[str]) -> list[str]:
        """Union message-cache entries and prefer readable plaintext rows.

        A rotated/new device can already have a placeholder for the same message
        id before the user imports an older backup.  Keeping that placeholder
        would hide the plaintext that the backup is supposed to recover.
        """
        merged: dict[str, str] = {}

        def key_for(raw: str) -> str:
            try:
                item = json.loads(raw)
                mid = int(item.get("id", 0) or 0)
                if mid:
                    return f"id:{mid}"
                wire_hash = str(item.get("wire_hash", "") or "")
                if wire_hash:
                    return f"wire:{wire_hash}"
            except Exception:
                pass
            return f"raw:{hashlib.sha256(raw.encode('utf-8')).hexdigest()}"

        def quality(raw: str) -> int:
            try:
                item = json.loads(raw)
                body = str(item.get("body", "") or "")
            except Exception:
                return 0
            if not body:
                return 0
            placeholders = (
                "[Forward-secret]",
                "[Message deleted]",
                "[Encrypted",
                "[Cannot",
            )
            if any(body.startswith(prefix) for prefix in placeholders):
                return 1
            return 2

        def keep(raw: str) -> None:
            key = key_for(raw)
            current = merged.get(key)
            if current is None or quality(raw) > quality(current):
                merged[key] = raw

        if os.path.exists(dst):
            try:
                with open(dst, "r", encoding="utf-8") as fh:
                    for line in fh:
                        token = line.strip()
                        if not token:
                            continue
                        try:
                            raw = decrypt_with_key(
                                self.master_key, token, check_replay=False)
                            keep(raw)
                        except Exception:
                            continue
            except OSError:
                pass
        for raw in incoming:
            keep(raw)
        return list(merged.values())

    # Server-consistency detection
    #
    # E2EE khÃ´ng ngÄƒn server che giáº¥u, sáº¯p xáº¿p láº¡i hoáº·c tráº£ thiáº¿u history. Pháº§n
    # transcript dÆ°á»›i Ä‘Ã¢y ghi láº¡i digest cá»§a cÃ¡c message Ä‘Ã£ tháº¥y Ä‘á»ƒ client phÃ¡t
    # hiá»‡n má»™t sá»‘ hÃ nh vi báº¥t thÆ°á»ng: message tá»«ng tháº¥y bá»‹ máº¥t, body bá»‹ thay Ä‘á»•i
    # hoáº·c thá»© tá»± history khÃ´ng nháº¥t quÃ¡n.

    def _load_transcript_state(self, conv_id: int) -> dict:
        """Đọc state transcript của hội thoại (digest các tin đã thấy) đã mã hóa."""
        if not self.secchat_dir or not self.master_key:
            return {"messages": {}}
        path = self.transcript_path(conv_id)
        if not os.path.exists(path):
            return {"messages": {}}
        try:
            with open(path, "r", encoding="utf-8") as fh:
                token = fh.read().strip()
            raw = decrypt_with_key(self.master_key, token, check_replay=False)
            data = json.loads(raw)
            if isinstance(data.get("messages"), dict):
                return data
        except Exception as exc:
            self.logger.warning(
                "Transcript state load failed conv=%d: %s", conv_id, exc)
        return {"messages": {}}

    def _save_transcript_state(self, conv_id: int, state: dict) -> None:
        """Ghi state transcript xuống đĩa (mã hóa bằng master key)."""
        if not self.secchat_dir or not self.master_key:
            return
        try:
            os.makedirs(self.secchat_dir, exist_ok=True)
            token = encrypt_with_key(
                self.master_key, json.dumps(state, ensure_ascii=False))
            with open(self.transcript_path(conv_id), "w", encoding="utf-8") as fh:
                fh.write(token)
        except Exception as exc:
            self.logger.warning(
                "Transcript state save failed conv=%d: %s", conv_id, exc)

    @staticmethod
    def _is_user_visible_body(body: str) -> bool:
        """True nếu body là tin người dùng thật (không phải control marker/placeholder).

        Lọc các marker điều khiển PQXDH (``__S2_CONTROL__``/``__S3_INIT__``) và các
        placeholder ([Forward-secret], [Cannot...], [Encrypted...]) để chúng không
        bị tính vào preview hay số tin chưa đọc.
        """
        body = str(body or "")
        if body in ("__S2_CONTROL__", "__S3_INIT__"):
            return False
        if not body or body.startswith(("[Forward-secret]", "[Cannot", "[Encrypted")):
            return False
        return True

    def _message_digest(self, item: dict) -> str:
        """Băm canonical một message (id, người gửi, body, edit, deleted) → digest chống sửa lén."""
        body = str(item.get("body", ""))
        canonical = {
            "id": int(item.get("id", item.get("msg_id", 0)) or 0),
            "sender_id": int(item.get("sender_id", item.get("from_id", 0)) or 0),
            "body": body,
            "edit_target": int(item.get("edit_target_message_id", 0) or 0),
            "deleted": bool(item.get("deleted", False)),
        }
        raw = json.dumps(canonical, sort_keys=True, ensure_ascii=False,
                         separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _canonical_transcript_checkpoint(payload: dict) -> bytes:
        """Serialize checkpoint dạng canonical (bỏ sig/hash) để ký và băm nhất quán."""
        clean = {
            k: v for k, v in payload.items()
            if k not in ("sig", "checkpoint_hash")
        }
        return json.dumps(
            clean, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")

    @classmethod
    def _transcript_checkpoint_hash(cls, payload: dict) -> str:
        """SHA-256 của checkpoint canonical (dùng đối chiếu transcript giữa các client)."""
        return hashlib.sha256(
            cls._canonical_transcript_checkpoint(payload)
        ).hexdigest()

    def _recompute_transcript_chain(self, conv_id: int, state: dict) -> dict:
        """TÃ­nh transcript head dáº¡ng append-only tá»« cÃ¡c message Ä‘Ã£ biáº¿t.

        Má»—i message má»›i hash kÃ¨m head trÆ°á»›c Ä‘Ã³, táº¡o má»™t chuá»—i bÄƒm Ä‘Æ¡n giáº£n.
        CÆ¡ cháº¿ nÃ y khÃ´ng che metadata, nhÆ°ng giÃºp cÃ¡c client so sÃ¡nh view cá»§a
        mÃ¬nh vÃ  phÃ¡t hiá»‡n khi server Ä‘Æ°a lá»‹ch sá»­ khÃ¡c nhau.
        """
        messages = state.setdefault("messages", {})
        items: list[tuple[int, str]] = []
        for sid, digest in list(messages.items()):
            try:
                mid = int(sid)
            except Exception:
                continue
            if mid > 0 and isinstance(digest, str) and digest:
                items.append((mid, digest))

        head = "0" * 64
        heads_by_id: dict[str, str] = {}
        sorted_items = sorted(items)
        for mid, digest in sorted_items:
            raw = json.dumps(
                {
                    "domain": "SecChatTranscript",
                    "conversation_id": int(conv_id),
                    "message_id": int(mid),
                    "message_digest": digest,
                    "prev": head,
                },
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            head = hashlib.sha256(raw).hexdigest()
            heads_by_id[str(mid)] = head

        state["transcript_head"] = head if items else ""
        state["transcript_message_count"] = len(items)
        state["transcript_first_message_id"] = int(sorted_items[0][0]) if sorted_items else 0
        state["transcript_last_message_id"] = int(sorted_items[-1][0]) if sorted_items else 0
        state["transcript_heads_by_id"] = heads_by_id
        return state

    def record_transcript_message(self, conv_id: int, msg_id: int, sender_id: int,
                                  body: str, ts: str, *,
                                  edit_target_message_id: int = 0,
                                  deleted: bool = False) -> None:
        """Ghi digest cá»§a message Ä‘Ã£ cháº¥p nháº­n vÃ o transcript cá»¥c bá»™."""
        if not msg_id or not self._is_user_visible_body(body):
            return
        state = self._load_transcript_state(conv_id)
        state.setdefault("messages", {})[str(int(msg_id))] = self._message_digest({
            "id": msg_id,
            "sender_id": sender_id,
            "body": body,
            "time": ts,
            "edit_target_message_id": edit_target_message_id,
            "deleted": deleted,
        })
        self._recompute_transcript_chain(int(conv_id), state)
        state["updated_at"] = time.time()
        self._save_transcript_state(conv_id, state)

    def verify_history_consistency(self, conv_id: int,
                                   messages: list[dict]) -> list[str]:
        """So sÃ¡nh history server tráº£ vá» vá»›i transcript Ä‘Ã£ lÆ°u trÆ°á»›c Ä‘Ã³.

        Náº¿u server tráº£ thiáº¿u message trong khoáº£ng client tá»«ng tháº¥y, Ä‘á»•i ná»™i dung
        message cÅ© hoáº·c tráº£ sai thá»© tá»± id, hÃ m tráº£ warning Ä‘á»ƒ UI hiá»ƒn thá»‹ cáº£nh
        bÃ¡o consistency. ÄÃ¢y lÃ  cÆ¡ cháº¿ phÃ¡t hiá»‡n gian láº­n/sai lá»‡ch, khÃ´ng pháº£i
        cÆ¡ cháº¿ tá»± sá»­a history.
        """
        relevant = []
        for msg in messages:
            mid = int(msg.get("id", 0) or 0)
            body = str(msg.get("body", ""))
            if mid > 0 and self._is_user_visible_body(body):
                relevant.append(msg)
        if not relevant:
            return []

        ids = [int(m.get("id", 0) or 0) for m in relevant]
        incoming = {str(i): self._message_digest(m)
                    for i, m in zip(ids, relevant)}
        state = self._load_transcript_state(conv_id)
        known = state.setdefault("messages", {})
        warnings: list[str] = []

        if ids != sorted(ids):
            warnings.append("Server returned this history out of message order.")

        min_id, max_id = min(ids), max(ids)
        for sid, digest in sorted(known.items(), key=lambda item: int(item[0])):
            try:
                mid = int(sid)
            except ValueError:
                continue
            if min_id <= mid <= max_id and sid not in incoming:
                warnings.append(
                    f"Previously seen message #{mid} is missing from server history.")
            elif sid in incoming and incoming[sid] != digest:
                warnings.append(
                    f"Previously seen message #{mid} changed in server history.")

        known.update(incoming)
        window_hash = hashlib.sha256(
            "|".join(f"{mid}:{incoming[str(mid)]}" for mid in ids)
            .encode("utf-8")
        ).hexdigest()
        state["last_window_hash"] = window_hash
        self._recompute_transcript_chain(int(conv_id), state)
        state["updated_at"] = time.time()
        self._save_transcript_state(conv_id, state)
        return warnings[:3]

    def create_transcript_checkpoint(self, conv_id: int) -> str:
        """Táº¡o checkpoint transcript cÃ³ chá»¯ kÃ½ Ä‘á»ƒ cÃ¡c thÃ nh viÃªn group so sÃ¡nh.

        Checkpoint khÃ´ng giáº¥u metadata. NÃ³ lÃ  lá»i kháº³ng Ä‘á»‹nh cÃ³ chá»¯ kÃ½ cá»§a
        client ráº±ng â€œtÃ´i Ä‘Ã£ cháº¥p nháº­n transcript Ä‘áº¿n message X vá»›i head Yâ€.
        Náº¿u thÃ nh viÃªn khÃ¡c tháº¥y head khÃ¡c táº¡i cÃ¹ng má»‘c, group cÃ³ thá»ƒ cáº£nh bÃ¡o
        server Ä‘ang Ä‘Æ°a view khÃ´ng nháº¥t quÃ¡n.
        """
        if not self.identity_sk or not self.identity_pk:
            raise CryptoStateError("Identity key is not loaded.")
        conv_id = int(conv_id)
        state = self._load_transcript_state(conv_id)
        self._recompute_transcript_chain(conv_id, state)
        count = int(state.get("transcript_message_count", 0) or 0)
        first_id = int(state.get("transcript_first_message_id", 0) or 0)
        last_id = int(state.get("transcript_last_message_id", 0) or 0)
        head = str(state.get("transcript_head", "") or "")
        if count <= 0 or first_id <= 0 or last_id <= 0 or not head:
            return ""

        payload = {
            "v": 2,
            "event": "transcript_checkpoint",
            "conversation_id": conv_id,
            "actor_uid": int(self.my_uid or 0),
            "message_count": count,
            "first_message_id": first_id,
            "last_message_id": last_id,
            "transcript_head": head,
            "prev_checkpoint_hash": str(
                state.get("last_own_transcript_checkpoint_hash", "") or ""),
            "identity_pk": base64.b64encode(self.identity_pk).decode("ascii"),
            "ts": int(time.time() * 1000),
        }
        payload["sig"] = base64.b64encode(
            identity_sign(
                self.identity_sk,
                self._canonical_transcript_checkpoint(payload),
            )
        ).decode("ascii")
        payload["checkpoint_hash"] = self._transcript_checkpoint_hash(payload)
        state["last_own_transcript_checkpoint_hash"] = payload["checkpoint_hash"]
        state["last_own_transcript_checkpoint"] = payload
        state["updated_at"] = time.time()
        self._save_transcript_state(conv_id, state)
        return PREFIX_MLS + json_b64(payload)

    def record_transcript_checkpoint(self, conv_id: int, payload: dict,
                                     *, verify_signature: bool = True) -> list[str]:
        """Ghi checkpoint transcript cá»§a peer vÃ  kiá»ƒm tra nÃ³ cÃ³ khá»›p view local."""
        conv_id = int(conv_id)
        warnings: list[str] = []
        try:
            if int(payload.get("conversation_id", 0) or 0) != conv_id:
                warnings.append("Transcript checkpoint targets a different conversation.")
            if str(payload.get("event", "") or "") != "transcript_checkpoint":
                warnings.append("Transcript checkpoint has an invalid event type.")
            actor_uid = int(payload.get("actor_uid", 0) or 0)
            first_id = int(payload.get("first_message_id", 0) or 0)
            last_id = int(payload.get("last_message_id", 0) or 0)
            count = int(payload.get("message_count", 0) or 0)
            head = str(payload.get("transcript_head", "") or "")
            identity_pk_b64 = str(payload.get("identity_pk", "") or "")
            if actor_uid <= 0 or first_id <= 0 or last_id <= 0 or count <= 0 or len(head) != 64:
                warnings.append("Transcript checkpoint is missing required fields.")
            if verify_signature:
                pk = base64.b64decode(identity_pk_b64.encode("ascii"))
                sig = base64.b64decode(str(payload.get("sig", "")).encode("ascii"))
                identity_verify(
                    pk, self._canonical_transcript_checkpoint(payload), sig)
        except Exception:
            warnings.append("Transcript checkpoint has an invalid signature or encoding.")
            actor_uid = int(payload.get("actor_uid", 0) or 0)
            first_id = int(payload.get("first_message_id", 0) or 0)
            last_id = int(payload.get("last_message_id", 0) or 0)
            head = str(payload.get("transcript_head", "") or "")
            identity_pk_b64 = str(payload.get("identity_pk", "") or "")

        state = self._load_transcript_state(conv_id)
        self._recompute_transcript_chain(conv_id, state)
        peers = state.setdefault("peer_transcript_checkpoints", {})
        peer_key = identity_pk_b64 or f"uid:{actor_uid}"
        previous = peers.get(peer_key) if isinstance(peers, dict) else None

        if isinstance(previous, dict):
            prev_last = int(previous.get("last_message_id", 0) or 0)
            prev_head = str(previous.get("transcript_head", "") or "")
            prev_hash = str(previous.get("checkpoint_hash", "") or "")
            declared_prev = str(payload.get("prev_checkpoint_hash", "") or "")
            if last_id < prev_last:
                warnings.append("Transcript checkpoint rolled back a peer view.")
            if last_id == prev_last and prev_head and head and prev_head != head:
                warnings.append("Transcript checkpoint changed a peer view at the same message.")
            if declared_prev and prev_hash and declared_prev != prev_hash:
                warnings.append("Transcript checkpoint chain does not continue the previous peer checkpoint.")

        local_first_id = int(state.get("transcript_first_message_id", 0) or 0)
        same_baseline = local_first_id > 0 and first_id > 0 and local_first_id == first_id
        if same_baseline:
            local_heads = state.get("transcript_heads_by_id", {})
            local_head_at_last = (
                local_heads.get(str(last_id)) if isinstance(local_heads, dict) else "")
            if local_head_at_last and head and local_head_at_last != head:
                warnings.append(
                    "Transcript checkpoint does not match the local message order.")
            elif int(state.get("transcript_last_message_id", 0) or 0) == last_id:
                local_head = str(state.get("transcript_head", "") or "")
                if local_head and head and local_head != head:
                    warnings.append(
                        "Transcript checkpoint does not match the local message order.")

        checkpoint_hash = self._transcript_checkpoint_hash(payload)
        stored = {
            "actor_uid": actor_uid,
            "identity_pk": identity_pk_b64,
            "message_count": int(payload.get("message_count", 0) or 0),
            "first_message_id": first_id,
            "last_message_id": last_id,
            "transcript_head": head,
            "prev_checkpoint_hash": str(
                payload.get("prev_checkpoint_hash", "") or ""),
            "checkpoint_hash": checkpoint_hash,
            "ts": int(payload.get("ts", 0) or 0),
            "seen_at": time.time(),
        }
        peers[peer_key] = stored
        state["peer_transcript_checkpoints"] = peers
        state["updated_at"] = time.time()
        self._save_transcript_state(conv_id, state)

        if warnings:
            for warning in warnings:
                self._add_control_warning(conv_id, warning)
        return warnings[:5]

    @staticmethod
    def normalize_group_members(members_or_ids) -> list[dict]:
        """Chuẩn hóa danh sách thành viên về [{user_id, role}] đã sort + khử trùng (admin ưu tiên)."""
        by_uid: dict[int, str] = {}
        for member in members_or_ids or []:
            if isinstance(member, dict):
                value = member.get("user_id", member.get("id", 0))
                role = str(member.get("role", "member") or "member")
            else:
                value = member
                role = "member"
            try:
                uid = int(value)
            except Exception:
                continue
            if uid <= 0:
                continue
            if role not in ("admin", "member"):
                role = "member"
            old = by_uid.get(uid)
            by_uid[uid] = "admin" if old == "admin" or role == "admin" else role
        return [
            {"user_id": uid, "role": by_uid[uid]}
            for uid in sorted(by_uid)
        ]

    @classmethod
    def group_membership_hash(cls, members_or_ids) -> str:
        """Hash canonical của danh sách thành viên + vai trò (so khớp view membership giữa client)."""
        canonical = cls.normalize_group_members(members_or_ids)
        return hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":"))
            .encode("utf-8")
        ).hexdigest()

    @classmethod
    def _group_role_for_uid(cls, members_or_ids, uid: int) -> str:
        """Trả về vai trò (admin/member) của một uid trong group; "" nếu không thuộc group."""
        uid = int(uid or 0)
        for member in cls.normalize_group_members(members_or_ids):
            if int(member["user_id"]) == uid:
                return str(member.get("role", "member") or "member")
        return ""

    def verify_group_membership(self, conv_id: int, members: list[dict],
                                *, expected_change: bool = False) -> list[str]:
        """Lưu snapshot membership nhóm mới nhất (chỉ là metadata cục bộ).

        Thay đổi thành viên MLS được xác thực bởi OpenMLS qua Commit/Welcome/
        GroupInfo. Helper này chỉ giữ snapshot metadata cho UI/cache nhất quán,
        KHÔNG cài một chuỗi commit song song ở tầng app (nên ``expected_change``
        hiện được giữ cho ổn định interface chứ chưa dùng).
        """
        state = self._load_transcript_state(conv_id)
        canonical = self.normalize_group_members(members)
        digest = self.group_membership_hash(canonical)
        ids_digest = self.group_member_ids_hash(canonical)

        state["membership_hash"] = digest
        state["member_ids_hash"] = ids_digest
        state["membership_members"] = canonical
        state["membership_updated_at"] = time.time()
        self._save_transcript_state(conv_id, state)
        return []

    @staticmethod
    def group_member_ids_hash(members_or_ids) -> str:
        """Hash của tập user_id thành viên (bỏ vai trò) — so khớp thành phần nhóm."""
        ids = []
        for member in CryptoSession.normalize_group_members(members_or_ids):
            ids.append(int(member["user_id"]))
        ids = sorted(set(ids))
        return hashlib.sha256(
            json.dumps(ids, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    # Identity and prekey bundles
    #
    # Identity key lÃ  khÃ³a Ä‘á»‹nh danh dÃ i háº¡n. Prekey bundle lÃ  dá»¯ liá»‡u public
    # server phÃ¡t cho ngÆ°á»i khÃ¡c khi há» muá»‘n báº¯t Ä‘áº§u DM báº±ng PQXDH. Private
    # prekey luÃ´n náº±m trÃªn client vÃ  Ä‘Æ°á»£c mÃ£ hÃ³a báº±ng master key.

    def save_identity_key(self) -> None:
        """LÆ°u secret identity key cá»¥c bá»™ sau khi mÃ£ hÃ³a báº±ng master key."""
        if not self.secchat_dir or not self.master_key or not self.identity_sk:
            return
        try:
            os.makedirs(self.secchat_dir, exist_ok=True)
            token = encrypt_with_key(
                self.master_key, base64.b64encode(self.identity_sk).decode())
            with open(self.identity_key_path(), "w", encoding="utf-8") as fh:
                fh.write(token)
        except Exception as exc:
            self.logger.warning("Identity key save failed: %s", exc)

    def load_or_create_identity_key(self) -> None:
        """Náº¡p identity key cÅ© hoáº·c táº¡o má»›i náº¿u thiáº¿t bá»‹ chÆ°a cÃ³.

        Identity key Ä‘á»•i lÃ m safety number Ä‘á»•i. VÃ¬ váº­y khi file local máº¥t hoáº·c
        bá»‹ lá»—i, client pháº£i coi Ä‘Ã¢y lÃ  identity má»›i vÃ  server sáº½ yÃªu cáº§u
        ``rotate_identity`` náº¿u identity Ä‘Ã£ tá»“n táº¡i trÆ°á»›c Ä‘Ã³.
        """
        if not self.secchat_dir or not self.master_key:
            return
        path = self.identity_key_path()
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    token = fh.read().strip()
                sk_b64 = decrypt_with_key(
                    self.master_key, token, check_replay=False)
                self.identity_sk = base64.b64decode(sk_b64)
                self.identity_pk = identity_pk_from_sk(self.identity_sk)
                return
            except Exception as exc:
                self.logger.warning(
                    "Identity key load failed, regenerating: %s", exc)
        self.identity_pk, self.identity_sk = identity_keygen()
        self.save_identity_key()

    def save_pqxdh_prekeys(self) -> None:
        """LÆ°u private prekey PQXDH cá»¥c bá»™.

        Server chá»‰ nháº­n public prekey. Private prekey Ä‘Æ°á»£c giá»¯ á»Ÿ Ä‘Ã¢y Ä‘á»ƒ responder
        cÃ³ thá»ƒ xá»­ lÃ½ ``S3PQI`` khi ngÆ°á»i khÃ¡c báº¯t Ä‘áº§u DM hoáº·c gá»­i Welcome group.
        """
        if not self.secchat_dir or not self.master_key or not self.pqxdh_prekeys:
            return
        try:
            os.makedirs(self.secchat_dir, exist_ok=True)
            token = encrypt_with_key(
                self.master_key,
                json.dumps(self.pqxdh_prekeys, separators=(",", ":"), ensure_ascii=False),
            )
            with open(self.pqxdh_prekeys_path(), "w", encoding="utf-8") as fh:
                fh.write(token)
        except Exception as exc:
            self.logger.warning("SecChat prekey save failed: %s", exc)

    def load_pqxdh_prekeys(self) -> dict | None:
        """Náº¡p bundle/private prekey tá»« Ä‘Ä©a náº¿u chÆ°a cÃ³ trong RAM."""
        if self.pqxdh_prekeys:
            return self.pqxdh_prekeys
        if not self.secchat_dir or not self.master_key:
            return None
        path = self.pqxdh_prekeys_path()
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as fh:
                token = fh.read().strip()
            raw = decrypt_with_key(self.master_key, token, check_replay=False)
            self.pqxdh_prekeys = json.loads(raw)
            return self.pqxdh_prekeys
        except Exception as exc:
            self.logger.warning("SecChat prekey load failed: %s", exc)
            return None

    @staticmethod
    def _clone_pqxdh_prekey_store(store: dict) -> dict:
        """Tạo bản sao sâu JSON-safe trước khi thử decapsulate (thao tác phá hủy store)."""
        return json.loads(json.dumps(store))

    def _respond_pqxdh_with_current_prekey(
            self, body: str) -> tuple[str, DoubleRatchet, str, int]:
        """Phía nhận xử lý một wire ``S3PQI`` để lập cùng root secret với phía gửi.

        Làm trên BẢN SAO store (vì decapsulate sẽ pop one-time prekey); chỉ commit
        store đã pop khi respond thành công, tránh mất OTK khi gặp wire hỏng.
        """
        store = self.load_pqxdh_prekeys()
        if not store:
            raise CryptoStateError("SecChat prekey store is not available.")
        candidate = self._clone_pqxdh_prekey_store(store)
        result = pqxdh_respond(body, candidate, expected_uid=self.my_uid)
        self.pqxdh_prekeys = candidate
        self.save_pqxdh_prekeys()
        return result

    def ensure_pqxdh_bundle_command(self) -> dict | None:
        """Tạo bundle PQXDH sạch ĐẦU TIÊN cho account chưa có prekey store cục bộ.

        Chỉ dùng khi account chưa có store nào. Luồng restore/replenish nên dùng
        ``fresh_pqxdh_bundle_command`` để sinh hẳn một batch OTK mới.
        """
        if self.load_pqxdh_prekeys() is not None:
            return None
        if not self.identity_pk or not self.identity_sk:
            return None
        upload, local = generate_local_bundle(
            self.identity_pk, self.identity_sk, otk_count=12)
        self.pqxdh_prekeys = local
        self.save_pqxdh_prekeys()
        return upload

    def current_pqxdh_bundle_command(self) -> dict | None:
        """Táº¡o command upload láº¡i public bundle hiá»‡n cÃ³.

        Chá»‰ dÃ¹ng khi cháº¯c cháº¯n one-time prekey trong store chÆ°a bá»‹ tiÃªu thá»¥ hoáº·c
        trong test. Trong váº­n hÃ nh tháº­t, nÃªn Æ°u tiÃªn táº¡o batch má»›i Ä‘á»ƒ trÃ¡nh dÃ¹ng
        láº¡i OTK.
        """
        store = self.load_pqxdh_prekeys()
        if not store:
            return self.ensure_pqxdh_bundle_command()
        if not self.identity_sk:
            self.load_or_create_identity_key()
        if not self.identity_sk:
            return None
        identity_pk = self.identity_pk or protocol_b64d(store.get("identity_pk", ""))
        if not identity_pk:
            return None
        curve = store.get("curve_signed") or {}
        pq = store.get("pq_signed") or {}
        curve_id = int(curve.get("key_id", 0) or 0)
        pq_id = int(pq.get("key_id", 0) or 0)
        curve_pk = protocol_b64d(curve.get("pk", ""))
        pq_pk = protocol_b64d(pq.get("pk", ""))
        pq_alg = str(pq.get("alg", "") or "")
        if curve_id <= 0 or pq_id <= 0 or not curve_pk or not pq_pk or not pq_alg:
            return None
        upload = {
            "type": "upload_pqxdh_bundle",
            "identity_pk": protocol_b64e(identity_pk),
            "curve_spk_id": curve_id,
            "curve_spk": protocol_b64e(curve_pk),
            "curve_spk_sig": protocol_b64e(sign_prekey(
                self.identity_sk, "curve-signed", curve_id, "X25519", curve_pk)),
            "pq_spk_id": pq_id,
            "pq_kem_alg": pq_alg,
            "pq_spk": protocol_b64e(pq_pk),
            "pq_spk_sig": protocol_b64e(sign_prekey(
                self.identity_sk, "pq-signed", pq_id, pq_alg, pq_pk)),
            "curve_one_time_prekeys": [],
            "pq_one_time_prekeys": [],
        }
        for kid_s, item in sorted((store.get("curve_one_time") or {}).items()):
            kid = int(kid_s)
            pk = protocol_b64d(item.get("pk", ""))
            upload["curve_one_time_prekeys"].append({
                "key_id": kid,
                "public_key": protocol_b64e(pk),
                "signature": protocol_b64e(sign_prekey(
                    self.identity_sk, "curve-otk", kid, "X25519", pk)),
            })
        for kid_s, item in sorted((store.get("pq_one_time") or {}).items()):
            kid = int(kid_s)
            alg = str(item.get("alg", pq_alg) or pq_alg)
            pk = protocol_b64d(item.get("pk", ""))
            upload["pq_one_time_prekeys"].append({
                "key_id": kid,
                "alg": alg,
                "public_key": protocol_b64e(pk),
                "signature": protocol_b64e(sign_prekey(
                    self.identity_sk, "pq-otk", kid, alg, pk)),
            })
        return upload

    def fresh_pqxdh_bundle_command(self) -> dict | None:
        """Sinh và lưu một bundle PQXDH MỚI cho identity hiện tại.

        Batch OTK cũ bị thay hẳn (không lưu trữ). Tính đúng đắn được đảm bảo bởi
        việc server không bao giờ trả về generation OTK cũ.
        """
        if not self.identity_sk:
            self.load_or_create_identity_key()
        if not self.identity_pk or not self.identity_sk:
            return None
        upload, local = generate_local_bundle(
            self.identity_pk, self.identity_sk, otk_count=12)
        self.pqxdh_prekeys = local
        self.save_pqxdh_prekeys()
        return upload

    def new_identity_key_record_command(self) -> dict | None:
        """Tạo command công bố identity key Ed25519 hiện tại."""
        return self.current_identity_key_record_command()

    def current_identity_key_record_command(self) -> dict | None:
        if not self.master_key or not self.identity_pk or not self.identity_sk:
            return None
        # Tự ký identity key (self-certification) bằng chính khóa bí mật identity.
        sig = identity_sign(self.identity_sk, self.identity_pk)
        return {
            "type": "upload_keys",
            "identity_pk": base64.b64encode(self.identity_pk).decode(),
            "identity_sig": base64.b64encode(sig).decode(),
            "identity_sk_enc": encrypt_key_with_master(self.master_key, self.identity_sk),
        }

    def restore_identity_key_record(self, msg: dict) -> dict:
        """Nạp identity secret đã mã hóa từ server hoặc tạo identity mới."""
        if not msg.get("found"):
            self.load_or_create_identity_key()
            return {"found": False, "upload": self.new_identity_key_record_command()}

        restored_identity = False
        identity_sk_enc = msg.get("identity_sk_enc", "") or ""
        if identity_sk_enc:
            try:
                sk = decrypt_key_with_master(self.master_key, identity_sk_enc)
                pk = identity_pk_from_sk(sk)
                pk_b64 = msg.get("identity_pk", "") or ""
                if pk_b64:
                    try:
                        server_pk = base64.b64decode(pk_b64)
                    except Exception:
                        server_pk = protocol_b64d(pk_b64)
                    if server_pk != pk:
                        raise CryptoStateError(
                            "Server identity backup does not match public identity")
                self.identity_sk = sk
                self.identity_pk = pk
                self.save_identity_key()
                restored_identity = True
            except Exception as exc:
                self.logger.warning("Identity key backup restore failed: %s", exc)
        if not restored_identity:
            self.load_or_create_identity_key()

        return {
            "found": True,
            "identity_secret_restored": restored_identity,
            "identity_secret_backup_missing": not bool(identity_sk_enc),
        }

    def rotate_identity_commands(self) -> tuple[dict, dict | None]:
        """Táº¡o identity key má»›i vÃ  cÃ¡c command upload tÆ°Æ¡ng á»©ng.

        Rotate identity lÃ  thao tÃ¡c báº£o máº­t nháº¡y cáº£m: safety number cá»§a má»i
        contact sáº½ Ä‘á»•i, verified flag pháº£i Ä‘Æ°á»£c review láº¡i, vÃ  auditor sáº½ ghi
        identity event má»›i.
        """
        if not self.master_key:
            raise CryptoStateError("Master key is not available")
        self.identity_pk, self.identity_sk = identity_keygen()
        self.save_identity_key()
        upload_keys = self.new_identity_key_record_command()
        if not upload_keys:
            raise CryptoStateError("Could not build the rotated key bundle")
        upload_keys["type"] = "rotate_identity"
        upload_pqxdh_bundle, local_prekeys = generate_local_bundle(
            self.identity_pk, self.identity_sk, otk_count=12)
        self.pqxdh_prekeys = local_prekeys
        self.save_pqxdh_prekeys()
        self.mls_identity_ready = False
        self.mls_credential_identity_b64 = ""
        self.mls_group_ready.clear()
        self.mls_handshake_seen.clear()
        if self.mls_bridge:
            try:
                self.mls_bridge.close()
            except Exception:
                pass
            self.mls_bridge = None
        for path in glob.glob(os.path.join(self.secchat_dir, "mls_*.bin")):
            try:
                os.remove(path)
            except OSError:
                pass
        return upload_keys, upload_pqxdh_bundle

    # SecChat state
    #
    # DR state va MLS group state duoc luu rieng theo conversation. Moi
    # láº§n encrypt/decrypt thÃ nh cÃ´ng, state Ä‘Æ°á»£c ghi láº¡i ngay Ä‘á»ƒ logout/relogin
    # khÃ´ng lÃ m máº¥t counter/chain key.

    def load_double_ratchet(self, conv_id: int) -> DoubleRatchet | None:
        """Náº¡p Double Ratchet state cá»§a DM."""
        conv_id = int(conv_id)
        if conv_id in self.double_ratchet_states:
            return self.double_ratchet_states[conv_id]
        if not self.secchat_dir or not self.master_key:
            return None
        path = self.double_ratchet_path(conv_id)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as fh:
                token = fh.read().strip()
            raw = decrypt_with_key(self.master_key, token, check_replay=False)
            state = DoubleRatchet.from_dict(json.loads(raw))
            self.double_ratchet_states[conv_id] = state
            return state
        except Exception as exc:
            self.logger.warning("SecChat DR load failed conv=%d: %s", conv_id, exc)
            return None

    def save_double_ratchet(self, conv_id: int) -> None:
        """LÆ°u Double Ratchet state sau khi ratchet tiáº¿n."""
        conv_id = int(conv_id)
        state = self.double_ratchet_states.get(conv_id)
        if not state or not self.secchat_dir or not self.master_key:
            return
        try:
            token = encrypt_with_key(
                self.master_key,
                json.dumps(state.to_dict(), separators=(",", ":")),
            )
            with open(self.double_ratchet_path(conv_id), "w", encoding="utf-8") as fh:
                fh.write(token)
        except Exception as exc:
            self.logger.warning("SecChat DR save failed conv=%d: %s", conv_id, exc)
        self.save_double_ratchet_sessions(conv_id)

    def load_double_ratchet_sessions(self, conv_id: int) -> dict[str, DoubleRatchet]:
        """Nạp các phiên Double Ratchet song song của MỘT hội thoại DM.

        Khi hai bên cùng khởi tạo DM một lúc (simultaneous start) sẽ có nhiều
        session_id; ta giữ tất cả để giải mã được tin từ mọi phiên cho tới khi hội
        tụ về một phiên canonical.
        """
        conv_id = int(conv_id)
        if conv_id in self.double_ratchet_session_states:
            sessions = self.double_ratchet_session_states[conv_id]
        else:
            sessions = {}
            if self.secchat_dir and self.master_key:
                path = self.double_ratchet_sessions_path(conv_id)
                if os.path.exists(path):
                    try:
                        with open(path, "r", encoding="utf-8") as fh:
                            token = fh.read().strip()
                        raw = decrypt_with_key(
                            self.master_key, token, check_replay=False)
                        for sid, item in (json.loads(raw) or {}).items():
                            if sid and isinstance(item, dict):
                                sessions[str(sid)] = DoubleRatchet.from_dict(item)
                    except Exception as exc:
                        self.logger.warning(
                            "SecChat DR session-map load failed conv=%d: %s",
                            conv_id, exc)
            self.double_ratchet_session_states[conv_id] = sessions
        current = self.double_ratchet_states.get(conv_id)
        if current and current.session_id:
            sessions[current.session_id] = current
        return sessions

    def save_double_ratchet_sessions(self, conv_id: int) -> None:
        """Ghi xuống đĩa mọi phiên DR đã biết, phục vụ phục hồi simultaneous-start."""
        conv_id = int(conv_id)
        if not self.secchat_dir or not self.master_key:
            return
        sessions = dict(self.double_ratchet_session_states.get(conv_id) or {})
        current = self.double_ratchet_states.get(conv_id)
        if current and current.session_id:
            sessions[current.session_id] = current
        if not sessions:
            return
        try:
            token = encrypt_with_key(
                self.master_key,
                json.dumps(
                    {sid: state.to_dict() for sid, state in sessions.items() if sid},
                    separators=(",", ":"),
                ),
            )
            with open(self.double_ratchet_sessions_path(conv_id), "w", encoding="utf-8") as fh:
                fh.write(token)
            self.double_ratchet_session_states[conv_id] = sessions
        except Exception as exc:
            self.logger.warning(
                "SecChat DR session-map save failed conv=%d: %s", conv_id, exc)

    def _remember_double_ratchet_session(self, conv_id: int, state: DoubleRatchet | None) -> None:
        """Ghi nhớ một phiên DR vào bản đồ session theo conv (chưa ghi xuống đĩa)."""
        if not state or not getattr(state, "session_id", ""):
            return
        conv_id = int(conv_id)
        sessions = self.load_double_ratchet_sessions(conv_id)
        sessions[state.session_id] = state
        self.double_ratchet_session_states[conv_id] = sessions

    def _select_canonical_double_ratchet_state(
            self, conv_id: int, candidate: DoubleRatchet | None = None
    ) -> DoubleRatchet | None:
        """Chọn phiên DR "chuẩn" khi tồn tại nhiều phiên (do simultaneous start).

        Quy ước: chọn session_id NHỎ NHẤT để cả hai bên hội tụ về cùng một phiên mà
        không cần thương lượng, rồi lưu nó làm state hiện hành.
        """
        conv_id = int(conv_id)
        current = self.load_double_ratchet(conv_id)
        if current:
            self._remember_double_ratchet_session(conv_id, current)
        if candidate:
            self._remember_double_ratchet_session(conv_id, candidate)
        sessions = self.load_double_ratchet_sessions(conv_id)
        if not sessions:
            return current or candidate
        chosen_sid = min(sessions.keys())
        chosen = sessions[chosen_sid]
        self.double_ratchet_states[conv_id] = chosen
        self.save_double_ratchet(conv_id)
        return chosen

    def _state_for_double_ratchet_wire(self, conv_id: int, body: str) -> DoubleRatchet | None:
        """Tìm đúng phiên DR để giải một wire ``S3DR`` dựa trên session_id trong header.

        Tin có thể thuộc một phiên song song khác phiên hiện hành; đọc sid từ header
        để chọn đúng state, tránh giải nhầm phiên.
        """
        conv_id = int(conv_id)
        sid = ""
        try:
            payload = json_unb64(body[len(PREFIX_DR):])
            header = payload.get("h") if isinstance(payload.get("h"), dict) else {}
            sid = str(header.get("sid") or payload.get("sid") or "")
        except Exception:
            sid = ""
        current = self.load_double_ratchet(conv_id)
        if current and (not sid or current.session_id == sid):
            return current
        sessions = self.load_double_ratchet_sessions(conv_id)
        if sid and sid in sessions:
            return sessions[sid]
        return current

    def _require_mls_bridge(self) -> MlsBridge:
        """Trả về bridge OpenMLS, đảm bảo identity MLS đã khởi tạo (raise nếu chưa)."""
        if not self.mls_bridge:
            self.mls_bridge = MlsBridge()
        if not self.mls_identity_ready:
            raise CryptoStateError("MLS identity is not initialized yet.")
        return self.mls_bridge

    def _save_mls_state(self) -> None:
        """Xuất snapshot state OpenMLS, mã hóa bằng master key rồi ghi xuống đĩa.

        Toàn bộ group state (epoch, secret tree, credential) được serialize và bọc
        master key, để logout/relogin vẫn vào lại group đúng epoch.
        """
        if not self.master_key or not self.secchat_dir or not self.mls_bridge:
            return
        if not self.mls_identity_ready:
            return
        try:
            snapshot = self.mls_bridge.export_state()
            payload = {
                "schema_version": 1,
                "state_b64": str(snapshot.get("state_b64", "") or ""),
                "ciphersuite": str(snapshot.get("ciphersuite", "") or ""),
                "pq_hybrid": bool(snapshot.get("pq_hybrid", False)),
                "pq_authentication": bool(snapshot.get("pq_authentication", False)),
                "credential_identity_b64": str(
                    snapshot.get("credential_identity_b64", "")
                    or self.mls_credential_identity_b64
                ),
                "groups": sorted(int(x) for x in snapshot.get("groups", []) or []),
            }
            if not payload["state_b64"]:
                return
            token = encrypt_with_key(
                self.master_key,
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
            )
            os.makedirs(self.secchat_dir, exist_ok=True)
            with open(self.mls_state_path(), "w", encoding="utf-8") as fh:
                fh.write(token)
        except Exception as exc:
            self.logger.warning("MLS state save failed: %s", exc)

    def _load_mls_state_into_bridge(self) -> bool:
        """Nạp lại MLS state từ đĩa vào bridge. Trả về True nếu khôi phục được.

        Nếu state hỏng hoặc không khớp ciphersuite, xóa file để buộc republish
        KeyPackage X-Wing mới (tránh kẹt ở state cũ không giải mã được).
        """
        if not self.master_key or not self.secchat_dir:
            return False
        path = self.mls_state_path()
        if not os.path.exists(path):
            return False
        try:
            with open(path, "r", encoding="utf-8") as fh:
                token = fh.read().strip()
            if not token:
                return False
            raw = decrypt_with_key(self.master_key, token, check_replay=False)
            payload = json.loads(raw)
            state_b64 = str(payload.get("state_b64", "") or "")
            if not state_b64:
                return False
            if not self.mls_bridge:
                self.mls_bridge = MlsBridge()
            result = self.mls_bridge.import_state(state_b64)
            self.mls_identity_ready = True
            self.mls_credential_identity_b64 = str(
                result.get("credential_identity_b64", "")
                or payload.get("credential_identity_b64", "")
                or ""
            )
            groups = {
                int(x) for x in (result.get("groups", []) or payload.get("groups", []) or [])
                if int(x or 0) > 0
            }
            self.mls_group_ready.update(groups)
            self.group_conv_ids.update(groups)
            return True
        except Exception as exc:
            self.logger.warning("MLS state load failed: %s", exc)
            try:
                if self.mls_bridge and self.mls_bridge.available():
                    os.remove(path)
                    self.mls_identity_ready = False
                    self.mls_credential_identity_b64 = ""
                    self.mls_group_ready.clear()
                    self.logger.warning(
                        "Discarded local MLS state so X-Wing packages can be republished.")
            except FileNotFoundError:
                pass
            except Exception as cleanup_exc:
                self.logger.warning("MLS state cleanup failed: %s", cleanup_exc)
            return False

    def initialize_mls_identity(self, *, email: str = "",
                                identity_version: int = 0) -> dict:
        """Khởi tạo identity MLS RFC 9420 cho account đang đăng nhập.

        OpenMLS tự sinh signing key MLS riêng cho Credential, còn Credential được
        bind với SecChat identity hiện tại qua JSON identity canonical và chữ ký
        KeyPackage khi upload. Server chỉ lưu/phát public material, không biết
        group secret.
        """
        if not self.identity_pk:
            raise CryptoStateError("SecChat identity key is not loaded.")
        if not self.mls_bridge:
            self.mls_bridge = MlsBridge()
        if self._load_mls_state_into_bridge():
            return {
                "ok": True,
                "restored": True,
                "ciphersuite": PQ_HYBRID_CIPHERSUITE,
                "pq_hybrid": True,
                "pq_authentication": False,
                "credential_identity_b64": self.mls_credential_identity_b64,
            }
        result = self.mls_bridge.init_identity(
            user_id=int(self.my_uid or 0),
            email=str(email or ""),
            secchat_identity_pk=protocol_b64e(self.identity_pk),
            secchat_identity_version=int(identity_version or 0),
        )
        self.mls_identity_ready = True
        self.mls_credential_identity_b64 = str(
            result.get("credential_identity_b64", "") or "")
        self._save_mls_state()
        return result

    @staticmethod
    def _mls_key_package_sig_msg(pkg: dict) -> bytes:
        """Dựng byte-string canonical để identity Ed25519 ký lên một KeyPackage MLS."""
        return (
            b"SecChatMLSKeyPackage\x00"
            + str(pkg.get("key_package_ref", "") or "").encode("utf-8")
            + b"\x00"
            + str(pkg.get("key_package_b64", "") or "").encode("utf-8")
            + b"\x00"
            + str(pkg.get("ciphersuite", "") or "").encode("utf-8")
        )

    def mls_key_package_upload_command(self, count: int = 8) -> dict:
        """Sinh KeyPackage OpenMLS và tạo command upload cho server.

        KeyPackage là single-use public material. Server có thể claim một package
        cho actor đang add member, nhưng không thể tự sinh Welcome hoặc commit vì
        không có MLS group state.
        """
        if not self.identity_sk:
            raise CryptoStateError("SecChat identity secret is not loaded.")
        bridge = self._require_mls_bridge()
        packages = bridge.top_up_key_packages(count=int(count))
        for pkg in packages:
            pkg["credential_identity_b64"] = self.mls_credential_identity_b64
            pkg["secchat_signature"] = protocol_b64e(
                identity_sign(self.identity_sk, self._mls_key_package_sig_msg(pkg)))
        self._save_mls_state()
        return {"type": "upload_mls_key_packages", "key_packages": packages}

    def create_mls_group(self, conv_id: int) -> dict:
        """Tạo MLS group state mới cho hội thoại (vai trò người tạo nhóm)."""
        conv_id = int(conv_id)
        result = self._require_mls_bridge().create_group(conv_id)
        self.group_conv_ids.add(conv_id)
        self.mls_group_ready.add(conv_id)
        self.group_epochs[conv_id] = int(result.get("epoch", 0) or 0)
        self._save_mls_state()
        return result

    def add_mls_members(self, conv_id: int, key_packages: list[str]) -> dict:
        """Thêm thành viên vào group MLS từ KeyPackage của họ.

        Sinh Welcome (cho người mới) + Commit (cho người cũ), đẩy group sang epoch
        mới với khóa nhóm được làm mới.
        """
        conv_id = int(conv_id)
        result = self._require_mls_bridge().add_members(
            conv_id, [str(kp) for kp in key_packages if kp])
        self.mls_group_ready.add(conv_id)
        self.group_epochs[conv_id] = int(result.get("epoch", 0) or 0)
        self._save_mls_state()
        return result

    def remove_mls_members(self, conv_id: int, user_ids: list[int]) -> dict:
        """Loại thành viên khỏi group MLS; sinh Commit, sang epoch mới.

        Người bị loại không tính được root secret mới nên mất khả năng đọc tin
        tương lai (post-compromise security ở cấp nhóm).
        """
        conv_id = int(conv_id)
        result = self._require_mls_bridge().remove_members(
            conv_id, [int(uid) for uid in user_ids if int(uid or 0) > 0])
        self.group_epochs[conv_id] = int(result.get("epoch", 0) or 0)
        if not result.get("active", True):
            self.mls_group_ready.discard(conv_id)
        self._save_mls_state()
        return result

    def join_mls_group_from_welcome(self, conv_id: int,
                                    welcome_b64: str) -> dict:
        """Thành viên mới vào group bằng cách xử lý Welcome → nhảy thẳng vào epoch hiện hành."""
        conv_id = int(conv_id)
        result = self._require_mls_bridge().join_from_welcome(
            conv_id, str(welcome_b64 or ""))
        self.group_conv_ids.add(conv_id)
        self.mls_group_ready.add(conv_id)
        self.group_epochs[conv_id] = int(result.get("epoch", 0) or 0)
        self._save_mls_state()
        return result

    def process_mls_commit(self, conv_id: int,
                           commit_b64: str) -> dict | None:
        """Áp một Commit nhận được để tiến group sang epoch mới (cập nhật khóa nhóm)."""
        conv_id = int(conv_id)
        if conv_id not in self.mls_group_ready:
            return None
        result = self._require_mls_bridge().process_commit(
            conv_id, str(commit_b64 or ""))
        self.group_epochs[conv_id] = int(result.get("epoch", 0) or 0)
        if result.get("active") is False:
            self.mls_group_ready.discard(conv_id)
        self._save_mls_state()
        return result

    def process_mls_handshake_items(self, conv_id: int,
                                    items: list[dict]) -> None:
        """Replay Welcome/Commit RFC 9420 theo thứ tự server lưu.

        Hàm này idempotent theo `id/kind/epoch`, vì UI có thể request handshake
        nhiều lần trước khi load history hoặc khi reconnect.
        """
        conv_id = int(conv_id)
        for item in sorted(items or [], key=lambda x: int(x.get("id", 0) or 0)):
            kind = str(item.get("kind", "") or "")
            row_id = int(item.get("id", 0) or 0)
            seen_key = f"{row_id}:{kind}:{item.get('epoch', '')}"
            if seen_key in self.mls_handshake_seen:
                continue
            message_b64 = str(item.get("mls_message_b64", "") or "")
            if not message_b64:
                continue
            try:
                if kind == "welcome":
                    target = int(item.get("target_user_id", 0) or 0)
                    if target and target != int(self.my_uid or 0):
                        self.mls_handshake_seen.add(seen_key)
                        continue
                    if conv_id not in self.mls_group_ready:
                        self.join_mls_group_from_welcome(conv_id, message_b64)
                elif kind == "commit":
                    self.process_mls_commit(conv_id, message_b64)
                self.mls_handshake_seen.add(seen_key)
            except Exception as exc:
                self.logger.warning(
                    "MLS handshake failed conv=%d kind=%s row=%d: %s",
                    conv_id, kind, row_id, exc)

    def mls_application_wire(self, conv_id: int, plaintext: str) -> str:
        """Mã hóa một tin nhóm bằng MLS (khóa epoch hiện tại) → wire ``S3MLS:``."""
        conv_id = int(conv_id)
        if conv_id not in self.mls_group_ready:
            raise CryptoStateError("MLS group state is not initialized yet.")
        message_b64 = self._require_mls_bridge().encrypt_application(
            conv_id, plaintext)
        self._save_mls_state()
        return PREFIX_MLS + json_b64({
            "schema_version": 1,
            "kind": "application",
            "conversation_id": conv_id,
            "sender_uid": int(self.my_uid or 0),
            "epoch_hint": int(self.group_epochs.get(conv_id, 0) or 0),
            "message_b64": message_b64,
        })

    def mls_control_message_b64(self, conv_id: int, control: dict) -> str:
        """Mã hóa một control message nhóm (vd thông báo hệ thống) bằng MLS, trả về base64."""
        conv_id = int(conv_id)
        if conv_id not in self.mls_group_ready:
            raise CryptoStateError("MLS group state is not initialized yet.")
        plain = json.dumps(
            {"type": "group_control", **dict(control or {})},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        message_b64 = self._require_mls_bridge().encrypt_application(conv_id, plain)
        self._save_mls_state()
        return message_b64

    def open_mls_application_wire(self, conv_id: int, wire: str) -> str:
        """Giải mã một wire ``S3MLS:`` application của group, trả về plaintext."""
        payload = json_unb64(wire[len(PREFIX_MLS):])
        if payload.get("kind") != "application":
            raise ValueError("Not an MLS application envelope")
        msg_conv = int(payload.get("conversation_id", conv_id) or 0)
        if msg_conv and msg_conv != int(conv_id):
            raise ValueError("MLS conversation mismatch")
        if int(conv_id) not in self.mls_group_ready:
            raise CryptoStateError("MLS group state is not initialized yet.")
        plain = self._require_mls_bridge().decrypt_application(
            int(conv_id), str(payload.get("message_b64", "") or ""))
        self._save_mls_state()
        return plain

    @staticmethod
    def is_mls_application_wire(body: str) -> bool:
        """True nếu body là envelope MLS application (prefix S3MLS, kind=application)."""
        if not isinstance(body, str) or not body.startswith(PREFIX_MLS):
            return False
        try:
            payload = json_unb64(body[len(PREFIX_MLS):])
            return payload.get("kind") == "application"
        except Exception:
            return False

    def initiate_pqxdh_dm(self, peer_bundle: dict, conv_id: int,
                       peer_uid: int,
                       sender_identity_version: int | None = None) -> tuple[str, str]:
        """Báº¯t Ä‘áº§u DM báº±ng PQXDH vÃ  lÆ°u Double Ratchet state Ä‘áº§u tiÃªn."""
        conv_id = int(conv_id)
        if self.load_double_ratchet(conv_id) is not None:
            raise CryptoStateError("DM key exchange is already complete.")
        store = self.load_pqxdh_prekeys()
        if not store:
            raise CryptoStateError("Local SecChat prekeys are not available yet.")
        token, state, fingerprint = pqxdh_initiate(
            peer_bundle, store, self.identity_pk, self.identity_sk,
            self.my_uid, int(peer_uid),
            sender_identity_version=sender_identity_version,
            conversation_id=conv_id)
        self.double_ratchet_states[conv_id] = state
        self._remember_double_ratchet_session(conv_id, state)
        self.conv_fingerprints[conv_id] = fingerprint
        self.conv_peer_uids[conv_id] = int(peer_uid)
        self.save_double_ratchet(conv_id)
        return token, fingerprint

    # Message payload privacy.
    #
    # Padding á»Ÿ táº§ng plaintext lÃ m server khÃ³ suy ra chÃ­nh xÃ¡c Ä‘á»™ dÃ i tin. NÃ³
    # khÃ´ng giáº¥u Ä‘Æ°á»£c metadata nhÆ° ai nháº¯n cho ai, thá»i Ä‘iá»ƒm gá»­i hay sá»‘ lÆ°á»£ng
    # message; cÃ¡c metadata Ä‘Ã³ cáº§n cÆ¡ cháº¿ khÃ¡c nhÆ° transcript/checkpoint Ä‘á»ƒ phÃ¡t
    # hiá»‡n gian láº­n, khÃ´ng pháº£i Ä‘á»ƒ áº©n hoÃ n toÃ n.

    _PADDED_PLAINTEXT_MARKER = "__secchat_payload_v1__"
    _PAD_BUCKETS = (256, 512, 1024, 2048, 4096, 8192, 16384)

    def _padding_bucket(self, n_bytes: int) -> int:
        for bucket in self._PAD_BUCKETS:
            if n_bytes <= bucket:
                return bucket
        return n_bytes

    def pack_plaintext(self, body: str) -> str:
        """Bá»c plaintext vá»›i padding ngáº«u nhiÃªn trÆ°á»›c khi E2EE.

        Server váº«n tháº¥y metadata Ä‘á»‹nh tuyáº¿n, nhÆ°ng ciphertext sáº½ khÃ´ng pháº£n Ã¡nh
        chÃ­nh xÃ¡c Ä‘á»™ dÃ i tin nháº¯n thÆ°á»ng.
        """
        if not isinstance(body, str):
            body = str(body)
        base = {
            "_type": self._PADDED_PLAINTEXT_MARKER,
            "body": body,
            "pad": "",
        }
        raw = json.dumps(base, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        target = self._padding_bucket(len(raw))
        if target > len(raw):
            # base64 expands data, so request fewer random bytes than the gap.
            need = max(1, int((target - len(raw)) * 0.72))
            base["pad"] = base64.b64encode(os.urandom(need)).decode("ascii")
        return json.dumps(base, ensure_ascii=False, separators=(",", ":"))

    def unpack_plaintext(self, body: str) -> str:
        """ThÃ¡o wrapper padding sau khi giáº£i mÃ£; body cÅ© khÃ´ng cÃ³ wrapper váº«n dÃ¹ng Ä‘Æ°á»£c."""
        if not isinstance(body, str) or not body.startswith("{"):
            return body
        try:
            obj = json.loads(body)
        except Exception:
            return body
        if obj.get("_type") != self._PADDED_PLAINTEXT_MARKER:
            return body
        inner = obj.get("body", "")
        return inner if isinstance(inner, str) else str(inner)

    def encrypt_for_conv(self, conv_id: int, body: str) -> str:
        """MÃ£ hÃ³a má»™t plaintext theo Ä‘Ãºng protocol cá»§a conversation.

        DM dung Double Ratchet ``S3DR``. Group dung MLS RFC 9420 ``S3MLS``.
        Náº¿u state chÆ°a sáºµn sÃ ng, hÃ m nÃ©m ``CryptoStateError`` Ä‘á»ƒ UI hiá»ƒn thá»‹
        tráº¡ng thÃ¡i retry thay vÃ¬ gá»­i plaintext.
        """
        conv_id = int(conv_id)
        payload_body = self.pack_plaintext(body)
        if conv_id in self.group_conv_ids:
            return self.mls_application_wire(conv_id, payload_body)
        state = self.load_double_ratchet(conv_id)
        if state is None:
            raise CryptoStateError("DM key exchange is not complete yet.")
        payload = state.encrypt(payload_body)
        self.save_double_ratchet(conv_id)
        return payload

    def handle_group_integrity_control(self, conv_id: int, body: str) -> bool:
        """Áp dụng control kiểm tra transcript/membership cục bộ.

        MLS Welcome, Commit và application message thật được xử lý bởi OpenMLS
        qua ``process_mls_handshake_items``. Hàm này chỉ nhận transcript
        checkpoint app-level để phát hiện lệch lịch sử; nó không tạo hoặc mở
        group secret.
        """
        if not isinstance(body, str) or not body.startswith(PREFIX_MLS):
            return False
        try:
            payload = json_unb64(body[len(PREFIX_MLS):])
        except Exception:
            return False
        kind = payload.get("event") or payload.get("kind")
        if kind == "transcript_checkpoint":
            self.record_transcript_checkpoint(
                int(conv_id), payload, verify_signature=True)
            return True
        return False

    @staticmethod
    def _hidden_result(body: str) -> dict:
        return {"status": "hidden", "body": body, "hidden": True}

    @staticmethod
    def _hide_history_message(msg: dict, body: str) -> None:
        msg["body"] = body
        msg["hidden"] = True

    def decrypt_live_message(self, msg: dict) -> dict:
        """Giáº£i mÃ£ hoáº·c phÃ¢n loáº¡i má»™t message live/offline tá»« server.

        Káº¿t quáº£ lÃ  dict nhá» nhÆ° ``message``, ``control``, ``pending`` hoáº·c
        ``hidden``. Controller chá»‰ cáº§n render, fetch state cÃ²n thiáº¿u hoáº·c
        queue láº¡i message; nÃ³ khÃ´ng cáº§n biáº¿t chi tiáº¿t wire format.
        """
        conv_id = int(msg.get("conversation_id", 0) or 0)
        sender_id = int(
            msg.get("from_id", 0)
            or msg.get("sender_id", 0)
            or 0
        )
        body = msg.get("body", "") or ""

        if isinstance(body, str) and body.startswith(PREFIX_PQ_INIT):
            if sender_id == self.my_uid:
                return {"status": "control"}
            existing = self.load_double_ratchet(conv_id)
            meta = {}
            try:
                meta = json_unb64(body[len(PREFIX_PQ_INIT):])
            except Exception:
                meta = {}
            incoming_sid = str(meta.get("sid", "") or "")
            if incoming_sid and incoming_sid in self.load_double_ratchet_sessions(conv_id):
                return {"status": "control"}
            if not self.load_pqxdh_prekeys():
                return {"status": "control"} if existing else {"status": "pending"}
            try:
                plain, state, fp, peer_uid = self._respond_pqxdh_with_current_prekey(
                    body)
                self._remember_double_ratchet_session(conv_id, state)
                self._select_canonical_double_ratchet_state(conv_id, state)
                self.conv_peer_uids[conv_id] = peer_uid
                self.conv_fingerprints[conv_id] = fp
                self.save_double_ratchet(conv_id)
                peer_identity_pk = str(meta.get("identity_pk", "") or "")
                peer_identity_version = meta.get("sender_identity_version")
                if peer_identity_pk:
                    self.record_identity_seen_unverified(
                        peer_uid,
                        identity_pk=peer_identity_pk,
                        identity_version=(
                            int(peer_identity_version)
                            if peer_identity_version is not None else None),
                        safety_number=fp,
                        event_type="pqxdh_initial",
                    )
                base = {
                    "peer_uid": peer_uid,
                    "peer_identity_pk": peer_identity_pk,
                    "peer_identity_version": peer_identity_version,
                }
                if plain == "__S3_INIT__":
                    return {
                        "status": "control",
                        "ready": True,
                        "fingerprint": fp,
                        **base,
                    }
                return {
                    "status": "message",
                    "body": self.unpack_plaintext(plain),
                    "ready": True,
                    "fingerprint": fp,
                    **base,
                }
            except Exception as exc:
                self.logger.warning(
                    "SecChat PQXDH receive failed conv=%d: %s", conv_id, exc)
                return self._hidden_result("[Cannot decrypt]")

        if self.handle_group_integrity_control(conv_id, body):
            return {"status": "control", "ready": True}

        if sender_id > 0 and sender_id == self.my_uid:
            return {"status": "self_echo"}

        if isinstance(body, str) and body.startswith(PREFIX_DR):
            state = self._state_for_double_ratchet_wire(conv_id, body)
            if not state:
                return {"status": "pending"}
            sid = state.session_id
            snapshot = DoubleRatchet.from_dict(state.to_dict())
            try:
                plain = state.decrypt(body)
                if self.double_ratchet_states.get(conv_id) is state:
                    self.save_double_ratchet(conv_id)
                else:
                    self._remember_double_ratchet_session(conv_id, state)
                    self.save_double_ratchet_sessions(conv_id)
                return {"status": "message", "body": self.unpack_plaintext(plain)}
            except Exception as exc:
                if self.double_ratchet_states.get(conv_id) is state:
                    self.double_ratchet_states[conv_id] = snapshot
                elif sid:
                    self.double_ratchet_session_states.setdefault(conv_id, {})[sid] = snapshot
                self.logger.warning(
                    "SecChat DR decrypt failed conv=%d: %s", conv_id, exc)
                return self._hidden_result("[Cannot decrypt]")

        if isinstance(body, str) and body.startswith(PREFIX_MLS):
            try:
                plain = self.open_mls_application_wire(conv_id, body)
                return {"status": "message", "body": self.unpack_plaintext(plain)}
            except Exception as exc:
                self.logger.warning(
                    "OpenMLS application decrypt failed conv=%d: %s", conv_id, exc)
                return self._hidden_result(
                    "[Encrypted message - MLS state unavailable]")

        return {"status": "message", "body": body}

    def decrypt_history_messages(self, conv_id: int, messages: list[dict]) -> list[dict]:
        """Giáº£i mÃ£ history theo thá»© tá»± an toÃ n cho ratchet vÃ  group control.

        History láº¥y tá»« server cÃ³ thá»ƒ chá»©a Welcome/commit/checkpoint xen giá»¯a tin
        á»©ng dá»¥ng. HÃ m nÃ y Ã¡p dá»¥ng control material trÆ°á»›c khi render app message,
        dÃ¹ng cache plaintext khi ratchet key cÅ© Ä‘Ã£ bá»‹ xÃ³a, vÃ  tráº£ placeholder
        rÃµ rÃ ng khi state cá»¥c bá»™ khÃ´ng Ä‘á»§ Ä‘á»ƒ giáº£i mÃ£.
        """
        conv_id = int(conv_id)
        cached = self.load_cached_messages(conv_id)
        fs_placeholder = "[Forward-secret]"
        prehandled_mls_controls: set[int] = set()

        # History co the chua app message truoc Welcome/Commit cai MLS state local,
        # vÃ¬ server lÆ°u event theo thá»© tá»± nháº­n vÃ  viá»‡c táº¡o group/gá»­i Welcome lÃ 
        # báº¥t Ä‘á»“ng bá»™. Do Ä‘Ã³ cáº§n apply control material trÆ°á»›c, rá»“i má»›i render láº¡i
        # message theo thá»© tá»± gá»‘c Ä‘á»ƒ khÃ´ng máº¥t lá»‹ch sá»­ cÃ³ thá»ƒ Ä‘á»c.
        for idx, item in enumerate(messages):
            raw = item.get("body", "") or ""
            if isinstance(raw, str) and raw.startswith(PREFIX_MLS):
                if self.handle_group_integrity_control(conv_id, raw):
                    prehandled_mls_controls.add(idx)

        for idx, m in enumerate(messages):
            body = m.get("body", "") or ""
            deleted = bool(m.get("deleted", False))
            mid = int(m.get("id", 0) or 0)
            sender_id = int(m.get("sender_id", 0) or 0)
            when = ts_short(m.get("time", ""))

            if deleted:
                m["body"] = ""
                continue

            if idx in prehandled_mls_controls:
                m["body"] = "__S2_CONTROL__"
                continue

            if isinstance(body, str) and body.startswith(PREFIX_PQ_INIT):
                if sender_id == self.my_uid:
                    m["body"] = "__S2_CONTROL__"
                    continue
                existing = self.load_double_ratchet(conv_id)
                meta = {}
                try:
                    meta = json_unb64(body[len(PREFIX_PQ_INIT):])
                except Exception:
                    meta = {}
                incoming_sid = str(meta.get("sid", "") or "")
                if incoming_sid and incoming_sid in self.load_double_ratchet_sessions(conv_id):
                    m["body"] = "__S2_CONTROL__"
                    continue
                if not self.load_pqxdh_prekeys():
                    if existing:
                        m["body"] = "__S2_CONTROL__"
                    else:
                        self._hide_history_message(m, fs_placeholder)
                    continue
                try:
                    plain, state, fp, peer_uid = self._respond_pqxdh_with_current_prekey(
                        body)
                    self._remember_double_ratchet_session(conv_id, state)
                    self._select_canonical_double_ratchet_state(conv_id, state)
                    self.conv_peer_uids[conv_id] = peer_uid
                    self.conv_fingerprints[conv_id] = fp
                    peer_identity_pk = str(meta.get("identity_pk", "") or "")
                    peer_identity_version = meta.get("sender_identity_version")
                    if peer_identity_pk:
                        self.record_identity_seen_unverified(
                            peer_uid,
                            identity_pk=peer_identity_pk,
                            identity_version=(
                                int(peer_identity_version)
                                if peer_identity_version is not None else None),
                            safety_number=fp,
                            event_type="pqxdh_initial",
                        )
                    self.save_double_ratchet(conv_id)
                    m["body"] = (
                        "__S2_CONTROL__"
                        if plain == "__S3_INIT__"
                        else self.unpack_plaintext(plain)
                    )
                except Exception as exc:
                    self.logger.warning(
                        "History SecChat PQXDH failed conv=%d msg=%d: %s",
                        conv_id, mid, exc)
                    self._hide_history_message(m, fs_placeholder)
                continue

            if self.handle_group_integrity_control(conv_id, body):
                m["body"] = "__S2_CONTROL__"
                continue

            if isinstance(body, str) and body.startswith(PREFIX_DR):
                hit = cached.get(mid) if mid else None
                if not hit:
                    hit = cached.get(self.wire_cache_key(body))
                if hit:
                    plain = self.unpack_plaintext(hit.get("body", fs_placeholder))
                    m["body"] = plain
                    if mid:
                        self.cache_message(conv_id, mid, sender_id, plain, when)
                    continue
                if sender_id == self.my_uid:
                    self._hide_history_message(m, fs_placeholder)
                    continue
                state = self._state_for_double_ratchet_wire(conv_id, body)
                if not state:
                    self._hide_history_message(m, fs_placeholder)
                    continue
                sid = state.session_id
                snapshot = DoubleRatchet.from_dict(state.to_dict())
                try:
                    plain = self.unpack_plaintext(state.decrypt(body))
                    m["body"] = plain
                    if self.double_ratchet_states.get(conv_id) is state:
                        self.save_double_ratchet(conv_id)
                    else:
                        self._remember_double_ratchet_session(conv_id, state)
                        self.save_double_ratchet_sessions(conv_id)
                    if mid:
                        self.cache_message(conv_id, mid, sender_id, plain, when)
                except Exception as exc:
                    if self.double_ratchet_states.get(conv_id) is state:
                        self.double_ratchet_states[conv_id] = snapshot
                    elif sid:
                        self.double_ratchet_session_states.setdefault(conv_id, {})[sid] = snapshot
                    self.logger.warning(
                        "History SecChat DR failed conv=%d msg=%d: %s",
                        conv_id, mid, exc)
                    self._hide_history_message(m, fs_placeholder)
                continue

            if isinstance(body, str) and body.startswith(PREFIX_MLS):
                hit = cached.get(mid) if mid else None
                if not hit:
                    hit = cached.get(self.wire_cache_key(body))
                if hit:
                    plain = self.unpack_plaintext(hit.get("body", fs_placeholder))
                    m["body"] = plain
                    if mid:
                        self.cache_message(conv_id, mid, sender_id, plain, when)
                    continue
                if sender_id == self.my_uid:
                    self._hide_history_message(m, fs_placeholder)
                    continue
                if conv_id not in self.mls_group_ready:
                    self._hide_history_message(
                        m, "[Encrypted message - MLS state unavailable]")
                    continue
                try:
                    plain = self.unpack_plaintext(
                        self.open_mls_application_wire(conv_id, body))
                    m["body"] = plain
                    if mid:
                        self.cache_message(conv_id, mid, sender_id, plain, when)
                except Exception as exc:
                    self.logger.warning(
                        "History OpenMLS decrypt failed conv=%d msg=%d: %s",
                        conv_id, mid, exc)
                    self._hide_history_message(
                        m, "[Encrypted message - MLS state unavailable]")
                continue

            m["body"] = self.unpack_plaintext(body)

        return messages

    # Trạng thái "đã xác minh safety number" theo từng hội thoại (lưu mã hóa cục bộ).

    def load_verified(self, conv_id: int) -> bool:
        """Äá»c tráº¡ng thÃ¡i ngÆ°á»i dÃ¹ng Ä‘Ã£ mark verified cho conversation."""
        conv_id = int(conv_id)
        if conv_id in self.conv_verified:
            return self.conv_verified[conv_id]
        if not self.secchat_dir or not self.master_key:
            return False
        path = self.verified_path(conv_id)
        if not os.path.exists(path):
            return False
        try:
            with open(path, "r", encoding="utf-8") as fh:
                token = fh.read().strip()
            result = decrypt_with_key(
                self.master_key, token, check_replay=False) == "1"
            self.conv_verified[conv_id] = result
            return result
        except Exception:
            return False

    def save_verified(self, conv_id: int, verified: bool) -> None:
        """LÆ°u tráº¡ng thÃ¡i verified cá»¥c bá»™ cho conversation."""
        conv_id = int(conv_id)
        self.conv_verified[conv_id] = bool(verified)
        if not self.master_key or not self.secchat_dir:
            return
        try:
            os.makedirs(self.secchat_dir, exist_ok=True)
            token = encrypt_with_key(self.master_key, "1" if verified else "0")
            with open(self.verified_path(conv_id), "w", encoding="utf-8") as fh:
                fh.write(token)
        except Exception as exc:
            self.logger.warning("Verified save failed conv=%d: %s", conv_id, exc)

    # Identity transparency audit state
    #
    # Auditor/transparency log giÃºp client kiá»ƒm tra identity key cÃ³ náº±m trong
    # log append-only cÃ³ checkpoint há»£p lá»‡ khÃ´ng. ÄÃ¢y lÃ  lá»›p phÃ¡t hiá»‡n server
    # thay key hoáº·c Ä‘Æ°a view identity khÃ¡c nhau, nhÆ°ng khÃ´ng thay tháº¿ hoÃ n toÃ n
    # viá»‡c ngÆ°á»i dÃ¹ng so sÃ¡nh safety number ngoÃ i kÃªnh SecChat.

    def load_identity_audit(self, user_id: int) -> dict:
        """Äá»c audit state cá»§a má»™t peer tá»« file local Ä‘Ã£ mÃ£ hÃ³a."""
        user_id = int(user_id)
        if user_id in self.identity_audit_states:
            return dict(self.identity_audit_states[user_id])
        if not self.secchat_dir or not self.master_key:
            return {"user_id": user_id, "status": "unknown", "history": []}
        path = self.identity_audit_path(user_id)
        if not os.path.exists(path):
            return {"user_id": user_id, "status": "unknown", "history": []}
        try:
            with open(path, "r", encoding="utf-8") as fh:
                token = fh.read().strip()
            raw = decrypt_with_key(self.master_key, token, check_replay=False)
            state = json.loads(raw)
            state.setdefault("user_id", user_id)
            state.setdefault("history", [])
            state.setdefault("last_error_code", "")
            self.identity_audit_states[user_id] = state
            return dict(state)
        except Exception as exc:
            self.logger.warning("Identity audit state load failed uid=%d: %s",
                                user_id, exc)
            return {"user_id": user_id, "status": "unknown", "history": []}

    def save_identity_audit(self, user_id: int, state: dict) -> None:
        """LÆ°u audit state cá»§a peer vÃ o file local Ä‘Ã£ mÃ£ hÃ³a."""
        user_id = int(user_id)
        state = dict(state or {})
        state["user_id"] = user_id
        state.setdefault("history", [])
        self.identity_audit_states[user_id] = state
        if not self.master_key or not self.secchat_dir:
            return
        try:
            os.makedirs(self.secchat_dir, exist_ok=True)
            token = encrypt_with_key(
                self.master_key,
                json.dumps(state, ensure_ascii=False, separators=(",", ":")),
            )
            with open(self.identity_audit_path(user_id), "w", encoding="utf-8") as fh:
                fh.write(token)
        except Exception as exc:
            self.logger.warning("Identity audit state save failed uid=%d: %s",
                                user_id, exc)

    def record_identity_audit_ok(self, user_id: int, *, identity_pk: str,
                                 identity_version: int, safety_number: str,
                                 checkpoint: dict, leaf: dict) -> dict:
        """Ghi nháº­n identity key cá»§a peer Ä‘Ã£ cÃ³ proof há»£p lá»‡ tá»« auditor.

        Náº¿u key/version thay Ä‘á»•i so vá»›i láº§n trÆ°á»›c, tráº¡ng thÃ¡i chuyá»ƒn sang
        ``key_changed`` Ä‘á»ƒ UI yÃªu cáº§u ngÆ°á»i dÃ¹ng review láº¡i safety number.
        """
        user_id = int(user_id)
        identity_version = int(identity_version)
        old = self.load_identity_audit(user_id)
        old_pk = str(old.get("identity_pk", "") or "")
        old_version = int(old.get("identity_version", -1) or -1)
        now = int(time.time())
        history = list(old.get("history") or [])
        changed = bool(old_pk and not _same_identity_key(old_pk, identity_pk))
        rollback = old_version > identity_version
        if changed or rollback or not history:
            history.append({
                "seen_at": now,
                "event_type": leaf.get("event_type", "initial"),
                "identity_version": identity_version,
                "identity_pk": identity_pk,
                "safety_number": safety_number,
                "device_label": leaf.get("device_label", "primary device"),
                "created_at": leaf.get("created_at", ""),
                "verified_after_change": False,
            })
            history = history[-20:]
        status = "key_changed" if changed or rollback else old.get("status", "unverified")
        if status in ("unknown", "audit_unavailable", "audit_mismatch"):
            status = "unverified"
        state = {
            "user_id": user_id,
            "status": status,
            "identity_pk": identity_pk,
            "identity_version": identity_version,
            "safety_number": safety_number,
            "checkpoint": checkpoint,
            "leaf": leaf,
            "history": history,
            "reviewed_at": old.get("reviewed_at", 0) if not changed else 0,
            "last_error": "",
            "last_error_code": "",
        }
        self.save_identity_audit(user_id, state)
        return state

    def record_identity_seen_unverified(self, user_id: int, *,
                                        identity_pk: str,
                                        identity_version: int | None,
                                        safety_number: str,
                                        event_type: str = "seen") -> dict:
        """LÆ°u identity peer tháº¥y trong transcript mÃ£ hÃ³a nhÆ°ng chÆ°a audit.

        DÃ¹ng khi ``S3PQI`` mang identity cá»§a sender nhÆ°ng controller chÆ°a kiá»ƒm
        tra auditor á»Ÿ thá»i Ä‘iá»ƒm Ä‘Ã³. UI váº«n cÃ³ safety number á»•n Ä‘á»‹nh Ä‘á»ƒ hiá»ƒn thá»‹,
        nhÆ°ng khÃ´ng tuyÃªn bá»‘ identity Ä‘Ã£ Ä‘Æ°á»£c auditor xÃ¡c nháº­n.
        """
        user_id = int(user_id)
        old = self.load_identity_audit(user_id)
        old_pk = str(old.get("identity_pk", "") or "")
        try:
            version_i = int(identity_version) if identity_version is not None else int(
                old.get("identity_version", 0) or 0)
        except Exception:
            version_i = int(old.get("identity_version", 0) or 0)
        try:
            old_version = int(old.get("identity_version", -1) or -1)
        except Exception:
            old_version = -1
        changed = bool(old_pk and not _same_identity_key(old_pk, identity_pk))
        rollback = identity_version is not None and old_version > version_i
        history = list(old.get("history") or [])
        if changed or rollback or not history:
            history.append({
                "seen_at": int(time.time()),
                "event_type": str(event_type or "seen"),
                "identity_version": version_i,
                "identity_pk": identity_pk,
                "safety_number": safety_number,
                "device_label": "primary device",
                "created_at": "",
                "verified_after_change": False,
            })
            history = history[-20:]
        status = "key_changed" if changed or rollback else old.get("status", "unverified")
        if status in ("unknown", "audit_unavailable", "audit_mismatch"):
            status = "unverified"
        state = {
            **old,
            "user_id": user_id,
            "status": status,
            "identity_pk": identity_pk,
            "identity_version": version_i,
            "safety_number": safety_number,
            "history": history,
            "last_error": "" if status != "key_changed" else old.get(
                "last_error", "Safety number changed and needs review."),
            "last_error_code": "" if status != "key_changed" else old.get(
                "last_error_code", ""),
            "reviewed_at": old.get("reviewed_at", 0) if not changed else 0,
        }
        self.save_identity_audit(user_id, state)
        return state

    def load_auditor_state(self) -> dict:
        if self.auditor_state:
            return dict(self.auditor_state)
        if not self.secchat_dir or not self.master_key:
            return {"status": "unknown", "checkpoint": {}, "observations": []}
        path = self.auditor_state_path()
        if not os.path.exists(path):
            return {"status": "unknown", "checkpoint": {}, "observations": []}
        try:
            with open(path, "r", encoding="utf-8") as fh:
                token = fh.read().strip()
            raw = decrypt_with_key(self.master_key, token, check_replay=False)
            state = json.loads(raw)
            state.setdefault("status", "unknown")
            state.setdefault("checkpoint", {})
            state.setdefault("observations", [])
            state.setdefault("last_error_code", "")
            self.auditor_state = state
            return dict(state)
        except Exception as exc:
            self.logger.warning("Auditor state load failed: %s", exc)
            return {"status": "unknown", "checkpoint": {}, "observations": []}

    def save_auditor_state(self, state: dict) -> None:
        state = dict(state or {})
        state.setdefault("status", "unknown")
        state.setdefault("checkpoint", {})
        state.setdefault("observations", [])
        state.setdefault("last_error_code", "")
        self.auditor_state = state
        if not self.secchat_dir or not self.master_key:
            return
        try:
            os.makedirs(self.secchat_dir, exist_ok=True)
            token = encrypt_with_key(
                self.master_key,
                json.dumps(state, ensure_ascii=False, separators=(",", ":")),
            )
            with open(self.auditor_state_path(), "w", encoding="utf-8") as fh:
                fh.write(token)
        except Exception as exc:
            self.logger.warning("Auditor state save failed: %s", exc)

    def record_auditor_checkpoint(self, checkpoint: dict, *, source: str = "",
                                  user_id: int = 0,
                                  identity_version: int = 0) -> dict:
        """Pin má»™t auditor checkpoint dÃ¹ng chung cho account trÃªn thiáº¿t bá»‹.

        Audit state theo peer phÃ¡t hiá»‡n key change cá»§a tá»«ng ngÆ°á»i. Checkpoint
        account-wide phÃ¡t hiá»‡n lá»—i náº·ng hÆ¡n: auditor/server Ä‘Æ°a cÃ¡c log head
        khÃ¡c nhau cho cÃ¹ng má»™t client á»Ÿ nhá»¯ng láº§n kiá»ƒm tra khÃ¡c nhau.
        """
        cp = dict(checkpoint or {})
        try:
            new_size = int(cp.get("tree_size", -1))
        except Exception:
            new_size = -1
        new_root = str(cp.get("root_hash", "") or "")
        if new_size < 0 or len(new_root) != 64:
            raise CryptoStateError("Malformed auditor checkpoint")

        state = self.load_auditor_state()
        old_cp = dict(state.get("checkpoint") or {})
        if old_cp:
            old_size = int(old_cp.get("tree_size", 0) or 0)
            old_root = str(old_cp.get("root_hash", "") or "")
            if new_size < old_size:
                raise CryptoStateError(
                    "Auditor checkpoint rolled back across identity checks")
            if new_size == old_size and old_root and new_root != old_root:
                raise CryptoStateError(
                    "Auditor split-view detected at the same log size")

        observations = list(state.get("observations") or [])
        observations.append({
            "seen_at": int(time.time()),
            "source": str(source or ""),
            "user_id": int(user_id or 0),
            "identity_version": int(identity_version or 0),
            "tree_size": new_size,
            "root_hash": new_root,
            "created_at": str(cp.get("created_at", "") or ""),
        })
        state.update({
            "status": "ok",
            "checkpoint": cp,
            "observations": observations[-50:],
            "last_error": "",
            "last_error_code": "",
            "updated_at": int(time.time()),
        })
        self.save_auditor_state(state)
        return dict(state)

    def record_identity_audit_problem(self, user_id: int, *, identity_pk: str,
                                      identity_version: int,
                                      safety_number: str,
                                      status: str, error: str,
                                      error_code: str = "") -> dict:
        """LÆ°u váº¥n Ä‘á» audit nhÆ°ng khÃ´ng xÃ³a identity Ä‘Ã£ tháº¥y."""
        user_id = int(user_id)
        old = self.load_identity_audit(user_id)
        history = list(old.get("history") or [])
        duplicate = False
        if history:
            last = history[-1]
            duplicate = (
                str(last.get("event_type", "")) == str(status)
                and int(last.get("identity_version", -1) or -1) == int(identity_version)
                and _same_identity_key(str(last.get("identity_pk", "")), identity_pk)
            )
        if duplicate:
            history[-1].update({
                "seen_at": int(time.time()),
                "safety_number": safety_number,
                "error": error,
                "error_code": error_code,
            })
        else:
            history.append({
                "seen_at": int(time.time()),
                "event_type": status,
                "identity_version": int(identity_version),
                "identity_pk": identity_pk,
                "safety_number": safety_number,
                "device_label": "primary device",
                "created_at": "",
                "verified_after_change": False,
                "error": error,
                "error_code": error_code,
            })
        state = {
            **old,
            "user_id": user_id,
            "status": status,
            "identity_pk": identity_pk,
            "identity_version": int(identity_version),
            "safety_number": safety_number,
            "history": history[-20:],
            "last_error": error,
            "last_error_code": error_code,
        }
        self.save_identity_audit(user_id, state)
        return state

    def mark_identity_reviewed(self, user_id: int, *, verified: bool) -> dict:
        """Ghi quyáº¿t Ä‘á»‹nh review cá»§a ngÆ°á»i dÃ¹ng cho identity hiá»‡n táº¡i."""
        state = self.load_identity_audit(user_id)
        state["status"] = "verified" if verified else "reviewed_unverified"
        state["reviewed_at"] = int(time.time())
        if state.get("history"):
            state["history"][-1]["verified_after_change"] = bool(verified)
        self.save_identity_audit(user_id, state)
        return state

    # Cleanup and password rewrap
    #
    # CÃ¡c hÃ m dÆ°á»›i Ä‘Ã¢y chá»‰ thao tÃ¡c state cá»¥c bá»™. ChÃºng khÃ´ng yÃªu cáº§u server Ä‘á»c
    # plaintext hoáº·c secret key, nhÆ°ng náº¿u xÃ³a nháº§m sáº½ lÃ m máº¥t kháº£ nÄƒng Ä‘á»c láº¡i
    # history/ratchet trÃªn thiáº¿t bá»‹ hiá»‡n táº¡i.

    def clear_stale_local_state(self) -> None:
        """XÃ³a state cá»¥c bá»™ cÃ³ thá»ƒ khÃ´ng cÃ²n khá»›p server/account hiá»‡n táº¡i."""
        self.conv_fingerprints.clear()
        self.conv_verified.clear()
        self.identity_audit_states.clear()
        self.auditor_state.clear()
        self.pqxdh_prekeys = None
        self.double_ratchet_states.clear()
        self.double_ratchet_session_states.clear()
        self.mls_group_ready.clear()
        self.mls_handshake_seen.clear()
        if not self.secchat_dir:
            return
        for pattern in (
            "verified_*.bin", "msgs_*.bin",
            "identity_audit_*.bin", "auditor_state.bin", "cache_policy.bin", "transcript_*.bin",
            "pqxdh_prekeys.bin", "dr_*.bin", "mls_*.bin",
        ):
            for path in glob.glob(os.path.join(self.secchat_dir, pattern)):
                try:
                    os.remove(path)
                except OSError:
                    pass

    def cleanup_conversation_state(self, conv_id: int) -> None:
        """XÃ³a state mÃ£ hÃ³a cá»§a má»™t conversation khá»i thiáº¿t bá»‹ hiá»‡n táº¡i."""
        conv_id = int(conv_id)
        self.conv_peer_uids.pop(conv_id, None)
        self.conv_verified.pop(conv_id, None)
        self.conv_fingerprints.pop(conv_id, None)
        self.double_ratchet_states.pop(conv_id, None)
        self.double_ratchet_session_states.pop(conv_id, None)
        self.mls_group_ready.discard(conv_id)
        if not self.secchat_dir:
            return
        for path in (
            self.double_ratchet_path(conv_id),
            self.double_ratchet_sessions_path(conv_id),
            self.verified_path(conv_id),
        ):
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass

    def rewrap_local_state(self, old_master: bytes, new_master: bytes) -> None:
        """Äá»•i lá»›p mÃ£ hÃ³a cá»§a toÃ n bá»™ local state khi ngÆ°á»i dÃ¹ng Ä‘á»•i máº­t kháº©u.

        Ná»™i dung state khÃ´ng thay Ä‘á»•i. HÃ m chá»‰ giáº£i mÃ£ tá»«ng file báº±ng master key
        cÅ© rá»“i mÃ£ hÃ³a láº¡i báº±ng master key má»›i. Náº¿u bá» bÆ°á»›c nÃ y, login báº±ng máº­t
        kháº©u má»›i sáº½ khÃ´ng Ä‘á»c Ä‘Æ°á»£c identity key, ratchet state, cache hoáº·c backup
        state cÅ©.
        """
        if not self.secchat_dir or not os.path.isdir(self.secchat_dir):
            return

        def rewrap_file(path: str, line_mode: bool) -> None:
            if not os.path.exists(path):
                return
            with open(path, "r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()
            out = []
            for line in lines:
                if not line.strip():
                    continue
                plain = decrypt_with_key(old_master, line.strip(), check_replay=False)
                out.append(encrypt_with_key(new_master, plain))
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                if line_mode:
                    fh.write("\n".join(out))
                    if out:
                        fh.write("\n")
                else:
                    fh.write(out[0] if out else "")
            os.replace(tmp, path)

        single_files = [
            self.identity_key_path(),
            self.cache_policy_path(),
            self.backup_state_path(),
            self.auditor_state_path(),
            self.pqxdh_prekeys_path(),
            *glob.glob(os.path.join(self.secchat_dir, "dr_*.bin")),
            *glob.glob(os.path.join(self.secchat_dir, "mls_*.bin")),
            *glob.glob(os.path.join(self.secchat_dir, "verified_*.bin")),
            *glob.glob(os.path.join(self.secchat_dir, "identity_audit_*.bin")),
            *glob.glob(os.path.join(self.secchat_dir, "transcript_*.bin")),
        ]
        for path in single_files:
            rewrap_file(path, line_mode=False)
        for path in glob.glob(os.path.join(self.secchat_dir, "msgs_*.bin")):
            rewrap_file(path, line_mode=True)
