"""Helper client cho identity transparency.

Auditor ký checkpoint cho identity log phía server. Client lưu checkpoint cuối
cùng đã chấp nhận, rồi kiểm tra mỗi PQXDH bundle bằng Merkle inclusion proof để
biết identity key hiện tại thật sự nằm trong log đã ký.

Cơ chế này không thay thế việc người dùng so sánh safety number ngoài kênh
SecChat. Nó chỉ làm server khó thay key âm thầm hơn: nếu server đưa key không
có trong log, rollback log hoặc cho cùng client thấy hai log head khác nhau,
client sẽ phát hiện và hiển thị audit warning.
"""

from __future__ import annotations

import hashlib
import json
import os
import base64
from urllib.error import HTTPError
from urllib.request import urlopen

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


AUDITOR_PUBLIC_KEY_HEX = (
    os.environ.get("SECCHAT_AUDITOR_PUBLIC_KEY")
    or "f628ba588012100eb8b19182fac2898a85f0f4c6157c5978d49d4551ba964b42"
)


AUDIT_ERROR_LABELS = {
    "checkpoint_malformed": "malformed checkpoint",
    "checkpoint_signature_invalid": "invalid checkpoint signature",
    "empty_root_invalid": "invalid empty tree root",
    "proof_index_out_of_range": "proof index out of range",
    "proof_malformed": "malformed inclusion proof",
    "proof_side_malformed": "malformed proof direction",
    "proof_root_mismatch": "inclusion proof root mismatch",
    "checkpoint_rollback": "checkpoint rollback",
    "checkpoint_split_view": "checkpoint split-view",
    "consistency_proof_malformed": "malformed consistency proof",
    "consistency_previous_root_mismatch": "consistency proof previous root mismatch",
    "consistency_new_root_mismatch": "consistency proof new root mismatch",
    "identity_user_mismatch": "identity proof user mismatch",
    "identity_version_mismatch": "identity proof version mismatch",
    "identity_version_not_found": "identity version not in log",
    "identity_key_mismatch": "identity proof key mismatch",
    "auditor_http_error": "auditor HTTP error",
    "auditor_unavailable": "auditor unavailable",
    "unknown": "unknown audit error",
}


def classify_audit_error(message: str) -> str:
    """Ánh xạ chuỗi lỗi audit (tiếng Anh, đa dạng) sang một mã code ổn định, máy đọc được."""
    text = str(message or "").lower()
    if "identity version not found" in text or "version not in log" in text:
        return "identity_version_not_found"
    if "auditor http" in text or "http error" in text:
        return "auditor_http_error"
    if "unavailable" in text or "timed out" in text or "connection" in text:
        return "auditor_unavailable"
    if "malformed auditor checkpoint" in text:
        return "checkpoint_malformed"
    if "checkpoint signature" in text:
        return "checkpoint_signature_invalid"
    if "empty identity tree root" in text:
        return "empty_root_invalid"
    if "proof index" in text or "index is out of range" in text:
        return "proof_index_out_of_range"
    if "proof side" in text or "proof direction" in text:
        return "proof_side_malformed"
    if "malformed identity log proof" in text:
        return "proof_malformed"
    if "inclusion proof" in text and "checkpoint" in text:
        return "proof_root_mismatch"
    if "rolled back" in text:
        return "checkpoint_rollback"
    if "split-view" in text or "same tree size" in text or "same log size" in text:
        return "checkpoint_split_view"
    if "malformed consistency proof" in text:
        return "consistency_proof_malformed"
    if "previous checkpoint" in text or "previous root" in text:
        return "consistency_previous_root_mismatch"
    if "new checkpoint" in text or "new root" in text:
        return "consistency_new_root_mismatch"
    if "different user" in text:
        return "identity_user_mismatch"
    if "different version" in text or "version not found" in text:
        return "identity_version_mismatch"
    if "key does not match" in text:
        return "identity_key_mismatch"
    return "unknown"


def audit_error_label(code: str) -> str:
    """Trả về nhãn người-đọc (ngắn gọn) cho một audit error code."""
    return AUDIT_ERROR_LABELS.get(str(code or ""), AUDIT_ERROR_LABELS["unknown"])


def audit_error_detail(code: str, message: str) -> str:
    """Ghép nhãn lỗi với message chi tiết thành một chuỗi để hiển thị cho người dùng."""
    label = audit_error_label(code)
    message = str(message or "").strip()
    return f"{label}: {message}" if message else label


def audit_status_for_code(code: str) -> str:
    """Quy đổi error code sang trạng thái: lỗi kết nối auditor → "audit_unavailable", còn lại → "audit_mismatch"."""
    if str(code or "") in {"auditor_unavailable", "auditor_http_error"}:
        return "audit_unavailable"
    return "audit_mismatch"


class AuditError(RuntimeError):
    """Lỗi khi checkpoint/proof identity transparency không hợp lệ."""

    def __init__(self, message: str, *, code: str = ""):
        super().__init__(message)
        self.code = code or classify_audit_error(message)


def _identity_bytes(text: str) -> bytes:
    """Decode identity key từ nhiều biến thể base64 để so sánh bytes thật."""
    raw = str(text or "").strip()
    if not raw:
        return b""
    raw = raw.replace("-", "+").replace("_", "/")
    raw += "=" * (-len(raw) % 4)
    return base64.b64decode(raw.encode("ascii"), validate=False)


def same_identity_key(a: str, b: str) -> bool:
    """So sánh identity key theo bytes, bỏ qua khác biệt base64 chuẩn/url-safe."""
    try:
        return _identity_bytes(a) == _identity_bytes(b)
    except Exception:
        return str(a or "") == str(b or "")


def default_auditor_url() -> str:
    """URL auditor mặc định; test/Docker có thể override bằng biến môi trường."""
    return os.environ.get("SECCHAT_AUDITOR_URL", "http://localhost:8890").rstrip("/")


def _fetch_json(url: str, path: str, timeout: float = 3.0) -> dict:
    """Gọi auditor HTTP endpoint và parse JSON."""
    try:
        with urlopen(f"{url.rstrip('/')}{path}", timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        try:
            body = json.loads(exc.read().decode("utf-8"))
        except Exception:
            body = {}
        error = str(body.get("error", "") or exc.reason or "")
        if "identity version not found" in error.lower():
            raise AuditError(
                "Identity version not found in auditor log",
                code="identity_version_not_found",
            ) from exc
        raise AuditError(
            f"Auditor HTTP error {exc.code}: {error or 'unknown error'}",
            code="auditor_http_error",
        ) from exc


def _node_hash(left_hex: str, right_hex: str) -> str:
    """Hash node trong Merkle tree với domain byte cho internal node."""
    return hashlib.sha256(
        b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
    ).hexdigest()


def _empty_root() -> str:
    """Root cố định khi log chưa có leaf nào."""
    return hashlib.sha256(b"SecChatEmptyIdentityTree").hexdigest()


def verify_checkpoint(checkpoint: dict, *, auditor_pk_hex: str = "") -> None:
    """Kiểm tra chữ ký Ed25519 của checkpoint auditor."""
    pk_hex = auditor_pk_hex or AUDITOR_PUBLIC_KEY_HEX
    tree_size = int(checkpoint.get("tree_size", -1))
    root_hash = str(checkpoint.get("root_hash", ""))
    created_at = str(checkpoint.get("created_at", ""))
    sig_hex = str(checkpoint.get("signature", ""))
    if tree_size < 0 or len(root_hash) != 64 or len(sig_hex) != 128 or not created_at:
        raise AuditError(
            "Malformed auditor checkpoint",
            code="checkpoint_malformed",
        )
    try:
        bytes.fromhex(root_hash)
        sig = bytes.fromhex(sig_hex)
        auditor_pk = bytes.fromhex(pk_hex)
    except Exception as exc:
        raise AuditError(
            "Malformed auditor checkpoint",
            code="checkpoint_malformed",
        ) from exc
    msg = f"SecChatAuditCheckpoint|{tree_size}|{root_hash}|{created_at}".encode("utf-8")
    try:
        Ed25519PublicKey.from_public_bytes(auditor_pk).verify(sig, msg)
    except Exception as exc:
        raise AuditError(
            "Invalid auditor checkpoint signature",
            code="checkpoint_signature_invalid",
        ) from exc


def verify_inclusion(leaf_hash: str, leaf_index: int, proof: list[dict],
                     checkpoint: dict) -> None:
    """Kiểm tra leaf identity có nằm trong Merkle root của checkpoint không."""
    tree_size = int(checkpoint.get("tree_size", -1))
    root_hash = str(checkpoint.get("root_hash", ""))
    if tree_size == 0:
        if root_hash != _empty_root():
            raise AuditError(
                "Invalid empty identity tree root",
                code="empty_root_invalid",
            )
        return
    if leaf_index < 0 or leaf_index >= tree_size:
        raise AuditError(
            "Identity log proof index is out of range",
            code="proof_index_out_of_range",
        )
    cur = str(leaf_hash)
    idx = int(leaf_index)
    for item in proof:
        sibling = str(item.get("hash", ""))
        if len(sibling) != 64:
            raise AuditError(
                "Malformed identity log proof",
                code="proof_malformed",
            )
        if item.get("side") == "left":
            cur = _node_hash(sibling, cur)
        elif item.get("side") == "right":
            cur = _node_hash(cur, sibling)
        else:
            raise AuditError(
                "Malformed identity log proof side",
                code="proof_side_malformed",
            )
        idx //= 2
    if cur != root_hash:
        raise AuditError(
            "Identity log inclusion proof does not match checkpoint",
            code="proof_root_mismatch",
        )


def check_consistency(url: str, old_checkpoint: dict | None,
                      new_checkpoint: dict) -> None:
    """Kiểm tra checkpoint mới không rollback hoặc đổi root ở cùng tree size.

    Endpoint consistency hiện ở mức demo: nó xác nhận metadata from/to và root.
    Client vẫn pin checkpoint cũ để phát hiện rollback/split-view đơn giản.
    """
    verify_checkpoint(new_checkpoint)
    if not old_checkpoint:
        return
    old_size = int(old_checkpoint.get("tree_size", 0) or 0)
    new_size = int(new_checkpoint.get("tree_size", 0) or 0)
    if new_size < old_size:
        raise AuditError(
            "Auditor checkpoint rolled back",
            code="checkpoint_rollback",
        )
    old_root = str(old_checkpoint.get("root_hash", ""))
    new_root = str(new_checkpoint.get("root_hash", ""))
    if old_size == new_size:
        if old_root != new_root:
            raise AuditError(
                "Auditor checkpoint changed at the same tree size",
                code="checkpoint_split_view",
            )
        return
    proof = _fetch_json(url, f"/consistency?from={old_size}&to={new_size}")
    if int(proof.get("from_size", -1)) != old_size:
        raise AuditError(
            "Malformed consistency proof: from_size does not match previous checkpoint",
            code="consistency_proof_malformed",
        )
    if int(proof.get("to_size", -1)) != new_size:
        raise AuditError(
            "Malformed consistency proof: to_size does not match new checkpoint",
            code="consistency_proof_malformed",
        )
    if str(proof.get("from_root", "")) != old_root:
        raise AuditError(
            "Consistency proof does not match previous checkpoint",
            code="consistency_previous_root_mismatch",
        )
    if str(proof.get("to_root", "")) != new_root:
        raise AuditError(
            "Consistency proof does not match new checkpoint",
            code="consistency_new_root_mismatch",
        )


def verify_identity_from_auditor(url: str, *, user_id: int,
                                 identity_version: int,
                                 identity_pk: str,
                                 previous_checkpoint: dict | None = None) -> dict:
    """Xác minh identity key/version của PQXDH bundle bằng auditor proof."""
    proof = _fetch_json(url, f"/identity/{int(user_id)}/{int(identity_version)}/proof")
    leaf = proof.get("leaf") or {}
    checkpoint = proof.get("checkpoint") or {}
    verify_checkpoint(checkpoint)
    leaf_user_id = int(leaf.get("user_id", 0))
    if leaf_user_id != int(user_id):
        raise AuditError(
            "Identity proof belongs to a different user",
            code="identity_user_mismatch",
        )
    leaf_version_raw = leaf.get("identity_version")
    leaf_version = -1 if leaf_version_raw is None else int(leaf_version_raw)
    if leaf_version != int(identity_version):
        raise AuditError(
            "Identity proof belongs to a different version",
            code="identity_version_mismatch",
        )
    try:
        same_identity = (
            _identity_bytes(str(leaf.get("identity_pk", "")))
            == _identity_bytes(str(identity_pk))
        )
    except Exception:
        same_identity = str(leaf.get("identity_pk", "")) == str(identity_pk)
    if not same_identity:
        raise AuditError(
            "Identity proof key does not match the PQXDH bundle",
            code="identity_key_mismatch",
        )
    verify_inclusion(
        str(leaf.get("leaf_hash", "")),
        -1 if proof.get("leaf_index") is None else int(proof.get("leaf_index")),
        list(proof.get("proof") or []),
        checkpoint,
    )
    check_consistency(url, previous_checkpoint, checkpoint)
    return {
        "status": "ok",
        "leaf": leaf,
        "checkpoint": checkpoint,
        "proof": proof.get("proof") or [],
    }


def fetch_identity_history(url: str, user_id: int) -> dict:
    """Lấy lịch sử identity đã audit của một user để hiển thị trong profile."""
    data = _fetch_json(url, f"/identity/{int(user_id)}")
    checkpoint = data.get("checkpoint") or {}
    verify_checkpoint(checkpoint)
    return data
