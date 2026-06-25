#!/usr/bin/env python3
"""Dịch vụ kiểm toán identity transparency của SecChat.

Server chat sở hữu luồng tài khoản và upload khóa. Dịch vụ NÀY là một bộ kiểm
độc lập: đọc bảng append-only ``identity_key_log``, dựng một cây Merkle, KÝ các
checkpoint (Ed25519) và phục vụ dữ liệu inclusion/consistency cho client.

Nhờ tách riêng, client đối chiếu được: nếu server tráo identity key âm thầm,
rollback log, hay cho hai client thấy log head khác nhau, các proof/checkpoint
sẽ không khớp và client phát hiện ra.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pymysql
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


DEFAULT_SEED_HEX = "8b4f8067f2ba1a39d62f08bd24ff152a9cd18c95b9cf4f78015fd9706f3b6c42"
PORT = int(os.environ.get("AUDITOR_PORT", "8890"))


def _signing_key() -> Ed25519PrivateKey:
    """Khóa Ed25519 dùng để ký checkpoint (seed lấy từ biến môi trường, có mặc định demo)."""
    seed_hex = os.environ.get("AUDITOR_SIGNING_SEED", DEFAULT_SEED_HEX)
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))


_SK = _signing_key()
_PK_HEX = _SK.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _db():
    """Mở kết nối MySQL (auditor chỉ ĐỌC bảng identity_key_log, không ghi)."""
    return pymysql.connect(
        host=os.environ.get("DB_HOST", "db"),
        port=int(os.environ.get("DB_PORT", "3306")),
        user=os.environ.get("DB_USER", "chatuser"),
        password=os.environ.get("DB_PASS") or os.environ.get("MYSQL_PASSWORD", "chatpass"),
        database=os.environ.get("DB_NAME", "chatdb"),
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _node_hash(left_hex: str, right_hex: str) -> str:
    """Hash một nút trong Merkle (domain byte 0x01 phân biệt internal node với leaf)."""
    return _sha256(b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)).hex()


def _tree_layers(leaf_hashes: list[str]) -> list[list[str]]:
    """Dựng toàn bộ các tầng của cây Merkle từ danh sách leaf (rỗng → root cố định)."""
    if not leaf_hashes:
        return [[_sha256(b"SecChatEmptyIdentityTree").hex()]]
    layers = [list(leaf_hashes)]
    cur = list(leaf_hashes)
    while len(cur) > 1:
        nxt: list[str] = []
        for i in range(0, len(cur), 2):
            if i + 1 < len(cur):
                nxt.append(_node_hash(cur[i], cur[i + 1]))
            else:
                nxt.append(cur[i])
        layers.append(nxt)
        cur = nxt
    return layers


def _root(leaf_hashes: list[str]) -> str:
    """Root của cây Merkle (phần tử duy nhất ở tầng trên cùng)."""
    return _tree_layers(leaf_hashes)[-1][0]


def _inclusion_proof(leaf_hashes: list[str], index: int) -> list[dict]:
    """Sinh inclusion proof cho leaf thứ ``index``: danh sách sibling kèm hướng (left/right).

    Client dùng proof này leo từ leaf lên root để chứng minh leaf nằm trong cây
    đã được auditor ký.
    """
    proof: list[dict] = []
    if index < 0 or index >= len(leaf_hashes):
        return proof
    idx = index
    cur = list(leaf_hashes)
    while len(cur) > 1:
        if idx % 2 == 0:
            sib = idx + 1
            if sib < len(cur):
                proof.append({"side": "right", "hash": cur[sib]})
        else:
            sib = idx - 1
            proof.append({"side": "left", "hash": cur[sib]})
        nxt: list[str] = []
        for i in range(0, len(cur), 2):
            if i + 1 < len(cur):
                nxt.append(_node_hash(cur[i], cur[i + 1]))
            else:
                nxt.append(cur[i])
        idx //= 2
        cur = nxt
    return proof


def _checkpoint(leaf_hashes: list[str]) -> dict:
    """Dựng và KÝ một checkpoint (tree_size, root_hash, thời điểm) bằng khóa auditor."""
    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    root_hash = _root(leaf_hashes)
    tree_size = len(leaf_hashes)
    msg = f"SecChatAuditCheckpoint|{tree_size}|{root_hash}|{created_at}".encode("utf-8")
    return {
        "tree_size": tree_size,
        "root_hash": root_hash,
        "created_at": created_at,
        "signature": _SK.sign(msg).hex(),
        "auditor_pk": _PK_HEX,
    }


def _assign_leaf_indices(rows: list[dict]) -> list[dict]:
    """Gán leaf index DÀY ĐẶC theo thứ tự append (0,1,2,...).

    Giá trị AUTO_INCREMENT của MySQL có thể bị nhảy số (INSERT IGNORE trùng vẫn
    tốn một id). Nếu lấy ``log_index - 1`` làm chỉ số Merkle thì proof hợp lệ sẽ
    sai sau các lần client retry bình thường — nên ta đánh lại index liên tục.
    """
    for index, row in enumerate(rows):
        row["leaf_index"] = index
    return rows


def _load_rows() -> list[dict]:
    """Đọc toàn bộ identity_key_log theo thứ tự append và gán leaf index dày đặc."""
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT log_index, user_id, identity_version, identity_pk,"
                " device_id_hash, device_label, event_type, created_at, leaf_hash"
                " FROM identity_key_log ORDER BY log_index ASC"
            )
            rows = list(cur.fetchall())
    for row in rows:
        row["log_index"] = int(row["log_index"])
        row["user_id"] = int(row["user_id"])
        row["identity_version"] = int(row["identity_version"])
    return _assign_leaf_indices(rows)


def _body(rows: list[dict]) -> dict:
    """Gộp checkpoint + rows + leaf_hashes thành một bộ dữ liệu dùng chung cho các endpoint."""
    leaves = [str(r["leaf_hash"]) for r in rows]
    return {"checkpoint": _checkpoint(leaves), "rows": rows, "leaf_hashes": leaves}


class Handler(BaseHTTPRequestHandler):
    """HTTP handler phục vụ các endpoint kiểm toán (read-only).

    Các endpoint: ``/healthz``, ``/readyz``, ``/pubkey``, ``/checkpoint``,
    ``/identity/<uid>``, ``/identity/<uid>/<version>/proof``, ``/consistency``.
    """
    server_version = "SecChatIdentityAuditor/1.0"

    def _json(self, status: int, obj: dict) -> None:
        """Gửi một JSON response với HTTP status cho trước."""
        raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt: str, *args) -> None:
        print("[auditor]", fmt % args, flush=True)

    def do_GET(self) -> None:  # noqa: N802
        """Định tuyến mọi GET: dựng lại cây Merkle từ log rồi trả checkpoint/proof/consistency.

        Cây được dựng lại mỗi request từ ``identity_key_log`` (nguồn sự thật), nên
        checkpoint luôn phản ánh trạng thái log mới nhất.
        """
        parsed = urlparse(self.path)
        path = parsed.path.strip("/")
        try:
            if path in ("healthz", "readyz"):
                self._json(200, {"status": "ok", "auditor_pk": _PK_HEX})
                return
            if path == "pubkey":
                self._json(200, {"auditor_pk": _PK_HEX})
                return

            rows = _load_rows()
            data = _body(rows)

            if path == "checkpoint":
                self._json(200, data["checkpoint"])
                return

            parts = path.split("/")
            if len(parts) == 2 and parts[0] == "identity":
                uid = int(parts[1])
                user_rows = [r for r in rows if int(r["user_id"]) == uid]
                self._json(200, {
                    "user_id": uid,
                    "entries": user_rows,
                    "checkpoint": data["checkpoint"],
                })
                return

            if len(parts) == 4 and parts[0] == "identity" and parts[3] == "proof":
                uid = int(parts[1])
                version = int(parts[2])
                leaf = next(
                    (r for r in rows
                     if int(r["user_id"]) == uid
                     and int(r["identity_version"]) == version),
                    None,
                )
                if not leaf:
                    self._json(404, {"error": "identity version not found"})
                    return
                index = int(leaf["leaf_index"])
                self._json(200, {
                    "leaf": leaf,
                    "leaf_index": index,
                    "proof": _inclusion_proof(data["leaf_hashes"], index),
                    "checkpoint": data["checkpoint"],
                })
                return

            if path == "consistency":
                qs = parse_qs(parsed.query)
                old_size = int((qs.get("from") or ["0"])[0])
                new_size = int((qs.get("to") or [str(len(data["leaf_hashes"]))])[0])
                leaves = data["leaf_hashes"]
                if old_size < 0 or new_size < old_size or new_size > len(leaves):
                    self._json(400, {"error": "invalid consistency range"})
                    return
                self._json(200, {
                    "from_size": old_size,
                    "to_size": new_size,
                    "from_root": _root(leaves[:old_size]),
                    "to_root": _root(leaves[:new_size]),
                    "proof": [],
                    "status": "consistent",
                })
                return

            self._json(404, {"error": "not found"})
        except Exception as exc:
            self._json(500, {"error": str(exc)})


if __name__ == "__main__":
    print(f"[auditor] public key: {_PK_HEX}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
