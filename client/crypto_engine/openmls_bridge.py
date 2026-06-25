"""Wrapper JSON cho bridge OpenMLS dùng bởi group E2EE.

Bridge Rust chạy OpenMLS RFC 9420 thật và giữ state group trong một tiến trình
riêng của client. Python chỉ truyền/nhận JSON command, không tự dựng TreeKEM,
Welcome hay Commit.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Any


DEFAULT_BRIDGE_BIN = "secchat_mls_bridge"
PQ_HYBRID_CIPHERSUITE = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519"
PQ_HYBRID_LABEL = "X-Wing ML-KEM-768 + X25519"


def b64e(raw: bytes) -> str:
    """Base64 url-safe không padding (đồng bộ với định dạng wire của SecChat)."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    """Giải mã chuỗi base64 url-safe thiếu padding do ``b64e`` tạo ra."""
    return base64.urlsafe_b64decode((text + ("=" * (-len(text) % 4))).encode("ascii"))


@dataclass
class MlsBridge:
    """Cầu nối tới tiến trình Rust chạy OpenMLS (RFC 9420).

    Mỗi command gửi dưới dạng MỘT dòng JSON qua stdin của tiến trình ``serve`` và
    nhận lại một dòng JSON qua stdout (có lock để tuần tự hóa). Toàn bộ logic MLS
    thật (TreeKEM, Welcome, Commit, mã hóa application với ciphersuite X-Wing)
    nằm trong binary Rust; Python ở đây chỉ điều phối I/O.
    """
    binary: str = DEFAULT_BRIDGE_BIN
    _proc: subprocess.Popen[str] | None = field(default=None, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def resolved_binary(self) -> str | None:
        """Tìm đường dẫn binary bridge (ưu tiên biến môi trường, rồi tra PATH)."""
        configured = os.environ.get("SECCHAT_MLS_BRIDGE_BIN") or self.binary
        if os.path.isabs(configured) and os.path.exists(configured):
            return configured
        return shutil.which(configured)

    def available(self) -> bool:
        """True nếu tìm thấy binary bridge OpenMLS trên máy (group MLS dùng được)."""
        return self.resolved_binary() is not None

    def _run_one_shot(self, name: str, timeout: float = 30.0) -> dict[str, Any]:
        """Chạy bridge một-lần (vd selftest) và parse dòng JSON cuối; raise nếu lỗi."""
        binary = self.resolved_binary()
        if not binary:
            raise RuntimeError("OpenMLS bridge binary is not available")
        proc = subprocess.run(
            [binary, name],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        raw = (proc.stdout or "").strip().splitlines()[-1] if proc.stdout else "{}"
        try:
            payload = json.loads(raw)
        except Exception as exc:
            raise RuntimeError(
                f"OpenMLS bridge returned invalid JSON: {raw!r}") from exc
        if proc.returncode != 0 or not payload.get("ok"):
            raise RuntimeError(str(payload.get("error") or proc.stderr or raw))
        return payload

    def start(self) -> None:
        """Khởi động tiến trình bridge ở chế độ ``serve`` nếu chưa chạy."""
        if self._proc and self._proc.poll() is None:
            return
        binary = self.resolved_binary()
        if not binary:
            raise RuntimeError("OpenMLS bridge binary is not available")
        self._proc = subprocess.Popen(
            [binary, "serve"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def close(self) -> None:
        """Đóng tiến trình bridge và dọn các stream (gọi khi logout/reset)."""
        proc = self._proc
        self._proc = None
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

    def command(self, cmd: str, timeout: float = 30.0, **kwargs: Any) -> dict[str, Any]:
        """Gửi MỘT command JSON tới bridge và đọc kết quả JSON (lock để tuần tự hóa).

        Raise ``RuntimeError`` nếu bridge dừng bất ngờ, trả JSON hỏng, hoặc
        ``ok`` là false.
        """
        del timeout  # bridge serve is line-oriented; subprocess timeout is not needed per command.
        self.start()
        proc = self._proc
        if not proc or not proc.stdin or not proc.stdout:
            raise RuntimeError("OpenMLS bridge process is not available")
        payload = {"cmd": cmd, **kwargs}
        line = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        with self._lock:
            proc.stdin.write(line + "\n")
            proc.stdin.flush()
            raw = proc.stdout.readline()
        if not raw:
            err = ""
            try:
                err = proc.stderr.read() if proc.stderr else ""
            except Exception:
                pass
            raise RuntimeError(f"OpenMLS bridge stopped unexpectedly: {err}")
        try:
            result = json.loads(raw)
        except Exception as exc:
            raise RuntimeError(
                f"OpenMLS bridge returned invalid JSON: {raw!r}") from exc
        if not result.get("ok"):
            raise RuntimeError(str(result.get("error") or raw))
        return result

    def selftest(self) -> dict[str, Any]:
        """Chạy selftest của bridge (tạo group → add → Welcome → encrypt → remove) để kiểm tra."""
        return self._run_one_shot("selftest", timeout=30.0)

    def init_identity(self, *, user_id: int, email: str,
                      secchat_identity_pk: str,
                      secchat_identity_version: int) -> dict[str, Any]:
        """Khởi tạo Credential MLS và bind với SecChat identity hiện tại."""
        return self.command(
            "init_identity",
            user_id=int(user_id),
            email=str(email or ""),
            secchat_identity_pk=str(secchat_identity_pk or ""),
            secchat_identity_version=int(secchat_identity_version or 0),
        )

    def top_up_key_packages(self, count: int = 8) -> list[dict[str, Any]]:
        """Sinh thêm KeyPackage (public, single-use) để người khác mời mình vào group."""
        result = self.command("top_up_key_packages", count=int(count))
        return list(result.get("key_packages") or [])

    def export_state(self) -> dict[str, Any]:
        """Xuất snapshot toàn bộ state MLS (để lưu mã hóa cục bộ)."""
        return self.command("export_state")

    def import_state(self, state_b64: str) -> dict[str, Any]:
        """Nạp lại state MLS từ snapshot đã lưu (sau relogin)."""
        return self.command("import_state", state_b64=str(state_b64 or ""))

    def create_group(self, conversation_id: int) -> dict[str, Any]:
        """Tạo group MLS mới (vai trò người tạo nhóm)."""
        return self.command("create_group", conversation_id=int(conversation_id))

    def add_members(self, conversation_id: int,
                    key_packages: list[str]) -> dict[str, Any]:
        """Thêm thành viên từ KeyPackage; bridge trả về Welcome + Commit, sang epoch mới."""
        return self.command(
            "add_members",
            conversation_id=int(conversation_id),
            key_packages=list(key_packages),
        )

    def remove_members(self, conversation_id: int,
                       user_ids: list[int]) -> dict[str, Any]:
        """Loại thành viên; bridge trả về Commit (group sang epoch mới)."""
        return self.command(
            "remove_members",
            conversation_id=int(conversation_id),
            user_ids=[int(uid) for uid in user_ids],
        )

    def join_from_welcome(self, conversation_id: int,
                          welcome_b64: str) -> dict[str, Any]:
        """Vào group bằng Welcome (vai trò thành viên mới)."""
        return self.command(
            "join_from_welcome",
            conversation_id=int(conversation_id),
            welcome_b64=str(welcome_b64),
        )

    def process_commit(self, conversation_id: int,
                       commit_b64: str) -> dict[str, Any]:
        """Áp một Commit nhận được để tiến group sang epoch mới."""
        return self.command(
            "process_commit",
            conversation_id=int(conversation_id),
            commit_b64=str(commit_b64),
        )

    def encrypt_application(self, conversation_id: int,
                            plaintext: str) -> str:
        """Mã hóa một tin application bằng khóa epoch hiện tại → message base64."""
        result = self.command(
            "encrypt_application",
            conversation_id=int(conversation_id),
            plaintext_b64=b64e(plaintext.encode("utf-8")),
        )
        return str(result["message_b64"])

    def decrypt_application(self, conversation_id: int,
                            message_b64: str) -> str:
        """Giải mã một tin application MLS → plaintext."""
        result = self.command(
            "decrypt_application",
            conversation_id=int(conversation_id),
            message_b64=str(message_b64),
        )
        return b64d(str(result["plaintext_b64"])).decode("utf-8")
