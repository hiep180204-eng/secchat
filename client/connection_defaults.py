"""Các giá trị mặc định về kết nối, dùng chung cho login/register/network.

Tự phát hiện môi trường (Docker hay native, Windows hay Linux) để chọn host/port/
đường dẫn chứng chỉ phù hợp; mọi giá trị đều có thể ghi đè bằng biến môi trường.
"""

from __future__ import annotations

import os
import platform
from pathlib import Path


def _inside_docker_client() -> bool:
    """Đoán client có đang chạy bên trong container Docker hay không."""
    return os.path.exists("/certs/chat.crt") or os.path.exists("/.dockerenv")


def default_server_host() -> str:
    """Host server mặc định (ưu tiên biến SECCHAT_SERVER_HOST)."""
    explicit = os.environ.get("SECCHAT_SERVER_HOST")
    if explicit:
        return explicit
    if platform.system() == "Windows":
        return "localhost"
    return "chat-server" if _inside_docker_client() else "localhost"


def default_server_port() -> str:
    """Cổng server mặc định (ưu tiên biến SECCHAT_SERVER_PORT)."""
    explicit = os.environ.get("SECCHAT_SERVER_PORT")
    if explicit:
        return explicit
    return "8888" if _inside_docker_client() and platform.system() != "Windows" else "18888"


def default_cert_path() -> str:
    """Đường dẫn chứng chỉ TLS của server để pin (ưu tiên biến SECCHAT_CERT_PATH)."""
    explicit = os.environ.get("SECCHAT_CERT_PATH")
    if explicit:
        return explicit
    if os.path.isfile("/certs/chat.crt"):
        return "/certs/chat.crt"
    repo_root = Path(__file__).resolve().parents[1]
    return str(repo_root / ".tmp_cert" / "chat.crt")
