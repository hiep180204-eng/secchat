"""Lớp mạng của client: kết nối WebSocket qua TLS tới server.

``WSNet`` mở socket TLS (có pin chứng chỉ server), bắt tay WebSocket, gửi JSON
command và phát signal khi nhận frame về cho controller (``App``). Không chứa
logic nghiệp vụ hay crypto — chỉ truyền/nhận khung dữ liệu.
"""

import os
import json
import socket
import ssl
import base64
import threading

from PyQt5.QtCore import QObject, pyqtSignal

from client.connection_defaults import default_cert_path


class WSNet(QObject):
    """Client WebSocket bất đồng bộ qua TLS (wss://).

    Chạy vòng nhận trên một daemon thread và phát Qt signal để mọi cập nhật UI
    diễn ra an toàn trên main thread.

    Mỗi instance có một bộ đếm thế hệ ``_gen`` tăng mỗi lần disconnect(). Recv-loop
    chụp lại _gen lúc bắt đầu và lặng lẽ bỏ qua việc phát signal nếu _gen đã đổi —
    tránh một sự kiện close cũ làm chết một phiên mới dùng lại cùng slot.
    """

    on_open  = pyqtSignal()
    on_close = pyqtSignal(str)
    on_msg   = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self._sock   = None
        self._active = False
        self._lock   = threading.Lock()
        self._gen    = 0            # generation counter

    # ------------------------------------------------------------------ public

    def connect_async(self, host: str, port: int):
        """Mở kết nối ở một thread nền (không chặn UI); phát on_open khi xong."""
        self._gen += 1
        threading.Thread(
            target=self._connect_worker,
            args=(host, port, self._gen),
            daemon=True,
        ).start()

    def disconnect(self):
        """Đóng socket và vô hiệu recv-loop đang chạy (tăng _gen)."""
        self._gen += 1              # invalidate any running recv-loop
        self._active = False
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass

    def send(self, obj: dict):
        """Đóng gói obj thành JSON, bọc trong frame WebSocket và gửi (có lock)."""
        payload = json.dumps(obj, ensure_ascii=False).encode()
        with self._lock:
            try:
                self._sock.sendall(self._frame(payload))
            except Exception as exc:
                self.on_close.emit(str(exc))

    # ------------------------------------------------------------------ internal

    # Docker clients use /certs/chat.crt; native clients use repo .tmp_cert.
    # Override by setting SECCHAT_CERT_PATH.
    _CERT_PATH = default_cert_path()

    def _connect_worker(self, host: str, port: int, gen: int):
        """Thread nền: bắt tay TLS (pin chứng chỉ) + Upgrade WebSocket, rồi vào recv-loop."""
        try:
            raw = socket.socket()
            raw.settimeout(10)
            raw.connect((host, port))
            raw.settimeout(None)

            # Wrap socket with TLS — require valid server certificate.
            # The server cert is pinned via the shared /certs/chat.crt mount.
            # Setting check_hostname=True enforces that the cert CN/SAN matches `host`.
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            cert_path = self._CERT_PATH
            if os.path.isfile(cert_path):
                ctx.load_verify_locations(cert_path)
                ctx.verify_mode   = ssl.CERT_REQUIRED
                ctx.check_hostname = True
            else:
                # Cert file missing — refuse connection rather than silently degrading.
                raise ConnectionError(
                    f"TLS cert not found at '{cert_path}'. "
                    "Set SECCHAT_CERT_PATH or ensure the /certs mount is available."
                )
            s = ctx.wrap_socket(raw, server_hostname=host)

            self._sock = s

            key = base64.b64encode(os.urandom(16)).decode()
            handshake = (
                f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\n"
                f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n\r\n"
            )
            s.sendall(handshake.encode())

            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = s.recv(1024)
                if not chunk:
                    raise ConnectionError("Server closed during handshake")
                resp += chunk

            if b"101" not in resp:
                raise ConnectionError("WebSocket handshake failed")

            self._active = True

            # Check generation before emitting — if it changed, a new
            # connect/disconnect was issued and this worker is stale.
            if self._gen != gen:
                return
            self.on_open.emit()
            self._recv_loop(gen)

        except Exception as exc:
            if self._gen == gen:
                self.on_close.emit(str(exc))

    def _recv_loop(self, gen: int):
        """Vòng nhận: đọc frame WebSocket, parse JSON, phát on_msg; phát on_close khi đứt."""
        buf = b""
        try:
            while self._active and self._gen == gen:
                chunk = self._sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while True:
                    payload, buf = self._parse(buf)
                    if payload is None:
                        break
                    if payload == b"CLOSE":
                        return
                    if payload:
                        if self._gen != gen:
                            return
                        try:
                            self.on_msg.emit(json.loads(payload.decode()))
                        except Exception:
                            pass
        except Exception as exc:
            if self._active and self._gen == gen:
                self.on_close.emit(str(exc))
                return

        # Only emit close if this recv-loop still owns the connection
        if self._gen == gen:
            self.on_close.emit("Connection closed")

    # ------------------------------------------------------------------ framing

    @staticmethod
    def _parse(buf: bytes):
        """Tách MỘT frame WebSocket từ buffer nhận về → (payload, phần còn lại)."""
        if len(buf) < 2:
            return None, buf
        b0, b1   = buf[0], buf[1]
        op       = b0 & 0x0F
        masked   = (b1 & 0x80) != 0
        plen     = b1 & 0x7F
        off      = 2
        if plen == 126:
            if len(buf) < 4:
                return None, buf
            plen = int.from_bytes(buf[2:4], "big")
            off  = 4
        elif plen == 127:
            if len(buf) < 10:
                return None, buf
            plen = int.from_bytes(buf[2:10], "big")
            off  = 10
        if masked:
            off += 4
        if len(buf) < off + plen:
            return None, buf
        data = buf[off : off + plen]
        if masked:
            mk   = buf[off - 4 : off]
            data = bytes(b ^ mk[i % 4] for i, b in enumerate(data))
        rest = buf[off + plen :]
        if op == 0x08:
            return b"CLOSE", rest
        if op == 0x09:
            return b"", rest
        return data, rest

    @staticmethod
    def _frame(payload: bytes) -> bytes:
        """Đóng payload thành frame WebSocket client→server (có mask theo chuẩn RFC 6455)."""
        n   = len(payload)
        mk  = os.urandom(4)
        hdr = bytearray([0x81])
        if n <= 125:
            hdr += bytes([0x80 | n])
        elif n <= 65535:
            hdr += bytes([0x80 | 126]) + n.to_bytes(2, "big")
        else:
            hdr += bytes([0x80 | 127]) + n.to_bytes(8, "big")
        hdr += mk
        return bytes(hdr) + bytes(b ^ mk[i % 4] for i, b in enumerate(payload))
