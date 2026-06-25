"""Trang đăng ký tài khoản của client SecChat.

Kiểm tra hợp lệ form (username/email/mật khẩu khớp), băm mật khẩu phía client
bằng PBKDF2 với salt = email (cùng cách với trang đăng nhập để hash khớp nhau),
rồi phát ``sig_register``. Mật khẩu thô không bao giờ gửi lên server.
"""
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QLabel,
)
from PyQt5.QtCore import Qt, pyqtSignal

from client.connection_defaults import default_server_host, default_server_port
from client.utils import hash_password  # PBKDF2 client-side password derivation

_DEFAULT_HOST = default_server_host()
_DEFAULT_PORT = default_server_port()


class RegisterPage(QWidget):
    """Màn hình đăng ký.

    Phát ``sig_register(host, port, username, email, pw_hash)`` khi hợp lệ.
    Phát ``sig_back()`` để quay lại trang đăng nhập.
    """

    sig_register = pyqtSignal(str, int, str, str, str)  # host, port, username, email, pw_hash
    sig_back     = pyqtSignal()

    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignCenter)

        title = QLabel("SecChat — Create Account")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color:#fff; font-size:20px; font-weight:700; margin-bottom:24px;")
        lay.addWidget(title)

        box = QWidget()
        box.setMaximumWidth(360)
        bl  = QVBoxLayout(box)
        bl.setSpacing(10)

        def lbl(text):
            l = QLabel(text)
            l.setStyleSheet("color:#b9bbbe; font-size:12px; font-weight:600;")
            return l

        bl.addWidget(lbl("SERVER"))
        self.e_host = QLineEdit(_DEFAULT_HOST)
        self.e_host.setObjectName("register.host")
        bl.addWidget(self.e_host)

        bl.addWidget(lbl("PORT"))
        self.e_port = QLineEdit(_DEFAULT_PORT)
        self.e_port.setObjectName("register.port")
        bl.addWidget(self.e_port)

        bl.addWidget(lbl("USERNAME"))
        self.e_user = QLineEdit()
        self.e_user.setObjectName("register.username")
        self.e_user.setPlaceholderText("Username (visible to others)")
        bl.addWidget(self.e_user)

        bl.addWidget(lbl("EMAIL"))
        self.e_email = QLineEdit()
        self.e_email.setObjectName("register.email")
        self.e_email.setPlaceholderText("Email address (used to log in)")
        bl.addWidget(self.e_email)

        bl.addWidget(lbl("PASSWORD"))
        self.e_pw = QLineEdit()
        self.e_pw.setObjectName("register.password")
        self.e_pw.setEchoMode(QLineEdit.Password)
        self.e_pw.setPlaceholderText("Password")
        bl.addWidget(self.e_pw)

        bl.addWidget(lbl("CONFIRM PASSWORD"))
        self.e_pw2 = QLineEdit()
        self.e_pw2.setObjectName("register.confirm")
        self.e_pw2.setEchoMode(QLineEdit.Password)
        self.e_pw2.setPlaceholderText("Confirm password")
        self.e_pw2.returnPressed.connect(self._register)
        bl.addWidget(self.e_pw2)

        bl.addSpacing(8)
        row = QHBoxLayout()
        btn_reg  = QPushButton("Register")
        btn_reg.setObjectName("register.submit")
        btn_reg.clicked.connect(self._register)
        btn_back = QPushButton("Back to Login")
        btn_back.setObjectName("ghost")
        btn_back.setProperty("testid", "register.back")
        btn_back.clicked.connect(self.sig_back.emit)
        row.addWidget(btn_reg)
        row.addWidget(btn_back)
        bl.addLayout(row)

        self.lbl_status = QLabel("")
        self.lbl_status.setObjectName("register.status")
        self.lbl_status.setAlignment(Qt.AlignCenter)
        self.lbl_status.setWordWrap(True)
        bl.addWidget(self.lbl_status)

        lay.addWidget(box, alignment=Qt.AlignCenter)

    # ------------------------------------------------------------------ public

    def set_status(self, msg: str, ok: bool = False):
        """Hiển thị dòng trạng thái (xanh nếu ok, đỏ nếu lỗi)."""
        color = "#57f287" if ok else "#ed4245"
        self.lbl_status.setStyleSheet(f"color:{color}; font-size:13px;")
        self.lbl_status.setText(msg)

    def clear_fields(self):
        """Xóa toàn bộ ô nhập (gọi khi rời trang)."""
        self.e_user.clear()
        self.e_email.clear()
        self.e_pw.clear()
        self.e_pw2.clear()
        self.lbl_status.clear()

    # ------------------------------------------------------------------ private

    def _register(self):
        """Kiểm tra hợp lệ form, băm mật khẩu rồi phát sig_register."""
        host  = self.e_host.text().strip() or _DEFAULT_HOST
        port  = int(self.e_port.text().strip() or _DEFAULT_PORT)
        user  = self.e_user.text().strip()
        email = self.e_email.text().strip()
        pw    = self.e_pw.text()
        pw2   = self.e_pw2.text()

        if not user:
            self.set_status("Username is required!")
            return
        if len(user) < 3:
            self.set_status("Username must be at least 3 characters!")
            return
        if not email or "@" not in email:
            self.set_status("Enter a valid email address!")
            return
        if not pw:
            self.set_status("Password is required!")
            return
        if len(pw) < 6:
            self.set_status("Password must be at least 6 characters!")
            return
        if pw != pw2:
            self.set_status("Passwords do not match!")
            return

        self.set_status("Registering...")
        # PBKDF2(pw, email, 100k) — same salt used on login page so hashes match.
        self.sig_register.emit(host, port, user, email, hash_password(pw, email))
