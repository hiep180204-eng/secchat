"""Trang đăng nhập của client SecChat.

Thu thập host/port/email/mật khẩu, băm mật khẩu phía client bằng PBKDF2
(``hash_password``) rồi phát signal ``sig_login`` cho controller ``App`` xử lý.
Mật khẩu thô KHÔNG bao giờ rời khỏi máy người dùng — server chỉ nhận pw_hash.
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


class LoginPage(QWidget):
    """Màn hình đăng nhập.

    Phát ``sig_login(host, port, email_or_username, pw_hash)`` khi đăng nhập.
    Phát ``sig_go_register()`` để chuyển sang trang đăng ký.
    """

    sig_login       = pyqtSignal(str, int, str, str)  # host, port, email, pw_hash
    sig_go_register = pyqtSignal()

    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignCenter)

        title = QLabel("SecChat")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color:#fff; font-size:24px; font-weight:700; margin-bottom:24px;")
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
        self.e_host.setObjectName("login.host")
        bl.addWidget(self.e_host)

        bl.addWidget(lbl("PORT"))
        self.e_port = QLineEdit(_DEFAULT_PORT)
        self.e_port.setObjectName("login.port")
        bl.addWidget(self.e_port)

        bl.addWidget(lbl("EMAIL"))
        self.e_email = QLineEdit()
        self.e_email.setObjectName("login.email")
        self.e_email.setPlaceholderText("Email address")
        bl.addWidget(self.e_email)

        bl.addWidget(lbl("PASSWORD"))
        self.e_pw = QLineEdit()
        self.e_pw.setObjectName("login.password")
        self.e_pw.setEchoMode(QLineEdit.Password)
        self.e_pw.setPlaceholderText("Password")
        self.e_pw.returnPressed.connect(self._login)
        bl.addWidget(self.e_pw)

        bl.addSpacing(8)
        btn_login = QPushButton("Log in")
        btn_login.setObjectName("login.submit")
        btn_login.clicked.connect(self._login)
        bl.addWidget(btn_login)

        # "Don't have an account? Register" row
        reg_row = QHBoxLayout()
        reg_row.setAlignment(Qt.AlignCenter)
        reg_lbl = QLabel("Don't have an account?")
        reg_lbl.setStyleSheet("color:#72767d; font-size:12px;")
        btn_reg = QPushButton("Register")
        btn_reg.setObjectName("ghost")
        btn_reg.setProperty("testid", "login.go_register")
        btn_reg.clicked.connect(self.sig_go_register.emit)
        reg_row.addWidget(reg_lbl)
        reg_row.addWidget(btn_reg)
        bl.addLayout(reg_row)

        self.lbl_status = QLabel("")
        self.lbl_status.setObjectName("login.status")
        self.lbl_status.setAlignment(Qt.AlignCenter)
        bl.addWidget(self.lbl_status)

        lay.addWidget(box, alignment=Qt.AlignCenter)

    # ------------------------------------------------------------------ public

    def set_status(self, msg: str, ok: bool = False):
        """Hiển thị dòng trạng thái (xanh nếu ok, đỏ nếu lỗi)."""
        color = "#57f287" if ok else "#ed4245"
        self.lbl_status.setStyleSheet(f"color:{color}; font-size:13px;")
        self.lbl_status.setText(msg)

    # ------------------------------------------------------------------ private

    def _login(self):
        """Đọc form, băm mật khẩu (PBKDF2 với salt = email) rồi phát sig_login."""
        host  = self.e_host.text().strip()  or _DEFAULT_HOST
        port  = int(self.e_port.text().strip() or _DEFAULT_PORT)
        email = self.e_email.text().strip()
        # PBKDF2(pw, email_or_username, 100k) — salt = the entered credential
        # so the hash produced here matches the one produced during registration.
        pw    = hash_password(self.e_pw.text(), email)
        if not email:
            self.set_status("Enter email!")
            return
        self.set_status("Connecting...")
        self.sig_login.emit(host, port, email, pw)
