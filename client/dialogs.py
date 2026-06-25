"""Các hộp thoại (dialog) của client SecChat.

Gồm: cắt ảnh avatar (vòng tròn kéo/thả), tạo nhóm, thêm vào nhóm, xem hồ sơ và
chỉnh sửa hồ sơ (đổi mật khẩu, quyền riêng tư, xoay khóa danh tính, sao lưu E2EE).
Mỗi dialog chỉ thu thập dữ liệu rồi trả kết quả; logic mạng/crypto do ``App`` xử lý.
"""
import os
import time

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QListWidget, QListWidgetItem, QScrollArea,
    QWidget, QCheckBox, QDialogButtonBox, QPushButton, QMessageBox,
    QFileDialog,
)
from PyQt5.QtCore import Qt, QRect, QRectF, QPoint, QTimer, QBuffer
from PyQt5.QtGui import QPainter, QPainterPath, QColor, QPen, QPixmap

from client.styles import CSS


class _CropWidget(QWidget):
    """Widget ảnh có lớp phủ vòng tròn cắt avatar (kéo để di chuyển, đổi kích thước được)."""

    _EDGE = 10  # px from circle edge that triggers resize mode

    def __init__(self, pixmap: QPixmap, parent=None):
        """Khởi tạo widget cắt ảnh và trạng thái vòng cắt ban đầu."""
        super().__init__(parent)
        self.setMinimumSize(400, 380)
        self.setMouseTracking(True)
        self._orig         = pixmap
        self._scaled       = QPixmap()
        self._off          = QPoint()
        self._circle       = QRect()
        self._drag_start   = None
        self._circle_start = None
        self._mode         = None   # "move" | "resize"

    # ── helpers ────────────────────────────────────────────────────────────

    def _rebuild(self):
        """Tính lại ảnh đã scale và offset khi widget đổi kích thước."""
        if self.width() <= 0 or self.height() <= 0:
            return
        self._scaled = self._orig.scaled(
            self.width(), self.height(),
            Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self._off = QPoint(
            (self.width()  - self._scaled.width())  // 2,
            (self.height() - self._scaled.height()) // 2,
        )
        self._circle = QRect()

    def _ensure_circle(self):
        """Khởi tạo vòng cắt mặc định (căn giữa) nếu chưa có."""
        if not self._circle.isNull():
            return
        w = self._scaled.width()
        h = self._scaled.height()
        r = max(40, (min(w, h) * 3) // 4)
        if r % 2:
            r -= 1
        self._circle = QRect(
            self._off.x() + (w - r) // 2,
            self._off.y() + (h - r) // 2,
            r, r,
        )

    def _img_r(self) -> QRect:
        """Hình chữ nhật bao quanh ảnh đã scale (toạ độ widget)."""
        return QRect(self._off, self._scaled.size())

    def _clamp(self):
        """Giữ vòng cắt luôn nằm trong phạm vi ảnh."""
        ir = self._img_r()
        c  = self._circle
        x  = max(ir.left(), min(c.left(), ir.right()  - c.width()))
        y  = max(ir.top(),  min(c.top(),  ir.bottom() - c.height()))
        self._circle.moveTo(x, y)

    def _near_edge(self, pos: QPoint) -> bool:
        """Kiểm tra con trỏ có nằm sát viền vòng cắt (để resize) không."""
        cx = self._circle.center().x()
        cy = self._circle.center().y()
        r  = self._circle.width() / 2.0
        d  = ((pos.x() - cx) ** 2 + (pos.y() - cy) ** 2) ** 0.5
        return abs(d - r) <= self._EDGE

    # ── Qt events ──────────────────────────────────────────────────────────

    def resizeEvent(self, event):
        """Override Qt: tính lại ảnh khi widget đổi kích thước."""
        self._rebuild()
        super().resizeEvent(event)

    def paintEvent(self, _event):
        """Override Qt: vẽ ảnh, lớp phủ mờ và vòng cắt."""
        if self._scaled.isNull():
            self._rebuild()
        if self._scaled.isNull():
            return
        self._ensure_circle()

        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.drawPixmap(self._off, self._scaled)

        full = QPainterPath()
        full.addRect(QRectF(self._img_r()))
        hole = QPainterPath()
        hole.addEllipse(QRectF(self._circle))
        p.fillPath(full.subtracted(hole), QColor(0, 0, 0, 160))

        p.setPen(QPen(QColor("#5865f2"), 2))
        p.setBrush(Qt.NoBrush)
        p.drawEllipse(self._circle)
        p.end()

    def mousePressEvent(self, event):
        """Override Qt: bắt đầu kéo (move/resize) vòng cắt."""
        if event.button() != Qt.LeftButton:
            return
        self._drag_start   = event.pos()
        self._circle_start = QRect(self._circle)
        self._mode = "resize" if self._near_edge(event.pos()) else "move"

    def mouseMoveEvent(self, event):
        """Override Qt: di chuyển hoặc đổi bán kính vòng cắt."""
        if self._near_edge(event.pos()):
            self.setCursor(Qt.SizeAllCursor)
        elif self._circle.contains(event.pos()):
            self.setCursor(Qt.OpenHandCursor)
        else:
            self.setCursor(Qt.ArrowCursor)

        if self._drag_start is None:
            return

        if self._mode == "resize":
            cx    = self._circle_start.center().x()
            cy    = self._circle_start.center().y()
            dx    = event.pos().x() - cx
            dy    = event.pos().y() - cy
            new_r = max(40, int((dx ** 2 + dy ** 2) ** 0.5))
            ir    = self._img_r()
            max_r = min(cx - ir.left(), ir.right()  - cx,
                        cy - ir.top(),  ir.bottom() - cy)
            new_r = min(new_r, int(max_r))
            self._circle = QRect(cx - new_r, cy - new_r, new_r * 2, new_r * 2)
        else:
            dx = event.pos().x() - self._drag_start.x()
            dy = event.pos().y() - self._drag_start.y()
            self._circle = QRect(
                self._circle_start.x() + dx,
                self._circle_start.y() + dy,
                self._circle_start.width(),
                self._circle_start.height(),
            )
            self._clamp()
        self.update()

    def mouseReleaseEvent(self, event):
        """Override Qt: kết thúc thao tác kéo vòng cắt."""
        if event.button() == Qt.LeftButton:
            self._drag_start = None
            self._mode       = None

    def wheelEvent(self, event):
        """Override Qt: phóng to/thu nhỏ vòng cắt bằng con lăn."""
        step = 8 if event.angleDelta().y() > 0 else -8
        r    = self._circle.width() // 2 + step
        cx   = self._circle.center().x()
        cy   = self._circle.center().y()
        ir   = self._img_r()
        max_r = min(cx - ir.left(), ir.right()  - cx,
                    cy - ir.top(),  ir.bottom() - cy)
        r = max(30, min(r, int(max_r)))
        self._circle = QRect(cx - r, cy - r, r * 2, r * 2)
        self._clamp()
        self.update()

    # ── result ─────────────────────────────────────────────────────────────

    def get_cropped(self, size: int = 80) -> QPixmap:
        """Trả về QPixmap hình tròn kích thước size×size từ vùng đã chọn."""
        from client.utils import make_circular_pixmap
        if self._scaled.isNull() or self._circle.isNull():
            return make_circular_pixmap(self._orig, size)
        sx = self._orig.width()  / self._scaled.width()
        sy = self._orig.height() / self._scaled.height()
        ox = int((self._circle.x()    - self._off.x()) * sx)
        oy = int((self._circle.y()    - self._off.y()) * sy)
        ow = max(1, int(self._circle.width()  * sx))
        oh = max(1, int(self._circle.height() * sy))
        cropped = self._orig.copy(QRect(ox, oy, ow, oh))
        return make_circular_pixmap(cropped, size)


class AvatarCropDialog(QDialog):
    """Hiển thị ảnh với vòng cắt; trả về byte PNG của phần tròn đã cắt."""

    def __init__(self, image_path: str, parent=None):
        """Khởi tạo dialog và dựng toàn bộ giao diện con."""
        super().__init__(parent)
        self.setWindowTitle("Crop Avatar")
        self.setMinimumSize(480, 560)
        self.setStyleSheet(CSS)
        self._data = None

        orig = QPixmap(image_path)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(8)

        hint = QLabel("Drag circle to move  ·  Drag edge or scroll wheel to resize")
        hint.setAlignment(Qt.AlignCenter)
        hint.setStyleSheet("color:#949ba4; font-size:12px;")
        lay.addWidget(hint)

        self._crop = _CropWidget(orig, self)
        lay.addWidget(self._crop)

        prev_row = QHBoxLayout()
        prev_row.addStretch()
        lbl_title = QLabel("Preview:")
        lbl_title.setStyleSheet("color:#b5bac1; font-size:12px;")
        prev_row.addWidget(lbl_title)
        self._lbl_prev = QLabel()
        self._lbl_prev.setFixedSize(60, 60)
        prev_row.addWidget(self._lbl_prev)
        prev_row.addStretch()
        lay.addLayout(prev_row)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self._on_ok)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

        self._timer = QTimer(self)
        self._timer.setInterval(120)
        self._timer.timeout.connect(self._refresh_preview)
        self._timer.start()

    def _refresh_preview(self):
        """Cập nhật ảnh xem trước nhỏ theo vùng cắt hiện tại."""
        self._lbl_prev.setPixmap(self._crop.get_cropped(60))

    def _on_ok(self):
        """Cắt ảnh, encode PNG rồi đóng dialog với kết quả."""
        pm  = self._crop.get_cropped(80)
        buf = QBuffer()
        buf.open(QBuffer.WriteOnly)
        pm.save(buf, "PNG")
        self._data = bytes(buf.data())
        self.accept()

    def get_result(self):
        """Trả về (byte PNG, mime) hoặc (None, None) nếu hủy."""
        return self._data, "image/png"


class CreateGroupDialog(QDialog):
    """Dialog tạo nhóm chat mới và chọn thành viên."""

    def __init__(self, friends: dict, parent=None):
        """Khởi tạo dialog và dựng toàn bộ giao diện con."""
        super().__init__(parent)
        self.setWindowTitle("Create Group Chat")
        self.setMinimumWidth(400)
        self.setStyleSheet(CSS)

        lay = QVBoxLayout(self)

        lay.addWidget(QLabel("Group Name:"))
        self.e_name = QLineEdit()
        self.e_name.setObjectName("group.name")
        self.e_name.setProperty("testid", "group.name")
        self.e_name.setPlaceholderText("Enter group name...")
        lay.addWidget(self.e_name)

        lay.addSpacing(10)
        lay.addWidget(QLabel("Select Members:"))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setMaximumHeight(300)

        container = QWidget()
        checks_layout = QVBoxLayout(container)
        checks_layout.setSpacing(4)

        self.checkboxes = []
        for fid, fdata in friends.items():
            cb = QCheckBox(fdata["username"])
            cb.setObjectName(f"group.member.{fid}")
            cb.setProperty("testid", f"group.member.{fid}")
            cb.setProperty("user_id", fid)
            self.checkboxes.append(cb)
            checks_layout.addWidget(cb)

        checks_layout.addStretch()
        scroll.setWidget(container)
        lay.addWidget(scroll)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

    def get_selected(self):
        """Trả về (tên nhóm, [user_id...]) của các thành viên được tick chọn."""
        name     = self.e_name.text().strip() or "Unnamed Group"
        selected = [cb.property("user_id") for cb in self.checkboxes if cb.isChecked()]
        return name, selected


class AddToGroupDialog(QDialog):
    """Dialog thêm một người bạn vào một nhóm sẵn có của người dùng."""

    def __init__(self, groups: list, parent=None):
        """Khởi tạo dialog và dựng toàn bộ giao diện con."""
        super().__init__(parent)
        self.setWindowTitle("Add to Group")
        self.setMinimumWidth(350)
        self.setStyleSheet(CSS)

        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Select a group:"))

        self.group_list = QListWidget()
        self.group_list.setObjectName("group.add_list")
        self.group_list.setProperty("testid", "group.add_list")
        for g in groups:
            item = QListWidgetItem(g["name"])
            item.setData(Qt.UserRole, g["conversation_id"])
            self.group_list.addItem(item)
        lay.addWidget(self.group_list)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

    def get_selected_group(self):
        """Trả về conversation_id của nhóm được chọn, hoặc None."""
        item = self.group_list.currentItem()
        return item.data(Qt.UserRole) if item else None


class ProfileViewDialog(QDialog):
    """Dialog chỉ-đọc hiển thị hồ sơ của một người dùng (của mình hoặc của bạn bè)."""

    def __init__(self, profile: dict, parent=None):
        """Khởi tạo dialog và dựng toàn bộ giao diện con."""
        super().__init__(parent)
        username = profile.get("username", "?")
        self.setWindowTitle(f"Profile — {username}")
        self.setMinimumSize(420, 520)
        self.setStyleSheet(CSS)

        outer = QVBoxLayout(self)
        outer.setSpacing(8)
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border:none; background:#313338; }")
        content = QWidget()
        scroll.setWidget(content)
        outer.addWidget(scroll, 1)

        lay = QVBoxLayout(content)
        lay.setSpacing(12)
        lay.setContentsMargins(20, 20, 20, 20)

        # Avatar (80 × 80)
        avatar_lbl = QLabel()
        avatar_lbl.setAlignment(Qt.AlignCenter)
        b64  = profile.get("avatar_b64", "") or ""
        if b64:
            from client.utils import avatar_from_b64
            pm = avatar_from_b64(b64, 80)
            if pm:
                avatar_lbl.setPixmap(pm)
            else:
                _set_initials(avatar_lbl, username, 80)
        else:
            _set_initials(avatar_lbl, username, 80)
        lay.addWidget(avatar_lbl)

        # Display name (or username fallback)
        display = profile.get("display_name") or username
        name_lbl = QLabel(display)
        name_lbl.setAlignment(Qt.AlignCenter)
        name_lbl.setStyleSheet(
            "color:#f2f3f5; font-size:16px; font-weight:700;")
        lay.addWidget(name_lbl)

        if profile.get("display_name") and profile["display_name"] != username:
            uname_lbl = QLabel(f"@{username}")
            uname_lbl.setAlignment(Qt.AlignCenter)
            uname_lbl.setStyleSheet("color:#949ba4; font-size:12px;")
            lay.addWidget(uname_lbl)

        # Bio
        bio = profile.get("bio") or ""
        if bio:
            bio_lbl = QLabel(bio)
            bio_lbl.setWordWrap(True)
            bio_lbl.setAlignment(Qt.AlignCenter)
            bio_lbl.setStyleSheet("color:#b5bac1; font-size:13px;")
            lay.addWidget(bio_lbl)

        # Status
        status = profile.get("status", "offline")
        if status == "online":
            status_text = "Online"
        else:
            last_seen = str(profile.get("last_seen", "") or "").strip()
            status_text = f"Last seen {last_seen}" if last_seen else "Offline"
        status_lbl = QLabel(status_text)
        status_lbl.setAlignment(Qt.AlignCenter)
        status_lbl.setStyleSheet(
            f"color:{'#23a55a' if status == 'online' else '#80848e'};"
            " font-size:12px;"
        )
        lay.addWidget(status_lbl)

        audit = profile.get("identity_audit") or {}
        remote_history = (profile.get("auditor_identity_history") or {}).get("entries") or []
        local_history = audit.get("history") or []
        history = remote_history or local_history
        if audit or history:
            title = QLabel("Identity history")
            title.setStyleSheet("color:#949ba4; font-size:12px; font-weight:700;")
            lay.addWidget(title)
            error = str(audit.get("last_error", "") or "")
            error_code = str(audit.get("last_error_code", "") or "")
            if error_code:
                try:
                    from client.crypto_engine.audit import audit_error_detail
                    error = audit_error_detail(error_code, error)
                except Exception:
                    error = f"{error_code}: {error}" if error else error_code
            summary = QLabel(
                f"Status: {str(audit.get('status', 'unknown')).replace('_', ' ')}"
                + (f"\nLast audit warning: {error}" if error else "")
            )
            summary.setWordWrap(True)
            summary.setStyleSheet(
                "QLabel { color:#b5bac1; background:#2b2d31; padding:8px; "
                "border-radius:6px; }"
            )
            lay.addWidget(summary)
            for item in list(history)[-5:]:
                try:
                    version_i = int(item.get("identity_version", -1))
                    version = "initial" if version_i == 0 else f"v{version_i}"
                except Exception:
                    version = "unknown"
                event = item.get("event_type", "seen")
                created = item.get("created_at") or item.get("seen_at", "")
                device = item.get("device_label", "primary device")
                safety = item.get("safety_number", "")
                row = QLabel(f"{version} - {event} - {created} - {device}\n{safety}")
                row.setWordWrap(True)
                row.setTextInteractionFlags(Qt.TextSelectableByMouse)
                row.setStyleSheet(
                    "QLabel { color:#dbdee1; background:#313338; padding:8px; "
                    "border-radius:6px; }"
                )
                lay.addWidget(row)

        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.rejected.connect(self.reject)
        outer.addWidget(btns)


class ProfileEditDialog(QDialog):
    """Dialog chỉnh sửa hồ sơ của chính người dùng đang đăng nhập."""

    def __init__(self, profile: dict, parent=None):
        """Khởi tạo dialog và dựng toàn bộ giao diện con."""
        super().__init__(parent)
        self.setWindowTitle("Edit Profile")
        self.setMinimumWidth(420)
        self.setStyleSheet(CSS)

        self._profile          = profile
        self._new_avatar_data  = None   # bytes | None
        self._new_avatar_mime  = None
        self._do_remove_avatar = False
        self._requested_action = None

        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.setContentsMargins(20, 20, 20, 20)

        # Avatar preview
        self.avatar_lbl = QLabel()
        self.avatar_lbl.setObjectName("profile.avatar.preview")
        self.avatar_lbl.setProperty("testid", "profile.avatar.preview")
        self.avatar_lbl.setAlignment(Qt.AlignCenter)
        self._refresh_avatar_preview(profile)
        lay.addWidget(self.avatar_lbl)

        # Avatar action buttons
        av_row = QHBoxLayout()
        btn_up = QPushButton("Upload Avatar")
        btn_up.setObjectName("small")
        btn_up.setProperty("testid", "profile.avatar.upload")
        btn_up.setFixedSize(132, 32)
        btn_up.clicked.connect(self._pick_avatar)
        av_row.addWidget(btn_up)

        btn_rm = QPushButton("Remove Avatar")
        btn_rm.setObjectName("danger")
        btn_rm.setProperty("testid", "profile.avatar.remove")
        btn_rm.setFixedSize(132, 32)
        btn_rm.clicked.connect(self._clear_avatar)
        av_row.addWidget(btn_rm)
        lay.addLayout(av_row)

        # Display name
        lay.addWidget(QLabel("Display Name:"))
        self.e_display = QLineEdit(profile.get("display_name") or "")
        self.e_display.setObjectName("profile.display_name")
        self.e_display.setProperty("testid", "profile.display_name")
        self.e_display.setPlaceholderText("Optional display name...")
        lay.addWidget(self.e_display)

        # Bio
        lay.addWidget(QLabel("Bio:"))
        self.e_bio = QLineEdit(profile.get("bio") or "")
        self.e_bio.setObjectName("profile.bio")
        self.e_bio.setProperty("testid", "profile.bio")
        self.e_bio.setPlaceholderText("Tell us about yourself...")
        lay.addWidget(self.e_bio)

        account_title = QLabel("Account and privacy")
        account_title.setStyleSheet("color:#949ba4; font-size:12px; font-weight:700;")
        lay.addWidget(account_title)

        account_row = QHBoxLayout()
        btn_pw = QPushButton("Change Password")
        btn_pw.setObjectName("small")
        btn_pw.setProperty("testid", "profile.change_password")
        btn_pw.clicked.connect(lambda: self._request_action("change_password"))
        account_row.addWidget(btn_pw)

        btn_privacy = QPushButton("Privacy")
        btn_privacy.setObjectName("small")
        btn_privacy.setProperty("testid", "profile.privacy")
        btn_privacy.clicked.connect(lambda: self._request_action("privacy"))
        account_row.addWidget(btn_privacy)

        btn_blocked = QPushButton("Blocked Users")
        btn_blocked.setObjectName("small")
        btn_blocked.setProperty("testid", "profile.blocked_users")
        btn_blocked.clicked.connect(lambda: self._request_action("blocked"))
        account_row.addWidget(btn_blocked)
        lay.addLayout(account_row)

        security_title = QLabel("Identity security")
        security_title.setStyleSheet("color:#949ba4; font-size:12px; font-weight:700;")
        lay.addWidget(security_title)
        rotate_note = QLabel(
            "Rotating the safety key publishes a new identity key bundle. "
            "Contacts will see a key-change warning and should verify you again."
        )
        rotate_note.setWordWrap(True)
        rotate_note.setStyleSheet("color:#b5bac1; font-size:12px;")
        lay.addWidget(rotate_note)

        security_row = QHBoxLayout()
        btn_rotate = QPushButton("Rotate Safety Key")
        btn_rotate.setObjectName("small")
        btn_rotate.setProperty("testid", "profile.rotate_identity")
        btn_rotate.setToolTip(
            "Publish a fresh identity and prekey bundle. Contacts will see a "
            "safety-number change."
        )
        btn_rotate.clicked.connect(lambda: self._request_action("rotate_identity"))
        security_row.addWidget(btn_rotate)
        security_row.addStretch()
        lay.addLayout(security_row)

        backup_title = QLabel("Backup and recovery")
        backup_title.setStyleSheet("color:#949ba4; font-size:12px; font-weight:700;")
        lay.addWidget(backup_title)

        backup_status = profile.get("backup_status") or {}
        self.backup_status_lbl = QLabel(self._backup_status_summary(backup_status))
        self.backup_status_lbl.setWordWrap(True)
        self.backup_status_lbl.setStyleSheet(
            "QLabel { color:#b5bac1; background:#2b2d31; padding:8px; "
            "border-radius:6px; }"
        )
        lay.addWidget(self.backup_status_lbl)

        backup_row = QHBoxLayout()
        btn_export = QPushButton("Export E2EE Backup")
        btn_export.setObjectName("small")
        btn_export.setProperty("testid", "profile.backup.export")
        btn_export.setToolTip(
            "Export local encrypted identity, ratchets, group state, and optional cache."
        )
        btn_export.clicked.connect(lambda: self._request_action("export_backup"))
        backup_row.addWidget(btn_export)

        btn_restore = QPushButton("Restore E2EE Backup")
        btn_restore.setObjectName("small")
        btn_restore.setProperty("testid", "profile.backup.restore")
        btn_restore.setToolTip(
            "Restore a passphrase-protected backup. This can replace local "
            "identity, ratchet, group, and verification state."
        )
        btn_restore.clicked.connect(lambda: self._request_action("restore_backup"))
        backup_row.addWidget(btn_restore)
        backup_row.addStretch()
        lay.addLayout(backup_row)

        backup_manage_row = QHBoxLayout()
        btn_backup_status = QPushButton("Backup Status")
        btn_backup_status.setObjectName("small")
        btn_backup_status.setProperty("testid", "profile.backup.status")
        btn_backup_status.setToolTip("Show local backup version and restore state")
        btn_backup_status.clicked.connect(lambda: self._request_action("backup_status"))
        backup_manage_row.addWidget(btn_backup_status)

        btn_revoke = QPushButton("Revoke Local Backups")
        btn_revoke.setObjectName("small")
        btn_revoke.setProperty("testid", "profile.backup.revoke")
        btn_revoke.setToolTip("Make this device refuse older known local backup files")
        btn_revoke.clicked.connect(lambda: self._request_action("revoke_backups"))
        backup_manage_row.addWidget(btn_revoke)
        backup_manage_row.addStretch()
        lay.addLayout(backup_manage_row)

        btns = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

    # ── helpers ──

    def _request_action(self, action: str):
        """Ghi nhận hành động người dùng chọn và đóng dialog."""
        self._requested_action = action
        self.accept()

    @staticmethod
    def _backup_status_summary(status: dict) -> str:
        """Tóm tắt trạng thái sao lưu E2EE thành câu mô tả."""
        generation = int(status.get("latest_generation", 0) or 0)
        if generation <= 0:
            return (
                "E2EE backup: no local backup recorded. If this device is lost "
                "without a backup file and passphrase, old E2EE state cannot be recovered."
            )
        ts = int(status.get("latest_created_at", 0) or 0)
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "unknown time"
        cache = "with message cache" if status.get("latest_include_cache") else "without message cache"
        revoked = int(status.get("revoked_before_generation", 0) or 0)
        suffix = f" Revoked through generation {revoked}." if revoked else ""
        return f"E2EE backup: generation {generation}, {when}, {cache}.{suffix}"

    def _refresh_avatar_preview(self, profile: dict):
        """Cập nhật ảnh avatar xem trước từ dữ liệu hồ sơ."""
        b64 = profile.get("avatar_b64", "") or ""
        if b64:
            from client.utils import avatar_from_b64
            pm = avatar_from_b64(b64, 80)
            if pm:
                self.avatar_lbl.setPixmap(pm)
                return
        _set_initials(self.avatar_lbl, profile.get("username", "?"), 80)

    def _pick_avatar(self):
        """Chọn ảnh, mở dialog cắt và lưu avatar mới."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Avatar", "",
            "Images (*.png *.jpg *.jpeg *.gif *.bmp *.webp)")
        if not path:
            return
        if os.path.getsize(path) > 2 * 1024 * 1024:
            QMessageBox.warning(self, "Too Large",
                                "Avatar image must be under 2 MB.")
            return
        orig = QPixmap(path)
        if orig.isNull():
            QMessageBox.warning(self, "Invalid Image",
                                "Could not load the selected image.")
            return
        dlg = AvatarCropDialog(path, self)
        if dlg.exec_() != QDialog.Accepted:
            return
        data, mime = dlg.get_result()
        if not data:
            return
        self._new_avatar_data  = data
        self._new_avatar_mime  = mime
        self._do_remove_avatar = False
        # Show circular preview
        pm = QPixmap()
        pm.loadFromData(data)
        if not pm.isNull():
            self.avatar_lbl.setPixmap(pm)

    def _clear_avatar(self):
        """Đánh dấu xóa avatar và hiển thị chữ cái đầu."""
        self._do_remove_avatar = True
        self._new_avatar_data  = None
        self._new_avatar_mime  = None
        _set_initials(self.avatar_lbl, self._profile.get("username", "?"), 80)

    def get_result(self):
        """Trả về (display_name, bio, avatar_data, avatar_mime, remove_avatar)."""
        return (
            self.e_display.text().strip(),
            self.e_bio.text().strip(),
            self._new_avatar_data,
            self._new_avatar_mime,
            self._do_remove_avatar,
        )

    def get_requested_action(self):
        """Trả về hành động phụ người dùng đã yêu cầu (nếu có)."""
        return self._requested_action


# ── module-level helper ───────────────────────────────────────────────────────

def _set_initials(lbl: QLabel, username: str, size: int):
    """Đặt avatar dạng chữ cái đầu (khi không có ảnh) lên một QLabel."""
    from client.utils import initials_pixmap
    lbl.setPixmap(initials_pixmap(username, size))
