"""Controller chÃ­nh cá»§a á»©ng dá»¥ng SecChat.

File nÃ y ná»‘i UI PyQt, WebSocket vÃ  ``CryptoSession``. Controller khÃ´ng nÃªn chá»©a
primitive máº­t mÃ£ tháº¥p táº§ng; nÃ³ chá»‰ quyáº¿t Ä‘á»‹nh khi nÃ o cáº§n fetch bundle, khi nÃ o
queue message, khi nÃ o cáº­p nháº­t UI vÃ  khi nÃ o gá»i crypto engine Ä‘á»ƒ mÃ£ hÃ³a/giáº£i
mÃ£. CÃ¡ch tÃ¡ch nÃ y giÃºp luá»“ng giao thá»©c dá»… kiá»ƒm thá»­ hÆ¡n vÃ  trÃ¡nh Ä‘á»ƒ UI vÃ´ tÃ¬nh
lÃ m lá»‡ch ratchet state.
"""

import os
import json
import base64
import logging
import hashlib

import time
from collections import deque

from cryptography.exceptions import InvalidTag
from PyQt5.QtWidgets import (QMainWindow, QStackedWidget, QMessageBox,
                             QDialog, QVBoxLayout, QLabel, QCheckBox,
                             QDialogButtonBox, QFileDialog, QInputDialog,
                             QLineEdit, QPushButton, QScrollArea, QWidget,
                             QApplication, QListWidget, QPlainTextEdit,
                             QComboBox)
from PyQt5.QtCore    import QTimer, Qt
from PyQt5.QtGui     import QFont, QPixmap, QPainter, QColor

from client.network               import WSNet
from client.styles                import CSS
from client.pages.login_page      import LoginPage
from client.pages.register_page   import RegisterPage
from client.pages.chat_page       import ChatPage, MAX_FILE_SIZE, _guess_mime
from client.utils import (
    ts_short,
    hash_password,
    derive_master_key,
)
from client.crypto_engine.secure_protocol import (
    b64d as protocol_b64d,
    json_unb64 as protocol_json_unb64,
    PREFIX_DR as WIRE_PREFIX_DR,
    PREFIX_MLS as WIRE_PREFIX_MLS,
    PREFIX_PQ_INIT as WIRE_PREFIX_PQ_INIT,
    safety_fingerprint as protocol_safety_fingerprint,
)
from client.crypto_engine.audit import (
    AuditError,
    audit_error_detail,
    audit_error_label,
    audit_status_for_code,
    classify_audit_error,
    default_auditor_url,
    fetch_identity_history,
    same_identity_key,
    verify_identity_from_auditor,
)
from client.crypto_engine.openmls_bridge import PQ_HYBRID_LABEL
from client.crypto_engine.session import CryptoSession, CryptoStateError


# Logger dÃ¹ng chung cho controller. Log á»Ÿ Ä‘Ã¢y chá»‰ ghi tráº¡ng thÃ¡i ká»¹ thuáº­t,
# khÃ´ng ghi plaintext message hoáº·c secret key.
_logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


def _crypto_property(attr: str):
    """Táº¡o property tÆ°Æ¡ng thÃ­ch cho code cÅ© khi crypto Ä‘Ã£ tÃ¡ch khá»i controller.

    TrÆ°á»›c Ä‘Ã¢y ``App`` giá»¯ nhiá»u field nhÆ° ``_master_key`` hoáº·c ``_double_ratchet_states``.
    Sau khi tÃ¡ch crypto engine, cÃ¡c field Ä‘Ã³ náº±m trong ``CryptoSession``. Helper
    nÃ y cho phÃ©p cÃ¡c Ä‘oáº¡n code cÃ²n láº¡i Ä‘á»c/ghi nhÆ° cÅ© nhÆ°ng thá»±c táº¿ chuyá»ƒn tiáº¿p
    vÃ o session crypto, giáº£m rá»§i ro pháº£i sá»­a quÃ¡ nhiá»u UI cÃ¹ng lÃºc.
    """
    def getter(self):
        """Getter cho một property động."""
        return getattr(self._crypto_session(), attr)

    def setter(self, value):
        """Setter cho một property động."""
        setattr(self._crypto_session(), attr, value)

    return property(getter, setter)


class App(QMainWindow):
    _master_key = _crypto_property("master_key")
    _secchat_dir = _crypto_property("secchat_dir")
    _my_uid = _crypto_property("my_uid")
    _identity_pk = _crypto_property("identity_pk")
    _identity_sk = _crypto_property("identity_sk")
    _conv_peer_uids = _crypto_property("conv_peer_uids")
    _conv_fingerprints = _crypto_property("conv_fingerprints")
    _conv_verified = _crypto_property("conv_verified")
    _group_conv_ids = _crypto_property("group_conv_ids")
    _group_epochs = _crypto_property("group_epochs")
    _pqxdh_prekeys = _crypto_property("pqxdh_prekeys")
    _double_ratchet_states = _crypto_property("double_ratchet_states")

    def _crypto_session(self) -> CryptoSession:
        """Trả về CryptoSession của phiên đăng nhập hiện tại."""
        if "_crypto" not in self.__dict__:
            self.__dict__["_crypto"] = CryptoSession(logger=_logger)
        return self.__dict__["_crypto"]

    def __init__(self):
        """Khởi tạo đối tượng và thiết lập trạng thái/giao diện ban đầu."""
        super().__init__()
        self.setWindowTitle("SecChat")
        self.resize(1100, 750)
        self.setStyleSheet(CSS)

        # CÃ¡c widget chÃ­nh tá»“n táº¡i suá»‘t vÃ²ng Ä‘á»i app. Khi login/logout chá»‰ reset
        # dá»¯ liá»‡u bÃªn trong, khÃ´ng táº¡o láº¡i toÃ n bá»™ window.
        self._stack    = QStackedWidget()
        self.setCentralWidget(self._stack)
        self._login    = LoginPage()
        self._chat     = ChatPage()
        self._register = RegisterPage()
        self._stack.addWidget(self._login)    # 0
        self._stack.addWidget(self._chat)     # 1
        self._stack.addWidget(self._register) # 2

        # Bá»™ Ä‘áº¿m tháº¿ há»‡ session. Má»—i láº§n login/logout tÄƒng má»™t láº§n Ä‘á»ƒ callback
        # tá»« WebSocket cÅ© khÃ´ng cÃ²n quyá»n cáº­p nháº­t UI/state cá»§a phiÃªn má»›i.
        self._session_gen = 0

        # State phiÃªn Ä‘Äƒng nháº­p. Pháº§n nháº¡y cáº£m náº±m trong CryptoSession vÃ  sáº½
        # Ä‘Æ°á»£c reset Ä‘á»“ng bá»™ á»Ÿ _init_session_state().
        self._ws: WSNet | None = None
        self._crypto = CryptoSession(logger=_logger)
        self._init_session_state()

        # Timer refresh tráº¡ng thÃ¡i báº¡n bÃ¨/inbox Ä‘á»‹nh ká»³.
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(5_000)
        self._poll_timer.timeout.connect(self._poll_status)

        # Debounce refresh inbox Ä‘á»ƒ khi nhiá»u event Ä‘áº¿n cÃ¹ng lÃºc chá»‰ gá»i server
        # má»™t láº§n sau khoáº£ng ngáº¯n, trÃ¡nh nháº¥p nhÃ¡y UI.
        self._inbox_refresh = QTimer(self)
        self._inbox_refresh.setSingleShot(True)
        self._inbox_refresh.timeout.connect(self._do_inbox_refresh)


        # Ná»‘i signal UI má»™t láº§n. CÃ¡c handler sau Ä‘Ã³ tá»± kiá»ƒm tra session hiá»‡n táº¡i
        # Ä‘á»ƒ trÃ¡nh xá»­ lÃ½ event tá»« phiÃªn Ä‘Ã£ logout.
        self._login.sig_login.connect(self._do_login)
        self._login.sig_go_register.connect(self._go_register)
        self._register.sig_register.connect(self._do_register)
        self._register.sig_back.connect(lambda: self._stack.setCurrentIndex(0))
        self._chat.sig_send.connect(self._send_message)
        self._chat.sig_send_reply.connect(self._send_reply_message)
        self._chat.sig_send_file.connect(self._send_file)
        self._chat.sig_history.connect(self._get_history)
        self._chat.sig_search.connect(self._search_user)
        self._chat.sig_friend_request.connect(self._friend_request)
        self._chat.sig_friend_accept.connect(self._friend_accept)
        self._chat.sig_friend_reject.connect(self._friend_reject)
        self._chat.sig_get_friends.connect(lambda: self._safe_send({"type": "get_friends"}))
        self._chat.sig_get_requests.connect(lambda: self._safe_send({"type": "get_requests"}))
        self._chat.sig_get_inbox.connect(lambda: self._safe_send({"type": "get_inbox"}))
        self._chat.sig_create_group.connect(self._create_group)
        self._chat.sig_add_to_group.connect(self._add_to_group)
        self._chat.sig_start_dm.connect(self._start_dm)
        self._chat.sig_unfriend.connect(self._unfriend)
        self._chat.sig_logout.connect(self._logout)
        self._chat.sig_change_password.connect(self._change_password)
        self._chat.sig_command.connect(self._handle_ui_command)
        self._chat.sig_clear_local_cache.connect(self._clear_local_message_cache)
        self._chat.sig_clear_conversation_cache.connect(
            self._clear_conversation_message_cache)
        self._chat.sig_update_cache_policy.connect(self._update_local_cache_policy)
        self._chat.sig_update_conversation_cache_policy.connect(
            self._update_conversation_cache_policy)
        # CÃ¡c thao tÃ¡c profile, inbox vÃ  chá»‰nh sá»­a message.
        self._chat.sig_view_profile.connect(self._view_profile)
        self._chat.sig_edit_profile.connect(self._edit_profile)
        self._chat.sig_disband_group.connect(self._disband_group)
        self._chat.sig_edit_message.connect(self._edit_message)
        self._chat.sig_delete_message.connect(self._delete_message)
        self._chat.sig_get_avatar.connect(self._fetch_avatar)
        # Má»Ÿ dialog xÃ¡c minh identity/safety number.
        self._chat.sig_verify_identity.connect(self._show_verify_dialog)
        self._chat.sig_rotate_identity.connect(self._rotate_identity)

        self._test_probe_timer = None
        self._init_test_probe()

    # ================================================================ test probe

    def _init_test_probe(self):
        """Khởi tạo cơ chế test-probe (chỉ dùng khi chạy kiểm thử tự động)."""
        if os.environ.get("SECCHAT_TEST_PROBE") != "1":
            return
        self._test_probe_path = os.environ.get(
            "SECCHAT_TEST_PROBE_PATH", "/tmp/secchat-ui-state.json")
        self._test_probe_command_path = os.environ.get(
            "SECCHAT_TEST_COMMAND_PATH", "/tmp/secchat-ui-command.json")
        interval = int(os.environ.get("SECCHAT_TEST_PROBE_INTERVAL_MS", "250") or "250")
        self._test_probe_timer = QTimer(self)
        self._test_probe_timer.setInterval(max(50, interval))
        self._test_probe_timer.timeout.connect(self._write_test_probe_snapshot)
        self._test_probe_timer.start()
        QTimer.singleShot(0, self._write_test_probe_snapshot)

    @staticmethod
    def _probe_json_safe(value):
        """(test probe) Chuyển một giá trị về dạng JSON an toàn để snapshot."""
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, (list, tuple, set)):
            return [App._probe_json_safe(v) for v in value]
        if isinstance(value, dict):
            return {
                str(k): App._probe_json_safe(v)
                for k, v in value.items()
                if isinstance(k, (str, int, float, bool))
            }
        return str(value)

    @staticmethod
    def _probe_text(widget):
        """(test probe) Trích text hiển thị của một widget."""
        if isinstance(widget, QLineEdit) and widget.echoMode() == QLineEdit.Password:
            return ""
        if isinstance(widget, QLineEdit):
            return widget.text()
        if isinstance(widget, QPlainTextEdit):
            return widget.toPlainText()
        if isinstance(widget, QComboBox):
            return widget.currentText()
        if hasattr(widget, "text"):
            return widget.text()
        return ""

    @staticmethod
    def _probe_geometry(widget):
        """(test probe) Trích hình học (vị trí/kích thước) của widget."""
        rect = widget.rect()
        top_left = widget.mapToGlobal(rect.topLeft())
        return {
            "x": int(top_left.x()),
            "y": int(top_left.y()),
            "w": int(rect.width()),
            "h": int(rect.height()),
            "cx": int(top_left.x() + rect.width() / 2),
            "cy": int(top_left.y() + rect.height() / 2),
        }

    def _probe_list_items(self, widget: QListWidget):
        """(test probe) Liệt kê các mục trong một list widget."""
        out = []
        for row in range(widget.count()):
            item = widget.item(row)
            item_rect = widget.visualItemRect(item)
            visible_rect = item_rect.intersected(widget.viewport().rect())
            rect = visible_rect if not visible_rect.isEmpty() else item_rect
            top_left = widget.viewport().mapToGlobal(rect.topLeft())
            data = {}
            for role_name, role in (
                ("user_role", Qt.UserRole),
                ("user_role_1", Qt.UserRole + 1),
                ("user_role_2", Qt.UserRole + 2),
                ("sidebar_text", Qt.UserRole + 40),
            ):
                try:
                    data[role_name] = self._probe_json_safe(item.data(role))
                except Exception:
                    data[role_name] = None
            logical_text = item.data(Qt.UserRole + 40)
            out.append({
                "row": row,
                "text": str(logical_text or item.text() or ""),
                "selected": item.isSelected(),
                "visible": not visible_rect.isEmpty(),
                "data": data,
                "geometry": {
                    "x": int(top_left.x()),
                    "y": int(top_left.y()),
                    "w": int(rect.width()),
                    "h": int(rect.height()),
                    "cx": int(top_left.x() + rect.width() / 2),
                    "cy": int(top_left.y() + rect.height() / 2),
                },
            })
        return out

    def _probe_widgets(self):
        """(test probe) Liệt kê các widget con phục vụ kiểm thử."""
        app = QApplication.instance()
        if app is None:
            return []
        out = []
        widget_types = (
            QPushButton, QLineEdit, QPlainTextEdit, QLabel, QListWidget,
            QCheckBox, QComboBox
        )
        for widget in app.allWidgets():
            if not isinstance(widget, widget_types):
                continue
            try:
                geo = self._probe_geometry(widget)
                if geo["w"] <= 0 or geo["h"] <= 0:
                    continue
                entry = {
                    "class": widget.__class__.__name__,
                    "object_name": widget.objectName(),
                    "testid": str(widget.property("testid") or ""),
                    "text": self._probe_text(widget),
                    "placeholder": (
                        widget.placeholderText()
                        if isinstance(widget, (QLineEdit, QPlainTextEdit)) else ""
                    ),
                    "visible": widget.isVisible(),
                    "enabled": widget.isEnabled(),
                    "geometry": geo,
                }
                if isinstance(widget, QListWidget):
                    entry["items"] = self._probe_list_items(widget)
                if isinstance(widget, QCheckBox):
                    entry["checked"] = widget.isChecked()
                if isinstance(widget, QComboBox):
                    entry["current_text"] = widget.currentText()
                    entry["count"] = widget.count()
                    entry["items"] = [
                        {
                            "row": i,
                            "text": widget.itemText(i),
                            "data": self._probe_json_safe(widget.itemData(i)),
                        }
                        for i in range(widget.count())
                    ]
                out.append(entry)
            except RuntimeError:
                continue
            except Exception as exc:
                out.append({"error": str(exc)})
        return out

    def _probe_message_texts(self):
        """(test probe) Lấy nội dung text các tin nhắn đang hiển thị."""
        labels = []
        try:
            content = self._chat.view.widget()
            for label in content.findChildren(QLabel):
                text = (label.text() or "").strip()
                if text and label.isVisible():
                    labels.append(text)
        except Exception:
            pass
        return labels

    def _probe_pending_bubbles(self):
        """(test probe) Lấy danh sách bong bóng tin đang chờ gửi."""
        out = []
        try:
            for conv_id, messages in (self._chat.hist or {}).items():
                for msg in messages:
                    if msg.get("sending") or msg.get("failed"):
                        out.append({
                            "conv_id": int(conv_id),
                            "msg_id": int(msg.get("msg_id", 0) or 0),
                            "body": str(msg.get("body", "")),
                            "sending": bool(msg.get("sending")),
                            "failed": bool(msg.get("failed")),
                            "failure_reason": str(msg.get("failure_reason", "") or ""),
                        })
        except Exception:
            pass
        return out

    def _probe_chat_state(self):
        """(test probe) Chụp trạng thái khung chat hiện tại."""
        chat = self._chat
        return {
            "me": chat.me,
            "my_id": int(chat.my_id or 0),
            "current_view": chat.current_view,
            "active_conv_id": int(chat.active_conv_id or 0),
            "pending_requests_count": int(getattr(chat, "_pending_requests_count", 0) or 0),
            "unread_conv_ids": sorted(int(x) for x in getattr(chat, "_unread_convs", set())),
            "header": chat.lbl_chat.text(),
            "presence": chat.lbl_chat_presence.text(),
            "typing": chat.lbl_typing.text(),
            "cache_state": chat.lbl_cache_state.text(),
            "consistency": chat.lbl_consistency.text(),
            "security_guide": chat.lbl_security_guide.text(),
            "message_texts": self._probe_message_texts(),
            "pending_error_bubbles": self._probe_pending_bubbles(),
            "security_warnings": self._probe_json_safe(getattr(chat, "_security_warnings", {})),
            "conversation_security": self._probe_json_safe(getattr(chat, "_conv_security", {})),
            "double_ratchet_ready_conv_ids": sorted(
                int(cid) for cid in getattr(self, "_double_ratchet_states", {}).keys()),
            "pqxdh_publish_blocked": bool(getattr(self, "_pqxdh_publish_blocked", False)),
            "pqxdh_bundle_ready": bool(getattr(self, "_pqxdh_bundle_ready", False)),
            "pqxdh_bundle_upload_pending": bool(
                getattr(self, "_pending_pqxdh_bundle_upload", False)),
            "kem_ready": bool(getattr(self, "_kem_ready", False)),
            "pending_pqxdh_dm": self._probe_json_safe(
                getattr(self, "_pending_pqxdh_dm", {})),
            "mls_identity_ready": bool(
                getattr(self._crypto_session(), "mls_identity_ready", False)),
            "mls_group_ready_conv_ids": sorted(
                int(cid) for cid in getattr(
                    self._crypto_session(), "mls_group_ready", set())),
            "pending_mls_prepare": self._probe_json_safe(
                getattr(self, "_pending_mls_prepare", [])),
            "pending_mls_ops": self._probe_json_safe(
                getattr(self, "_pending_mls_ops", {})),
            "pending_mls_claims": self._probe_json_safe(
                getattr(self, "_pending_mls_claims", {})),
        }

    def _test_probe_snapshot(self):
        """(test probe) Dựng snapshot tổng hợp trạng thái UI."""
        page_map = {0: "login", 1: "chat", 2: "register"}
        geo = self._probe_geometry(self)
        return {
            "probe_version": 1,
            "timestamp": time.time(),
            "current_page": page_map.get(self._stack.currentIndex(), "unknown"),
            "session_active": bool(getattr(self, "_session_active", False)),
            "window": {
                "title": self.windowTitle(),
                "geometry": geo,
                "visible": self.isVisible(),
                "enabled": self.isEnabled(),
            },
            "login_status": self._login.lbl_status.text(),
            "register_status": self._register.lbl_status.text(),
            "chat": self._probe_chat_state(),
            "widgets": self._probe_widgets(),
        }

    def _write_test_probe_snapshot(self):
        """(test probe) Ghi snapshot trạng thái ra tệp cho test đọc."""
        if os.environ.get("SECCHAT_TEST_PROBE") != "1":
            return
        try:
            self._consume_test_probe_command()
            snapshot = self._test_probe_snapshot()
            path = self._test_probe_path
            directory = os.path.dirname(path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            tmp_path = f"{path}.tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, ensure_ascii=False, sort_keys=True)
            os.replace(tmp_path, path)
        except Exception:
            _logger.exception("failed to write UI test probe snapshot")

    def _consume_test_probe_command(self):
        """(test probe) Đọc và thực thi lệnh điều khiển từ test."""
        path = getattr(self, "_test_probe_command_path", "")
        if not path or not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                command = json.load(f)
            try:
                os.remove(path)
            except OSError:
                pass
            if not isinstance(command, dict):
                return
            typ = str(command.get("type", ""))
            if typ == "open_conversation":
                conv_id = int(command.get("conversation_id", 0) or 0)
                if conv_id > 0:
                    self._chat._switch_to_conv(
                        conv_id, bool(command.get("is_group", False)))
            elif typ == "start_dm":
                user_id = int(command.get("user_id", 0) or 0)
                if user_id > 0:
                    self._chat.sig_start_dm.emit(user_id)
        except Exception:
            _logger.exception("failed to consume UI test probe command")

    # ================================================================ session state

    def _init_session_state(self):
        """ÄÆ°a toÃ n bá»™ state runtime vá» máº·c Ä‘á»‹nh khi login/logout.

        HÃ m nÃ y khÃ´ng chá»‰ xÃ³a biáº¿n UI mÃ  cÃ²n reset CryptoSession trong RAM. CÃ¡c
        file local Ä‘Ã£ mÃ£ hÃ³a trÃªn Ä‘Ä©a khÃ´ng bá»‹ xÃ³a, trá»« khi user chá»§ Ä‘á»™ng xÃ³a
        cache hoáº·c state.
        """
        self._crypto_session().reset()
        self._pending          = None     # action Ä‘ang chá» auth/register
        self._pending_password = ""
        self._account_username = ""
        self._auth_credential  = ""
        self._last_host        = ""
        self._last_port        = 0
        self._last_auth_email  = ""
        self._last_auth_pw_hash = ""
        self._reconnect_attempts = 0
        self._password_change_pending = None
        self._master_key       = None     # master key dáº«n xuáº¥t tá»« máº­t kháº©u
        self._kem_ready        = False
        self._pending_kem_queue = []      # [(conv_id, uid)] Ä‘ang chá» key/bundle
        self._pending_messages  = []      # message Ä‘áº¿n trÆ°á»›c khi cÃ³ key giáº£i mÃ£
        self._pending_edits     = []      # edit event Ä‘áº¿n trÆ°á»›c khi cÃ³ key/target
        self._inbox_conv_ids    = []      # conv_id trong inbox má»›i nháº¥t
        self._inbox_loaded      = False
        self._session_active    = False   # True khi Ä‘Ã£ Ä‘Äƒng nháº­p thÃ nh cÃ´ng
        self._profile_edit_mode = False   # Ä‘ang chá» profile cá»§a chÃ­nh mÃ¬nh Ä‘á»ƒ edit
        self._identity_rotation_pending = False
        self._server_identity_pk = ""
        self._avatar_fetch_uids = set()   # user_ids pending silent avatar fetch
        self._auditor_url = default_auditor_url()
        self._conv_fingerprints = {}      # conv_id -> safety number text
        # State phá»¥ trá»£ cho group E2EE. Secret group tháº­t náº±m trong CryptoSession;
        # cÃ¡c map á»Ÿ Ä‘Ã¢y chá»‰ phá»¥c vá»¥ Ä‘iá»u phá»‘i UI/server event.
        self._group_conv_ids        = set()  # conv_id cá»§a cÃ¡c group
        self._pending_create_members = {}    # group_name -> member uid vá»«a chá»n
        self._group_members_cache = {}        # conv_id -> danh sÃ¡ch member/role
        # Runtime crypto fields are properties backed by CryptoSession; App keeps
        # short names for UI coordination only.
        self._my_uid          = 0    # user_id cá»§a chÃ­nh mÃ¬nh sau khi login
        self._secchat_dir     = ""   # thÆ° má»¥c ~/.secchat/{username}/
        self._conv_peer_uids  = {}   # conv_id -> user_id Ä‘á»‘i phÆ°Æ¡ng trong DM
        # â”€â”€ Group key epoch tracking (post-compromise security on member changes) â”€â”€
        self._group_epochs    = {}   # conv_id -> epoch group hiá»‡n táº¡i
        # â”€â”€ Identity verification (safety numbers) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        self._conv_verified   = {}     # verified flag cá»¥c bá»™ theo conversation
        # Ed25519 long-term identity key signs PQXDH and MLS material.
        self._identity_pk     = b''    # Ed25519 identity public key
        self._identity_sk     = b''    # Ed25519 identity secret key
        # â”€â”€ Message deduplication cache â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        self._seen_msg_ids    = {}     # chá»‘ng duplicate khi server echo/history
        # â”€â”€ Self-echo handling â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        # Server broadcast láº¡i message cho chÃ­nh sender. Client khÃ´ng Ä‘Æ°á»£c giáº£i
        # mÃ£ echo cá»§a chÃ­nh mÃ¬nh báº±ng receive ratchet, vÃ¬ nhÆ° váº­y sáº½ lÃ m lá»‡ch
        # counter nháº­n. Thay vÃ o Ä‘Ã³ plaintext Ä‘Ã£ gá»­i Ä‘Æ°á»£c giá»¯ trong FIFO ngáº¯n Ä‘á»ƒ
        # thay tháº¿ pending bubble khi echo cÃ³ id tháº­t tá»« server.
        self._self_pending_plaintexts = {}   # conv_id -> deque[plaintext]
        self._self_pending_ids = {}          # conv_id -> deque[negative UI msg_id]
        # State SecChat. Private prekey, Double Ratchet va MLS group state deu
        # Ä‘Æ°á»£c lÆ°u mÃ£ hÃ³a dÆ°á»›i CryptoSession; App chá»‰ giá»¯ queue Ä‘iá»u phá»‘i.
        self._pqxdh_prekeys = None              # bundle/private prekey local
        self._double_ratchet_states = {}              # conv_id -> DoubleRatchet
        self._pending_pqxdh_dm = {}             # peer_uid -> conv_id
        self._pqxdh_bundle_ready = False
        self._pending_pqxdh_bundle_upload = False
        self._pqxdh_publish_blocked = False
        self._mls_key_packages_ready = False
        self._pending_mls_ops = {}            # operation_id -> pending MLS group operation
        self._pending_mls_claims = {}         # target_uid -> [operation_id]
        self._pending_mls_prepare = []        # queued UI intents waiting for prepare response
        self._expected_group_membership_change = set()
        self._manual_group_info_requests = set()
        self._last_transcript_checkpoint = {} # conv_id -> má»‘c gá»­i checkpoint gáº§n nháº¥t
        self._own_identity_version = 0

    # ================================================================ safe send

    def _safe_send(self, obj: dict):
        """Gá»­i JSON náº¿u WebSocket cá»§a phiÃªn hiá»‡n táº¡i cÃ²n sá»‘ng."""
        if self._session_active and self._ws:
            try:
                self._ws.send(obj)
                return True
            except Exception:
                return False
        return False

    def _mls_debug(self, event: str, **fields) -> None:
        """Ghi log debug cho luồng MLS (khi bật cờ debug)."""
        if os.environ.get("SECCHAT_TEST_PROBE") != "1":
            return
        safe = {k: self._probe_json_safe(v) for k, v in fields.items()}
        try:
            with open("/tmp/secchat-mls-debug.log", "a", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "ts": time.time(),
                    "event": event,
                    **safe,
                }, ensure_ascii=False, sort_keys=True) + "\n")
        except Exception:
            pass

    def _handle_ui_command(self, obj: dict):
        """Send UI commands and route group changes through OpenMLS prepare/apply.

        For membership or group-info changes, the UI intent is saved until the
        server returns a prepared operation. The client then creates the OpenMLS
        Commit/Welcome/GroupInfo or encrypted control message and applies it.
        """
        t = str(obj.get("type", ""))
        group_id = int(obj.get("group_id", obj.get("conversation_id", 0)) or 0)
        if group_id > 0 and t == "get_group_info":
            self._manual_group_info_requests.add(group_id)
        if group_id > 0 and t in (
                "remove_member", "set_member_role", "update_group_info", "leave_group"):
            op = t
            target_uid = int(obj.get("user_id", 0) or 0)
            if op == "leave_group":
                target_uid = int(self._my_uid or 0)
            intent = {
                "operation": op,
                "conversation_id": group_id,
                "target_user_id": target_uid,
                "role": str(obj.get("role", "") or ""),
                "name": str(obj.get("name", "") or ""),
                "description": str(obj.get("description", "") or ""),
            }
            self._pending_mls_prepare.append(intent)
            prepare = {
                "type": "prepare_group_change",
                "operation": op,
                "conversation_id": group_id,
            }
            if target_uid > 0:
                prepare["user_id"] = target_uid
            if intent["role"]:
                prepare["role"] = intent["role"]
            if op == "update_group_info":
                prepare["name"] = intent["name"]
                prepare["description"] = intent["description"]
            return self._safe_send(prepare)
        ok = self._safe_send(obj)
        if ok and t in (
                "mute_conversation", "archive_conversation", "pin_conversation",
                "mark_unread", "mark_read", "set_disappearing"):
            self._inbox_refresh.start(500)
        return ok

    @staticmethod
    def _group_info_intent_hash(obj: dict) -> str:
        """Táº¡o hash ngáº¯n cho pháº§n group info mÃ  user Ä‘á»‹nh sá»­a."""
        raw = json.dumps({
            "name": str(obj.get("name", "") or ""),
            "description": str(obj.get("description", "") or ""),
        }, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        import hashlib
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def _normalize_group_members(members_or_ids) -> list[dict]:
        """Chuáº©n hÃ³a member list vá» dáº¡ng á»•n Ä‘á»‹nh Ä‘á»ƒ hash/kÃ½ commit."""
        out = {}
        names = {}
        for item in members_or_ids or []:
            if isinstance(item, dict):
                uid = int(item.get("user_id", item.get("id", 0)) or 0)
                role = str(item.get("role", "member") or "member")
                username = str(
                    item.get("username", "")
                    or item.get("name", "")
                    or item.get("display_name", "")
                    or ""
                )
            else:
                uid = int(item or 0)
                role = "member"
                username = ""
            if uid <= 0:
                continue
            if role not in ("admin", "member"):
                role = "member"
            out[uid] = "admin" if out.get(uid) == "admin" or role == "admin" else role
            if username and uid not in names:
                names[uid] = username
        result = []
        for uid in sorted(out):
            item = {"user_id": uid, "role": out[uid]}
            if names.get(uid):
                item["username"] = names[uid]
            result.append(item)
        return result

    @staticmethod
    def _role_for_member(members, uid: int) -> str:
        """Trả vai trò (admin/member) của uid trong danh sách thành viên group."""
        uid = int(uid or 0)
        for member in App._normalize_group_members(members):
            if int(member.get("user_id", 0) or 0) == uid:
                return str(member.get("role", "member") or "member")
        return ""

    def _members_after_from_event(self, group_id: int, msg: dict,
                                  *, fallback_ids=None) -> list[dict]:
        """Láº¥y danh sÃ¡ch member sau thay Ä‘á»•i tá»« server event hoáº·c cache."""
        members = msg.get("members")
        if isinstance(members, list) and members:
            normalized = self._normalize_group_members(members)
            target_uid = int(msg.get("user_id", 0) or 0)
            target_name = str(msg.get("username", "") or msg.get("target_username", "") or "")
            if target_uid > 0 and target_name:
                for member in normalized:
                    if int(member.get("user_id", 0) or 0) == target_uid:
                        member["username"] = target_name
                        break
            return normalized
        ids = msg.get("member_ids", fallback_ids or [])
        cached = {
            int(m.get("user_id", 0) or 0): m
            for m in self._group_members_cache.get(int(group_id), [])
        }
        out = []
        for uid in ids or []:
            try:
                uid_i = int(uid)
            except Exception:
                continue
            if uid_i > 0:
                cached_member = cached.get(uid_i, {})
                entry = {
                    "user_id": uid_i,
                    "role": str(cached_member.get("role", "member") or "member"),
                }
                if cached_member.get("username"):
                    entry["username"] = str(cached_member.get("username"))
                out.append(entry)
        return self._normalize_group_members(out)

    def _display_name_for_user(self, group_id: int, uid: int,
                               msg: dict | None = None,
                               *, username_field: str = "username") -> str:
        """Tên hiển thị của một uid (ưu tiên cache thành viên/bạn bè)."""
        uid = int(uid or 0)
        if uid <= 0:
            return ""
        if msg:
            direct = str(msg.get(username_field, "") or "")
            if direct:
                return direct
            for key in ("username", "target_username"):
                direct = str(msg.get(key, "") or "")
                if direct:
                    return direct
            for member in msg.get("members") or []:
                try:
                    if int(member.get("user_id", member.get("id", 0)) or 0) == uid:
                        name = str(member.get("username", "") or member.get("name", "") or "")
                        if name:
                            return name
                except Exception:
                    continue
        for member in self._group_members_cache.get(int(group_id), []):
            if int(member.get("user_id", 0) or 0) == uid:
                name = str(member.get("username", "") or member.get("name", "") or "")
                if name:
                    return name
        friend = getattr(self._chat, "friends", {}).get(uid, {})
        name = str(friend.get("username", "") or friend.get("name", "") or "")
        return name or f"User#{uid}"

    @staticmethod
    def _membership_event_key(event_type: str, target_uid: int, role: str,
                              operation_id: str):
        """Khóa khử trùng lặp cho một event thay đổi thành viên group."""
        operation_id = str(operation_id or "")
        if not operation_id:
            return None
        return (str(event_type), int(target_uid or 0), str(role or ""), operation_id)

    def _system_event_kwargs(self, msg: dict) -> dict:
        """Dựng tham số để lưu/hiển thị một system event của group."""
        out = {}
        try:
            sid = int(msg.get("system_event_id", msg.get("id", 0)) or 0)
        except Exception:
            sid = 0
        try:
            after_id = int(msg.get("after_message_id", 0) or 0)
        except Exception:
            after_id = 0
        if sid > 0:
            out["system_event_id"] = sid
        if after_id > 0:
            out["after_message_id"] = after_id
        ts = ts_short(msg.get("event_time", msg.get("time", "")))
        if ts:
            out["ts"] = ts
        return out

    def _group_system_event_key(self, msg: dict):
        """Khóa định danh duy nhất cho một system event group."""
        event_type = str(msg.get("event_type", msg.get("type", "")) or "")
        uid = int(msg.get("user_id", msg.get("target_user_id", 0)) or 0)
        role = str(msg.get("role", "") or "")
        operation_id = str(msg.get("operation_id", "") or "")
        if event_type in ("member_left", "member_removed"):
            return self._membership_event_key(
                "member_removed", uid, "", operation_id)
        if event_type == "member_added":
            return self._membership_event_key(
                "member_added", uid, "", operation_id)
        if event_type == "member_role_changed":
            return self._membership_event_key(
                "member_role_changed", uid, role, operation_id)
        if event_type == "group_info_updated":
            return self._membership_event_key(
                "group_info_updated", 0, "", operation_id)
        return self._membership_event_key(event_type, uid, role, operation_id)

    def _group_system_event_text(self, group_id: int, msg: dict) -> str:
        """Dựng câu mô tả cho một system event group ("X đã vào nhóm"...) để hiển thị."""
        event_type = str(msg.get("event_type", msg.get("type", "")) or "")
        uid = int(msg.get("user_id", msg.get("target_user_id", 0)) or 0)
        actor_uid = int(msg.get("by_user_id", msg.get("actor_id", 0)) or 0)
        who = (
            "You" if uid == int(self._my_uid or 0)
            else self._display_name_for_user(group_id, uid, msg)
        )
        actor = str(msg.get("by_username", "") or "")
        if not actor and actor_uid > 0 and actor_uid != uid:
            actor = self._display_name_for_user(
                group_id, actor_uid, msg, username_field="by_username")
        if event_type == "member_added":
            if uid == int(self._my_uid or 0):
                return f"{actor or 'Someone'} added you to the group."
            return f"{who} joined the group."
        if event_type == "member_left":
            return "You left the group." if uid == int(self._my_uid or 0) else f"{who} left the group."
        if event_type == "member_removed":
            if uid == int(self._my_uid or 0):
                return "You were removed from the group."
            return f"{who} was removed from the group."
        if event_type == "member_role_changed":
            role = str(msg.get("role", "") or "member")
            role_text = "admin" if role == "admin" else "member"
            if actor and actor != who:
                return f"{actor} made {who} {role_text}."
            return f"{who} was made {role_text}."
        if event_type == "group_info_updated":
            return "Group info was updated."
        return ""

    def _prepare_group_system_events_for_history(self, group_id: int,
                                                 events: list) -> list[dict]:
        """Chuẩn hóa các system event group khi nạp lịch sử."""
        prepared = []
        for raw in events or []:
            if not isinstance(raw, dict):
                continue
            item = dict(raw)
            members_after = self._members_after_from_event(group_id, item)
            if members_after:
                self._group_members_cache[int(group_id)] = members_after
            text = self._group_system_event_text(group_id, item)
            if not text:
                continue
            item["text"] = text
            item["event_key"] = self._group_system_event_key(item)
            prepared.append(item)
        return prepared

    def _members_before_for_change(self, group_id: int, after_members: list[dict],
                                   operation: str, target_uid: int,
                                   target_role: str = "member") -> list[dict]:
        """Æ¯á»›c lÆ°á»£ng member list trÆ°á»›c thay Ä‘á»•i khi server chá»‰ gá»­i state sau."""
        cached = self._group_members_cache.get(int(group_id))
        if cached:
            return self._normalize_group_members(cached)
        before = self._normalize_group_members(after_members)
        target_uid = int(target_uid or 0)
        if operation == "add_member":
            before = [m for m in before if int(m.get("user_id", 0) or 0) != target_uid]
        elif operation in ("remove_member", "member_left") and target_uid > 0:
            if not self._role_for_member(before, target_uid):
                before.append({
                    "user_id": target_uid,
                    "role": target_role if target_role in ("admin", "member") else "member",
                })
        return self._normalize_group_members(before)

    # ================================================================ login / register

    def _go_register(self):
        """Chuyá»ƒn sang trang Ä‘Äƒng kÃ½ vÃ  giá»¯ nguyÃªn host/port tá»« trang login."""
        self._register.e_host.setText(self._login.e_host.text())
        self._register.e_port.setText(self._login.e_port.text())
        self._stack.setCurrentIndex(2)

    def _do_login(self, host: str, port: int, email: str, pw_hash: str):
        """Bắt đầu đăng nhập: mở kết nối WebSocket rồi gửi gói ``auth`` với pw_hash."""
        self._teardown_ws()
        self._init_session_state()
        self._session_gen += 1
        self._last_host = host
        self._last_port = int(port)
        self._last_auth_email = email
        self._last_auth_pw_hash = pw_hash
        self._pending          = {"action": "login", "email": email, "pw_hash": pw_hash}
        self._pending_password = self._login.e_pw.text()
        self._setup_ws()
        self._ws.connect_async(host, port)

    def _do_register(self, host: str, port: int, username: str, email: str, pw_hash: str):
        """Bắt đầu đăng ký: mở kết nối rồi gửi gói ``register`` (sau đó tự đăng nhập)."""
        self._teardown_ws()
        self._init_session_state()
        self._session_gen += 1
        self._last_host = host
        self._last_port = int(port)
        self._last_auth_email = email
        self._last_auth_pw_hash = pw_hash
        self._pending = {"action": "register", "username": username,
                         "email": email, "pw_hash": pw_hash}
        self._pending_password = self._register.e_pw.text()
        self._setup_ws()
        self._ws.connect_async(host, port)

    # ================================================================ WebSocket lifecycle

    def _setup_ws(self):
        """Táº¡o WebSocket má»›i vÃ  ná»‘i callback cho phiÃªn hiá»‡n táº¡i."""
        self._ws = WSNet()
        self._ws.on_open.connect(self._net_open)
        self._ws.on_close.connect(self._net_close)
        self._ws.on_msg.connect(self._net_msg)

    def _teardown_ws(self):
        """ÄÃ³ng WebSocket hiá»‡n táº¡i vÃ  ngáº¯t callback Ä‘á»ƒ trÃ¡nh event phiÃªn cÅ©."""
        self._poll_timer.stop()
        self._inbox_refresh.stop()
        if self._ws is None:
            return
        old = self._ws
        self._ws = None            # cháº·n callback cÅ© tÃ¡c Ä‘á»™ng lÃªn phiÃªn má»›i
        try: old.on_open.disconnect()
        except TypeError: pass
        try: old.on_close.disconnect()
        except TypeError: pass
        try: old.on_msg.disconnect()
        except TypeError: pass
        try: old.disconnect()
        except Exception: pass

    def _net_open(self):
        if not self._pending or not self._ws:
            return
        # á»ž bÆ°á»›c auth/register chÆ°a cÃ³ session active, nÃªn pháº£i gá»­i trá»±c tiáº¿p
        # qua _ws thay vÃ¬ _safe_send().
        action = self._pending["action"]
        if action in ("login", "reconnect"):
            self._ws.send({
                "type":     "auth",
                "email":    self._pending["email"],
                "password": self._pending["pw_hash"],
            })
        else:  # register
            self._ws.send({
                "type":     "register",
                "username": self._pending["username"],
                "email":    self._pending["email"],
                "password": self._pending["pw_hash"],
            })

    def _net_close(self, reason: str):
        # Bá» qua close event tá»« WebSocket Ä‘Ã£ bá»‹ teardown.
        if not self._ws:
            return
        cur = self._stack.currentIndex()
        if cur == 0:
            self._login.set_status(reason)
        elif cur == 2:
            self._register.set_status(reason)
        else:
            # Äang á»Ÿ chat mÃ  máº¥t káº¿t ná»‘i: dá»«ng poll Ä‘á»ƒ UI khÃ´ng gá»­i request ná»¯a.
            self._session_active = False
            self._poll_timer.stop()
            self._inbox_refresh.stop()
            if hasattr(self._chat, "mark_pending_sends_failed"):
                self._chat.mark_pending_sends_failed(
                    "Connection was interrupted. Retry after SecChat reconnects.")
            self._schedule_reconnect(reason)

    def _schedule_reconnect(self, reason: str = ""):
        """Lên lịch thử kết nối lại sau khi rớt mạng (có backoff giữa các lần)."""
        if not self._last_host or not self._last_port or not self._last_auth_pw_hash:
            return
        if self.__dict__.get("_reconnect_scheduled", False):
            return
        self._reconnect_scheduled = True
        self._chat.show_security_warning(
            int(self._chat.active_conv_id or 0),
            "Connection was interrupted. SecChat will reconnect automatically; "
            "failed messages can be retried after reconnect.",
        )
        delay = min(10_000, 1500 + int(self.__dict__.get("_reconnect_attempts", 0)) * 1000)
        QTimer.singleShot(delay, self._attempt_reconnect)

    def _attempt_reconnect(self):
        """Thử kết nối lại tới server và đăng nhập lại bằng credential đã lưu trong phiên."""
        self._reconnect_scheduled = False
        if self._session_active or self._stack.currentIndex() != 1:
            return
        if not self._last_host or not self._last_port or not self._last_auth_pw_hash:
            return
        self._reconnect_attempts = int(self.__dict__.get("_reconnect_attempts", 0)) + 1
        self._pending = {
            "action": "reconnect",
            "email": self._last_auth_email or self._auth_credential,
            "pw_hash": self._last_auth_pw_hash,
        }
        self._teardown_ws()
        self._setup_ws()
        self._ws.connect_async(self._last_host, self._last_port)

    def _net_msg(self, msg: dict):
        # Bá» qua message tá»« socket cÅ© sau khi logout/reconnect.
        if not self._ws:
            return
        t = msg.get("type", "")
        handler = self._MSG_HANDLERS.get(t)
        if handler:
            try:
                handler(self, msg)
            except Exception:
                _logger.exception("Unhandled error in message handler for type=%r", t)

    # ================================================================ message handlers

    def _handle_ok(self, msg):
        """Xử lý response "ok" chung từ server (diễn giải theo nội dung msg)."""
        if msg.get("msg") == "PQXDH bundle uploaded":
            self._pending_pqxdh_bundle_upload = False
            self._pqxdh_publish_blocked = False
            self._pqxdh_bundle_ready = True
            self._kem_ready = True
            self._drain_pending_key_requests()
            return
        if msg.get("msg") in ("Avatar uploaded", "Avatar removed"):
            try:
                uid = int(self._my_uid or 0)
                self._chat._avatar_paths.pop(uid, None)
                self._chat._avatar_pending.discard(uid)
                self._fetch_avatar(uid)
                self._safe_send({"type": "get_friends"})
                self._safe_send({"type": "get_inbox"})
            except Exception:
                pass
            return
        if self._password_change_pending and msg.get("msg") == "Password changed successfully":
            self._complete_password_change()
            return
        if (self.__dict__.get("_identity_rotation_pending")
                and msg.get("msg") == "Identity rotated"):
            self._identity_rotation_pending = False
            self._pqxdh_publish_blocked = False
            self._server_identity_pk = (
                base64.b64encode(self._identity_pk).decode()
                if self._identity_pk else ""
            )
            if (self._load_pqxdh_prekeys() is not None
                    and not self.__dict__.get("_pending_pqxdh_bundle_upload")
                    and not self.__dict__.get("_pqxdh_bundle_ready")):
                self._publish_fresh_pqxdh_bundle_for_current_device()
            QMessageBox.information(
                self._chat, "Safety Key",
                "Your safety key was rotated. Existing contacts will see a "
                "safety number change and should verify you again.",
            )
            return

        if not self._pending:
            return
        action = self._pending["action"]

        if action == "reconnect":
            self._session_active = True
            self._reconnect_attempts = 0
            self._pending = None
            self._chat.show_security_warning(0, [])
            self._safe_send({"type": "get_friends"})
            self._safe_send({"type": "get_requests"})
            self._safe_send({"type": "get_inbox"})
            self._poll_timer.start()
            return

        cur = self._stack.currentIndex()
        # Chá»‰ xá»­ lÃ½ ok tá»« trang login/register. Khi Ä‘ang á»Ÿ chat, nhiá»u ok chá»‰
        # lÃ  xÃ¡c nháº­n thao tÃ¡c nhá» nhÆ° gá»­i request nÃªn khÃ´ng Ä‘á»•i mÃ n hÃ¬nh.
        if cur not in (0, 2):
            return

        if action == "register":
            # Register only creates the account on the server. The client keeps
            # the same socket and immediately sends auth so the user lands in
            # the product without retyping credentials.
            email = self._pending.get("email", "")
            pw_hash = self._pending.get("pw_hash", "")
            self._pending = {"action": "login", "email": email, "pw_hash": pw_hash}
            self._register.set_status("Registration successful. Logging in...", ok=True)
            if self._ws:
                self._ws.send({
                    "type": "auth",
                    "email": email,
                    "password": pw_hash,
                })
            return

        # Login thÃ nh cÃ´ng. Pháº£i dÃ¹ng username tháº­t server tráº£ vá» Ä‘á»ƒ derive
        # master key; náº¿u user nháº­p email, master key váº«n pháº£i giá»‘ng khi há» nháº­p
        # username á»Ÿ láº§n Ä‘Äƒng nháº­p khÃ¡c.
        actual_username = msg.get("username", self._pending.get("email", ""))
        self._master_key       = derive_master_key(self._pending_password, actual_username)
        self._account_username = actual_username
        self._auth_credential  = self._pending.get("email", "")
        self._pending_password = ""
        self._session_active   = True
        self._pending          = None
        uid = msg.get("user_id", 0)
        self._my_uid = uid
        # ThÆ° má»¥c local riÃªng cá»§a account Ä‘á»ƒ lÆ°u ratchet/cache/identity state.
        self._secchat_dir = os.path.join(
            os.path.expanduser("~"), ".secchat", actual_username)
        try:
            os.makedirs(self._secchat_dir, exist_ok=True)
        except OSError:
            pass
        self._chat.reset()
        self._chat.set_me(actual_username, uid)
        self._chat.show_security_warning(0, [])
        self._crypto_session().load_cache_policy()
        self._crypto_session().enforce_cache_policy()
        self._chat.set_cache_policy(self._crypto_session().get_cache_policy())
        self._stack.setCurrentIndex(1)

        # Báº¯t Ä‘áº§u náº¡p key, danh sÃ¡ch báº¡n bÃ¨ vÃ  inbox.
        self._safe_send({"type": "get_my_keys"})
        self._safe_send({"type": "get_friends"})
        self._safe_send({"type": "get_requests"})
        self._safe_send({"type": "get_inbox"})

        # Báº¯t Ä‘áº§u refresh Ä‘á»‹nh ká»³ sau khi session active.
        self._poll_timer.start()
        # Kiá»ƒm tra tuá»•i khÃ³a ná»n; khÃ´ng tá»± rotate identity trong im láº·ng.

    def _handle_error(self, msg):
        """Xử lý response "error" từ server: hiển thị thông báo phù hợp cho người dùng."""
        text = msg.get("msg", "Error")
        if text == "Invalid credentials":
            text = "Email or password is incorrect"
        if text == "No PQXDH bundle found":
            peer_uid = int(msg.get("user_id", 0) or 0)
            conv_id = int(self._pending_pqxdh_dm.pop(peer_uid, 0) or 0)
            if conv_id > 0:
                self._chat.show_security_warning(
                    conv_id,
                    "This contact has not published SecChat encryption keys yet. "
                    "Ask them to log in once, then retry the conversation.",
                )
            text = (
                "This contact has not published encryption keys yet. "
                "Ask them to log in once, then try again."
            )
        if (text == "Identity change requires rotate_identity"
                and self.__dict__.get("_pending_pqxdh_bundle_upload")):
            self._pending_pqxdh_bundle_upload = False
            self._pqxdh_bundle_ready = False
            self._kem_ready = False
            self._pqxdh_publish_blocked = True
            QMessageBox.warning(
                self._chat,
                "Key Publishing Failed",
                "This account already has a different safety key on the server, "
                "but this VNC does not have the encrypted identity backup needed "
                "to publish a matching SecChat bundle.\n\n"
                "Log in once on the VNC that still has the account cache so it "
                "can backfill the identity backup, restore an E2EE backup here, "
                "or rotate the safety key deliberately.",
            )
            return
        if (self.__dict__.get("_pending_pqxdh_bundle_upload")
                and text in ("Invalid PQXDH bundle", "Failed to upload PQXDH bundle")):
            self._pending_pqxdh_bundle_upload = False
            self._pqxdh_bundle_ready = False
            self._kem_ready = False
            self._pqxdh_publish_blocked = True
            QMessageBox.warning(
                self._chat,
                "Key Publishing Failed",
                "This VNC could not publish a fresh SecChat key bundle for "
                f"the current account:\n{text}\n\n"
                "Restore an E2EE backup here or rotate the safety key deliberately "
                "before starting new encrypted conversations from this VNC.",
            )
            return
        if self._password_change_pending:
            self._password_change_pending = None
            QMessageBox.warning(self._chat, "Change Password", text)
            return
        if self.__dict__.get("_identity_rotation_pending"):
            self._identity_rotation_pending = False
            QMessageBox.warning(self._chat, "Safety Key", text)
            return
        cur = self._stack.currentIndex()
        send_error_fragments = (
            "Cannot send message",
            "Not a member of this conversation",
            "Group has been disbanded",
            "Rate limit exceeded",
            "Message body is empty or too large",
            "Unsupported or unsupported encrypted message",
        )
        if cur == 1 and any(fragment in text for fragment in send_error_fragments):
            try:
                self._chat.mark_pending_sends_failed(text)
            except Exception:
                pass
        if cur == 0:
            self._login.set_status(text)
        elif cur == 2:
            self._register.set_status(text)
        else:
            QMessageBox.warning(self._chat, "Error", text)

    def _handle_session_replaced(self, msg):
        text = str(msg.get("msg", "") or "This account signed in on another device.")
        self._logout_local(notify_server=False, status=text)

    def _handle_friends_list(self, msg):
        """Nhận danh sách bạn bè từ server và cập nhật sidebar."""
        self._chat.update_friends(msg.get("friends", []))

    def _handle_friend_requests(self, msg):
        """Nhận danh sách lời mời kết bạn đang chờ và cập nhật UI."""
        self._chat.update_requests(msg.get("requests", []))

    @staticmethod
    def _preview_plaintext(body: str) -> str:
        """RÃºt gá»n plaintext Ä‘á»ƒ hiá»ƒn thá»‹ preview trong inbox/pins."""
        if body.startswith("__SYSTEM__:"):
            return body[len("__SYSTEM__:"):].strip()
        if body.startswith("FILE:"):
            return "[File]"
        if body.startswith("SCMSG:1:"):
            try:
                raw = body[len("SCMSG:1:"):]
                pad = "=" * (-len(raw) % 4)
                meta = json.loads(
                    base64.urlsafe_b64decode((raw + pad).encode("ascii"))
                    .decode("utf-8")
                )
                inner = str(meta.get("body", body))
                return "[File]" if inner.startswith("FILE:") else inner
            except Exception:
                return body
        return body

    @staticmethod
    def _is_secure_control_wire(body: str) -> bool:
        """Nháº­n diá»‡n wire ``S3MLS`` chá»‰ lÃ  control, khÃ´ng pháº£i tin chat."""
        if not isinstance(body, str) or not body.startswith(WIRE_PREFIX_MLS):
            return False
        try:
            payload = protocol_json_unb64(body[len(WIRE_PREFIX_MLS):])
        except Exception:
            return False
        return (payload.get("event") or payload.get("kind")) in {
            "commit", "welcome", "transcript_checkpoint",
        }

    def _latest_visible_preview(self, conv_id: int) -> str:
        """Láº¥y preview Ä‘á»c Ä‘Æ°á»£c gáº§n nháº¥t tá»« history UI/cache cá»§a conversation."""
        for item in reversed(self._chat.hist.get(int(conv_id), [])):
            if item.get("hidden"):
                continue
            if item.get("deleted"):
                continue
            body = str(item.get("body", "") or "")
            if not body or body in ("__KEM_INIT__", "__S2_CONTROL__", "__S3_INIT__"):
                continue
            if body.startswith("__SYSTEM__:"):
                return self._preview_plaintext(body)
            if body.startswith("[Encrypted") or body.startswith("[Cannot"):
                continue
            return self._preview_plaintext(body)
        return ""

    def _handle_inbox(self, msg):
        """Chuáº©n hÃ³a inbox server tráº£ vá» trÆ°á»›c khi Ä‘Æ°a vÃ o sidebar.

        Server chá»‰ lÆ°u ciphertext nÃªn preview Æ°u tiÃªn láº¥y plaintext Ä‘Ã£ cache
        sau khi client tá»«ng giáº£i mÃ£ message.
        """
        all_convs   = msg.get("conversations", [])
        dm_convs    = [c for c in all_convs if not c.get("is_group", False)]
        group_convs = [c for c in all_convs if c.get("is_group", False)]
        my_uid = int(getattr(self, "_my_uid", 0) or 0)

        for c in dm_convs + group_convs:
            c["conversation_id"] = int(c["conversation_id"])
            conv_id  = c["conversation_id"]
            if not c.get("is_group", False):
                peer_uid = int(
                    c.get("with_user_id", 0)
                    or c.get("other_id", 0)
                    or c.get("user_id", 0)
                    or c.get("friend_id", 0)
                    or 0
                )
                c["with_user_id"] = peer_uid
                c["user_id"] = peer_uid
            is_saved = False
            if (my_uid > 0 and not c.get("is_group", False)
                    and int(c.get("with_user_id", 0) or 0) == my_uid):
                c["hidden"] = True
                continue
            # Chuáº©n hÃ³a field riÃªng cá»§a group Ä‘á»ƒ ChatPage khÃ´ng pháº£i Ä‘oÃ¡n kiá»ƒu.
            if c.get("is_group"):
                c["creator_id"]   = int(c.get("creator_id", 0) or 0)
                c["is_disbanded"] = bool(c.get("is_disbanded", False))
            last_msg = c.get("last_message", "")
            last_id  = int(c.get("last_message_id", 0) or 0)
            last_sender_id = int(c.get("last_sender_id", 0) or 0)
            c["last_message_id"] = last_id
            c["last_sender_id"] = last_sender_id
            if not c.get("is_group", False) and not is_saved:
                peer_uid = int(c.get("with_user_id", 0) or 0)
                if peer_uid > 0 and peer_uid != my_uid:
                    self._conv_peer_uids[conv_id] = peer_uid
            if last_msg.startswith("__SYSTEM__:"):
                c["last_message"] = self._preview_plaintext(last_msg)
            elif self._is_secure_control_wire(last_msg):
                c["last_message"] = self._latest_visible_preview(conv_id)
                if not c["last_message"]:
                    c["unread_count"] = 0
            elif (last_msg.startswith(WIRE_PREFIX_PQ_INIT)
                  or last_msg.startswith(WIRE_PREFIX_DR)
                  or last_msg.startswith(WIRE_PREFIX_MLS)):
                hit = self._load_cached_messages(conv_id).get(last_id) if last_id else None
                if hit:
                    pt = self._crypto_session().unpack_plaintext(hit.get("body", ""))
                    c["last_message"] = self._preview_plaintext(pt)
                else:
                    c["last_message"] = ""
                    if last_msg.startswith(WIRE_PREFIX_PQ_INIT):
                        c["unread_count"] = 0
            elif last_msg.startswith("FILE:"):
                c["last_message"] = "[File]"

        # Ghi danh sÃ¡ch conv hiá»‡n cÃ³ vÃ  thá»­ khÃ´i phá»¥c key cÃ²n thiáº¿u.
        dm_convs = [c for c in dm_convs if not c.get("hidden")]
        self._inbox_conv_ids = [c["conversation_id"] for c in dm_convs + group_convs]
        self._group_conv_ids = {c["conversation_id"] for c in group_convs}
        self._inbox_loaded = True

        self._chat.update_inbox(dm_convs, group_convs)
        for conv_id in self._inbox_conv_ids:
            try:
                self._refresh_security_ui(conv_id)
            except Exception:
                pass
        pending = self._chat._pending_open_conv
        if pending:
            self._chat._pending_open_conv = None
            is_group = bool(getattr(
                self._chat, "_pending_open_is_group",
                pending in self._group_conv_ids,
            ))
            self._chat._pending_open_is_group = False
            self._chat._switch_to_conv(pending, is_group=is_group)

    def _handle_search_result(self, msg):
        self._chat.update_search_results(msg.get("users", []))

    # Message pipeline
    #
    # Server gá»­i cÃ¹ng má»™t event cho message live, offline queue vÃ  self echo.
    # Controller Ä‘Æ°a event vÃ o CryptoSession Ä‘á»ƒ phÃ¢n loáº¡i/giáº£i mÃ£, sau Ä‘Ã³ má»›i
    # quyáº¿t Ä‘á»‹nh render, queue láº¡i hay fetch key cÃ²n thiáº¿u.

    def _handle_message(self, msg):
        """Xá»­ lÃ½ má»™t message event tá»« server."""
        conv_id = int(msg.get("conversation_id", 0) or 0)
        sender_id = int(
            msg.get("from_id", 0)
            or msg.get("sender_id", 0)
            or 0
        )
        msg_id = int(msg.get("id", 0) or 0)

        seen = self._seen_msg_ids.setdefault(conv_id, set()) if msg_id else None
        if msg_id:
            if msg_id in seen:
                return

        def mark_seen() -> None:
            if not msg_id or seen is None:
                return
            seen.add(msg_id)
            if len(seen) > 10_000:
                while len(seen) > 9_000:
                    seen.pop()

        result = self._crypto_session().decrypt_live_message(msg)
        status = result.get("status")
        if status == "pending":
            if not any(
                    int(p.get("id", 0) or 0) == msg_id and msg_id > 0
                    for p in self._pending_messages):
                self._pending_messages.append(msg)
            return
        if status == "hidden":
            mark_seen()
            self._inbox_refresh.start(500)
            return
        mark_seen()
        if status == "control":
            warnings = self._crypto_session().pop_control_warnings(conv_id)
            if warnings:
                self._chat.show_security_warning(conv_id, warnings)
            if result.get("peer_uid"):
                self._conv_peer_uids[conv_id] = int(result.get("peer_uid", 0) or 0)
            if result.get("peer_identity_pk"):
                self._record_incoming_pq_identity(conv_id, result)
            if result.get("fingerprint"):
                self._conv_fingerprints[conv_id] = result["fingerprint"]
                verified = self._conv_verified.get(conv_id, False)
                if conv_id == self._chat.active_conv_id:
                    fp = self._safety_fingerprint_for_conv(conv_id) or result["fingerprint"]
                    self._chat.set_fingerprint(fp, verified=verified)
                try:
                    self._refresh_security_ui(conv_id)
                except Exception:
                    pass
            if result.get("ready"):
                self._flush_pending(conv_id)
                self._inbox_refresh.start(500)
            return
        if result.get("peer_uid"):
            self._conv_peer_uids[conv_id] = int(result.get("peer_uid", 0) or 0)
        if result.get("peer_identity_pk"):
            self._record_incoming_pq_identity(conv_id, result)
        if status == "self_echo":
            queue = self._self_pending_plaintexts.get(conv_id)
            body = queue.popleft() if queue else "[message sent]"
            id_queue = self.__dict__.setdefault("_self_pending_ids", {}).get(conv_id)
            pending_id = id_queue.popleft() if id_queue else 0
            self._chat.remove_pending_send(conv_id, body, pending_id=pending_id)
        else:
            body = result.get("body", msg.get("body", ""))

        ts = ts_short(msg.get("time", ""))
        self._handle_decrypted_message(msg, conv_id, sender_id, body, ts, msg_id)
        if status != "self_echo":
            self._safe_send({"type": "get_friends"})
        self._inbox_refresh.start(500)

    def _handle_decrypted_message(self, raw_msg, conv_id: int, sender_id: int,
                                  body: str, ts: str, msg_id: int):
        """Render message Ä‘Ã£ giáº£i mÃ£, cáº­p nháº­t cache vÃ  transcript."""
        body = self._crypto_session().unpack_plaintext(body)
        edit_target = int(raw_msg.get("edit_target_message_id", 0) or 0)
        is_plain = (
            body != "[message sent]"
            and not body.startswith("[ðŸ”")
            and not body.startswith("[ðŸ”")
            and not body.startswith("[Cannot")
            and not body.startswith("[Encrypted")
        )
        if edit_target > 0:
            updated = self._chat.apply_edit_event(
                conv_id, edit_target, body, sender_id, ts)
            if msg_id > 0:
                self._crypto_session().record_transcript_message(
                    conv_id, msg_id, sender_id, body,
                    raw_msg.get("time", ts),
                    edit_target_message_id=edit_target,
                    deleted=bool(raw_msg.get("deleted", False)))
            if is_plain:
                self._cache_message(conv_id, msg_id, sender_id, body, ts)
                if updated:
                    self._cache_message(conv_id, edit_target, sender_id, body, ts)
            self._maybe_send_transcript_checkpoint(conv_id)
            return

        self._chat.add_msg(
            conv_id, sender_id, body, ts, msg_id,
            pinned=bool(raw_msg.get("pinned", False)),
            reactions=raw_msg.get("reactions", []),
            forwarded_from_id=int(raw_msg.get("forwarded_from_id", 0) or 0),
            reply_to_message_id=int(raw_msg.get("reply_to_message_id", 0) or 0),
        )
        if msg_id > 0:
            self._crypto_session().record_transcript_message(
                conv_id, msg_id, sender_id, body,
                raw_msg.get("time", ts),
                deleted=bool(raw_msg.get("deleted", False)))
        if is_plain:
            self._cache_message(conv_id, msg_id, sender_id, body, ts)
        self._maybe_send_transcript_checkpoint(conv_id)

    def _maybe_send_transcript_checkpoint(self, conv_id: int, *, force: bool = False):
        """Gá»­i checkpoint transcript group theo nhá»‹p Ä‘á»ƒ so sÃ¡nh view giá»¯a client."""
        conv_id = int(conv_id or 0)
        if conv_id <= 0 or conv_id not in self._group_conv_ids:
            return
        if not self._identity_sk or not self._identity_pk:
            return
        now = time.monotonic()
        if "_last_transcript_checkpoint" not in self.__dict__:
            self._last_transcript_checkpoint = {}
        last = float(self._last_transcript_checkpoint.get(conv_id, 0.0) or 0.0)
        if not force and now - last < 5.0:
            return
        try:
            wire = self._crypto_session().create_transcript_checkpoint(conv_id)
        except Exception as exc:
            _logger.warning(
                "transcript checkpoint create failed conv=%s: %s", conv_id, exc)
            return
        if not wire:
            return
        if self._safe_send({
            "type": "message",
            "conversation_id": conv_id,
            "body": wire,
        }):
            self._last_transcript_checkpoint[conv_id] = now

    def _flush_pending(self, conv_id: int):
        """Thá»­ xá»­ lÃ½ láº¡i cÃ¡c message tá»«ng bá»‹ queue vÃ¬ thiáº¿u key."""
        remaining = []
        for m in self._pending_messages:
            if int(m.get("conversation_id", 0)) == conv_id:
                self._handle_message(m)
            else:
                remaining.append(m)
        self._pending_messages = remaining

    def _flush_pending_edits(self, conv_id: int):
        """Thá»­ xá»­ lÃ½ láº¡i edit event tá»«ng bá»‹ queue vÃ¬ thiáº¿u key/target."""
        remaining = []
        for m in self._pending_edits:
            if int(m.get("conversation_id", 0)) == conv_id:
                self._handle_message_edited(m)
            else:
                remaining.append(m)
        self._pending_edits = remaining

    def _handle_history(self, msg):
        """Giáº£i mÃ£ history Ä‘áº§y Ä‘á»§ rá»“i merge vÃ o UI.

        ÄÃ¢y lÃ  nguá»“n authoritative cho pinned/reactions/edited/deleted. Live
        message nháº­n lÃºc offline cÃ³ thá»ƒ tá»›i trÆ°á»›c history; ChatPage sáº½ merge theo
        message id Ä‘á»ƒ khÃ´ng máº¥t tin cÅ© vÃ  khÃ´ng duplicate tin offline.
        """
        conv_id = int(msg.get("conversation_id", 0) or 0)
        messages = msg.get("messages", [])
        messages = self._crypto_session().decrypt_history_messages(conv_id, messages)
        control_warnings = self._crypto_session().pop_control_warnings(conv_id)
        if control_warnings:
            self._chat.show_security_warning(conv_id, control_warnings)
        warnings = self._crypto_session().verify_history_consistency(
            conv_id, messages)
        if warnings:
            self._chat.show_security_warning(conv_id, warnings)

        for m in messages:
            mid_seen = int(m.get("id", 0) or 0)
            if mid_seen:
                seen = self._seen_msg_ids.setdefault(conv_id, set())
                seen.add(mid_seen)
                if len(seen) > 10_000:
                    while len(seen) > 9_000:
                        seen.pop()
            edit_target = int(m.get("edit_target_message_id", 0) or 0)
            plain = m.get("body", "")
            if (edit_target and plain and plain != "[Forward-secret]"
                    and not plain.startswith("[Cannot")
                    and not plain.startswith("[Encrypted")):
                self._cache_message(
                    conv_id, edit_target, int(m.get("sender_id", 0) or 0),
                    plain, ts_short(m.get("time", "")))

        system_events = self._prepare_group_system_events_for_history(
            conv_id, msg.get("system_events", []))
        self._chat.load_history(conv_id, messages, system_events)
        if conv_id == self._chat.active_conv_id:
            if self._is_group_conv(conv_id):
                self._chat.set_fingerprint("", verified=False)
            else:
                fp = self._safety_fingerprint_for_conv(conv_id)
                self._chat.set_fingerprint(fp, verified=self._load_verified(conv_id))
            self._refresh_security_ui(conv_id)
        self._maybe_send_transcript_checkpoint(conv_id, force=True)
        self._inbox_refresh.start(500)


    # Social/group events

    def _handle_friend_request_received(self, msg):
        """Nhận event có lời mời kết bạn mới → refresh danh sách requests."""
        self._safe_send({"type": "get_requests"})
        self._chat.notify_friend_request(msg.get("from", "Someone"))

    def _handle_friend_accepted(self, msg):
        """Nhận event lời mời được chấp nhận → refresh danh sách bạn bè."""
        self._safe_send({"type": "get_friends"})
        self._safe_send({"type": "get_inbox"})

    @staticmethod
    def _mls_group_id_b64(conv_id: int) -> str:
        """Mã hóa base64 group id MLS tất định từ conv_id (khớp với bridge Rust)."""
        raw = f"secchat-group:{int(conv_id)}".encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    def _pop_pending_mls_prepare(self, operation: str, conversation_id: int,
                                 target_user_id: int = 0) -> dict:
        """Lấy ra và xóa một thao tác group MLS đang chờ server prepare."""
        for idx, item in enumerate(list(self._pending_mls_prepare)):
            if str(item.get("operation", "")) != str(operation):
                continue
            conv = int(item.get("conversation_id", 0) or 0)
            target = int(item.get("target_user_id", 0) or 0)
            if conversation_id and conv and conv != int(conversation_id):
                continue
            if target_user_id and target and target != int(target_user_id):
                continue
            return self._pending_mls_prepare.pop(idx)
        return {"operation": operation, "conversation_id": conversation_id,
                "target_user_id": target_user_id}

    def _queue_mls_claim(self, operation_id: str, user_id: int) -> None:
        """Xếp hàng việc claim KeyPackage cho một thành viên sắp được add vào group."""
        user_id = int(user_id or 0)
        if user_id <= 0:
            return
        self._pending_mls_claims.setdefault(user_id, []).append(operation_id)
        self._mls_debug("claim_key_package_send", operation_id=operation_id,
                        user_id=user_id)
        self._safe_send({"type": "claim_mls_key_package", "user_id": user_id})

    def _handle_group_change_prepared(self, msg):
        """Server đã prepare thay đổi group → client tạo commit MLS tương ứng."""
        operation_id = str(msg.get("operation_id", "") or "")
        operation = str(msg.get("operation", "") or "")
        conv_id = int(msg.get("conversation_id", 0) or 0)
        target_uid = int(msg.get("target_user_id", 0) or 0)
        self._mls_debug("prepared_received", msg=msg)
        if not operation_id or not operation or conv_id <= 0:
            return
        intent = self._pop_pending_mls_prepare(operation, conv_id, target_uid)
        self._mls_debug("prepared_intent", operation_id=operation_id,
                        operation=operation, conv_id=conv_id, intent=intent)
        ctx = {
            "operation_id": operation_id,
            "operation": operation,
            "conversation_id": conv_id,
            "target_user_id": target_uid,
            "intent": intent,
            "targets": [],
            "claimed": {},
            "group_id_b64": self._mls_group_id_b64(conv_id),
        }
        self._pending_mls_ops[operation_id] = ctx
        try:
            if operation == "create_group":
                created = self._crypto_session().create_mls_group(conv_id)
                self._mls_debug("create_group_local", operation_id=operation_id,
                                conv_id=conv_id, created=created)
                ctx["group_id_b64"] = str(
                    created.get("group_id_b64", ctx["group_id_b64"]) or ctx["group_id_b64"])
                targets = [int(uid) for uid in intent.get("members", []) if int(uid) > 0]
                ctx["targets"] = targets
                if not targets:
                    self._apply_mls_group_op(ctx)
                    return
                for uid in targets:
                    self._queue_mls_claim(operation_id, uid)
                return
            if operation == "add_member":
                target = int(target_uid or intent.get("target_user_id", 0) or 0)
                ctx["targets"] = [target] if target > 0 else []
                if target > 0:
                    self._queue_mls_claim(operation_id, target)
                return
            if operation in ("remove_member", "leave_group"):
                target = int(target_uid or intent.get("target_user_id", 0) or self._my_uid)
                result = self._crypto_session().remove_mls_members(conv_id, [target])
                ctx.update(result)
                self._apply_mls_group_op(ctx)
                return
            if operation in ("set_member_role", "update_group_info"):
                control = {
                    "operation": operation,
                    "conversation_id": conv_id,
                    "target_user_id": target_uid,
                    "role": str(intent.get("role", "") or msg.get("role", "") or ""),
                    "name": str(intent.get("name", "") or ""),
                    "description": str(intent.get("description", "") or ""),
                    "actor_uid": int(self._my_uid or 0),
                    "ts": int(time.time() * 1000),
                }
                ctx["control_b64"] = self._crypto_session().mls_control_message_b64(
                    conv_id, control)
                self._apply_mls_group_op(ctx)
        except Exception as exc:
            self._pending_mls_ops.pop(operation_id, None)
            _logger.warning("MLS group operation prepare failed: %s", exc)
            self._chat.show_security_warning(
                conv_id,
                f"MLS group operation failed before apply: {exc}",
            )

    def _handle_mls_key_package(self, msg):
        """Nhận một KeyPackage MLS đã claim cho thành viên sắp thêm."""
        user_id = int(msg.get("user_id", 0) or 0)
        self._mls_debug("key_package_received", user_id=user_id,
                        found=bool(msg.get("found")),
                        has_key_package=bool(msg.get("key_package_b64")))
        op_ids = self._pending_mls_claims.get(user_id, [])
        if not op_ids:
            return
        operation_id = op_ids.pop(0)
        if not op_ids:
            self._pending_mls_claims.pop(user_id, None)
        ctx = self._pending_mls_ops.get(operation_id)
        if not ctx:
            return
        if not msg.get("found"):
            self._pending_mls_ops.pop(operation_id, None)
            self._chat.show_security_warning(
                int(ctx.get("conversation_id", 0) or 0),
                f"User {user_id} has no available MLS KeyPackage. Ask them to log in once.",
            )
            return
        ctx.setdefault("claimed", {})[user_id] = str(
            msg.get("key_package_b64", "") or "")
        self._finalize_mls_claimed_op(ctx)

    def _finalize_mls_claimed_op(self, ctx: dict) -> None:
        """Hoàn tất thao tác group sau khi đã claim đủ KeyPackage."""
        targets = [int(uid) for uid in ctx.get("targets", []) if int(uid) > 0]
        claimed = ctx.get("claimed", {})
        if any(uid not in claimed for uid in targets):
            return
        conv_id = int(ctx.get("conversation_id", 0) or 0)
        try:
            result = self._crypto_session().add_mls_members(
                conv_id, [claimed[uid] for uid in targets])
            self._mls_debug("add_members_local", operation_id=ctx.get("operation_id"),
                            conv_id=conv_id, targets=targets, result=result)
            ctx.update(result)
            welcome = str(result.get("welcome_b64", "") or "")
            if welcome:
                ctx["welcomes"] = [
                    {"target_user_id": uid, "welcome_b64": welcome}
                    for uid in targets
                ]
            self._apply_mls_group_op(ctx)
        except Exception as exc:
            self._pending_mls_ops.pop(str(ctx.get("operation_id", "")), None)
            _logger.warning("MLS add-members failed: %s", exc)
            self._chat.show_security_warning(
                conv_id,
                f"MLS add-member failed: {exc}",
            )

    def _apply_mls_group_op(self, ctx: dict) -> None:
        """Áp dụng một thao tác MLS (add/remove/update) vào group cục bộ."""
        operation_id = str(ctx.get("operation_id", "") or "")
        conv_id = int(ctx.get("conversation_id", 0) or 0)
        if not operation_id or conv_id <= 0:
            return
        payload = {
            "type": "apply_group_change",
            "operation_id": operation_id,
            "conversation_id": conv_id,
            "group_id_b64": str(ctx.get("group_id_b64", "") or self._mls_group_id_b64(conv_id)),
            "epoch": int(ctx.get("epoch", self._group_epochs.get(conv_id, 0)) or 0),
        }
        for key in ("commit_b64", "group_info_b64", "ratchet_tree_b64", "control_b64"):
            if ctx.get(key):
                payload[key] = ctx[key]
        welcomes = ctx.get("welcomes") or []
        if welcomes:
            payload["welcomes"] = welcomes
        self._mls_debug("apply_group_change_send", payload={
            k: ("<bytes>" if k.endswith("_b64") else v)
            for k, v in payload.items()
        })
        self._safe_send(payload)

    def _handle_group_change_applied(self, msg):
        """Server xác nhận đã áp thay đổi group → cập nhật trạng thái cục bộ."""
        self._mls_debug("applied_received", msg=msg)
        operation_id = str(msg.get("operation_id", "") or "")
        ctx = self._pending_mls_ops.pop(operation_id, {}) if operation_id else {}
        conv_id = int(msg.get("conversation_id", ctx.get("conversation_id", 0)) or 0)
        if conv_id > 0:
            self._group_conv_ids.add(conv_id)
            self._safe_send({"type": "get_mls_handshake", "conversation_id": conv_id})
            self._safe_send({"type": "get_group_info", "group_id": conv_id})
        self._safe_send({"type": "get_inbox"})

    def _handle_mls_handshake(self, msg):
        """Nhận handshake MLS (commit/welcome) từ server và xử lý."""
        conv_id = int(msg.get("conversation_id", 0) or 0)
        if conv_id <= 0:
            return
        items = msg.get("items", [])
        self._mls_debug("handshake_received", conv_id=conv_id,
                        count=len(items or []))
        self._crypto_session().process_mls_handshake_items(conv_id, items)
        self._group_conv_ids.add(conv_id)
        if conv_id == self._chat.active_conv_id:
            self._safe_send({"type": "history", "conversation_id": conv_id})
        self._flush_pending(conv_id)

    def _handle_mls_key_packages_uploaded(self, msg):
        """Xác nhận đã upload KeyPackage MLS lên server."""
        self._mls_key_packages_ready = True

    def _handle_group_created(self, msg):
        """Server confirms that a group change was applied after an MLS Commit."""
        conv_id = int(msg.get("conversation_id", 0))
        name = msg.get("name", "")

        if conv_id > 0:
            self._group_conv_ids.add(conv_id)
            members = self._pending_create_members.pop(name, [])
            if members:
                self._group_members_cache[conv_id] = self._normalize_group_members(
                    [{"user_id": self._my_uid, "role": "admin"}]
                    + [{"user_id": int(uid), "role": "member"} for uid in members])
            self._chat._pending_open_conv = conv_id
            self._chat._pending_open_is_group = True
            self._safe_send({"type": "get_mls_handshake", "conversation_id": conv_id})
        self._safe_send({"type": "get_inbox"})
    def _handle_dm_ready(self, msg):
        """Server Ä‘Ã£ táº¡o hoáº·c tÃ¬m tháº¥y DM, báº¯t Ä‘áº§u/khÃ´i phá»¥c key exchange náº¿u cáº§n.

        Náº¿u Double Ratchet state Ä‘Ã£ tá»“n táº¡i, khÃ´ng cháº¡y láº¡i PQXDH vÃ¬ Ä‘iá»u Ä‘Ã³ sáº½
        ghi Ä‘Ã¨ state cÅ© vÃ  lÃ m tin offline tá»« chain cÅ© khÃ´ng giáº£i mÃ£ Ä‘Æ°á»£c.
        """
        conv_id  = int(msg.get("conversation_id", 0))
        with_uid = int(msg.get("with_user_id", 0))
        if conv_id > 0 and with_uid > 0 and with_uid != int(self._my_uid or 0):
            self._conv_peer_uids[conv_id] = with_uid
        self._safe_send({"type": "get_inbox"})
        self._chat._pending_open_conv = conv_id
        self._chat._pending_open_is_group = False

        # DM cÅ© pháº£i dÃ¹ng láº¡i Double Ratchet state Ä‘Ã£ lÆ°u. Cháº¡y PQXDH láº¡i
        # cho cÃ¹ng conversation sáº½ ghi Ä‘Ã¨ dr_*.bin vÃ  lÃ m máº¥t kháº£ nÄƒng giáº£i mÃ£
        # tin offline thuá»™c chain cÅ©.
        if conv_id > 0 and with_uid > 0 and self._load_double_ratchet(conv_id) is not None:
            return
        if self.__dict__.get("_pqxdh_publish_blocked"):
            self._chat.show_security_warning(
                conv_id,
                "This VNC cannot publish a matching SecChat key bundle for "
                "this account yet. Restore an E2EE backup on this VNC or rotate "
                "the safety key deliberately before starting a new encrypted DM segment.",
            )
            return

        if conv_id > 0 and with_uid > 0:
            self._pending_pqxdh_dm[with_uid] = conv_id
            if self._kem_ready:
                self._safe_send({"type": "get_pqxdh_bundle", "user_id": with_uid})
            else:
                self._pending_kem_queue.append((conv_id, with_uid))

    def _handle_added_to_group(self, msg):
        """Member má»›i nháº­n event Ä‘Æ°á»£c thÃªm vÃ o group."""
        conv_id = int(msg.get("conversation_id", 0))
        self._group_conv_ids.add(conv_id)
        if conv_id > 0:
            by_name = str(msg.get("by_username", "") or msg.get("by", "") or "Someone")
            if hasattr(self._chat, "add_system_event"):
                self._chat.add_system_event(
                    conv_id,
                    f"{by_name} added you to the group.",
                    event_key=self._membership_event_key(
                        "member_added", int(self._my_uid or 0), "",
                        str(msg.get("operation_id", "") or "")),
                    **self._system_event_kwargs(msg),
                )
            self._expected_group_membership_change.add(conv_id)
            members_after = self._members_after_from_event(conv_id, msg)
            if members_after:
                self._group_members_cache[conv_id] = members_after
            self._safe_send({"type": "get_mls_handshake", "conversation_id": conv_id})
            self._safe_send({"type": "get_group_info", "group_id": conv_id})
        self._safe_send({"type": "get_inbox"})

    def _handle_member_added(self, msg):
        """Refresh UI after an MLS add-member operation has been applied."""
        group_id = int(msg.get("group_id", 0))
        new_uid = int(msg.get("user_id", 0))
        if group_id <= 0:
            return
        self._expected_group_membership_change.add(group_id)
        self._group_conv_ids.add(group_id)
        members_after = self._members_after_from_event(
            group_id, msg, fallback_ids=msg.get("member_ids", []) or [new_uid])
        if members_after:
            self._group_members_cache[group_id] = members_after
        added_name = self._display_name_for_user(group_id, new_uid, msg)
        if (hasattr(self._chat, "add_system_event")
                and new_uid > 0
                and new_uid != int(self._my_uid or 0)):
            self._chat.add_system_event(
                group_id,
                f"{added_name} joined the group.",
                event_key=self._membership_event_key(
                    "member_added", new_uid, "",
                    str(msg.get("operation_id", "") or "")),
                **self._system_event_kwargs(msg),
            )
        self._safe_send({"type": "get_mls_handshake", "conversation_id": group_id})
        self._safe_send({"type": "get_group_info", "group_id": group_id})
        self._safe_send({"type": "get_inbox"})
    def _handle_friend_removed(self, msg):
        self._safe_send({"type": "get_friends"})
        self._safe_send({"type": "get_inbox"})

    # Profile and account settings

    def _handle_profile(self, msg):
        """Äá»‹nh tuyáº¿n profile server tráº£ vá»: cache avatar, edit own profile hoáº·c view contact."""
        uid      = int(msg.get("user_id", 0))
        username = msg.get("username", "")

        # 1. Silent avatar fetch: chá»‰ cáº­p nháº­t cache avatar, khÃ´ng má»Ÿ dialog.
        if uid in self._avatar_fetch_uids:
            self._avatar_fetch_uids.discard(uid)
            b64 = msg.get("avatar_b64", "") or ""
            self._chat.set_user_avatar(uid, b64, username)
            # Náº¿u cÅ©ng Ä‘ang edit own profile, tiáº¿p tá»¥c má»Ÿ dialog edit.
            if not self._profile_edit_mode:
                return

        # 2. Edit own profile.
        if self._profile_edit_mode:
            self._profile_edit_mode = False
            self._show_edit_profile_dialog(msg)
            return

        # 3. Xem profile ngÆ°á»i khÃ¡c, kÃ¨m lá»‹ch sá»­ audit identity náº¿u cÃ³.
        if uid > 0:
            enriched = dict(msg)
            enriched["identity_audit"] = self._crypto_session().load_identity_audit(uid)
            try:
                enriched["auditor_identity_history"] = fetch_identity_history(
                    self._auditor_url, uid)
            except Exception:
                pass
            msg = enriched
        self._chat.show_profile(msg)

    def _show_edit_profile_dialog(self, profile: dict):
        """Mở dialog chỉnh sửa hồ sơ cá nhân."""
        from PyQt5.QtWidgets import QDialog
        from client.dialogs import ProfileEditDialog
        enriched = dict(profile)
        enriched["backup_status"] = self._crypto_session().get_backup_status()
        dlg = ProfileEditDialog(enriched, self._chat)
        if dlg.exec_() != QDialog.Accepted:
            return
        action = dlg.get_requested_action()
        if action == "change_password":
            self._chat._show_change_password()
            return
        if action == "privacy":
            self._safe_send({"type": "get_privacy"})
            return
        if action == "blocked":
            self._safe_send({"type": "get_blocked_list"})
            return
        if action == "rotate_identity":
            self._rotate_identity()
            return
        if action == "export_backup":
            self._export_e2ee_backup()
            return
        if action == "restore_backup":
            self._restore_e2ee_backup()
            return
        if action == "backup_status":
            self._show_backup_status()
            return
        if action == "revoke_backups":
            self._revoke_local_backups()
            return
        display_name, bio, avatar_data, avatar_mime, remove_av = dlg.get_result()
        # Always save text fields (even if unchanged â€” server is idempotent)
        self._safe_send({
            "type":         "update_profile",
            "display_name": display_name,
            "bio":          bio,
        })
        if remove_av:
            self._safe_send({"type": "remove_avatar"})
        elif avatar_data:
            self._safe_send({
                "type": "upload_avatar",
                "data": base64.b64encode(avatar_data).decode(),
                "mime": avatar_mime,
            })

    # Broadcast handlers: cÃ¡c event server phÃ¡t cho nhiá»u client sau má»™t thao tÃ¡c
    # nhÆ° edit/delete/pin/reaction/group update.

    def _handle_message_edited(self, msg):
        """Nhận event chỉnh sửa tin và cập nhật UI/cache."""
        conv_id  = int(msg.get("conversation_id", 0))
        msg_id   = int(msg.get("id", 0))
        new_body = msg.get("new_body", "")
        updated = self._chat.update_message(
            conv_id, msg_id, new_body, edited=True, deleted=False)
        if not new_body.startswith("[Cannot"):
            sender_id = int(msg.get("from_id", 0) or 0)
            if not sender_id and updated:
                sender_id = int(updated.get("sender_id", 0) or 0)
            ts = ts_short(msg.get("time", ""))
            if not ts and updated:
                ts = updated.get("ts", "")
            self._cache_message(
                conv_id, msg_id, sender_id, new_body, ts)
        self._inbox_refresh.start(500)

    def _handle_message_deleted(self, msg):
        """Nhận event tin nhắn bị xóa → cập nhật UI và cache."""
        conv_id = int(msg.get("conversation_id", 0))
        msg_id  = int(msg.get("id", 0))
        self._chat.update_message(conv_id, msg_id, "", edited=False, deleted=True)
        self._inbox_refresh.start(500)

    def _handle_group_disbanded(self, msg):
        """Nhận event group bị giải tán → gỡ khỏi danh sách."""
        conv_id = int(msg.get("conversation_id", 0))
        self._chat.mark_group_disbanded(conv_id)
        self._cleanup_conv_state(conv_id)
        self._inbox_refresh.start(500)

    def _handle_profile_updated(self, msg):
        """Báº¡n bÃ¨ cáº­p nháº­t profile: refresh danh sÃ¡ch vÃ  avatar cache."""
        self._safe_send({"type": "get_friends"})
        uid = int(msg.get("user_id", 0))
        if uid > 0:
            # Bá» pending Ä‘á»ƒ _fetch_avatar Ä‘Æ°á»£c phÃ©p táº£i láº¡i avatar má»›i.
            self._chat._avatar_pending.discard(uid)
            self._fetch_avatar(uid)

    # Key exchange, identity audit and security UI

    def _handle_privacy_settings(self, msg):
        """Nhận thiết lập quyền riêng tư từ server và mở dialog cấu hình."""
        self._chat.show_privacy_settings(msg)

    def _handle_blocked_list(self, msg):
        """Nhận danh sách người bị chặn và hiển thị."""
        self._chat.show_blocked_list(msg.get("users", []))

    def _handle_group_info(self, msg):
        """Nháº­n group info vÃ  kiá»ƒm tra membership consistency.

        Request ná»™i bá»™ chá»‰ sync cache/state. Chá»‰ request do user báº¥m má»›i má»Ÿ
        dialog group info Ä‘á»ƒ trÃ¡nh popup báº¥t ngá» trÃªn mÃ¡y member Ä‘Æ°á»£c add.
        """
        group_id = int(msg.get("group_id", 0) or 0)
        show_dialog = False
        if group_id > 0:
            show_dialog = group_id in self._manual_group_info_requests
            self._manual_group_info_requests.discard(group_id)
            expected = group_id in self._expected_group_membership_change
            members = msg.get("members", [])
            warnings = self._crypto_session().verify_group_membership(
                group_id, members, expected_change=expected)
            self._expected_group_membership_change.discard(group_id)
            if warnings:
                self._chat.show_security_warning(group_id, warnings)
            if members:
                self._group_members_cache[group_id] = self._normalize_group_members(members)
        if show_dialog:
            self._chat.show_group_info(msg)

    def _handle_pinned_messages(self, msg):
        """Nhận danh sách tin được ghim của hội thoại."""
        conv_id = int(msg.get("conversation_id", 0))
        cached = self._load_cached_messages(conv_id)
        messages = []
        for raw in msg.get("messages", []):
            item = dict(raw)
            body = item.get("body", "")
            mid = int(item.get("message_id", 0) or 0)
            if (body.startswith(WIRE_PREFIX_PQ_INIT)
                  or body.startswith(WIRE_PREFIX_DR)
                  or body.startswith(WIRE_PREFIX_MLS)):
                hit = cached.get(mid)
                body = hit.get("body", "[Encrypted message]") if hit else "[Encrypted message]"
            elif body.startswith("FILE:"):
                body = "[File]"
            body = self._crypto_session().unpack_plaintext(body)
            body = self._preview_plaintext(body)
            item["body"] = body
            messages.append(item)
        self._chat.show_pinned_messages(conv_id, messages)

    def _handle_message_pinned(self, msg):
        """Nhận event một tin được ghim → cập nhật UI."""
        conv_id = int(msg.get("conversation_id", 0) or 0)
        msg_id = int(msg.get("message_id", 0) or 0)
        if conv_id and msg_id:
            self._chat.set_message_pinned(conv_id, msg_id, True)
        self._inbox_refresh.start(500)

    def _handle_message_unpinned(self, msg):
        """Nhận event một tin được bỏ ghim → cập nhật UI."""
        conv_id = int(msg.get("conversation_id", 0) or 0)
        msg_id = int(msg.get("message_id", 0) or 0)
        if conv_id and msg_id:
            self._chat.set_message_pinned(conv_id, msg_id, False)
        self._inbox_refresh.start(500)

    def _handle_reaction_added(self, msg):
        """Nhận event thêm reaction → cập nhật bong bóng tin."""
        self._chat.update_reaction(
            int(msg.get("conversation_id", 0) or 0),
            int(msg.get("message_id", 0) or 0),
            msg.get("emoji", ""),
            int(msg.get("user_id", 0) or 0),
            True,
        )

    def _handle_reaction_removed(self, msg):
        """Nhận event gỡ reaction → cập nhật bong bóng tin."""
        self._chat.update_reaction(
            int(msg.get("conversation_id", 0) or 0),
            int(msg.get("message_id", 0) or 0),
            msg.get("emoji", ""),
            int(msg.get("user_id", 0) or 0),
            False,
        )

    def _handle_member_removed(self, msg):
        """Refresh UI after an MLS remove-member operation has been applied."""
        group_id = int(msg.get("group_id", 0) or 0)
        target_uid = int(msg.get("user_id", 0) or 0)
        if group_id <= 0:
            return
        name = self._display_name_for_user(group_id, target_uid, msg)
        operation = str(msg.get("operation", "") or "")
        by_uid = int(msg.get("by_user_id", 0) or 0)
        if hasattr(self._chat, "add_system_event"):
            if target_uid == self._my_uid:
                text = (
                    "You left the group."
                    if operation == "leave_group" or by_uid == self._my_uid
                    else "You were removed from the group."
                )
            else:
                text = (
                    f"{name} left the group."
                    if operation == "leave_group"
                    else f"{name} was removed from the group."
                )
            self._chat.add_system_event(
                group_id,
                text,
                event_key=self._membership_event_key(
                    "member_removed", target_uid, "",
                    str(msg.get("operation_id", "") or "")),
                **self._system_event_kwargs(msg),
            )
        self._expected_group_membership_change.add(group_id)
        if target_uid == self._my_uid:
            self._cleanup_conv_state(group_id)
            self._group_conv_ids.discard(group_id)
            self._group_members_cache.pop(group_id, None)
            self._safe_send({"type": "get_inbox"})
            return
        members_after = self._members_after_from_event(
            group_id, msg, fallback_ids=msg.get("member_ids", []) or [])
        if members_after:
            self._group_members_cache[group_id] = members_after
        self._safe_send({"type": "get_mls_handshake", "conversation_id": group_id})
        self._safe_send({"type": "get_group_info", "group_id": group_id})
        self._safe_send({"type": "get_inbox"})
    def _handle_ui_refresh(self, msg):
        """Yêu cầu làm mới một phần UI sau khi trạng thái đổi."""
        group_id = int(msg.get("group_id", msg.get("conversation_id", 0)) or 0)
        if group_id > 0 and msg.get("type") in (
                "member_left", "member_role_changed", "group_info_updated"):
            if hasattr(self._chat, "add_system_event"):
                event_type = msg.get("type")
                uid = int(msg.get("user_id", 0) or 0)
                operation_id = str(msg.get("operation_id", "") or "")
                if event_type == "member_left":
                    who = "You" if uid == self._my_uid else self._display_name_for_user(group_id, uid, msg)
                    self._chat.add_system_event(
                        group_id,
                        f"{who} left the group.",
                        event_key=self._membership_event_key(
                            "member_removed", uid, "", operation_id),
                        **self._system_event_kwargs(msg),
                    )
                elif event_type == "member_role_changed":
                    role = str(msg.get("role", "") or "member")
                    who = "You" if uid == self._my_uid else self._display_name_for_user(group_id, uid, msg)
                    actor_uid = int(msg.get("by_user_id", 0) or 0)
                    actor = str(msg.get("by_username", "") or "")
                    if not actor and actor_uid > 0 and actor_uid != uid:
                        actor = self._display_name_for_user(group_id, actor_uid, {})
                    role_text = "admin" if role == "admin" else "member"
                    if actor and actor != who:
                        text = f"{actor} made {who} {role_text}."
                    else:
                        text = f"{who} was made {role_text}."
                    self._chat.add_system_event(
                        group_id,
                        text,
                        event_key=self._membership_event_key(
                            "member_role_changed", uid, role, operation_id),
                        **self._system_event_kwargs(msg),
                    )
                elif event_type == "group_info_updated":
                    self._chat.add_system_event(
                        group_id,
                        "Group info was updated.",
                        event_key=self._membership_event_key(
                            "group_info_updated", 0, "", operation_id),
                        **self._system_event_kwargs(msg),
                    )
            self._expected_group_membership_change.add(group_id)
            members_after = self._members_after_from_event(group_id, msg)
            if members_after:
                self._group_members_cache[group_id] = members_after
            self._safe_send({"type": "get_mls_handshake", "conversation_id": group_id})
            self._safe_send({"type": "get_group_info", "group_id": group_id})
        self._safe_send({"type": "get_inbox"})
    def _handle_presence(self, msg):
        """Nhận cập nhật trạng thái online/offline của bạn bè."""
        self._safe_send({"type": "get_friends"})
        self._safe_send({"type": "get_inbox"})

    def _handle_typing_start(self, msg):
        """Nhận tín hiệu đối phương bắt đầu gõ."""
        self._chat.set_typing(
            int(msg.get("conversation_id", 0) or 0),
            int(msg.get("from_id", 0) or 0),
            msg.get("from", ""),
            True,
        )

    def _handle_typing_stop(self, msg):
        """Nhận tín hiệu đối phương ngừng gõ."""
        self._chat.set_typing(
            int(msg.get("conversation_id", 0) or 0),
            int(msg.get("from_id", 0) or 0),
            msg.get("from", ""),
            False,
        )

    def _peer_uid_for_conv(self, conv_id: int) -> int:
        """TÃ¬m user_id Ä‘á»‘i phÆ°Æ¡ng cá»§a DM."""
        conv_id = int(conv_id or 0)
        if conv_id in self._conv_peer_uids:
            return int(self._conv_peer_uids.get(conv_id, 0) or 0)
        for c in getattr(self._chat, "dm_convs", []):
            if int(c.get("conversation_id", 0) or 0) == conv_id:
                peer_uid = int(
                    c.get("with_user_id", 0)
                    or c.get("other_id", 0)
                    or c.get("user_id", 0)
                    or c.get("friend_id", 0)
                    or 0
                )
                if peer_uid == int(self._my_uid or 0):
                    return 0
                return peer_uid
        return 0

    def _is_saved_message_conv(self, conv_id: int) -> bool:
        """Saved Messages Ä‘Ã£ bá»‹ gá»¡; giá»¯ stub Ä‘á»ƒ cÃ¡c flow cÅ© khÃ´ng lá»—i."""
        return False

    def _safety_fingerprint_for_conv(self, conv_id: int) -> str:
        """TÃ­nh safety number canonical tá»« identity key hiá»‡n táº¡i cá»§a hai bÃªn."""
        conv_id = int(conv_id or 0)
        if self._is_saved_message_conv(conv_id):
            return ""
        peer_uid = self._peer_uid_for_conv(conv_id)
        if peer_uid > 0 and self._identity_pk:
            audit = self._crypto_session().load_identity_audit(peer_uid)
            identity_pk = str(audit.get("identity_pk", "") or "")
            if identity_pk:
                try:
                    fp = protocol_safety_fingerprint(self._identity_pk, protocol_b64d(identity_pk))
                    self._conv_fingerprints[conv_id] = fp
                    return fp
                except Exception:
                    pass
        return self._conv_fingerprints.get(conv_id, "")

    def _security_status_for_conv(self, conv_id: int) -> dict:
        """Tá»•ng há»£p tráº¡ng thÃ¡i báº£o máº­t Ä‘á»ƒ sidebar/header hiá»ƒn thá»‹.

        Verify/audit warning khÃ´ng cháº·n gá»­i tin. NÃ³ chá»‰ nháº¯c ngÆ°á»i dÃ¹ng chÆ°a nÃªn
        tin cháº¯c identity cho tá»›i khi review safety number.
        """
        if self._is_saved_message_conv(conv_id):
            return {
                "status": "none",
                "label": "",
                "blocked": False,
                "detail": "",
                "audit": {},
            }
        if self._is_group_conv(conv_id):
            return {
                "status": "group_mls_pq",
                "label": "MLS PQ",
                "blocked": False,
                "detail": (
                    f"Group MLS ciphersuite: {PQ_HYBRID_LABEL}. "
                    "PQ confidentiality; Ed25519 classical authentication."
                ),
                "audit": {},
            }
        peer_uid = self._peer_uid_for_conv(conv_id)
        audit = self._crypto_session().load_identity_audit(peer_uid) if peer_uid else {}
        status = audit.get("status", "unknown")
        verified = self._conv_verified.get(int(conv_id), False)
        has_fingerprint = bool(
            self._safety_fingerprint_for_conv(conv_id)
            or self._conv_fingerprints.get(int(conv_id))
        )
        if status == "key_changed":
            label = "key changed"
        elif status == "audit_mismatch":
            label = App._audit_error_badge_label(audit)
        elif status == "audit_unavailable":
            label = App._audit_error_badge_label(audit)
        elif verified:
            status = "verified"
            label = "verified"
        elif status == "reviewed_unverified":
            label = "unverified"
        elif has_fingerprint:
            status = "unverified"
            label = "verify"
        else:
            label = "verify"
        return {
            "status": status,
            "label": label,
            "blocked": False,
            "detail": App._audit_error_detail_text(audit),
            "audit": audit,
        }

    @staticmethod
    def _audit_error_badge_label(audit: dict) -> str:
        """Nhãn ngắn cho badge lỗi kiểm toán (audit)."""
        status = str((audit or {}).get("status", "") or "")
        code = str((audit or {}).get("last_error_code", "") or "")
        if code:
            return f"audit {audit_error_label(code)}"
        if status == "audit_unavailable":
            return "audit unavailable"
        return "audit warning"

    @staticmethod
    def _audit_error_detail_text(audit: dict) -> str:
        """Mô tả chi tiết một lỗi kiểm toán để hiển thị."""
        code = str((audit or {}).get("last_error_code", "") or "")
        message = str((audit or {}).get("last_error", "") or "")
        if code:
            return audit_error_detail(code, message)
        return message

    @staticmethod
    def _audit_state_stops_key_exchange(state: dict) -> bool:
        """Audit warning khÃ´ng cháº·n key exchange theo quyáº¿t Ä‘á»‹nh UX hiá»‡n táº¡i."""
        return False

    @staticmethod
    def _identity_version_label(version) -> str:
        """Label dá»… hiá»ƒu cho UI; protocol váº«n dÃ¹ng sá»‘ 0 cho identity Ä‘áº§u tiÃªn."""
        try:
            v = int(version)
        except Exception:
            return "unknown"
        return "initial" if v == 0 else f"v{v}"

    def _refresh_security_ui(self, conv_id: int) -> None:
        """Äá»“ng bá»™ badge/banner báº£o máº­t cho má»™t conversation."""
        info = self._security_status_for_conv(conv_id)
        self._chat.set_conversation_security(
            conv_id,
            str(info.get("status", "unverified")),
            str(info.get("label", "verify")),
            str(info.get("detail", "")),
            bool(info.get("blocked", False)),
        )

    def _require_identity_review_before_send(self, conv_id: int) -> bool:
        """Giá»¯ tÃªn cÅ© nhÆ°ng luÃ´n cho gá»­i; verify chá»‰ lÃ  cáº£nh bÃ¡o tin cáº­y."""
        self._refresh_security_ui(conv_id)
        return True

    def _audit_pqxdh_bundle_identity(self, conv_id: int, msg: dict) -> dict:
        """Kiá»ƒm tra identity trong PQXDH bundle báº±ng auditor náº¿u cÃ³ thá»ƒ.

        Náº¿u auditor lá»—i hoáº·c proof khÃ´ng há»£p lá»‡, hÃ m lÆ°u tráº¡ng thÃ¡i cáº£nh bÃ¡o Ä‘á»ƒ
        UI hiá»ƒn thá»‹ nhÆ°ng khÃ´ng dá»«ng DM/group key exchange. Chá»‰ lá»—i crypto tháº­t
        nhÆ° signature sai má»›i cháº·n á»Ÿ táº§ng CryptoSession.
        """
        peer_uid = int(msg.get("user_id", 0) or 0)
        identity_pk = str(msg.get("identity_pk", "") or "")
        identity_version = int(msg.get("identity_version", 0) or 0)
        if self._is_saved_message_conv(conv_id) or peer_uid <= 0:
            return {"status": "none", "identity_pk": identity_pk}
        safety = ""
        try:
            if self._identity_pk and identity_pk:
                safety = protocol_safety_fingerprint(self._identity_pk, protocol_b64d(identity_pk))
        except Exception:
            safety = ""
        self._conv_fingerprints[int(conv_id)] = safety or self._conv_fingerprints.get(
            int(conv_id), "")
        previous = self._crypto_session().load_auditor_state()
        try:
            result = verify_identity_from_auditor(
                self._auditor_url,
                user_id=peer_uid,
                identity_version=identity_version,
                identity_pk=identity_pk,
                previous_checkpoint=previous.get("checkpoint"),
            )
            try:
                self._crypto_session().record_auditor_checkpoint(
                    result.get("checkpoint") or {},
                    source="pqxdh_bundle",
                    user_id=peer_uid,
                    identity_version=identity_version,
                )
            except Exception as exc:
                raise AuditError(
                    str(exc),
                    code=classify_audit_error(str(exc)),
                ) from exc
            state = self._crypto_session().record_identity_audit_ok(
                peer_uid,
                identity_pk=identity_pk,
                identity_version=identity_version,
                safety_number=safety,
                checkpoint=result.get("checkpoint") or {},
                leaf=result.get("leaf") or {},
            )
        except AuditError as exc:
            error_code = str(getattr(exc, "code", "") or classify_audit_error(str(exc)))
            audit_status = audit_status_for_code(error_code)
            auditor_state = self._crypto_session().load_auditor_state()
            auditor_state.update({
                "status": audit_status,
                "last_error": str(exc),
                "last_error_code": error_code,
                "updated_at": int(time.time()),
            })
            self._crypto_session().save_auditor_state(auditor_state)
            state = self._recover_identity_audit_version_mismatch(
                peer_uid, identity_pk, identity_version, safety, str(exc), error_code)
            if not state:
                state = self._crypto_session().record_identity_audit_problem(
                    peer_uid,
                    identity_pk=identity_pk,
                    identity_version=identity_version,
                    safety_number=safety,
                    status=audit_status,
                    error=str(exc),
                    error_code=error_code,
                )
        except Exception as exc:
            error_code = "auditor_unavailable"
            error = f"Auditor is unavailable: {exc}"
            auditor_state = self._crypto_session().load_auditor_state()
            if not auditor_state.get("checkpoint"):
                auditor_state.update({
                    "status": "audit_unavailable",
                    "last_error": error,
                    "last_error_code": error_code,
                    "updated_at": int(time.time()),
                })
                self._crypto_session().save_auditor_state(auditor_state)
            state = self._crypto_session().record_identity_audit_problem(
                peer_uid,
                identity_pk=identity_pk,
                identity_version=identity_version,
                safety_number=safety,
                status="audit_unavailable",
                error=error,
                error_code=error_code,
            )
        self._refresh_security_ui(conv_id)
        return state

    def _recover_identity_audit_version_mismatch(
            self, peer_uid: int, identity_pk: str, identity_version: int,
            safety: str, error: str, error_code: str = "") -> dict | None:
        """Náº¿u server/bundle lá»‡ch version nhÆ°ng key giá»‘ng log, dÃ¹ng version trong log.

        TrÆ°á»ng há»£p nÃ y khÃ´ng pháº£i key substitution: identity key bytes giá»‘ng entry
        Ä‘Ã£ Ä‘Æ°á»£c auditor kÃ½, chá»‰ cÃ³ sá»‘ version bá»‹ stale/lá»‡ch do retry hoáº·c dá»¯ liá»‡u
        cÅ©. UI khÃ´ng nÃªn hiá»‡n audit mismatch Ä‘á» cho cÃ¹ng má»™t safety number.
        """
        if error_code not in {
                "identity_version_mismatch",
                "identity_version_not_found",
        }:
            return None
        try:
            history = fetch_identity_history(self._auditor_url, peer_uid)
        except Exception:
            return None
        entries = list(history.get("entries") or [])
        match = None
        for entry in reversed(entries):
            if same_identity_key(str(entry.get("identity_pk", "")), identity_pk):
                match = entry
                break
        if not match:
            return None
        try:
            effective_version = int(match.get("identity_version", identity_version) or 0)
            result = verify_identity_from_auditor(
                self._auditor_url,
                user_id=peer_uid,
                identity_version=effective_version,
                identity_pk=identity_pk,
                previous_checkpoint=self._crypto_session().load_auditor_state()
                .get("checkpoint"),
            )
            self._crypto_session().record_auditor_checkpoint(
                result.get("checkpoint") or {},
                source="pqxdh_bundle_version_recovered",
                user_id=peer_uid,
                identity_version=effective_version,
            )
            return self._crypto_session().record_identity_audit_ok(
                peer_uid,
                identity_pk=identity_pk,
                identity_version=effective_version,
                safety_number=safety,
                checkpoint=result.get("checkpoint") or {},
                leaf=result.get("leaf") or {},
            )
        except Exception:
            return None

    def _record_incoming_pq_identity(self, conv_id: int, result: dict) -> None:
        """LÆ°u identity cá»§a sender nháº­n tá»« ``S3PQI`` Ä‘á»ƒ hai bÃªn cÃ³ cÃ¹ng safety code."""
        if self._is_saved_message_conv(conv_id):
            return
        peer_uid = int(result.get("peer_uid", 0) or 0)
        identity_pk = str(result.get("peer_identity_pk", "") or "")
        if peer_uid <= 0 or not identity_pk:
            return
        identity_version_raw = result.get("peer_identity_version")
        try:
            identity_version = (
                int(identity_version_raw)
                if identity_version_raw is not None else None)
        except Exception:
            identity_version = None
        safety = ""
        try:
            safety = protocol_safety_fingerprint(self._identity_pk, protocol_b64d(identity_pk))
            self._conv_fingerprints[int(conv_id)] = safety
        except Exception:
            safety = str(result.get("fingerprint", "") or "")
        if identity_version is None:
            self._crypto_session().record_identity_seen_unverified(
                peer_uid,
                identity_pk=identity_pk,
                identity_version=None,
                safety_number=safety,
                event_type="pqxdh_initial",
            )
        else:
            self._audit_pqxdh_bundle_identity(
                conv_id,
                {
                    "user_id": peer_uid,
                    "identity_pk": identity_pk,
                    "identity_version": identity_version,
                },
            )
        self._refresh_security_ui(conv_id)

    def _handle_identity_changed(self, msg):
        """Xá»­ lÃ½ thÃ´ng bÃ¡o identity key cá»§a contact Ä‘Ã£ Ä‘á»•i."""
        uid = int(msg.get("user_id", 0) or 0)
        if uid <= 0 or uid == self._my_uid:
            return
        identity_pk = str(msg.get("identity_pk", "") or "")
        identity_version = int(msg.get("identity_version", 0) or 0)
        affected = []
        for conv_id, peer_uid in list(self._conv_peer_uids.items()):
            if int(peer_uid) == uid:
                affected.append(conv_id)
                self._conv_verified[conv_id] = False
                try:
                    self._save_verified(conv_id, False)
                except Exception:
                    pass
                if conv_id == self._chat.active_conv_id:
                    self._chat.set_fingerprint(
                        self._conv_fingerprints.get(conv_id, ""), verified=False)
                if identity_pk:
                    safety = ""
                    try:
                        safety = protocol_safety_fingerprint(self._identity_pk, protocol_b64d(identity_pk))
                    except Exception:
                        pass
                    old = self._crypto_session().load_identity_audit(uid)
                    hist = list(old.get("history") or [])
                    hist.append({
                        "seen_at": int(time.time()),
                        "event_type": "rotation",
                        "identity_version": identity_version,
                        "identity_pk": identity_pk,
                        "safety_number": safety,
                        "device_label": "primary device",
                        "created_at": "",
                        "verified_after_change": False,
                    })
                    old.update({
                        "status": "key_changed",
                        "identity_pk": identity_pk,
                        "identity_version": identity_version,
                        "safety_number": safety,
                        "history": hist[-20:],
                        "last_error": "Safety number changed and needs review.",
                        "last_error_code": "",
                    })
                    self._crypto_session().save_identity_audit(uid, old)
                self._refresh_security_ui(conv_id)
        name = self._chat.friends.get(uid, {}).get("username") or f"User#{uid}"
        warning = (
            f"{name}'s safety number changed. This can be normal after a key "
            "rotation, but it can also mean someone is trying to substitute a "
            "key. Compare the safety number again outside SecChat before "
            "trusting this conversation."
        )
        QMessageBox.warning(
            self._chat, "Safety Number Changed",
            warning,
        )

    def _handle_safety_number_changed(self, msg):
        """Xử lý khi safety number của đối phương thay đổi (cảnh báo)."""
        self._handle_identity_changed(msg)

    def _handle_pqxdh_bundle(self, msg):
        """Nháº­n PQXDH bundle cá»§a peer Ä‘á»ƒ báº¯t Ä‘áº§u DM."""
        peer_uid = int(msg.get("user_id", 0) or 0)
        if peer_uid <= 0:
            return
        pending_dm = int(self._pending_pqxdh_dm.get(peer_uid, 0) or 0)
        if pending_dm > 0 and self._load_double_ratchet(pending_dm) is not None:
            self._pending_pqxdh_dm.pop(peer_uid, None)
            return

        store = self._load_pqxdh_prekeys()
        if not store:
            QMessageBox.warning(
                self._chat, "Key Exchange Failed",
                "Local SecChat prekeys are not available yet.")
            return

        conv_id = self._pending_pqxdh_dm.pop(peer_uid, 0)
        if conv_id <= 0:
            return
        if self._load_double_ratchet(conv_id) is not None:
            return
        self._audit_pqxdh_bundle_identity(conv_id, msg)
        try:
            token, fp = self._crypto_session().initiate_pqxdh_dm(
                msg, conv_id, peer_uid,
                sender_identity_version=self.__dict__.get("_own_identity_version", 0))
            if conv_id == self._chat.active_conv_id and not self._is_saved_message_conv(conv_id):
                verified = self._conv_verified.get(conv_id, False)
                self._chat.set_fingerprint(
                    self._safety_fingerprint_for_conv(conv_id) or fp,
                    verified=verified)
            self._safe_send({
                "type": "message",
                "conversation_id": conv_id,
                "body": token,
            })
            self._flush_pending(conv_id)
        except Exception as exc:
            _logger.error("SecChat PQXDH initiate failed: %s", exc)
            QMessageBox.warning(
                self._chat, "Key Exchange Failed",
                f"Could not establish SecChat encryption:\n{exc}",
            )

    def _is_group_conv(self, conv_id: int) -> bool:
        """Kiểm tra conv_id có phải hội thoại nhóm hay không."""
        try:
            return int(conv_id) in self._group_conv_ids
        except Exception:
            return int(conv_id) in self.__dict__.get("_group_conv_ids", set())

    def _handle_my_keys(self, msg):
        """Nạp identity key của chính mình rồi kiểm tra trạng thái PQXDH."""
        self._server_identity_pk = str(msg.get("identity_pk", "") or "")
        try:
            self._own_identity_version = int(msg.get("identity_version", 0) or 0)
        except Exception:
            self._own_identity_version = 0
        force_pqxdh_publish = False
        try:
            result = self._crypto_session().restore_identity_key_record(msg)
            if not result.get("found"):
                upload = result.get("upload")
                if upload:
                    self._safe_send(upload)
                force_pqxdh_publish = True
            else:
                if result.get("identity_secret_backup_missing"):
                    server_identity = str(msg.get("identity_pk", "") or "")
                    local_identity = (
                        base64.b64encode(self._identity_pk).decode()
                        if self._identity_pk else ""
                    )
                    if (self._identity_sk and
                            (not server_identity
                             or same_identity_key(server_identity, local_identity))):
                        self._upload_current_key_bundle()
                    elif server_identity:
                        self._pqxdh_publish_blocked = True
                        self._pending_pqxdh_bundle_upload = False
                        self._pqxdh_bundle_ready = False
                        self._kem_ready = False
                force_pqxdh_publish = (
                    bool(result.get("identity_secret_restored"))
                    or self._crypto_session().load_pqxdh_prekeys() is None
                )
        except Exception as exc:
            _logger.warning("Key restore failed: %s", exc)
            self._upload_identity_bundle()
            force_pqxdh_publish = True
        if force_pqxdh_publish and not self.__dict__.get("_pqxdh_publish_blocked"):
            self._publish_fresh_pqxdh_bundle_for_current_device()
        self._initialize_mls_for_current_account()
        self._publish_mls_key_packages(count=12)
        self._safe_send({"type": "get_my_pqxdh_status"})

    def _drain_pending_key_requests(self):
        """Retry cÃ¡c request key bá»‹ chá» trong lÃºc local bundle chÆ°a publish."""
        if (self.__dict__.get("_pending_pqxdh_bundle_upload")
                or self.__dict__.get("_pqxdh_publish_blocked")
                or not self.__dict__.get("_pqxdh_bundle_ready", False)):
            return
        self._kem_ready = True
        queue = self._pending_kem_queue[:]
        self._pending_kem_queue.clear()
        for conv_id, uid in queue:
            if uid > 0:
                self._pending_pqxdh_dm[uid] = conv_id
                self._safe_send({"type": "get_pqxdh_bundle", "user_id": uid})

    def _handle_pqxdh_status(self, msg):
        """Äáº£m báº£o server cÃ³ PQXDH bundle/prekey cá»§a account hiá»‡n táº¡i."""
        try:
            self._own_identity_version = int(
                msg.get("identity_version", self.__dict__.get("_own_identity_version", 0)) or 0)
        except Exception:
            pass
        if self.__dict__.get("_pqxdh_publish_blocked"):
            self._pending_pqxdh_bundle_upload = False
            self._pqxdh_bundle_ready = False
            self._kem_ready = False
            return
        if self.__dict__.get("_pending_pqxdh_bundle_upload"):
            self._pqxdh_bundle_ready = False
            self._kem_ready = False
            return
        has_bundle = bool(msg.get("has_bundle", False))
        curve_count = int(msg.get("curve_prekeys", 0) or 0)
        pq_count = int(msg.get("pq_prekeys", 0) or 0)
        need_upload = (
            not has_bundle
            or curve_count < 3
            or pq_count < 3
            or self._crypto_session().load_pqxdh_prekeys() is None
        )
        if need_upload:
            self._publish_fresh_pqxdh_bundle_for_current_device()
            return
        self._pending_pqxdh_bundle_upload = False
        self._pqxdh_bundle_ready = True
        self._drain_pending_key_requests()

    def _clear_stale_local_state(self) -> None:
        self._crypto_session().clear_stale_local_state()

    # Local plaintext cache giÃºp Ä‘á»c láº¡i history sau relogin trong khi váº«n giá»¯
    # forward secrecy cho ratchet. Má»—i plaintext tá»«ng Ä‘á»c Ä‘Æ°á»£c ghi vÃ o file cache
    # mÃ£ hÃ³a báº±ng master key; khi history reload khÃ´ng cÃ²n message key cÅ©, UI tra
    # cache nÃ y Ä‘á»ƒ khÃ´i phá»¥c ná»™i dung Ä‘á»c Ä‘Æ°á»£c trÃªn cÃ¹ng thiáº¿t bá»‹.

    def _msg_cache_path(self, conv_id: int) -> str:
        """Đường dẫn tệp cache tin nhắn cục bộ của một hội thoại."""
        return self._crypto_session().msg_cache_path(conv_id)

    @staticmethod
    def _wire_cache_key(wire: str) -> str:
        """Khóa lưu cache cho bản mã (wire) của một tin."""
        return CryptoSession.wire_cache_key(wire)

    def _cache_message(self, conv_id: int, msg_id: int, sender_id: int,
                       plaintext: str, ts: str) -> None:
        """Lưu một tin đã giải mã vào cache cục bộ (nếu chính sách cho phép)."""
        self._crypto_session().cache_message(
            conv_id, msg_id, sender_id, plaintext, ts)

    def _cache_outgoing_wire(self, conv_id: int, wire: str, sender_id: int,
                             plaintext: str, ts: str = "") -> None:
        """Lưu bản mã tin gửi đi để hiển thị lại khi cần."""
        self._crypto_session().cache_outgoing_wire(
            conv_id, wire, sender_id, plaintext, ts)

    def _load_cached_messages(self, conv_id: int) -> dict:
        """Nạp các tin đã cache của một hội thoại từ đĩa."""
        return self._crypto_session().load_cached_messages(conv_id)

    def _clear_local_message_cache(self):
        """Xóa toàn bộ cache tin nhắn cục bộ."""
        removed = self._crypto_session().clear_message_cache()
        for conv_id in list(self._chat.hist.keys()):
            self._chat.invalidate_history(conv_id, clear_messages=False)
        QMessageBox.information(
            self._chat,
            "Local Cache",
            f"Cleared {removed} local message cache file(s).",
        )

    def _clear_conversation_message_cache(self, conv_id: int):
        """Xóa cache tin nhắn của một hội thoại."""
        conv_id = int(conv_id or 0)
        removed = self._crypto_session().clear_message_cache(conv_id)
        if conv_id:
            self._chat.invalidate_history(conv_id, clear_messages=False)
        QMessageBox.information(
            self._chat,
            "Local Cache",
            "Cleared this conversation's local message cache."
            if removed else "No local message cache was stored for this conversation.",
        )

    def _update_local_cache_policy(self, policy: dict):
        """Cập nhật chính sách cache cục bộ toàn cục."""
        saved = self._crypto_session().set_cache_policy(
            enabled=bool(policy.get("enabled", True)),
            ttl_days=int(policy.get("ttl_days", 30)),
            clear_on_logout=bool(policy.get("clear_on_logout", False)),
            disabled_conversation_ids=policy.get("disabled_conversation_ids"),
        )
        self._chat.set_cache_policy(saved)

    def _update_conversation_cache_policy(self, conv_id: int, enabled: bool):
        """Cập nhật chính sách cache cho riêng một hội thoại."""
        conv_id = int(conv_id or 0)
        saved = self._crypto_session().set_conversation_cache_enabled(
            conv_id, bool(enabled))
        self._chat.set_cache_policy(saved)
        if conv_id:
            self._chat.invalidate_history(conv_id, clear_messages=False)
        self._inbox_refresh.start(300)

    # â”€â”€ Ratchet state persistence helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    # SecChat encrypted-at-rest state helpers.

    def _backup_passphrase(self, title: str) -> str | None:
        """Lấy/nhập passphrase dùng để mã hóa bản sao lưu E2EE."""
        value, ok = QInputDialog.getText(
            self._chat,
            title,
            "Backup passphrase:",
            QLineEdit.Password,
        )
        if not ok:
            return None
        value = value or ""
        report = CryptoSession.backup_passphrase_report(value)
        if not report.get("ok"):
            QMessageBox.warning(
                self._chat,
                title,
                str(report.get("message") or "Backup passphrase is too weak."),
            )
            return None
        return value

    @staticmethod
    def _fmt_backup_time(ts: int) -> str:
        """Định dạng thời điểm sao lưu để hiển thị."""
        try:
            ts = int(ts or 0)
        except Exception:
            ts = 0
        if ts <= 0:
            return "never"
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

    def _backup_status_text(self) -> str:
        """Dựng chuỗi mô tả trạng thái sao lưu hiện tại."""
        status = self._crypto_session().get_backup_status()
        generation = int(status.get("latest_generation", 0) or 0)
        if generation <= 0:
            latest = "No local backup has been recorded on this device."
        else:
            latest = (
                f"Latest local backup: generation {generation}\n"
                f"Created: {self._fmt_backup_time(status.get('latest_created_at', 0))}\n"
                f"Backup id: {status.get('latest_backup_id', '') or 'unknown'}\n"
                f"Device label: {status.get('latest_device_label', '') or 'primary device'}\n"
                f"Includes message cache: {'yes' if status.get('latest_include_cache') else 'no'}"
            )
        restored = ""
        if status.get("restored_from_backup_id"):
            restored = (
                "\n\nLast restore:\n"
                f"Backup id: {status.get('restored_from_backup_id')}\n"
                f"Time: {self._fmt_backup_time(status.get('restored_at', 0))}"
            )
        revoked = ""
        if int(status.get("revoked_before_generation", 0) or 0) > 0:
            revoked = (
                "\n\nLocal revoke policy:\n"
                f"This device refuses backups up to generation "
                f"{status.get('revoked_before_generation')} and "
                f"{status.get('revoked_count', 0)} explicit backup id(s)."
            )
        return (
            latest
            + restored
            + revoked
            + "\n\nBackups are encrypted with a separate passphrase. "
            "A revoked local backup file may still exist elsewhere; this device "
            "only refuses to restore backups it can identify as revoked."
        )

    def _show_backup_status(self):
        """Hiển thị trạng thái sao lưu cho người dùng."""
        QMessageBox.information(
            self._chat,
            "E2EE Backup Status",
            self._backup_status_text(),
        )

    def _revoke_local_backups(self):
        """Thu hồi/xóa các bản sao lưu cục bộ."""
        if QMessageBox.question(
            self._chat,
            "Revoke Local Backups",
            "Mark known local E2EE backups as revoked on this device?\n\n"
            "This does not delete copied backup files and cannot revoke a backup "
            "on another device. It only makes this client refuse older local "
            "backup files with matching metadata.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        self._crypto_session().revoke_local_backups()
        QMessageBox.information(
            self._chat,
            "E2EE Backup Status",
            self._backup_status_text(),
        )

    def _export_e2ee_backup(self):
        """Xuất bản sao lưu trạng thái E2EE (đã mã hóa bằng passphrase)."""
        path, _ = QFileDialog.getSaveFileName(
            self._chat,
            "Export E2EE Backup",
            "secchat-e2ee-backup.json",
            "SecChat Backup (*.json);;All Files (*)",
        )
        if not path:
            return
        include_cache = QMessageBox.question(
            self._chat,
            "Export E2EE Backup",
            "Include local plaintext message cache in this backup?\n\n"
            "Including it preserves readable history/previews after restore, "
            "but the backup contains more sensitive local data. Conversations "
            "marked No local cache are not included.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        ) == QMessageBox.Yes
        passphrase = self._backup_passphrase("Export E2EE Backup")
        if passphrase is None:
            return
        try:
            result = self._crypto_session().export_e2ee_backup(
                path,
                passphrase,
                account_username=self._account_username,
                include_cache=include_cache,
            )
            QMessageBox.information(
                self._chat,
                "E2EE Backup",
                f"Exported {result['files']} encrypted state file(s).\n\n"
                f"Backup id: {result.get('backup_id', 'unknown')}\n"
                f"Generation: {result.get('backup_generation', 0)}\n"
                f"Includes message cache: {'yes' if result.get('include_cache') else 'no'}",
            )
        except Exception as exc:
            QMessageBox.warning(self._chat, "E2EE Backup Failed", str(exc))

    def _restore_e2ee_backup(self):
        """Khôi phục trạng thái E2EE từ bản sao lưu đã mã hóa."""
        path, _ = QFileDialog.getOpenFileName(
            self._chat,
            "Restore E2EE Backup",
            "",
            "SecChat Backup (*.json);;All Files (*)",
        )
        if not path:
            return
        try:
            info = self._crypto_session().inspect_e2ee_backup(path)
            backup_summary = (
                f"Backup id: {info.get('backup_id') or 'unknown'}\n"
                f"Generation: {info.get('generation') or 'unknown'}\n"
                f"Created: {self._fmt_backup_time(info.get('created_at', 0))}\n"
                f"Account: {info.get('account_username') or 'unknown'}\n"
                f"Includes message cache: {'yes' if info.get('include_cache') else 'no'}\n\n"
            )
            backup_fp = str(info.get("identity_fingerprint", "") or "")
            current_identity = self._identity_pk or b""
            current_fp = (
                hashlib.sha256(current_identity).hexdigest()[:24]
                if current_identity else ""
            )
            current_identity_b64 = (
                base64.b64encode(current_identity).decode()
                if current_identity else ""
            )
            server_identity = str(
                self.__dict__.get("_server_identity_pk", "") or "")
            server_matches_current = bool(
                server_identity
                and current_identity_b64
                and same_identity_key(server_identity, current_identity_b64)
            )
            preserve_current_identity = bool(
                backup_fp
                and current_fp
                and backup_fp != current_fp
                and server_matches_current
                and not self.__dict__.get("_pqxdh_publish_blocked")
            )
            if preserve_current_identity:
                backup_summary += (
                    "This backup was made with a different safety key. "
                    "SecChat will merge readable cached history only and keep "
                    "the current safety key.\n\n"
                )
        except Exception as exc:
            QMessageBox.warning(self._chat, "E2EE Restore Failed", str(exc))
            return
        if QMessageBox.question(
            self._chat,
            "Restore E2EE Backup",
            backup_summary
            + "Restore local E2EE state from this backup?\n\n"
            "Current local keys, ratchets, group state, verification state, "
            "and optional cached messages may be overwritten. On a new device, "
            "this can change what identity and ratchet state the app uses. "
            "Contacts should verify your safety number again after restore.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        passphrase = self._backup_passphrase("Restore E2EE Backup")
        if passphrase is None:
            return
        try:
            result = self._crypto_session().restore_e2ee_backup(
                path,
                passphrase,
                preserve_current_identity=preserve_current_identity,
            )
            self._chat.set_cache_policy(self._crypto_session().get_cache_policy())
            active_conv_id = int(self._chat.active_conv_id or 0)
            conv_ids = {int(conv_id) for conv_id in self._chat.hist.keys()}
            if active_conv_id > 0:
                conv_ids.add(active_conv_id)
            for conv_id in conv_ids:
                self._chat.invalidate_history(conv_id, clear_messages=True)
            if result.get("preserved_current_identity"):
                self._safe_send({"type": "get_inbox"})
                if active_conv_id > 0:
                    self._get_history(active_conv_id)
                QMessageBox.information(
                    self._chat,
                    "E2EE Backup",
                    f"Merged {result['files']} encrypted cache file(s).\n\n"
                    "The current safety key was kept. Old identity, prekey, "
                    "ratchet, group and verification state from the backup was "
                    "not published over the rotated account state.",
                )
                return
            self._pqxdh_publish_blocked = False
            self._upload_current_key_bundle()
            self._publish_fresh_pqxdh_bundle_for_current_device()
            self._safe_send({"type": "get_inbox"})
            QMessageBox.information(
                self._chat,
                "E2EE Backup",
                f"Restored {result['files']} encrypted state file(s).\n\n"
                "Your key bundle was re-published for this account. "
                "Review safety numbers with contacts after restoring on a new device.",
            )
        except InvalidTag:
            QMessageBox.warning(
                self._chat,
                "E2EE Restore Failed",
                "Backup could not be decrypted. Check the backup passphrase "
                "and make sure the file was not modified.",
            )
        except Exception as exc:
            QMessageBox.warning(self._chat, "E2EE Restore Failed", str(exc))

    def _pqxdh_prekeys_path(self) -> str:
        """Đường dẫn tệp lưu prekey PQXDH cục bộ."""
        return self._crypto_session().pqxdh_prekeys_path()

    def _save_pqxdh_prekeys(self) -> None:
        """Lưu bộ prekey PQXDH (riêng tư) xuống đĩa."""
        self._crypto_session().save_pqxdh_prekeys()

    def _load_pqxdh_prekeys(self) -> dict | None:
        """Nạp bộ prekey PQXDH từ đĩa."""
        return self._crypto_session().load_pqxdh_prekeys()

    def _ensure_pqxdh_bundle(self) -> None:
        """Đảm bảo đã có bundle PQXDH hợp lệ (tạo mới nếu thiếu)."""
        try:
            upload = self._crypto_session().ensure_pqxdh_bundle_command()
            if upload:
                self._safe_send(upload)
        except Exception as exc:
            _logger.error("SecChat bundle generation failed: %s", exc)
            QMessageBox.warning(
                self._chat, "Key Publishing Failed",
                f"Could not publish the SecChat PQXDH bundle:\n{exc}",
            )

    def _initialize_mls_for_current_account(self) -> bool:
        """Khởi tạo trạng thái MLS cho tài khoản đang đăng nhập."""
        try:
            self._crypto_session().initialize_mls_identity(
                email=self._auth_credential or self._account_username,
                identity_version=int(self.__dict__.get("_own_identity_version", 0) or 0),
            )
            return True
        except Exception as exc:
            _logger.warning("OpenMLS identity init failed: %s", exc)
            if self._stack.currentIndex() == 1:
                self._chat.show_security_warning(
                    0,
                    "OpenMLS identity is not available on this VNC. Group E2EE "
                    "will not be ready until the MLS bridge starts successfully.",
                )
            return False

    def _publish_mls_key_packages(self, count: int = 8) -> bool:
        """Sinh và upload KeyPackage MLS lên server."""
        if not self._session_active:
            return False
        try:
            if not self._crypto_session().mls_identity_ready:
                if not self._initialize_mls_for_current_account():
                    return False
            cmd = self._crypto_session().mls_key_package_upload_command(count=count)
            ok = self._safe_send(cmd)
            self._mls_debug("publish_key_packages", ok=ok, count=count)
            if ok:
                self._mls_key_packages_ready = True
            return ok
        except Exception as exc:
            self._mls_key_packages_ready = False
            _logger.warning("OpenMLS KeyPackage publish failed: %s", exc)
            self._chat.show_security_warning(
                0,
                f"Could not publish MLS KeyPackages: {exc}",
            )
            return False

    def _publish_fresh_pqxdh_bundle_for_current_device(self) -> bool:
        """Publish a PQXDH bundle whose private prekeys live on this VNC."""
        try:
            upload = self._crypto_session().fresh_pqxdh_bundle_command()
        except Exception as exc:
            _logger.error("SecChat bundle generation failed: %s", exc)
            self._pending_pqxdh_bundle_upload = False
            self._pqxdh_bundle_ready = False
            self._kem_ready = False
            QMessageBox.warning(
                self._chat, "Key Publishing Failed",
                f"Could not publish the SecChat PQXDH bundle:\n{exc}",
            )
            return False
        if not upload:
            self._pending_pqxdh_bundle_upload = False
            self._pqxdh_bundle_ready = False
            self._kem_ready = False
            return False
        self._pending_pqxdh_bundle_upload = True
        self._pqxdh_publish_blocked = False
        self._pqxdh_bundle_ready = False
        self._kem_ready = False
        sent = self._safe_send(upload)
        if not sent:
            self._pending_pqxdh_bundle_upload = False
        return sent

    def _load_double_ratchet(self, conv_id: int):
        """Nạp trạng thái Double Ratchet của các DM từ store cục bộ."""
        return self._crypto_session().load_double_ratchet(conv_id)

    def _save_double_ratchet(self, conv_id: int) -> None:
        """Lưu trạng thái Double Ratchet của các DM xuống đĩa."""
        self._crypto_session().save_double_ratchet(conv_id)

    def _handle_group_integrity_control(self, conv_id: int, body: str) -> bool:
        """Xử lý thông điệp kiểm tra tính toàn vẹn thành viên group."""
        handled = self._crypto_session().handle_group_integrity_control(conv_id, body)
        if handled:
            self._flush_pending(conv_id)
            if conv_id == self._chat.active_conv_id:
                self._safe_send({"type": "history", "conversation_id": conv_id})
        return handled

    def _peer_uid_for_dm_conv(self, conv_id: int) -> int:
        """Trả uid đối phương của một hội thoại DM."""
        conv_id = int(conv_id or 0)
        peer_uid = int(self._conv_peer_uids.get(conv_id, 0) or 0)
        if peer_uid > 0:
            return peer_uid
        for conv in getattr(self._chat, "dm_convs", []) or []:
            if int(conv.get("conversation_id", 0) or 0) != conv_id:
                continue
            peer_uid = int(
                conv.get("with_user_id", 0)
                or conv.get("user_id", 0)
                or conv.get("other_id", 0)
                or 0
            )
            if peer_uid > 0:
                self._conv_peer_uids[conv_id] = peer_uid
                return peer_uid
        return 0

    def _ensure_pqxdh_dm_session(self, conv_id: int) -> bool:
        """Start a fresh PQXDH segment for an existing DM if local state is absent."""
        conv_id = int(conv_id or 0)
        if conv_id <= 0 or self._is_group_conv(conv_id) or self._is_saved_message_conv(conv_id):
            return False
        if self._load_double_ratchet(conv_id) is not None:
            return True
        if self.__dict__.get("_pqxdh_publish_blocked"):
            return False
        peer_uid = self._peer_uid_for_dm_conv(conv_id)
        if peer_uid <= 0 or peer_uid == int(self._my_uid or 0):
            return False
        if int(self._pending_pqxdh_dm.get(peer_uid, 0) or 0) == conv_id:
            return False
        self._pending_pqxdh_dm[peer_uid] = conv_id
        if (self.__dict__.get("_kem_ready", False)
                and not self.__dict__.get("_pending_pqxdh_bundle_upload")):
            self._safe_send({"type": "get_pqxdh_bundle", "user_id": peer_uid})
        else:
            item = (conv_id, peer_uid)
            if item not in self._pending_kem_queue:
                self._pending_kem_queue.append(item)
        return False

    def _retry_identity_blocked_key_work(self, peer_uid: int) -> None:
        """Thử lại các thao tác khóa bị chặn do chờ xác minh danh tính."""
        peer_uid = int(peer_uid or 0)
        if peer_uid <= 0:
            return
        if int(self._pending_pqxdh_dm.get(peer_uid, 0) or 0) > 0:
            self._safe_send({"type": "get_pqxdh_bundle", "user_id": peer_uid})

    def _load_verified(self, conv_id: int) -> bool:
        """Nạp danh sách danh tính đã xác minh từ đĩa."""
        return self._crypto_session().load_verified(conv_id)

    def _save_verified(self, conv_id: int, verified: bool) -> None:
        """Lưu danh sách danh tính đã xác minh xuống đĩa."""
        self._crypto_session().save_verified(conv_id, verified)

    @staticmethod
    def _safety_short_code(fp: str) -> str:
        """Dạng safety number rút gọn (chuỗi số) để so khớp."""
        digits = "".join(ch for ch in str(fp) if ch.isdigit())
        if len(digits) < 12:
            digest = hashlib.sha256(str(fp).encode("utf-8")).digest()
            digits = f"{int.from_bytes(digest[:8], 'big') % 10**12:012d}"
        return " ".join(digits[i:i + 3] for i in range(0, 12, 3))

    @staticmethod
    def _safety_visual_code(fp: str, cells: int = 13, scale: int = 9) -> QPixmap:
        """Dạng safety number trực quan để người dùng đối chiếu."""
        digest = hashlib.sha256(("secchat-safety-visual:" + str(fp)).encode("utf-8")).digest()
        pix = QPixmap(cells * scale, cells * scale)
        pix.fill(QColor("#f2f3f5"))
        painter = QPainter(pix)
        painter.setPen(Qt.NoPen)

        def draw_cell(x: int, y: int, color: str) -> None:
            painter.setBrush(QColor(color))
            painter.drawRect(x * scale, y * scale, scale, scale)

        bit_index = 0
        for y in range(cells):
            for x in range(cells):
                border = x in (0, cells - 1) or y in (0, cells - 1)
                finder = (
                    (x < 4 and y < 4) or
                    (x >= cells - 4 and y < 4) or
                    (x < 4 and y >= cells - 4)
                )
                if border:
                    draw_cell(x, y, "#1e1f22")
                elif finder:
                    draw_cell(x, y, "#1e1f22" if (x + y) % 2 == 0 else "#ffffff")
                else:
                    byte = digest[(bit_index // 8) % len(digest)]
                    bit = (byte >> (bit_index % 8)) & 1
                    draw_cell(x, y, "#1e1f22" if bit else "#ffffff")
                    bit_index += 1
        painter.end()
        return pix

    def _show_verify_dialog(self, conv_id: int) -> None:
        """Show a modal safety-number verification dialog for *conv_id*."""
        conv_id = int(conv_id or 0)
        is_group_conv = getattr(self, "_is_group_conv", lambda _cid: False)
        if is_group_conv(conv_id):
            QMessageBox.information(
                self._chat,
                "Not Available",
                "Group identity is checked through MLS membership state. "
                "Review individual member identities from their profiles.",
            )
            return
        fp = self._safety_fingerprint_for_conv(conv_id)
        if not fp:
            QMessageBox.information(
                self._chat, "Not Available",
                "Key fingerprint not yet available.\n"
                "Open the conversation first so that the key exchange completes.",
            )
            return
        already = self._conv_verified.get(conv_id, False)
        peer_uid = self._peer_uid_for_conv(conv_id)
        audit = self._crypto_session().load_identity_audit(peer_uid) if peer_uid else {}
        auditor_state = self._crypto_session().load_auditor_state()
        short_code = self._safety_short_code(fp)

        dlg = QDialog(self._chat)
        dlg.setWindowTitle("Verify Conversation Identity")
        dlg.setMinimumSize(600, 520)
        outer_layout = QVBoxLayout(dlg)
        outer_layout.setSpacing(8)
        scroll = QScrollArea(dlg)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border:none; background:#313338; }")
        content = QWidget()
        scroll.setWidget(content)
        outer_layout.addWidget(scroll, 1)
        layout = QVBoxLayout(content)
        layout.setSpacing(12)

        audit_status = str(audit.get("status", "unknown")).replace("_", " ")
        if already:
            status_text = "Verified"
        elif any(k in audit_status for k in ("changed", "mismatch", "unavailable")):
            status_text = f"Not verified - {audit_status}"
        else:
            status_text = "Not verified"
        status = QLabel(status_text)
        status.setAlignment(Qt.AlignCenter)
        status.setStyleSheet(
            "QLabel { padding:6px 10px; border-radius:6px; font-weight:700; "
            + ("color:#1e1f22; background:#57f287;" if already else
               "color:#1e1f22; background:#fee75c;")
            + " }"
        )
        layout.addWidget(status)

        intro = QLabel(
            "Compare this code with your contact through a channel outside "
            "SecChat, such as a call or an in-person check. If the code does "
            "not match, do not trust the conversation identity."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        lbl_short_title = QLabel("Short check code")
        lbl_short_title.setStyleSheet("color:#72767d; font-weight:600;")
        layout.addWidget(lbl_short_title)

        lbl_short = QLabel(short_code)
        lbl_short.setObjectName("safetyShortCode")
        lbl_short.setFont(QFont("Courier New", 22, QFont.Bold))
        lbl_short.setAlignment(Qt.AlignCenter)
        lbl_short.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lbl_short.setStyleSheet(
            "QLabel { color:#f2f3f5; background:#1e1f22; padding:12px; "
            "border-radius:8px; letter-spacing:1px; }"
        )
        layout.addWidget(lbl_short)

        visual = QLabel()
        visual.setAlignment(Qt.AlignCenter)
        visual.setPixmap(self._safety_visual_code(fp))
        visual.setToolTip(
            "Visual check code generated from the same safety number. It is "
            "for quick visual comparison, not a scannable QR code."
        )
        layout.addWidget(visual)

        lbl_full_title = QLabel("Full safety number")
        lbl_full_title.setStyleSheet("color:#72767d; font-weight:600;")
        layout.addWidget(lbl_full_title)

        lbl_fp = QLabel(fp)
        lbl_fp.setFont(QFont("Courier New", 12))
        lbl_fp.setAlignment(Qt.AlignCenter)
        lbl_fp.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lbl_fp.setWordWrap(True)
        layout.addWidget(lbl_fp)

        proof_title = QLabel("Identity transparency")
        proof_title.setStyleSheet("color:#72767d; font-weight:600;")
        layout.addWidget(proof_title)

        checkpoint = audit.get("checkpoint") or {}
        proof_lines = [
            f"Audit status: {audit_status}",
            f"Identity version: {App._identity_version_label(audit.get('identity_version'))}",
        ]
        if checkpoint:
            proof_lines.append(
                f"Log head: size {checkpoint.get('tree_size', '?')} / "
                f"{str(checkpoint.get('root_hash', ''))[:16]}...")
        global_cp = auditor_state.get("checkpoint") or {}
        if global_cp:
            proof_lines.append(
                f"Pinned account log: size {global_cp.get('tree_size', '?')} / "
                f"{str(global_cp.get('root_hash', ''))[:16]}...")
            proof_lines.append(
                "Cross-contact checkpoint pinning is active on this device.")
        if audit.get("last_error"):
            proof_lines.append(
                f"Last warning: {App._audit_error_detail_text(audit)}")
        if auditor_state.get("last_error"):
            proof_lines.append(
                "Checkpoint warning: "
                f"{App._audit_error_detail_text(auditor_state)}")
        proof_lbl = QLabel("\n".join(proof_lines))
        proof_lbl.setWordWrap(True)
        proof_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        proof_lbl.setStyleSheet(
            "QLabel { color:#b5bac1; background:#2b2d31; padding:10px; "
            "border-radius:6px; }"
        )
        layout.addWidget(proof_lbl)

        history = list(audit.get("history") or [])[-5:]
        if history:
            hist_title = QLabel("Identity history")
            hist_title.setStyleSheet("color:#72767d; font-weight:600;")
            layout.addWidget(hist_title)
            for item in history:
                seen = item.get("created_at") or time.strftime(
                    "%Y-%m-%d %H:%M:%S",
                    time.localtime(int(item.get("seen_at", 0) or 0)),
                )
                text = (
                    f"{App._identity_version_label(item.get('identity_version'))} - "
                    f"{item.get('event_type', 'seen')} - {seen} - "
                    f"{item.get('device_label', 'primary device')}\n"
                    f"{item.get('safety_number', '')}"
                )
                row = QLabel(text)
                row.setWordWrap(True)
                row.setTextInteractionFlags(Qt.TextSelectableByMouse)
                row.setStyleSheet(
                    "QLabel { color:#dbdee1; background:#313338; padding:8px; "
                    "border-radius:6px; }"
                )
                layout.addWidget(row)

        chk = QCheckBox("The code matches what my contact sees")
        chk.setToolTip(
            "Only check this after comparing the short code or full safety "
            "number through a channel outside SecChat."
        )
        chk.setChecked(already)
        layout.addWidget(chk)

        action_note = QLabel(
            "Mark Verified means you personally confirmed the code through a "
            "different channel. Continue Unverified allows messaging, but the "
            "conversation remains marked as not verified."
        )
        action_note.setWordWrap(True)
        action_note.setStyleSheet(
            "QLabel { color:#b5bac1; background:#2b2d31; padding:8px; "
            "border-radius:6px; }"
        )
        layout.addWidget(action_note)

        btns = QDialogButtonBox()
        btn_verify = QPushButton("Mark Verified")
        btn_unverify = QPushButton("Continue Unverified")
        btn_cancel = QPushButton("Cancel")
        btn_verify.setToolTip(
            "Use only after the code matches what your contact sees outside SecChat."
        )
        btn_unverify.setToolTip(
            "Continue without trusting the identity. The conversation badge stays unverified."
        )
        btn_verify.setEnabled(chk.isChecked())
        chk.toggled.connect(btn_verify.setEnabled)
        btns.addButton(btn_verify, QDialogButtonBox.AcceptRole)
        btns.addButton(btn_unverify, QDialogButtonBox.DestructiveRole)
        btns.addButton(btn_cancel, QDialogButtonBox.RejectRole)
        btn_verify.clicked.connect(lambda: dlg.done(QDialog.Accepted))
        btn_unverify.clicked.connect(lambda: dlg.done(2))
        btn_cancel.clicked.connect(dlg.reject)
        outer_layout.addWidget(btns)

        result = dlg.exec_()
        if result == QDialog.Accepted:
            self._save_verified(conv_id, True)
            if peer_uid:
                self._crypto_session().mark_identity_reviewed(peer_uid, verified=True)
            self._chat.set_fingerprint(fp, verified=True)
            self._refresh_security_ui(conv_id)
            self._retry_identity_blocked_key_work(peer_uid)
        elif result == 2:
            self._save_verified(conv_id, False)
            if peer_uid:
                self._crypto_session().mark_identity_reviewed(peer_uid, verified=False)
            self._chat.set_fingerprint(fp, verified=False)
            self._refresh_security_ui(conv_id)
            self._retry_identity_blocked_key_work(peer_uid)

    # â”€â”€ Operational hardening helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _cleanup_conv_state(self, conv_id: int) -> None:
        self._seen_msg_ids.pop(conv_id, None)
        self._crypto_session().cleanup_conversation_state(conv_id)

    # â”€â”€ dispatch table â”€â”€

    _MSG_HANDLERS = {
        "ok":                      _handle_ok,
        "error":                   _handle_error,
        "session_replaced":        _handle_session_replaced,
        "friends_list":            _handle_friends_list,
        "friend_requests":         _handle_friend_requests,
        "inbox":                   _handle_inbox,
        "search_result":           _handle_search_result,
        "message":                 _handle_message,
        "history":                 _handle_history,
        "friend_request_received": _handle_friend_request_received,
        "friend_accepted":         _handle_friend_accepted,
        "group_created":           _handle_group_created,
        "group_change_prepared":   _handle_group_change_prepared,
        "group_change_applied":    _handle_group_change_applied,
        "mls_key_packages_uploaded": _handle_mls_key_packages_uploaded,
        "mls_key_package":         _handle_mls_key_package,
        "mls_handshake":           _handle_mls_handshake,
        "dm_ready":                _handle_dm_ready,
        "added_to_group":          _handle_added_to_group,
        "member_added":            _handle_member_added,
        "friend_removed":          _handle_friend_removed,
        "pqxdh_bundle":            _handle_pqxdh_bundle,
        "my_keys":                 _handle_my_keys,
        "pqxdh_status":            _handle_pqxdh_status,
        "profile":                 _handle_profile,
        "message_edited":          _handle_message_edited,
        "message_deleted":         _handle_message_deleted,
        "group_disbanded":         _handle_group_disbanded,
        "profile_updated":         _handle_profile_updated,
        "privacy_settings":        _handle_privacy_settings,
        "blocked_list":            _handle_blocked_list,
        "group_info":              _handle_group_info,
        "pinned_messages":         _handle_pinned_messages,
        "presence":                _handle_presence,
        "message_pinned":          _handle_message_pinned,
        "message_unpinned":        _handle_message_unpinned,
        "reaction_added":          _handle_reaction_added,
        "reaction_removed":        _handle_reaction_removed,
        "typing_start":            _handle_typing_start,
        "typing_stop":             _handle_typing_stop,
        "identity_changed":        _handle_identity_changed,
        "safety_number_changed":   _handle_safety_number_changed,
        "disappearing_updated":    _handle_ui_refresh,
        "member_left":             _handle_ui_refresh,
        "member_removed":          _handle_member_removed,
        "member_role_changed":     _handle_ui_refresh,
        "group_info_updated":      _handle_ui_refresh,
    }

    # ================================================================ key helpers

    # â”€â”€ Ed25519 identity key helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _identity_key_path(self) -> str:
        """Đường dẫn tệp lưu khóa danh tính Ed25519 cục bộ."""
        return self._crypto_session().identity_key_path()

    def _save_identity_key(self) -> None:
        """Lưu khóa danh tính Ed25519 xuống đĩa."""
        self._crypto_session().save_identity_key()

    def _load_or_create_identity_key(self) -> None:
        self._crypto_session().load_or_create_identity_key()

    # ── Identity key bundle upload ───────────────────────────────────────────

    def _upload_identity_bundle(self):
        """Công bố lại bundle identity Ed25519 lên server (đường khôi phục)."""
        try:
            cmd = self._crypto_session().new_identity_key_record_command()
            self._safe_send(cmd)
        except Exception as exc:
            _logger.warning("Key bundle generation failed: %s", exc)
    def _upload_current_key_bundle(self):
        """Upload bundle khóa công khai hiện tại lên server."""
        cmd = self._crypto_session().current_identity_key_record_command()
        if cmd:
            self._safe_send(cmd)
    def _rotate_identity(self):
        """Xoay (tạo mới) khóa danh tính và công bố lại."""
        if not self._session_active or not self._master_key:
            QMessageBox.warning(self._chat, "Safety Key", "You are not logged in.")
            return
        reply = QMessageBox.question(
            self._chat,
            "Rotate Safety Key",
            "Rotate your safety key now?\n\n"
            "Your existing conversations stay encrypted, but contacts will see "
            "a safety number change and should verify you again. Do this after "
            "a suspected key compromise, device migration, or when you want a "
            "fresh identity/prekey bundle.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        try:
            rotate_cmd, prekey_cmd = self._crypto_session().rotate_identity_commands()
            self._identity_rotation_pending = True
            self._pqxdh_publish_blocked = False
            self._pqxdh_bundle_ready = False
            self._kem_ready = False
            self._pending_pqxdh_bundle_upload = bool(prekey_cmd)
            self._safe_send(rotate_cmd)
            if prekey_cmd:
                if not self._safe_send(prekey_cmd):
                    self._pending_pqxdh_bundle_upload = False
        except Exception as exc:
            self._identity_rotation_pending = False
            self._pending_pqxdh_bundle_upload = False
            _logger.exception("Identity rotation failed")
            QMessageBox.warning(
                self._chat, "Safety Key",
                f"Could not rotate the safety key:\n{exc}",
            )
    def _change_password(self, current_password: str, new_password: str):
        """Bắt đầu luồng đổi mật khẩu."""
        if not self._session_active or not self._master_key:
            QMessageBox.warning(self._chat, "Change Password", "You are not logged in.")
            return
        credential = self._auth_credential or self._account_username
        if not credential or not self._account_username:
            QMessageBox.warning(self._chat, "Change Password",
                                "Cannot determine the login credential for this session.")
            return
        self._password_change_pending = {
            "old_master": self._master_key,
            "new_master": derive_master_key(new_password, self._account_username),
        }
        self._safe_send({
            "type": "change_password",
            "old_password": hash_password(current_password, credential),
            "new_password": hash_password(new_password, credential),
        })

    def _complete_password_change(self):
        """Hoàn tất đổi mật khẩu sau khi server chấp nhận."""
        pending = self._password_change_pending
        self._password_change_pending = None
        if not pending:
            return
        old_master = pending["old_master"]
        new_master = pending["new_master"]
        try:
            self._rewrap_local_e2ee_state(old_master, new_master)
            self._master_key = new_master
            self._upload_current_key_bundle()
            QMessageBox.information(
                self._chat, "Change Password", "Password changed successfully.")
        except Exception as exc:
            _logger.exception("Local E2EE rewrap after password change failed")
            QMessageBox.warning(
                self._chat, "Change Password",
                "Password changed on the server, but local encrypted state could "
                f"not be re-wrapped:\n{exc}")

    def _rewrap_local_e2ee_state(self, old_master: bytes, new_master: bytes):
        """Mã hóa lại trạng thái E2EE cục bộ bằng khóa mới (sau đổi mật khẩu)."""
        self._crypto_session().rewrap_local_state(old_master, new_master)

    # ================================================================ outgoing actions

    def _encrypt_for_conv(self, conv_id: int, body: str):
        """Mã hóa một body để gửi vào hội thoại (DM hoặc group)."""
        try:
            if (not self._is_group_conv(conv_id)
                    and self.__dict__.get("_pqxdh_publish_blocked")):
                raise CryptoStateError(
                    "This VNC cannot publish a matching SecChat key bundle "
                    "for this account yet. Restore an E2EE backup on this VNC "
                    "or rotate the safety key deliberately before starting a "
                    "new encrypted DM segment."
                )
            return self._crypto_session().encrypt_for_conv(conv_id, body)
        except CryptoStateError as exc:
            title = "Encryption not ready"
            detail = str(exc)
            if self._is_group_conv(conv_id):
                detail = detail or "Group epoch state is not initialized yet."
            else:
                self._ensure_pqxdh_dm_session(conv_id)
                detail = detail or "DM key exchange is not complete yet."
            QMessageBox.warning(self._chat, title, detail + " Please wait a moment and try again.")
            return None
    def _send_message(self, conv_id: int, body: str, reply_to_message_id: int = 0):
        """Mã hóa và gửi một tin nhắn văn bản."""
        if not self._require_identity_review_before_send(conv_id):
            self._chat.show_send_failed(
                conv_id, body,
                "This conversation is not verified yet.")
            return
        payload = self._encrypt_for_conv(conv_id, body)
        if not payload:
            self._chat.show_send_failed(
                conv_id, body,
                "Encryption is not ready yet. Retry after the key exchange finishes.")
            return
        pending_id = self._chat.show_send_pending(
            conv_id, body, reply_to_message_id=int(reply_to_message_id or 0))
        self._cache_outgoing_wire(conv_id, payload, self._my_uid, body)
        # Cache plaintext for the self-echo branch in _handle_message
        self._self_pending_plaintexts.setdefault(conv_id, deque()).append(body)
        self.__dict__.setdefault("_self_pending_ids", {}).setdefault(
            conv_id, deque()).append(pending_id)
        msg = {
            "type":            "message",
            "conversation_id": int(conv_id),
            "body":            payload,
        }
        if int(reply_to_message_id or 0) > 0:
            msg["reply_to_message_id"] = int(reply_to_message_id)
        ok = self._safe_send(msg)
        if not ok:
            self._chat.remove_pending_send(conv_id, pending_id=pending_id)
            try:
                self._self_pending_plaintexts.get(conv_id, deque()).pop()
            except Exception:
                pass
            try:
                self.__dict__.setdefault("_self_pending_ids", {}).get(
                    conv_id, deque()).pop()
            except Exception:
                pass
            self._chat.show_send_failed(
                conv_id, body, "Connection is not available. Retry after reconnecting.")

    def _send_reply_message(self, conv_id: int, reply_to_message_id: int, body: str):
        """Mã hóa và gửi một tin trả lời (reply)."""
        self._send_message(
            int(conv_id), body,
            reply_to_message_id=int(reply_to_message_id or 0))

    def _send_file(self, conv_id: int, file_path: str):
        """Mã hóa và gửi một tệp đính kèm."""
        if not self._require_identity_review_before_send(conv_id):
            self._chat.show_send_failed(
                conv_id, os.path.basename(file_path) if file_path else "file",
                "This conversation is not verified yet.",
                file_path=file_path)
            return
        try:
            file_path = os.path.abspath(file_path)
            sz = os.path.getsize(file_path)
            if sz > MAX_FILE_SIZE:
                QMessageBox.warning(self._chat, "Error",
                                    f"File too large ({sz / 1024:.1f} KB). "
                                    f"Max {MAX_FILE_SIZE // 1024} KB.")
                return
            if sz == 0:
                QMessageBox.warning(self._chat, "Error", "File is empty.")
                return
            name = os.path.basename(file_path)
            mime = _guess_mime(name)
            with open(file_path, "rb") as f:
                raw = f.read()
            b64 = base64.b64encode(raw).decode("ascii")
            meta = json.dumps({"name": name, "mime": mime, "size": sz}, ensure_ascii=True)
            body = f"FILE:{meta}:{b64}"
            payload = self._encrypt_for_conv(conv_id, body)
            if not payload:
                self._chat.show_send_failed(
                    conv_id, body,
                    "Encryption is not ready yet. Retry after the key exchange finishes.",
                    file_path=file_path)
                return
            pending_id = self._chat.show_send_pending(
                conv_id, body, file_path=file_path)
            self._self_pending_plaintexts.setdefault(conv_id, deque()).append(body)
            self.__dict__.setdefault("_self_pending_ids", {}).setdefault(
                conv_id, deque()).append(pending_id)
            ok = self._safe_send({
                "type":            "message",
                "conversation_id": int(conv_id),
                "body":            payload,
            })
            if not ok:
                self._chat.remove_pending_send(conv_id, pending_id=pending_id)
                try:
                    self._self_pending_plaintexts.get(conv_id, deque()).pop()
                except Exception:
                    pass
                try:
                    self.__dict__.setdefault("_self_pending_ids", {}).get(
                        conv_id, deque()).pop()
                except Exception:
                    pass
                self._chat.show_send_failed(
                    conv_id, body,
                    "Connection is not available. Retry after reconnecting.",
                    file_path=file_path)
        except Exception as e:
            QMessageBox.warning(self._chat, "Error", f"Cannot send file:\n{e}")

    def _get_history(self, conv_id: int):
        """Yêu cầu server gửi lịch sử tin nhắn của hội thoại."""
        if self._is_group_conv(conv_id):
            self._safe_send({"type": "get_mls_handshake", "conversation_id": conv_id})
            self._safe_send({"type": "history", "conversation_id": conv_id})
            self._chat.set_fingerprint("", verified=False)
            self._refresh_security_ui(conv_id)
            return
        self._safe_send({"type": "history", "conversation_id": conv_id})
        self._ensure_pqxdh_dm_session(conv_id)
        # Update safety-number fingerprint + verified status when switching conversations
        fp = self._safety_fingerprint_for_conv(conv_id)
        if not fp and conv_id in self._conv_verified:
            # verified status already known; fingerprint will arrive with pubkey
            pass
        verified = self._load_verified(conv_id)
        self._chat.set_fingerprint(fp, verified=verified)
        self._refresh_security_ui(conv_id)

    def _search_user(self, query: str):
        """Tìm người dùng theo từ khóa."""
        self._safe_send({"type": "search_user", "query": query})

    def _friend_request(self, tid: int):
        """Gửi lời mời kết bạn."""
        self._safe_send({"type": "friend_request", "target_id": tid})

    def _friend_accept(self, rid: int):
        """Chấp nhận một lời mời kết bạn."""
        self._safe_send({"type": "friend_accept", "requester_id": rid})

    def _friend_reject(self, oid: int):
        """Từ chối một lời mời kết bạn."""
        self._safe_send({"type": "friend_reject", "other_id": oid})
        QTimer.singleShot(500, lambda: self._safe_send({"type": "get_requests"}))

    def _create_group(self, name: str, members: list):
        """Tạo một nhóm chat mới (khởi tạo group MLS)."""
        self._pending_create_members[name] = list(members)
        self._pending_mls_prepare.append({
            "operation": "create_group",
            "name": name,
            "members": [int(uid) for uid in members],
        })
        self._safe_send({
            "type": "prepare_group_change",
            "operation": "create_group",
            "name": name,
            "members": members,
        })

    def _add_to_group(self, gid: int, uid: int):
        """Thêm một thành viên vào nhóm."""
        self._pending_mls_prepare.append({
            "operation": "add_member",
            "conversation_id": int(gid),
            "target_user_id": int(uid),
        })
        self._safe_send({
            "type": "prepare_group_change",
            "operation": "add_member",
            "conversation_id": int(gid),
            "user_id": int(uid),
        })

    def _start_dm(self, uid: int):
        """Bắt đầu một hội thoại DM với một người dùng."""
        self._safe_send({"type": "start_dm", "user_id": uid})

    def _unfriend(self, oid: int):
        """Hủy kết bạn với một người dùng."""
        self._safe_send({"type": "unfriend", "other_id": oid})
        QTimer.singleShot(500, lambda: self._safe_send({"type": "get_friends"}))
        QTimer.singleShot(500, lambda: self._safe_send({"type": "get_inbox"}))

    # â”€â”€ Profile / inbox / message-edit actions â”€â”€

    def _fetch_avatar(self, user_id: int):
        """Silent avatar fetch â€” no dialog will open when server replies."""
        if user_id in self._avatar_fetch_uids:
            return
        self._avatar_fetch_uids.add(user_id)
        self._safe_send({"type": "get_profile", "user_id": user_id})

    def _view_profile(self, user_id: int):
        """Yêu cầu xem hồ sơ của một người dùng."""
        self._profile_edit_mode = False
        self._safe_send({"type": "get_profile", "user_id": user_id})

    def _edit_profile(self):
        """Mở chỉnh sửa hồ sơ của chính mình."""
        self._profile_edit_mode = True
        self._safe_send({"type": "get_profile", "user_id": 0})

    def _disband_group(self, conv_id: int):
        """Giải tán một nhóm (chỉ admin)."""
        self._safe_send({"type": "disband_group", "group_id": conv_id})

    def _edit_message(self, conv_id: int, msg_id: int, new_body: str):
        """Chỉnh sửa nội dung một tin đã gửi."""
        payload = self._encrypt_for_conv(conv_id, new_body)
        if not payload:
            return
        self._self_pending_plaintexts.setdefault(conv_id, deque()).append(new_body)
        self._safe_send({
            "type":       "edit_message",
            "message_id": msg_id,
            "new_body":   payload,
        })

    def _delete_message(self, conv_id: int, msg_id: int):
        self._safe_send({"type": "delete_message", "message_id": msg_id})

    # ================================================================ polling

    def _poll_status(self):
        """Periodic refresh for online/offline status."""
        if self._session_active:
            self._safe_send({"type": "get_friends"})
            self._safe_send({"type": "get_inbox"})

    def _do_inbox_refresh(self):
        self._safe_send({"type": "get_inbox"})

    # ================================================================ logout

    def _logout_local(self, *, notify_server: bool, status: str = ""):
        clear_cache = bool(self._crypto_session().cache_clear_on_logout)
        if notify_server and self._session_active and self._ws:
            try:
                self._ws.send({"type": "logout"})
            except Exception:
                pass
        if clear_cache:
            self._crypto_session().clear_message_cache()
        self._session_active = False
        self._session_gen += 1
        self._poll_timer.stop()
        self._inbox_refresh.stop()
        self._teardown_ws()
        self._init_session_state()
        self._chat.reset()
        self._stack.setCurrentIndex(0)
        self._login.set_status(status)
        self._register.set_status("")

    def _logout(self):
        # Notify server before closing so it can clear auth and mark the user offline.
        self._logout_local(notify_server=True)

    def closeEvent(self, ev):
        """Override Qt: dọn dẹp tài nguyên khi đóng cửa sổ."""
        ev.ignore()
        self.showMinimized()
