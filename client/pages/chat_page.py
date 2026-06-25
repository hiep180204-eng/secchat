"""Giao diện chat của client SecChat (trang chính sau khi đăng nhập).

``ChatPage`` là widget trung tâm: sidebar danh sách hội thoại/bạn bè, khung tin
nhắn (mỗi tin một row widget trong QScrollArea), ô soạn tin và các thao tác trên
tin (edit/delete/reaction/pin/reply/forward/file).

Trang này chỉ lo HIỂN THỊ và phát signal khi người dùng thao tác; mọi logic mạng
và crypto do controller ``App`` cùng ``CryptoSession`` đảm nhận.
"""

import os
import base64
import json
import tempfile
from PyQt5.QtWidgets import (
    QPlainTextEdit, QWidget, QFrame, QVBoxLayout, QHBoxLayout, QGridLayout,
    QPushButton, QLineEdit, QLabel, QSizePolicy,
    QListWidget, QListWidgetItem, QScrollArea,
    QStackedWidget, QDialog, QMessageBox, QApplication,
    QFileDialog, QShortcut, QDialogButtonBox, QInputDialog, QComboBox, QCheckBox,
)
from PyQt5.QtCore import QSize, Qt, pyqtSignal, QTimer, QPoint, QEvent
from PyQt5.QtGui  import QKeySequence, QCursor, QPixmap, QColor, QBrush
from client.utils   import ts_short
from client.components.message_list import MessageListView
from client.components.scrolling import capture_vertical_scroll, restore_vertical_scroll

# Font stack có hỗ trợ Unicode cho cả Windows và container Linux. Điều này quan
# trọng vì UI có tiếng Việt, tên file và reaction emoji; nếu thiếu font phù hợp
# text sẽ bị ô vuông hoặc sai dấu.
import platform as _plat
if _plat.system() == "Windows":
    _FONT_FAMILY = '"Segoe UI", "Microsoft YaHei", "Yu Gothic UI", "Malgun Gothic", sans-serif'
else:
    _FONT_FAMILY = '"Noto Sans CJK SC", "Noto Sans", "Liberation Sans", "DejaVu Sans", sans-serif'


from client.dialogs import CreateGroupDialog, AddToGroupDialog


class ChatInput(QPlainTextEdit):
    """Ô nhập chat có hỗ trợ IME và gửi bằng Enter.

    QTextEdit mặc định khó phân biệt Enter để gửi với Enter đang dùng cho bộ gõ
    Telex/CJK. Lớp nhỏ này chỉ emit ``sig_submit`` khi người dùng thật sự nhấn
    Enter ngoài quá trình compose, còn Shift+Enter vẫn xuống dòng.
    """
    sig_submit = pyqtSignal()

    def __init__(self, parent=None):
        """Khởi tạo đối tượng và thiết lập trạng thái/giao diện ban đầu."""
        super().__init__(parent)
        # Bật IME để gõ tiếng Việt Telex/CJK ổn định trong Qt.
        self.setAttribute(Qt.WA_InputMethodEnabled, True)
        self.setAttribute(Qt.WA_KeyCompression, False)

    def keyPressEvent(self, event):
        # Khi IME đang compose, không coi Enter là gửi tin. Nếu không, người dùng
        # có thể bị gửi message giữa lúc đang hoàn tất ký tự có dấu.
        if event.key() == Qt.Key_Return and not (event.modifiers() & Qt.ShiftModifier):
            self.sig_submit.emit()
            return
        super().keyPressEvent(event)

    def inputMethodQuery(self, query):
        """Giữ thông tin cursor/widget chính xác cho IME."""
        return super().inputMethodQuery(query)


class _ClickableLabel(QLabel):
    """QLabel có thể click, dùng cho avatar/tên/profile nhỏ trong UI."""
    clicked = pyqtSignal()

    def __init__(self, text="", parent=None):
        """Khởi tạo đối tượng và thiết lập trạng thái/giao diện ban đầu."""
        super().__init__(text, parent)
        self.setCursor(Qt.PointingHandCursor)

    def mousePressEvent(self, event):
        """Override Qt: xử lý sự kiện nhấn chuột."""
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


class _SidebarRow(QPushButton):
    """Một dòng trong sidebar (hội thoại/bạn bè): click trái để mở, click phải mở menu ngữ cảnh."""
    def __init__(self, on_left_click=None, on_context_menu=None, parent=None):
        """Khởi tạo đối tượng và thiết lập trạng thái/giao diện ban đầu."""
        super().__init__(parent)
        self._on_left_click = on_left_click
        self._on_context_menu = on_context_menu
        self.setText("")
        self.setFlat(True)
        self.setFocusPolicy(Qt.NoFocus)

    def bind_click_surface(self, widget):
        """Gắn xử lý click cho một widget bề mặt (ví dụ avatar/nhãn)."""
        widget.setAttribute(Qt.WA_TransparentForMouseEvents, False)
        widget.installEventFilter(self)
        if self._on_left_click:
            widget.setCursor(Qt.PointingHandCursor)

    def _handle_mouse_press(self, event, global_pos=None) -> bool:
        """Xử lý sự kiện nhấn chuột nội bộ của widget."""
        if event.button() == Qt.LeftButton and self._on_left_click:
            self._on_left_click()
            event.accept()
            return True
        if event.button() == Qt.RightButton and self._on_context_menu:
            menu_pos = QPoint(global_pos or self.mapToGlobal(event.pos()))
            QTimer.singleShot(
                80,
                lambda pos=menu_pos: self._on_context_menu(QPoint(pos)),
            )
            event.accept()
            return True
        return False

    def eventFilter(self, obj, event):
        """Override Qt: lọc sự kiện cho đối tượng đang theo dõi."""
        if event.type() == QEvent.MouseButtonPress:
            try:
                if self._handle_mouse_press(event, obj.mapToGlobal(event.pos())):
                    return True
            except RuntimeError:
                return False
        if event.type() == QEvent.ContextMenu and self._on_context_menu:
            try:
                self._on_context_menu(QPoint(event.globalPos()))
                event.accept()
                return True
            except RuntimeError:
                return False
        return super().eventFilter(obj, event)

    def mousePressEvent(self, event):
        """Override Qt: xử lý sự kiện nhấn chuột."""
        if self._handle_mouse_press(event):
            return
        super().mousePressEvent(event)

    def contextMenuEvent(self, event):
        """Override Qt: mở menu ngữ cảnh khi click phải."""
        if self._on_context_menu:
            self._on_context_menu(QPoint(event.globalPos()))
            event.accept()
            return
        super().contextMenuEvent(event)


MAX_FILE_SIZE = 1 * 1024 * 1024    # 1 MB sau khi tính overhead E2EE/base64

IMAGE_MIMES = {"image/png", "image/jpeg", "image/jpg", "image/gif",
               "image/bmp", "image/webp", "image/svg+xml"}
VIDEO_MIMES = {"video/mp4", "video/webm", "video/avi", "video/mov",
               "video/mkv", "video/quicktime", "video/x-msvideo",
               "video/x-matroska"}

SIDEBAR_ROW_HEIGHT = 58
SIDEBAR_HIDDEN_ITEM_BRUSH = QBrush(QColor(0, 0, 0, 0))
SIDEBAR_TEXT_ROLE = Qt.UserRole + 40
IDENTITY_REVIEW_STATUSES = (
    "unverified", "reviewed_unverified", "key_changed",
    "audit_mismatch", "audit_unavailable",
)
REACTION_EMOJIS = [
    "👍", "👎", "❤️", "😂", "😮", "😢", "😡", "🎉",
    "🔥", "👏", "🙏", "✅", "👀", "💯", "🤔", "👌",
    "🚀", "✨", "🙌", "😊", "😎", "😅", "😭", "😤",
    "🤝", "💪", "⭐", "🌟", "📌", "🫡", "👋", "💬",
    "🔒", "🔑", "🛡️", "⚠️", "📎", "🧠", "☕", "🎯",
    "🥳", "😇", "🙃", "😐", "😬", "🤯", "😍", "😴",
]

def _guess_mime(name: str) -> str:
    ext = os.path.splitext(name)[1].lower()
    m = {
        ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".gif": "image/gif", ".bmp": "image/bmp", ".webp": "image/webp",
        ".svg": "image/svg+xml",
        ".mp4": "video/mp4", ".webm": "video/webm", ".avi": "video/x-msvideo",
        ".mov": "video/quicktime", ".mkv": "video/x-matroska",
        ".pdf": "application/pdf", ".zip": "application/zip",
        ".txt": "text/plain", ".doc": "application/msword",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }
    return m.get(ext, "application/octet-stream")


class ChatPage(QWidget):
    """Màn hình chat chính sau khi đăng nhập.

    ChatPage chỉ làm UI và phát signal. Nó không gọi WebSocket trực tiếp và
    không tự xử lý crypto. Thiết kế này giữ ranh giới rõ: ChatPage hiển thị,
    App điều phối network, CryptoSession xử lý E2EE/local state.
    """

    # Các signal là hợp đồng giữa UI và App. UI không biết command WebSocket cụ
    # thể, chỉ báo “người dùng muốn gửi tin”, “muốn xem history”, “muốn verify”.
    sig_send           = pyqtSignal(int, str)   # conv_id, body
    sig_send_reply     = pyqtSignal(int, int, str) # conv_id, reply_to_msg_id, body
    sig_send_file      = pyqtSignal(int, str)   # conv_id, file_path
    sig_history        = pyqtSignal(int)         # conv_id
    sig_search         = pyqtSignal(str)
    sig_friend_request = pyqtSignal(int)         # target_id
    sig_friend_accept  = pyqtSignal(int)         # requester_id
    sig_friend_reject  = pyqtSignal(int)         # other_id
    sig_get_friends    = pyqtSignal()
    sig_get_requests   = pyqtSignal()
    sig_get_inbox      = pyqtSignal()
    sig_create_group   = pyqtSignal(str, list)   # name, [user_id]
    sig_add_to_group   = pyqtSignal(int, int)    # group_id, user_id
    sig_start_dm       = pyqtSignal(int)         # user_id
    sig_unfriend       = pyqtSignal(int)         # other_id
    sig_logout         = pyqtSignal()
    sig_change_password = pyqtSignal(str, str)   # current_password, new_password
    sig_command        = pyqtSignal(dict)         # passthrough UI command
    sig_clear_local_cache = pyqtSignal()          # delete local plaintext cache files
    sig_clear_conversation_cache = pyqtSignal(int) # delete one conversation cache
    sig_update_cache_policy = pyqtSignal(dict)    # local plaintext-cache policy
    sig_update_conversation_cache_policy = pyqtSignal(int, bool)

    # ── Profile / inbox / message-edit signals ───────────────────────────────
    sig_view_profile   = pyqtSignal(int)          # user_id → request profile for viewing
    sig_edit_profile   = pyqtSignal()             # request own profile for editing
    sig_disband_group  = pyqtSignal(int)          # conv_id (group_id) → disband
    sig_edit_message   = pyqtSignal(int, int, str) # conv_id, msg_id, new_body
    sig_delete_message = pyqtSignal(int, int)     # conv_id, msg_id
    sig_get_avatar     = pyqtSignal(int)          # user_id → silent avatar fetch
    # Identity verification dialog
    sig_verify_identity = pyqtSignal(int)         # conv_id → open safety-number dialog
    sig_rotate_identity = pyqtSignal()            # rotate own safety key bundle

    def __init__(self):
        """Khởi tạo đối tượng và thiết lập trạng thái/giao diện ban đầu."""
        super().__init__()
        self.me              = ""
        self.my_id           = 0
        self.active_conv_id  = 0
        # hist: conv_id -> [{"sender_id", "body", "ts", "msg_id", "edited", "deleted"}]
        self.hist            = {}
        self._history_loaded_convs = set()
        self._history_loading_convs = set()
        self._message_widgets = {}
        self._message_search_query = ""
        self._failed_send_counter = 0
        self._notifications_enabled = True
        self._local_cache_policy = {
            "enabled": True,
            "ttl_days": 30,
            "clear_on_logout": False,
            "disabled_conversation_ids": [],
        }
        self._security_warnings = {}
        self._conv_security = {}
        self._security_blocked_convs = set()
        self._fingerprint_present = False
        self._fingerprint_verified = False
        self._active_is_group = False
        self._system_event_keys = set()
        self.friends         = {}       # user_id -> user dict
        self.dm_convs        = []
        self.group_convs     = []
        self.current_view    = "chat"
        self._pending_open_conv       = None
        self._pending_open_is_group   = False
        self._pending_requests_count  = 0
        self._temp_dir       = tempfile.mkdtemp(prefix="secchat_")
        self._temp_counter   = 0
        self._disbanded_convs = set()   # conv_ids of disbanded groups
        self._avatar_paths    = {}      # user_id -> temp PNG path
        self._avatar_pending  = set()   # user_ids already requested
        self._unread_convs    = set()   # conv_ids with unread messages
        self._edit_widget     = None    # QFrame overlay for inline edit
        self._editing_msg     = None    # (conv_id, msg_id) being edited
        self._reply_target    = None    # {"conv_id", "msg_id", "preview"}
        self._pending_edit_events = {}   # conv_id -> [edit event dicts]
        self._typing_convs = {}          # conv_id -> {user_id: username}
        self._typing_timers = {}         # (conv_id, user_id) -> QTimer
        self._request_refresh_timers = []
        self._typing_active_sent = False
        self._typing_conv_id = 0
        self._metadata_protection_enabled = False
        self._typing_indicators_enabled = True
        self._last_read_sent = {}        # conv_id -> message_id
        self._pending_read_clear_convs = set()
        self._scroll_to_latest_after_history = set()
        self._active_context_popover = None
        self._context_popover_buttons = []
        self._context_popover_focus_index = -1
        self._typing_idle_timer = QTimer(self)
        self._typing_idle_timer.setSingleShot(True)
        self._typing_idle_timer.setInterval(2500)
        self._typing_idle_timer.timeout.connect(self._send_typing_stop)
        self._build()
        app = QApplication.instance()
        if app is not None:
            app.installEventFilter(self)

    def set_metadata_protection(self, enabled: bool):
        self._metadata_protection_enabled = bool(enabled)
        self._typing_indicators_enabled = not self._metadata_protection_enabled
        # Typing indicator có thể bật/tắt theo metadata protection. Trạng thái
        # đã đọc chỉ được dùng cục bộ để xóa unread, không broadcast cho peer.
        if self._metadata_protection_enabled:
            self._send_typing_stop()

    # ================================================================ build UI

    def _build(self):
        """Dựng toàn bộ giao diện trang chat."""
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_sidebar())
        root.addWidget(self._build_chat_area())

    def _build_sidebar(self) -> QFrame:
        """Dựng sidebar (danh sách hội thoại/bạn bè)."""
        sb = QFrame()
        sb.setObjectName("sidebar")
        sb.setFixedWidth(260)
        sl = QVBoxLayout(sb)
        sl.setContentsMargins(0, 0, 0, 0)
        sl.setSpacing(0)

        # Top bar
        top = QFrame()
        top.setObjectName("topbar")
        top.setFixedHeight(48)
        tl = QHBoxLayout(top)
        tl.setContentsMargins(12, 0, 12, 0)
        title = QLabel("SecChat")
        title.setStyleSheet("color:#fff; font-size:14px; font-weight:700;")
        tl.addWidget(title)
        sl.addWidget(top)

        # Navigation buttons
        self.btn_chat = QPushButton("Chats")
        self.btn_chat.setObjectName("nav_active")
        self.btn_chat.setProperty("testid", "chat.nav.chats")
        self.btn_chat.clicked.connect(lambda: self._switch_view("chat"))
        sl.addWidget(self.btn_chat)

        self.btn_search = QPushButton("Search")
        self.btn_search.setObjectName("nav")
        self.btn_search.setProperty("testid", "chat.nav.search")
        self.btn_search.clicked.connect(lambda: self._switch_view("search"))
        sl.addWidget(self.btn_search)

        self.btn_requests = QPushButton("Requests")
        self.btn_requests.setObjectName("nav")
        self.btn_requests.setProperty("testid", "chat.nav.requests")
        self.btn_requests.clicked.connect(lambda: self._switch_view("requests"))
        sl.addWidget(self.btn_requests)

        # Stacked content pages
        self.content_stack = QStackedWidget()
        self.content_stack.addWidget(self._build_chat_panel())
        self.content_stack.addWidget(self._build_search_panel())
        self.content_stack.addWidget(self._build_requests_panel())
        sl.addWidget(self.content_stack)

        # Bottom user bar
        sl.addWidget(self._build_user_bar())
        return sb

    def _build_chat_panel(self) -> QWidget:
        """Dựng panel chat chính (header + khung tin + ô soạn)."""
        page = QWidget()
        lay  = QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        btn_new_group = QPushButton("+ New Group")
        btn_new_group.setObjectName("ghost")
        btn_new_group.setProperty("testid", "chat.new_group")
        btn_new_group.setStyleSheet(
            "QPushButton#ghost { margin:8px 10px 4px 10px; padding:8px 12px;"
            " text-align:left; border-radius:6px; }"
            "QPushButton#ghost:hover { background:#5d6068; }"
        )
        btn_new_group.clicked.connect(self._show_create_group)
        lay.addWidget(btn_new_group)

        lay.addWidget(self._section_label("DIRECT MESSAGES"))
        self.dm_list = QListWidget()
        self.dm_list.setObjectName("chat.dm_list")
        self._configure_sidebar_list(self.dm_list)
        self.dm_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.dm_list.setTextElideMode(Qt.ElideRight)
        self.dm_list.itemClicked.connect(self._on_dm_click)
        self.dm_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.dm_list.customContextMenuRequested.connect(self._dm_context_menu)
        lay.addWidget(self.dm_list)

        lay.addWidget(self._section_label("GROUPS"))
        self.group_list = QListWidget()
        self.group_list.setObjectName("chat.group_list")
        self._configure_sidebar_list(self.group_list)
        self.group_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.group_list.setTextElideMode(Qt.ElideRight)
        self.group_list.itemClicked.connect(self._on_group_click)
        self.group_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.group_list.customContextMenuRequested.connect(self._group_context_menu)
        lay.addWidget(self.group_list)

        lay.addWidget(self._section_label("FRIENDS"))
        self.friend_list = QListWidget()
        self.friend_list.setObjectName("chat.friend_list")
        self._configure_sidebar_list(self.friend_list)
        self.friend_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.friend_list.setTextElideMode(Qt.ElideRight)
        self.friend_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.friend_list.customContextMenuRequested.connect(self._friend_context_menu)
        lay.addWidget(self.friend_list)

        return page

    def _build_search_panel(self) -> QWidget:
        """Dựng panel tìm kiếm người dùng."""
        page = QWidget()
        lay  = QVBoxLayout(page)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(8)

        row = QHBoxLayout()
        self.e_search = QLineEdit()
        self.e_search.setObjectName("chat.search_input")
        self.e_search.setPlaceholderText("Search users...")
        self.e_search.returnPressed.connect(self._do_search)
        row.addWidget(self.e_search)

        btn_go = QPushButton("Go")
        btn_go.setObjectName("small")
        btn_go.setProperty("testid", "chat.search_go")
        btn_go.setMinimumWidth(40)
        btn_go.setMaximumWidth(50)
        btn_go.clicked.connect(self._do_search)
        row.addWidget(btn_go)
        lay.addLayout(row)

        self.search_results = QListWidget()
        self.search_results.setObjectName("chat.search_results")
        self.search_results.setContextMenuPolicy(Qt.CustomContextMenu)
        self.search_results.customContextMenuRequested.connect(self._search_context_menu)
        lay.addWidget(self.search_results)

        return page

    def _build_requests_panel(self) -> QWidget:
        """Dựng panel danh sách lời mời kết bạn."""
        page = QWidget()
        lay  = QVBoxLayout(page)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(8)

        self.request_list = QListWidget()
        self.request_list.setObjectName("chat.request_list")
        self.request_list.setSpacing(2)
        self.request_list.setUniformItemSizes(False)
        self.request_list.setStyleSheet(
        "QListWidget::item { padding: 0px; margin: 2px 4px; border-radius: 6px; }")
        lay.addWidget(self.request_list)

        return page

    def _build_user_bar(self) -> QFrame:
        """Dựng thanh thông tin người dùng (avatar/tên/menu)."""
        bar = QFrame()
        bar.setFixedHeight(56)
        bar.setStyleSheet("background:#1e1f22; border-top: 1px solid #111214;")
        bl = QHBoxLayout(bar)
        bl.setContentsMargins(12, 0, 12, 0)
        bl.setSpacing(8)

        # Own avatar (32×32, clickable → edit profile)
        self.lbl_my_avatar = QLabel()
        self.lbl_my_avatar.setObjectName("chat.my_avatar")
        self.lbl_my_avatar.setFixedSize(36, 36)
        self.lbl_my_avatar.setCursor(Qt.PointingHandCursor)
        self.lbl_my_avatar.setToolTip("Profile and account settings")
        self.lbl_my_avatar.setStyleSheet(
            "QLabel { border-radius: 18px; }")
        self.lbl_my_avatar.mousePressEvent = lambda _e: self.sig_edit_profile.emit()
        bl.addWidget(self.lbl_my_avatar)

        # Username button — clicking opens edit profile dialog
        self.lbl_me = QPushButton("")
        self.lbl_me.setObjectName("chat.me")
        self.lbl_me.setCursor(Qt.PointingHandCursor)
        self.lbl_me.setToolTip("Profile and account settings")
        self.lbl_me.setStyleSheet(
            "QPushButton { color:#f2f3f5; font-size:13px; font-weight:600;"
            " background:transparent; border:none; text-align:left; padding:2px 4px; }"
            "QPushButton:hover { color:#ffffff; background:#2e3035;"
            " border-radius:4px; }"
        )
        self.lbl_me.clicked.connect(self.sig_edit_profile.emit)
        bl.addWidget(self.lbl_me)
        bl.addStretch()

        btn_logout = QPushButton("Exit")
        btn_logout.setObjectName("ghost")
        btn_logout.setProperty("testid", "chat.exit")
        btn_logout.setMinimumSize(48, 30)
        btn_logout.setMaximumHeight(32)
        btn_logout.setToolTip("Logout")
        btn_logout.clicked.connect(self.sig_logout.emit)
        bl.addWidget(btn_logout)

        return bar

    def _build_chat_area(self) -> QWidget:
        """Dựng vùng cuộn chứa các tin nhắn."""
        rp = QWidget()
        rl = QVBoxLayout(rp)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(0)

        # Header
        hdr = QFrame()
        hdr.setObjectName("header")
        hdr.setFixedHeight(48)
        hl  = QHBoxLayout(hdr)
        hl.setContentsMargins(16, 0, 16, 0)
        title_box = QVBoxLayout()
        title_box.setContentsMargins(0, 0, 0, 0)
        title_box.setSpacing(0)
        self.lbl_chat = QLabel("Select a conversation")
        self.lbl_chat.setObjectName("chat.header.title")
        self.lbl_chat.setStyleSheet("color:#fff; font-size:15px; font-weight:700;")
        self.lbl_chat_presence = QLabel("")
        self.lbl_chat_presence.setObjectName("chat.header.presence")
        self.lbl_chat_presence.setStyleSheet(
            "color:#949ba4; font-size:11px; font-weight:500;")
        title_box.addWidget(self.lbl_chat)
        title_box.addWidget(self.lbl_chat_presence)
        hl.addLayout(title_box, 1)
        hl.addStretch()

        self.e_msg_search = QLineEdit()
        self.e_msg_search.setObjectName("chat.message_search")
        self.e_msg_search.setPlaceholderText("Search messages")
        self.e_msg_search.setClearButtonEnabled(True)
        self.e_msg_search.setMaximumWidth(220)
        self.e_msg_search.setToolTip("Search in the current conversation")
        self.e_msg_search.textChanged.connect(self._on_message_search_changed)
        hl.addWidget(self.e_msg_search)

        self.btn_pins = QPushButton("Pins")
        self.btn_pins.setObjectName("ghost")
        self.btn_pins.setProperty("testid", "chat.pins")
        self.btn_pins.setMinimumWidth(64)
        self.btn_pins.setMaximumHeight(30)
        self.btn_pins.setToolTip("Pinned messages")
        self.btn_pins.clicked.connect(
            lambda: self.sig_command.emit({
                "type": "get_pinned_messages",
                "conversation_id": int(self.active_conv_id),
            }) if self.active_conv_id else None
        )
        hl.addWidget(self.btn_pins)
        # Safety-number label — click to open verification dialog.
        self.lbl_fingerprint = _ClickableLabel("")
        self.lbl_fingerprint.setObjectName("chat.fingerprint")
        self.lbl_fingerprint.setToolTip(
            "Verify the safety number with your contact outside SecChat."
        )
        self.lbl_fingerprint.setStyleSheet(
            "color:#b5bac1; font-size:12px; font-weight:600;"
        )
        self.lbl_fingerprint.clicked.connect(
            lambda: self._request_identity_review()
        )
        hl.addWidget(self.lbl_fingerprint)

        self.lbl_cache_state = QLabel("")
        self.lbl_cache_state.setObjectName("chat.cache_state")
        self.lbl_cache_state.setStyleSheet(
            "QLabel { color:#949ba4; font-size:11px; font-weight:600; }"
        )
        self.lbl_cache_state.hide()
        hl.addWidget(self.lbl_cache_state)

        self.lbl_consistency = QLabel("")
        self.lbl_consistency.setObjectName("chat.consistency")
        self.lbl_consistency.setToolTip("")
        self.lbl_consistency.setStyleSheet(
            "QLabel { color:#faa61a; font-size:11px; font-weight:600; }"
        )
        self.lbl_consistency.hide()
        hl.addWidget(self.lbl_consistency)

        self.btn_warning_details = QPushButton("Details")
        self.btn_warning_details.setObjectName("small")
        self.btn_warning_details.setProperty("testid", "chat.warning_details")
        self.btn_warning_details.setToolTip("Show history and group consistency warnings")
        self.btn_warning_details.clicked.connect(self._show_security_warning_details)
        self.btn_warning_details.hide()
        hl.addWidget(self.btn_warning_details)

        self.btn_review_identity = QPushButton("Review identity")
        self.btn_review_identity.setObjectName("small")
        self.btn_review_identity.setProperty("testid", "chat.review_identity")
        self.btn_review_identity.setToolTip("Review this contact's identity history")
        self.btn_review_identity.clicked.connect(
            lambda: self._request_identity_review()
        )
        self.btn_review_identity.hide()
        hl.addWidget(self.btn_review_identity)
        rl.addWidget(hdr)

        self.lbl_security_guide = QLabel("")
        self.lbl_security_guide.setObjectName("securityGuide")
        self.lbl_security_guide.setWordWrap(True)
        self.lbl_security_guide.setContentsMargins(14, 7, 14, 7)
        self.lbl_security_guide.setStyleSheet(
            "QLabel#securityGuide { color:#dbdee1; background:#2b2d31; "
            "border-left:3px solid #5865f2; font-size:12px; }"
        )
        self.lbl_security_guide.hide()
        rl.addWidget(self.lbl_security_guide)

        # Message view
        self.view = MessageListView()
        self.view.setObjectName("chat.message_view")
        self.view.file_dropped.connect(self._send_dropped_file)
        self.view.verticalScrollBar().valueChanged.connect(self._reposition_edit)
        rl.addWidget(self.view)

        self.lbl_typing = QLabel("")
        self.lbl_typing.setObjectName("chat.typing")
        self.lbl_typing.setFixedHeight(22)
        self.lbl_typing.setContentsMargins(16, 0, 16, 0)
        self.lbl_typing.setStyleSheet(
            "color:#949ba4; font-size:12px; background:#313338;"
        )
        rl.addWidget(self.lbl_typing)

        self.reply_bar = QFrame()
        self.reply_bar.setObjectName("replyBar")
        self.reply_bar.setStyleSheet(
            "QFrame#replyBar { background:#2b2d31; border-left:3px solid #5865f2; }"
        )
        rb = QHBoxLayout(self.reply_bar)
        rb.setContentsMargins(14, 8, 12, 8)
        rb.setSpacing(8)
        self.lbl_reply = QLabel("")
        self.lbl_reply.setObjectName("chat.reply_preview")
        self.lbl_reply.setWordWrap(True)
        self.lbl_reply.setStyleSheet("color:#dbdee1; font-size:12px;")
        rb.addWidget(self.lbl_reply, 1)
        btn_cancel_reply = QPushButton("Cancel")
        btn_cancel_reply.setObjectName("ghost")
        btn_cancel_reply.setProperty("testid", "chat.cancel_reply")
        btn_cancel_reply.setFixedSize(84, 30)
        btn_cancel_reply.clicked.connect(self._clear_reply_target)
        rb.addWidget(btn_cancel_reply)
        self.reply_bar.hide()
        rl.addWidget(self.reply_bar)

        # Input bar
        ib = QFrame()
        ib.setObjectName("inputbar")
        ib.setMinimumHeight(52)
        ib.setMaximumHeight(160)
        il = QHBoxLayout(ib)
        il.setContentsMargins(12, 10, 12, 10)
        il.setSpacing(8)
        il.setAlignment(Qt.AlignBottom)

        # Attach file button
        btn_attach = QPushButton("+")
        btn_attach.setObjectName("chat.attach")
        btn_attach.setProperty("testid", "chat.attach")
        btn_attach.setToolTip("Attach file (max 10 MB)")
        btn_attach.setStyleSheet(
            "QPushButton { background:#383a40; border:none; border-radius:6px;"
            "font-size:20px; font-weight:700; color:#b5bac1;"
            "min-width:36px; max-width:36px; min-height:36px; max-height:36px; }"
            "QPushButton:hover { background:#404249; color:#dbdee1; }")
        btn_attach.clicked.connect(self._attach_file)
        il.addWidget(btn_attach)

        self.inp = ChatInput()
        self.inp.setObjectName("chat.message_input")
        self.inp.setPlaceholderText("Message...")
        self.inp.setMaximumHeight(140)
        self.inp.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.inp.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        self.inp.setStyleSheet(
            "QPlainTextEdit { background:#383a40; border:none; border-radius:8px;"
            "padding:8px 12px; color:#dbdee1; font-size:14px; }"
        )
        self.inp.sig_submit.connect(self._send)
        self.inp.textChanged.connect(self._on_input_changed)
        il.addWidget(self.inp)

        self._btn_send = QPushButton("Send")
        self._btn_send.setObjectName("chat.send")
        self._btn_send.setMinimumSize(60, 36)
        self._btn_send.setMaximumHeight(36)
        self._btn_send.clicked.connect(self._send)
        il.addWidget(self._btn_send)
        rl.addWidget(ib)

        return rp

    @staticmethod
    def _section_label(text: str) -> QLabel:
        """Tạo nhãn tiêu đề cho một mục trong sidebar."""
        lbl = QLabel(text)
        lbl.setObjectName("section")
        return lbl

    @staticmethod
    def _clip_text(value: str, limit: int) -> str:
        """Cắt ngắn chuỗi quá dài và thêm dấu ba chấm."""
        text = " ".join(str(value or "").splitlines()).strip()
        if len(text) <= limit:
            return text
        return text[:max(0, limit - 3)].rstrip() + "..."

    def _configure_sidebar_list(self, widget: QListWidget):
        """Cấu hình một QListWidget của sidebar (style/hành vi)."""
        widget.setSpacing(2)
        widget.setUniformItemSizes(False)
        widget.viewport().setProperty("secchat_sidebar_owner", widget.objectName())
        widget.viewport().installEventFilter(self)
        widget.setStyleSheet(
            "QListWidget { padding:4px 6px; background:transparent; border:none; outline:0; }"
            "QListWidget::item { padding:0px; margin:2px 0px; border:none;"
            " background:transparent; color:transparent; }"
            "QListWidget::item:selected { background:transparent; color:transparent; }"
            "QListWidget::item:hover { background:transparent; color:transparent; }"
        )

    def _clear_list_item_widgets(self, widget: QListWidget):
        """Gỡ và hủy các widget con của một list trước khi nạp lại."""
        for row in range(widget.count()):
            item = widget.item(row)
            child = widget.itemWidget(item)
            if child is not None:
                widget.removeItemWidget(item)
                child.hide()
                child.setParent(None)
                child.deleteLater()
        widget.clear()

    def _begin_list_refresh(self, widget: QListWidget):
        """Bắt đầu cập nhật danh sách (khóa vẽ lại cho mượt)."""
        state = capture_vertical_scroll(widget)
        updates_enabled = widget.updatesEnabled()
        widget.setUpdatesEnabled(False)
        return state, updates_enabled

    def _end_list_refresh(self, widget: QListWidget, state, updates_enabled: bool):
        """Kết thúc cập nhật danh sách (mở lại vẽ và phục hồi cuộn)."""
        restore_vertical_scroll(widget, state)
        widget.setUpdatesEnabled(updates_enabled)
        for delay in (0, 20, 80):
            QTimer.singleShot(
                delay, lambda w=widget: self._normalize_short_list_scroll(w))

    @staticmethod
    def _normalize_short_list_scroll(widget: QListWidget):
        """Chuẩn hóa vị trí cuộn khi danh sách ngắn."""
        try:
            bar = widget.verticalScrollBar()
            if bar is None:
                return
            visible_height = int(widget.viewport().height())
            content_height = 0
            for row in range(widget.count()):
                content_height += max(0, int(widget.sizeHintForRow(row)))
            if content_height <= max(0, visible_height - 2):
                bar.setValue(0)
        except RuntimeError:
            return
        except Exception:
            return

    @staticmethod
    def _sidebar_presence_color(presence: str) -> str:
        """Màu chấm trạng thái online/offline trong sidebar."""
        if presence == "online":
            return "#3ba55d"
        if presence == "group":
            return "#5865f2"
        if presence == "warn":
            return "#faa61a"
        return "#4e505a"

    def _sidebar_row_widget(
            self, *, title: str, subtitle: str = "", leading: str = "",
            presence: str = "offline", badges: list[str] | None = None,
            unread: bool = False, active: bool = False,
            tooltip: str = "", on_left_click=None,
            on_context_menu=None) -> QFrame:
        """Tạo hàng sidebar ổn định theo kiểu app chat: avatar, title, preview."""
        badges = [str(b) for b in (badges or []) if str(b or "").strip()]
        summary = subtitle or " · ".join(badges[:3])

        row = _SidebarRow(
            on_left_click=on_left_click,
            on_context_menu=on_context_menu,
        )
        row.setObjectName("sidebarRow")
        row.setToolTip(tooltip or title)
        row.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        if on_left_click:
            row.setCursor(Qt.PointingHandCursor)
        row.setStyleSheet(
            "QPushButton#sidebarRow { background:%s; border:none; border-radius:6px;"
            " text-align:left; padding:0px; }"
            "QPushButton#sidebarRow:hover { background:#35373c; }"
            % ("#404249" if active else "transparent")
        )

        lay = QHBoxLayout(row)
        lay.setContentsMargins(8, 5, 8, 5)
        lay.setSpacing(8)

        avatar_text = self._clip_text(leading or (title[:1].upper() if title else "?"), 2)
        avatar = QLabel(avatar_text)
        avatar.setAlignment(Qt.AlignCenter)
        avatar.setFixedSize(32, 32)
        avatar.setStyleSheet(
            "QLabel { background:%s; color:#ffffff; border-radius:16px;"
            " font-size:13px; font-weight:700; }"
            % self._sidebar_presence_color(presence)
        )
        row.bind_click_surface(avatar)
        lay.addWidget(avatar, 0, Qt.AlignVCenter)

        text_col = QVBoxLayout()
        text_col.setContentsMargins(0, 0, 0, 0)
        text_col.setSpacing(1)

        title_lbl = QLabel(self._clip_text(title, 24))
        title_lbl.setTextFormat(Qt.PlainText)
        title_lbl.setToolTip(title)
        title_lbl.setStyleSheet(
            "color:%s; font-size:13px; font-weight:%s;"
            % ("#ffffff" if unread or active else "#dbdee1",
               "700" if unread else "600")
        )
        row.bind_click_surface(title_lbl)
        text_col.addWidget(title_lbl)

        sub_lbl = QLabel(self._clip_text(summary, 38))
        sub_lbl.setTextFormat(Qt.PlainText)
        sub_lbl.setToolTip(summary)
        sub_lbl.setStyleSheet(
            "color:%s; font-size:12px;"
            % ("#b5bac1" if unread else "#949ba4")
        )
        row.bind_click_surface(sub_lbl)
        text_col.addWidget(sub_lbl)
        lay.addLayout(text_col, 1)

        if unread:
            dot = QLabel("")
            dot.setFixedSize(8, 8)
            dot.setStyleSheet(
                "QLabel { background:#5865f2; border-radius:4px; }"
            )
            row.bind_click_surface(dot)
            lay.addWidget(dot, 0, Qt.AlignVCenter)

        return row

    @staticmethod
    def _hide_native_sidebar_text(item: QListWidgetItem, logical_text: str = "") -> None:
        """Ẩn hẳn DisplayRole khi đã dùng custom row widget.

        Qt có thể paint lại DisplayRole trong lúc hover/selected dù item có
        widget riêng. Vì vậy text phục vụ test/probe nằm trong role riêng, còn
        text native để trống để không còn lớp UI cũ lóe phía sau.
        """
        item.setData(SIDEBAR_TEXT_ROLE, str(logical_text or item.text() or ""))
        item.setText("")
        item.setForeground(SIDEBAR_HIDDEN_ITEM_BRUSH)

    @staticmethod
    def sidebar_item_text(item: QListWidgetItem) -> str:
        """Dựng nhãn hiển thị cho một dòng sidebar."""
        if item is None:
            return ""
        return str(item.data(SIDEBAR_TEXT_ROLE) or item.text() or "")

    def _is_group_conversation_id(self, conv_id: int) -> bool:
        """Kiểm tra một id có phải hội thoại nhóm không."""
        conv_id = int(conv_id or 0)
        if conv_id <= 0:
            return False
        if conv_id == int(self.active_conv_id or 0) and self.__dict__.get("_active_is_group", False):
            return True
        return any(int(g.get("conversation_id", 0) or 0) == conv_id for g in self.group_convs)

    def _request_identity_review(self) -> None:
        """Phát yêu cầu mở màn hình xác minh danh tính."""
        conv_id = int(self.active_conv_id or 0)
        if conv_id <= 0 or self._is_group_conversation_id(conv_id):
            return
        self.sig_verify_identity.emit(conv_id)

    # ================================================================ navigation

    def _switch_view(self, view: str):
        """Chuyển giữa các view chính (chat/tìm kiếm/lời mời)."""
        self.current_view = view
        for btn, name in [
            (self.btn_chat,     "chat"),
            (self.btn_search,   "search"),
            (self.btn_requests, "requests"),
        ]:
            btn.setObjectName("nav_active" if view == name else "nav")
            btn.setStyle(btn.style())

        index_map = {"chat": 0, "search": 1, "requests": 2}
        self.content_stack.setCurrentIndex(index_map[view])

        if view == "requests":
            self._pending_requests_count = 0
            self.btn_requests.setText("Requests")
            self.btn_requests.setStyleSheet("")
            self.sig_get_requests.emit()

        if view == "chat":
            if self.active_conv_id:
                self._unread_convs.discard(self.active_conv_id)
            if "btn_chat" in self.__dict__:
                self._update_chat_badge()
            # Re-render so any messages that arrived while away are visible
            if self.active_conv_id and self.active_conv_id in self.hist:
                self._redraw()

    def _on_message_search_changed(self, text: str):
        """Xử lý khi từ khóa tìm trong hội thoại thay đổi."""
        self._message_search_query = (text or "").strip().lower()
        if self.active_conv_id:
            self._redraw()

    # ================================================================ context menus

    def _context_action(self, text: str, callback, enabled: bool = True) -> dict:
        """Tạo một mục hành động cho menu ngữ cảnh."""
        return {
            "text": str(text),
            "callback": callback,
            "enabled": bool(enabled),
        }

    def _close_context_popover(self):
        """Đóng popover menu ngữ cảnh đang mở."""
        pop = self.__dict__.get("_active_context_popover")
        self._active_context_popover = None
        self._context_popover_buttons = []
        self._context_popover_focus_index = -1
        if pop is not None:
            try:
                pop.close()
                pop.setParent(None)
                pop.deleteLater()
            except RuntimeError:
                pass

    def _focus_context_popover_button(self, index: int):
        """Focus nút trong popover ngữ cảnh (điều hướng bàn phím)."""
        buttons = [
            b for b in self.__dict__.get("_context_popover_buttons", [])
            if b.isEnabled()
        ]
        if not buttons:
            self._context_popover_focus_index = -1
            return
        index = max(0, min(int(index), len(buttons) - 1))
        self._context_popover_focus_index = index
        buttons[index].setFocus(Qt.OtherFocusReason)

    def _handle_context_popover_key(self, event) -> bool:
        """Xử lý phím khi popover ngữ cảnh đang mở."""
        buttons = [
            b for b in self.__dict__.get("_context_popover_buttons", [])
            if b.isEnabled()
        ]
        if not buttons:
            return False
        key = event.key()
        idx = int(self.__dict__.get("_context_popover_focus_index", -1))
        if key in (Qt.Key_Down, Qt.Key_Tab):
            self._focus_context_popover_button((idx + 1) % len(buttons))
            return True
        if key in (Qt.Key_Up, Qt.Key_Backtab):
            self._focus_context_popover_button(
                (idx - 1) % len(buttons) if idx >= 0 else len(buttons) - 1)
            return True
        if key in (Qt.Key_Return, Qt.Key_Enter, Qt.Key_Space):
            if idx < 0:
                self._focus_context_popover_button(0)
                return True
            buttons[idx].click()
            return True
        if key == Qt.Key_Escape:
            self._close_context_popover()
            return True
        return False

    def eventFilter(self, obj, event):
        """Override Qt: lọc sự kiện cho đối tượng đang theo dõi."""
        if event.type() == QEvent.MouseButtonPress:
            owner = str(obj.property("secchat_sidebar_owner") or "")
            if owner:
                handled = self._handle_sidebar_viewport_mouse(owner, event)
                if handled:
                    return True
            if self._handle_global_sidebar_mouse(event):
                return True
        if event.type() == QEvent.KeyPress:
            pop = self.__dict__.get("_active_context_popover")
            buttons = self.__dict__.get("_context_popover_buttons", [])
            if obj is pop or obj in buttons:
                if self._handle_context_popover_key(event):
                    return True
        return super().eventFilter(obj, event)

    def _handle_sidebar_viewport_mouse(self, owner: str, event) -> bool:
        """Xử lý chuột trên vùng trống của sidebar."""
        if owner == "chat.dm_list":
            widget = self.dm_list
        elif owner == "chat.group_list":
            widget = self.group_list
        elif owner == "chat.friend_list":
            widget = self.friend_list
        else:
            return False
        return self._handle_sidebar_item_mouse(
            owner, widget, event.pos(), event.button(),
            widget.viewport().mapToGlobal(event.pos()))

    def _handle_global_sidebar_mouse(self, event) -> bool:
        """Bắt click bên ngoài để đóng popover sidebar."""
        try:
            global_pos = event.globalPos()
        except AttributeError:
            return False
        for owner, widget in (
                ("chat.dm_list", self.dm_list),
                ("chat.group_list", self.group_list),
                ("chat.friend_list", self.friend_list),
        ):
            if not widget.isVisible():
                continue
            local = widget.viewport().mapFromGlobal(global_pos)
            if not widget.viewport().rect().contains(local):
                continue
            if self._handle_sidebar_item_mouse(
                    owner, widget, local, event.button(), global_pos):
                return True
        return False

    def _handle_sidebar_item_mouse(
            self, owner: str, widget: QListWidget, pos: QPoint,
            button, global_pos: QPoint | None = None) -> bool:
        """Xử lý chuột trên một dòng sidebar (trái/phải)."""
        item = widget.itemAt(pos)
        if item is None:
            return False
        if button == Qt.LeftButton:
            conv_id = int(item.data(Qt.UserRole) or 0)
            if owner == "chat.dm_list" and conv_id > 0:
                self._switch_to_conv(conv_id, is_group=False)
                return True
            if owner == "chat.group_list" and conv_id > 0:
                self._switch_to_conv(conv_id, is_group=True)
                return True
            return False
        if button == Qt.RightButton:
            if global_pos is not None:
                pos = widget.viewport().mapFromGlobal(global_pos)
            pos = QPoint(pos)
            def show_menu(menu_pos=pos):
                if owner == "chat.dm_list":
                    self._dm_context_menu(QPoint(menu_pos))
                elif owner == "chat.group_list":
                    self._group_context_menu(QPoint(menu_pos))
                elif owner == "chat.friend_list":
                    self._friend_context_menu(QPoint(menu_pos))
            QTimer.singleShot(80, show_menu)
            return True
        return False

    def _show_context_popover(self, anchor: QWidget, global_pos: QPoint,
                              actions: list[dict | None]):
        """Hiển thị popover menu ngữ cảnh tại vị trí con trỏ."""
        cleaned: list[dict | None] = []
        for action in actions:
            if action is None:
                if cleaned and cleaned[-1] is not None:
                    cleaned.append(None)
            elif action.get("text"):
                cleaned.append(action)
        if cleaned and cleaned[-1] is None:
            cleaned.pop()
        actions = cleaned
        if not actions:
            return
        self._close_context_popover()
        parent = anchor.window() if anchor is not None else self
        pop = QFrame(parent, Qt.Popup | Qt.FramelessWindowHint)
        pop.setObjectName("secchatContextPopover")
        pop.setFocusPolicy(Qt.StrongFocus)
        pop.setStyleSheet(
            "QFrame#secchatContextPopover { background:#2b2d31;"
            " border:1px solid #1e1f22; border-radius:8px; }"
            "QPushButton#secchatContextAction { background:transparent;"
            " border:none; color:#dbdee1; text-align:left; padding:8px 14px;"
            " min-width:210px; min-height:18px; border-radius:4px;"
            " font-size:13px; }"
            "QPushButton#secchatContextAction:hover { background:#35373c; }"
            "QPushButton#secchatContextAction:disabled { color:#6d737d; }"
            "QFrame#secchatContextSeparator { background:#3f4147;"
            " min-height:1px; max-height:1px; margin:4px 8px; }"
        )
        layout = QVBoxLayout(pop)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(2)
        buttons = []

        for action in actions:
            if action is None:
                sep = QFrame(pop)
                sep.setObjectName("secchatContextSeparator")
                layout.addWidget(sep)
                continue
            text = str(action.get("text", ""))
            btn = QPushButton(text, pop)
            btn.setObjectName("secchatContextAction")
            btn.setProperty("action_text", text)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setFocusPolicy(Qt.StrongFocus)
            btn.setEnabled(bool(action.get("enabled", True)))

            def invoke(_checked=False, cb=action.get("callback")):
                self._close_context_popover()
                if cb:
                    cb()

            btn.clicked.connect(invoke)
            layout.addWidget(btn)
            btn.installEventFilter(self)
            buttons.append(btn)

        pop.adjustSize()
        pos = QPoint(global_pos)
        try:
            screen = QApplication.screenAt(pos)
            if screen is not None:
                geom = screen.availableGeometry()
                x = min(max(pos.x(), geom.left()), geom.right() - pop.width())
                y = min(max(pos.y(), geom.top()), geom.bottom() - pop.height())
                pos = QPoint(max(geom.left(), x), max(geom.top(), y))
        except Exception:
            pass
        pop.move(pos)
        pop.show()
        self._active_context_popover = pop
        self._context_popover_buttons = buttons
        self._context_popover_focus_index = -1
        pop.installEventFilter(self)
        pop.setFocus(Qt.PopupFocusReason)

    def _dm_context_menu(self, pos: QPoint):
        """Dựng menu ngữ cảnh cho một hội thoại DM."""
        item = self.dm_list.itemAt(pos)
        if not item:
            return
        conv_id = int(item.data(Qt.UserRole))
        actions = [
            self._context_action(
                "Open",
                lambda cid=conv_id: self._switch_to_conv(cid, is_group=False),
            ),
            self._context_action(
                "Verify Identity",
                lambda cid=conv_id: self.sig_verify_identity.emit(cid),
            ),
            None,
        ]
        actions.extend(self._conversation_action_specs(conv_id))
        self._show_context_popover(
            self.dm_list, self.dm_list.viewport().mapToGlobal(pos), actions)

    def _group_context_menu(self, pos: QPoint):
        """Dựng menu ngữ cảnh cho một nhóm."""
        item = self.group_list.itemAt(pos)
        if not item:
            return
        conv_id = int(item.data(Qt.UserRole))

        creator_id   = 0
        is_disbanded = conv_id in self._disbanded_convs
        for g in self.group_convs:
            if g["conversation_id"] == conv_id:
                creator_id   = int(g.get("creator_id", 0))
                is_disbanded = is_disbanded or bool(g.get("is_disbanded", False))
                break

        actions = [
            self._context_action(
                "Open",
                lambda cid=conv_id: self._switch_to_conv(cid, is_group=True),
            ),
            self._context_action(
                "Group Info",
                lambda cid=conv_id: self.sig_command.emit({
                    "type": "get_group_info",
                    "group_id": int(cid),
                }),
            ),
            self._context_action(
                "Add Member",
                lambda cid=conv_id: self._show_add_member_to_group(cid),
            ),
            None,
        ]
        actions.extend(self._conversation_action_specs(conv_id))
        actions.append(None)

        if not is_disbanded:
            actions.append(self._context_action(
                "Leave Group",
                lambda cid=conv_id: self._confirm_leave_group(cid),
            ))

        if creator_id == self.my_id and not is_disbanded:
            actions.append(self._context_action(
                "Disband Group",
                lambda cid=conv_id: self._confirm_disband(cid),
            ))

        self._show_context_popover(
            self.group_list, self.group_list.viewport().mapToGlobal(pos), actions)

    def _conversation_action_specs(self, conv_id: int) -> list[dict | None]:
        """Khai báo các hành động dùng chung cho menu hội thoại."""
        conv_id = int(conv_id)
        cache_enabled = self._is_cache_enabled_for_conversation(conv_id)
        return [
            self._context_action(
                "Pinned Messages",
                lambda cid=conv_id: self.sig_command.emit({
                    "type": "get_pinned_messages",
                    "conversation_id": int(cid),
                }),
            ),
            self._context_action(
                "Mute 1 Hour",
                lambda cid=conv_id: self._send_conversation_pref({
                    "type": "mute_conversation",
                    "conversation_id": int(cid),
                    "mute_secs": 3600,
                }),
            ),
            self._context_action(
                "Unmute",
                lambda cid=conv_id: self._send_conversation_pref({
                    "type": "mute_conversation",
                    "conversation_id": int(cid),
                    "mute_secs": 0,
                }),
            ),
            self._context_action(
                "Toggle Archive",
                lambda cid=conv_id: self._send_conversation_pref({
                    "type": "archive_conversation",
                    "conversation_id": int(cid),
                }),
            ),
            self._context_action(
                "Toggle Pin Conversation",
                lambda cid=conv_id: self._send_conversation_pref({
                    "type": "pin_conversation",
                    "conversation_id": int(cid),
                }),
            ),
            self._context_action(
                "Mark Unread",
                lambda cid=conv_id: self._send_conversation_pref({
                    "type": "mark_unread",
                    "conversation_id": int(cid),
                }),
            ),
            None,
            self._context_action(
                "Disable Local Cache" if cache_enabled else "Enable Local Cache",
                lambda cid=conv_id, enabled=cache_enabled:
                self.sig_update_conversation_cache_policy.emit(
                    int(cid), not enabled),
            ),
            self._context_action(
                "Clear This Conversation Cache",
                lambda cid=conv_id: self._confirm_clear_conversation_cache(cid),
            ),
            self._context_action(
                "Disappearing Timer...",
                lambda cid=conv_id: self._set_disappearing_timer(cid),
            ),
        ]

    def _search_context_menu(self, pos: QPoint):
        """Dựng menu ngữ cảnh cho kết quả tìm kiếm người dùng."""
        item = self.search_results.itemAt(pos)
        if not item:
            return
        user_id  = int(item.data(Qt.UserRole))
        username = item.data(Qt.UserRole + 1)
        is_friend = user_id in self.friends

        actions = [
            self._context_action(
                "View Profile",
                lambda uid=user_id: self.sig_view_profile.emit(uid),
            )
        ]

        if not is_friend:
            actions.append(self._context_action(
                "Send Friend Request",
                lambda uid=user_id, name=username:
                self._send_friend_request(uid, name),
            ))
        else:
            actions.append(self._context_action(
                "Start Conversation",
                lambda uid=user_id: self.sig_start_dm.emit(uid),
            ))
            if self.group_convs:
                actions.append(self._context_action(
                    "Add to Group",
                    lambda uid=user_id: self._show_add_to_group(uid),
                ))

        actions.extend([
            None,
            self._context_action(
                "Block User",
                lambda uid=user_id, name=username:
                self._confirm_block_user(uid, name),
            ),
        ])

        self._show_context_popover(
            self.search_results, self.search_results.viewport().mapToGlobal(pos), actions)

    def _friend_context_menu(self, pos: QPoint):
        """Dựng menu ngữ cảnh cho một người bạn."""
        item = self.friend_list.itemAt(pos)
        if not item:
            return
        user_id  = int(item.data(Qt.UserRole))
        username = self.friends.get(user_id, {}).get("username", f"User#{user_id}")

        actions = [
            self._context_action(
                "View Profile",
                lambda uid=user_id: self.sig_view_profile.emit(uid),
            ),
            self._context_action(
                "Start Conversation",
                lambda uid=user_id: self.sig_start_dm.emit(uid),
            ),
            self._context_action(
                "Remove Friend",
                lambda uid=user_id: self._confirm_unfriend(uid),
            ),
        ]

        if self.group_convs:
            actions.append(self._context_action(
                "Add to Group",
                lambda uid=user_id: self._show_add_to_group(uid),
            ))

        actions.extend([
            None,
            self._context_action(
                "Block User",
                lambda uid=user_id, name=username:
                self._confirm_block_user(uid, name),
            ),
        ])

        self._show_context_popover(
            self.friend_list, self.friend_list.viewport().mapToGlobal(pos), actions)

    # ================================================================ dialogs

    def _send_friend_request(self, user_id: int, username: str):
        """Phát signal gửi lời mời kết bạn."""
        self.sig_friend_request.emit(user_id)
        QMessageBox.information(self, "Friend Request", f"Friend request sent to {username}!")

    def _show_create_group(self):
        """Mở dialog tạo nhóm mới."""
        if not self.friends:
            QMessageBox.warning(self, "No Friends", "You need friends to create a group!")
            return
        dlg = CreateGroupDialog(self.friends, self)
        if dlg.exec_() == QDialog.Accepted:
            name, members = dlg.get_selected()
            if members:
                self.sig_create_group.emit(name, members)
            else:
                QMessageBox.warning(self, "No Members", "Please select at least one member!")

    def _show_add_to_group(self, user_id: int):
        """Mở dialog thêm thành viên (từ danh sách bạn)."""
        if not self.group_convs:
            QMessageBox.warning(self, "No Groups", "You don't have any groups yet!")
            return
        dlg = AddToGroupDialog(self.group_convs, self)
        if dlg.exec_() == QDialog.Accepted:
            group_id = dlg.get_selected_group()
            if group_id:
                self.sig_add_to_group.emit(group_id, user_id)

    def _show_add_member_to_group(self, group_id: int):
        """Mở dialog thêm một thành viên vào nhóm hiện tại."""
        if not self.friends:
            QMessageBox.warning(self, "No Friends", "You need friends to add a member.")
            return
        labels = [
            f"{data.get('username', f'User#{uid}')} (#{uid})"
            for uid, data in sorted(self.friends.items(), key=lambda kv: kv[1].get("username", ""))
        ]
        choice, ok = QInputDialog.getItem(
            self, "Add Member", "Friend:", labels, 0, False)
        if not ok or not choice:
            return
        try:
            uid = int(choice.rsplit("#", 1)[1].rstrip(")"))
        except (IndexError, ValueError):
            return
        self.sig_add_to_group.emit(group_id, uid)

    def _set_disappearing_timer(self, conv_id: int):
        """Đặt thời gian tự hủy tin cho hội thoại."""
        choices = {
            "Off": 0,
            "1 hour": 3600,
            "1 day": 86400,
            "7 days": 604800,
        }
        choice, ok = QInputDialog.getItem(
            self, "Disappearing Timer", "Delete messages after:",
            list(choices.keys()), 0, False)
        if ok:
            secs = choices.get(choice, 0)
            if secs > 0:
                confirm = QMessageBox.question(
                    self,
                    "Disappearing Timer",
                    "Messages in this conversation will be deleted from the "
                    "server after the selected time. This affects history for "
                    "all members. Continue?",
                    QMessageBox.Yes | QMessageBox.No,
                )
                if confirm != QMessageBox.Yes:
                    return
            self.sig_command.emit({
                "type": "set_disappearing",
                "conversation_id": int(conv_id),
                "disappear_after_secs": secs,
            })
            self._update_conversation_pref(
                conv_id, disappear_after_secs=(None if secs == 0 else secs))

    def _send_conversation_pref(self, command: dict):
        """Apply a visible local state change, then send the preference command."""
        conv_id = int(command.get("conversation_id", 0) or 0)
        if conv_id <= 0:
            return
        typ = str(command.get("type", ""))
        if typ == "mute_conversation":
            self._update_conversation_pref(
                conv_id, muted=int(command.get("mute_secs", 0) or 0) > 0)
        elif typ == "archive_conversation":
            self._update_conversation_pref(conv_id, toggle_archived=True)
        elif typ == "pin_conversation":
            self._update_conversation_pref(conv_id, toggle_pinned=True)
        elif typ == "mark_unread":
            self._update_conversation_pref(conv_id, unread=True)
        self.sig_command.emit(command)

    def _update_conversation_pref(
            self, conv_id: int, *, muted=None, archived=None, toggle_archived=False,
            pinned=None, toggle_pinned=False, unread=None,
            disappear_after_secs="__keep__"):
        """Update sidebar state immediately for per-user conversation prefs."""
        conv_id = int(conv_id or 0)
        if conv_id <= 0:
            return
        changed = False
        for convs in (self.dm_convs, self.group_convs):
            for c in convs:
                if int(c.get("conversation_id", 0) or 0) != conv_id:
                    continue
                if muted is not None:
                    c["muted"] = bool(muted)
                    if muted:
                        self._unread_convs.discard(conv_id)
                if archived is not None:
                    c["archived"] = bool(archived)
                if toggle_archived:
                    c["archived"] = not bool(c.get("archived"))
                if pinned is not None:
                    c["pinned_conversation"] = bool(pinned)
                if toggle_pinned:
                    c["pinned_conversation"] = not bool(c.get("pinned_conversation"))
                if disappear_after_secs != "__keep__":
                    c["disappear_after_secs"] = disappear_after_secs
                if unread is not None:
                    if unread:
                        c["unread_count"] = max(1, int(c.get("unread_count", 0) or 0))
                        c["force_unread"] = True
                    else:
                        c["unread_count"] = 0
                        c["force_unread"] = False
                changed = True
                break
        if unread is not None:
            if unread:
                self._unread_convs.add(conv_id)
            else:
                self._unread_convs.discard(conv_id)
            changed = True
        if changed:
            if "dm_list" in self.__dict__:
                self._refresh_dm_list()
            if "group_list" in self.__dict__:
                self._refresh_group_list()
            self._update_chat_badge()

    def _clear_unread_without_sidebar_refresh(self, conv_id: int) -> None:
        """Clear read state while a sidebar row may still be handling a click."""
        conv_id = int(conv_id or 0)
        if conv_id <= 0:
            return
        for convs in (self.dm_convs, self.group_convs):
            for c in convs:
                if int(c.get("conversation_id", 0) or 0) == conv_id:
                    c["unread_count"] = 0
                    c["force_unread"] = False
        self._unread_convs.discard(conv_id)
        self._update_chat_badge()

    def _confirm_block_user(self, user_id: int, username: str):
        """Hỏi xác nhận trước khi chặn người dùng."""
        reply = QMessageBox.question(
            self, "Block User",
            f"Block {username}? They will not be able to interact with you.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.sig_command.emit({"type": "block_user", "user_id": int(user_id)})

    def _show_change_password(self):
        """Mở dialog đổi mật khẩu."""
        dlg = QDialog(self)
        dlg.setWindowTitle("Change Password")
        dlg.setMinimumWidth(360)
        lay = QVBoxLayout(dlg)
        lay.setSpacing(10)

        current = QLineEdit()
        current.setObjectName("password.current")
        current.setProperty("testid", "password.current")
        current.setEchoMode(QLineEdit.Password)
        current.setPlaceholderText("Current password")
        lay.addWidget(current)

        new_pw = QLineEdit()
        new_pw.setObjectName("password.new")
        new_pw.setProperty("testid", "password.new")
        new_pw.setEchoMode(QLineEdit.Password)
        new_pw.setPlaceholderText("New password")
        lay.addWidget(new_pw)

        confirm = QLineEdit()
        confirm.setObjectName("password.confirm")
        confirm.setProperty("testid", "password.confirm")
        confirm.setEchoMode(QLineEdit.Password)
        confirm.setPlaceholderText("Confirm new password")
        lay.addWidget(confirm)

        status = QLabel("")
        status.setObjectName("password.status")
        status.setProperty("testid", "password.status")
        status.setStyleSheet("color:#ed4245; font-size:12px;")
        lay.addWidget(status)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        lay.addWidget(btns)

        def accept():
            cur = current.text()
            new = new_pw.text()
            if not cur:
                status.setText("Current password is required.")
                return
            if len(new) < 6:
                status.setText("New password must be at least 6 characters.")
                return
            if new != confirm.text():
                status.setText("New passwords do not match.")
                return
            self.sig_change_password.emit(cur, new)
            dlg.accept()

        btns.accepted.connect(accept)
        btns.rejected.connect(dlg.reject)
        dlg.exec_()

    def _confirm_disband(self, conv_id: int):
        """Hỏi xác nhận trước khi giải tán nhóm."""
        reply = QMessageBox.question(
            self, "Disband Group",
            "Disband this group for ALL members?\nThis cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.sig_disband_group.emit(conv_id)

    def _confirm_leave_group(self, conv_id: int):
        """Hỏi xác nhận trước khi rời nhóm."""
        reply = QMessageBox.question(
            self, "Leave Group",
            "Leave this group?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.sig_command.emit({"type": "leave_group", "group_id": int(conv_id)})
            self.remove_conversation(int(conv_id))
            return True
        return False

    def _do_delete_message(self, conv_id: int, msg_id: int):
        """Thực hiện xóa một tin nhắn (sau khi xác nhận)."""
        reply = QMessageBox.question(
            self, "Delete Message",
            "Delete this message? This cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.sig_delete_message.emit(conv_id, msg_id)

    # ================================================================ public update API

    def set_fingerprint(self, fp: str, verified: bool = False):
        """Hiển thị hoặc xóa safety number trên header hội thoại.

        Header chỉ hiển thị dạng rút gọn để không chiếm diện tích. Người dùng
        click vào label để mở dialog verify có safety number đầy đủ và lịch sử
        identity/audit.
        """
        if self.__dict__.get("_active_is_group", False):
            self._fingerprint_present = False
            self._fingerprint_verified = False
            self.lbl_fingerprint.setText("")
            self.lbl_fingerprint.setToolTip(
                "Group identity is checked through MLS membership state and member profiles."
            )
            self.lbl_fingerprint.setStyleSheet(
                "color:#b5bac1; font-size:12px; font-weight:600;"
            )
            if "btn_review_identity" in self.__dict__:
                self.btn_review_identity.hide()
            self._update_security_guidance_label()
            return
        self._fingerprint_present = bool(fp)
        self._fingerprint_verified = bool(verified)
        if fp:
            parts = str(fp).split()
            short = " ".join(parts[:2]) if len(parts) >= 2 else str(fp)[:13]
            if verified:
                self.lbl_fingerprint.setText(f"Verified {short}")
                self.lbl_fingerprint.setToolTip(
                    "This conversation identity was verified. Click to view "
                    "the full safety number."
                )
                self.lbl_fingerprint.setStyleSheet(
                    "color:#57f287; font-size:12px; font-weight:700;"
                    " text-decoration:underline;"
                )
            else:
                self.lbl_fingerprint.setText(f"Verify safety {short}")
                self.lbl_fingerprint.setToolTip(
                    "Not verified. Compare the safety number with your contact "
                    "outside SecChat before trusting this identity."
                )
                self.lbl_fingerprint.setStyleSheet(
                    "color:#fee75c; font-size:12px; font-weight:700;"
                    " text-decoration:underline;"
                )
        else:
            self.lbl_fingerprint.setText("")
            self.lbl_fingerprint.setToolTip(
                "Safety number appears after key exchange completes."
            )
            self.lbl_fingerprint.setStyleSheet(
                "color:#b5bac1; font-size:12px; font-weight:600;"
            )
        self._update_security_guidance_label()

    def set_conversation_security(self, conv_id: int, status: str,
                                  label: str = "", detail: str = "",
                                  blocked: bool = False):
        """Cập nhật badge/cảnh báo bảo mật cho một conversation.

        ``blocked`` hiện chỉ dành cho lỗi thật sự không gửi được. Trạng thái
        chưa verify, key changed hoặc audit warning vẫn cho gửi tin nhưng hiển
        thị cảnh báo để người dùng không nhầm là identity đã đáng tin.
        """
        conv_id = int(conv_id)
        status = str(status or "unverified")
        if (self._is_group_conversation_id(conv_id)
                and status in IDENTITY_REVIEW_STATUSES + ("verified", "unknown")):
            status = "group_mls_pq"
            if not label or label in ("verify", "unverified", "key changed"):
                label = "MLS PQ"
            detail = detail or "Group security is tracked through MLS state and member roles."
            blocked = False
        if status in ("none", "saved"):
            self._conv_security.pop(conv_id, None)
            self._security_blocked_convs.discard(conv_id)
            self._refresh_dm_list()
            self._refresh_group_list()
            if conv_id == int(self.active_conv_id or 0):
                self._update_security_warning_label()
                self._update_security_guidance_label()
                self._set_input_enabled(conv_id not in self._disbanded_convs)
            return
        label = label or status.replace("_", " ")
        self._conv_security[conv_id] = {
            "status": status,
            "label": label,
            "detail": detail or "",
            "blocked": bool(blocked),
        }
        if blocked:
            self._security_blocked_convs.add(conv_id)
        else:
            self._security_blocked_convs.discard(conv_id)
        self._refresh_dm_list()
        self._refresh_group_list()
        if conv_id == int(self.active_conv_id or 0):
            self._update_security_warning_label()
            self._update_security_guidance_label()
            self._set_input_enabled(conv_id not in self._disbanded_convs)

    def set_cache_policy(self, policy: dict):
        """Đồng bộ policy plaintext cache từ controller vào UI."""
        disabled_ids = []
        for cid in policy.get("disabled_conversation_ids", []):
            try:
                cid_i = int(cid)
            except Exception:
                continue
            if cid_i > 0:
                disabled_ids.append(cid_i)
        self._local_cache_policy = {
            "enabled": bool(policy.get("enabled", True)),
            "ttl_days": int(policy.get("ttl_days", 30)),
            "clear_on_logout": bool(policy.get("clear_on_logout", False)),
            "disabled_conversation_ids": sorted(set(disabled_ids)),
        }
        self._update_cache_status_label()
        self._update_security_guidance_label()

    def _cache_disabled_ids(self) -> set[int]:
        """Tập hội thoại đang tắt cache cục bộ."""
        out: set[int] = set()
        for cid in self._local_cache_policy.get("disabled_conversation_ids", []):
            try:
                cid_i = int(cid)
            except Exception:
                continue
            if cid_i > 0:
                out.add(cid_i)
        return out

    def _is_cache_enabled_for_conversation(self, conv_id: int) -> bool:
        """Kiểm tra một hội thoại có bật cache cục bộ không."""
        return (
            bool(self._local_cache_policy.get("enabled", True))
            and int(conv_id or 0) > 0
            and int(conv_id) not in self._cache_disabled_ids()
        )

    def _cache_retention_label(self) -> str:
        """Nhãn mô tả chính sách lưu giữ cache."""
        ttl = int(self._local_cache_policy.get("ttl_days", 30))
        if ttl < 0:
            return "forever"
        if ttl == 1:
            return "1 day"
        return f"{ttl} days"

    def _update_cache_status_label(self):
        """Cập nhật nhãn cache trong header theo conversation hiện tại."""
        if "lbl_cache_state" not in self.__dict__:
            return
        conv_id = int(self.active_conv_id or 0)
        if conv_id <= 0:
            self.lbl_cache_state.hide()
            self._update_security_guidance_label()
            return
        global_enabled = bool(self._local_cache_policy.get("enabled", True))
        if not global_enabled:
            self.lbl_cache_state.setText("Cache off")
            self.lbl_cache_state.setToolTip(
                "This device is not storing decrypted message cache. "
                "Old forward-secret messages may be unavailable after relogin."
            )
            self.lbl_cache_state.show()
            self._update_security_guidance_label()
            return
        if conv_id in self._cache_disabled_ids():
            self.lbl_cache_state.setText("No local cache")
            self.lbl_cache_state.setToolTip(
                "This conversation is marked sensitive on this device. "
                "Decrypted plaintext cache is not stored for it."
            )
            self.lbl_cache_state.show()
            self._update_security_guidance_label()
            return
        retention = self._cache_retention_label()
        self.lbl_cache_state.setText(f"Cache {retention}")
        self.lbl_cache_state.setToolTip(
            "Decrypted message cache is stored locally for previews and "
            "history recovery. It is encrypted with your local master key."
        )
        self.lbl_cache_state.show()
        self._update_security_guidance_label()

    def show_security_warning(self, conv_id: int, warnings: list[str] | str):
        """Lưu warning history/group/connection và refresh banner nếu đang mở."""
        if isinstance(warnings, str):
            warnings = [warnings]
        warnings = [str(w) for w in warnings if str(w).strip()]
        store = self.__dict__.setdefault("_security_warnings", {})
        if warnings:
            store[int(conv_id)] = warnings
        else:
            store.pop(int(conv_id), None)
        if int(conv_id) == int(self.active_conv_id or 0):
            self._update_security_warning_label()
            self._update_security_guidance_label()

    def _update_security_warning_label(self):
        """Render banner cảnh báo bảo mật/consistency trong header."""
        conv_id = int(self.active_conv_id or 0)
        sec = self.__dict__.get("_conv_security", {}).get(conv_id, {})
        is_group = self._is_group_conversation_id(conv_id)
        if is_group and sec.get("status") in IDENTITY_REVIEW_STATUSES + ("verified", "unknown"):
            sec = {}
        warnings = self.__dict__.get("_security_warnings", {}).get(
            int(self.active_conv_id or 0), [])
        blocked = bool(sec.get("blocked"))
        needs_identity_review = (
            not is_group
            and (sec.get("status") in IDENTITY_REVIEW_STATUSES or blocked)
        )
        if not warnings and not blocked and sec.get("status") not in (
                "key_changed", "audit_mismatch", "audit_unavailable"):
            if "lbl_consistency" in self.__dict__:
                self.lbl_consistency.hide()
                self.lbl_consistency.setText("")
                self.lbl_consistency.setToolTip("")
            if "btn_review_identity" in self.__dict__:
                self.btn_review_identity.setVisible(needs_identity_review)
            if "btn_warning_details" in self.__dict__:
                self.btn_warning_details.hide()
            self._update_security_guidance_label()
            return
        if "lbl_consistency" not in self.__dict__:
            return
        if blocked:
            text = "Identity warning"
        elif sec.get("status") == "audit_unavailable":
            text = "Audit unavailable"
        elif sec.get("status") == "audit_mismatch":
            text = "Audit warning"
        elif sec.get("status") == "key_changed":
            text = "Key changed"
        elif warnings and any(
                "connection was interrupted" in str(w).lower()
                or "reconnect" in str(w).lower()
                for w in warnings):
            text = "Connection warning"
        else:
            text = "History warning"
        tips = list(warnings)
        if sec.get("detail"):
            tips.insert(0, str(sec.get("detail")))
        self.lbl_consistency.setText(text)
        self.lbl_consistency.setToolTip("\n".join(tips))
        self.lbl_consistency.show()
        if "btn_warning_details" in self.__dict__:
            self.btn_warning_details.setVisible(bool(warnings))
        if "btn_review_identity" in self.__dict__:
            self.btn_review_identity.setVisible(needs_identity_review)
        self._update_security_guidance_label()

    def _show_security_warning_details(self):
        """Hiển thị chi tiết cảnh báo bảo mật danh tính."""
        conv_id = int(self.active_conv_id or 0)
        warnings = self.__dict__.get("_security_warnings", {}).get(conv_id, [])
        if not warnings:
            QMessageBox.information(
                self,
                "Warning Details",
                "There are no history or group consistency warnings for this conversation.",
            )
            return
        QMessageBox.warning(
            self,
            "Warning Details",
            "\n\n".join(str(w) for w in warnings),
        )

    def _security_guidance_parts(self) -> tuple[list[str], str]:
        """Dựng các phần nội dung hướng dẫn xử lý cảnh báo bảo mật."""
        conv_id = int(self.active_conv_id or 0)
        if conv_id <= 0:
            return [], "#5865f2"
        sec = self.__dict__.get("_conv_security", {}).get(conv_id, {})
        is_group = self._is_group_conversation_id(conv_id)
        if is_group and sec.get("status") in IDENTITY_REVIEW_STATUSES + ("verified", "unknown"):
            sec = {}
        warnings = self.__dict__.get("_security_warnings", {}).get(conv_id, [])
        loading = conv_id in self.__dict__.get("_history_loading_convs", set())
        parts: list[str] = []
        border = "#5865f2"

        if not is_group and bool(sec.get("blocked")):
            parts.append(
                "This conversation is not verified. You can send messages, but "
                "verify the safety code before trusting the identity."
            )
            border = "#ed4245"
        elif not is_group and sec.get("status") == "key_changed":
            parts.append(
                "This contact's safety key changed. Treat the conversation as "
                "unverified until you compare the new code outside SecChat. "
                "You can keep chatting while the warning is visible."
            )
            border = "#ed4245"
        elif not is_group and sec.get("status") == "audit_mismatch":
            parts.append(
                "Identity audit failed. The server view of this key may be "
                "inconsistent. You can send messages, but verify the safety code "
                "before trusting the identity."
            )
            border = "#ed4245"
        elif not is_group and sec.get("status") == "audit_unavailable":
            parts.append(
                "Identity audit is unavailable. You can keep chatting, but manual "
                "safety-number verification matters more."
            )
            border = "#faa61a"
        elif (not is_group and (
                sec.get("status") in ("unverified", "reviewed_unverified")
                or (self._fingerprint_present and not self._fingerprint_verified))):
            parts.append(
                "This conversation is not verified. Compare the safety number "
                "outside SecChat before relying on the identity."
            )
            border = "#fee75c"

        if loading:
            parts.append(
                "Loading history. Offline messages may appear before older "
                "history until the full sync finishes."
            )

        if warnings and not bool(sec.get("blocked")):
            warning_text = " ".join(str(w).lower() for w in warnings)
            connection_only = (
                ("connection was interrupted" in warning_text
                 or "reconnect" in warning_text
                 or "disconnected" in warning_text)
                and not any(token in warning_text for token in (
                    "history",
                    "transcript",
                    "group",
                    "membership",
                    "audit",
                    "message order",
                    "server returned",
                ))
            )
            if connection_only:
                parts.append(
                    "Connection warning. SecChat is reconnecting; wait until "
                    "the connection is back before retrying failed sends."
                )
            else:
                parts.append(
                    "History or group consistency warning. Open the warning "
                    "details before trusting the conversation view."
                )
            if border == "#5865f2":
                border = "#faa61a"

        global_enabled = bool(self._local_cache_policy.get("enabled", True))
        if not global_enabled:
            parts.append(
                "Local plaintext cache is off. This reduces data stored on this "
                "device, but old forward-secret messages may not be readable later."
            )
        elif conv_id in self._cache_disabled_ids():
            parts.append(
                "Local cache is disabled for this conversation. Preview and old "
                "history recovery may be limited on this device."
            )

        return parts[:3], border

    def _update_security_guidance_label(self):
        """Cập nhật nhãn hướng dẫn bảo mật theo trạng thái."""
        if "lbl_security_guide" not in self.__dict__:
            return
        parts, border = self._security_guidance_parts()
        if not parts:
            self.lbl_security_guide.hide()
            self.lbl_security_guide.setText("")
            return
        self.lbl_security_guide.setText("  |  ".join(parts))
        self.lbl_security_guide.setToolTip("\n\n".join(parts))
        self.lbl_security_guide.setStyleSheet(
            "QLabel#securityGuide { color:#dbdee1; background:#2b2d31; "
            f"border-left:3px solid {border}; font-size:12px; }}"
        )
        self.lbl_security_guide.show()

    def set_me(self, name: str, uid: int):
        self.me    = name
        self.my_id = uid
        self.lbl_me.setText(name)
        # Load own initials avatar; App will replace once real avatar arrives
        from client.utils import initials_pixmap
        pm = initials_pixmap(name, 36)
        self.lbl_my_avatar.setPixmap(pm)
        # Request own avatar silently
        if uid > 0 and uid not in self._avatar_pending:
            self._avatar_pending.add(uid)
            self.sig_get_avatar.emit(uid)

    def update_friends(self, friends: list):
        """Cập nhật danh sách bạn bè trong sidebar."""
        scroll_state, updates_enabled = self._begin_list_refresh(self.friend_list)
        self.friends.clear()
        self._clear_list_item_widgets(self.friend_list)
        for f in friends:
            fid = f["id"]
            self.friends[fid] = f
            online = f.get("status") == "online"
            status_text = "Online" if online else "Offline"
            if not online and f.get("last_seen"):
                status_text = f"Last seen {f['last_seen']}"
            item = QListWidgetItem()
            item.setText(f"{'●' if online else '○'}  {f.get('username', f'User#{fid}')}")
            if f.get("status") == "online":
                item.setToolTip("Online")
            elif f.get("last_seen"):
                item.setToolTip(f"Last seen {f['last_seen']}")
            else:
                item.setToolTip("Offline")
            item.setData(Qt.UserRole, fid)
            self._hide_native_sidebar_text(
                item, f"{f.get('username', f'User#{fid}')}\n    {status_text}")
            self.friend_list.addItem(item)
            item.setSizeHint(QSize(0, SIDEBAR_ROW_HEIGHT))
            self.friend_list.setItemWidget(item, self._sidebar_row_widget(
                title=f.get("username", f"User#{fid}"),
                subtitle=status_text,
                leading=(f.get("username", "?")[:1] or "?").upper(),
                presence="online" if online else "offline",
                tooltip=f"{f.get('username', f'User#{fid}')}\n{status_text}",
                on_context_menu=(
                    lambda global_pos, lst=self.friend_list:
                    self._friend_context_menu(lst.viewport().mapFromGlobal(global_pos))
                ),
            ))
        self._end_list_refresh(self.friend_list, scroll_state, updates_enabled)

    def update_inbox(self, dm_convs: list, group_convs: list):
        self.dm_convs    = dm_convs
        self.group_convs = group_convs

        # Keep disbanded set in sync
        active = int(self.active_conv_id or 0)
        last_read_sent = self.__dict__.setdefault("_last_read_sent", {})
        pending_read = self.__dict__.setdefault("_pending_read_clear_convs", set())
        current_conv_ids = set()
        unread_convs = set()
        for g in group_convs:
            if g.get("is_disbanded"):
                self._disbanded_convs.add(g["conversation_id"])
        for c in list(dm_convs) + list(group_convs):
            cid = int(c.get("conversation_id", 0) or 0)
            if cid <= 0:
                continue
            current_conv_ids.add(cid)
            last_message_id = int(c.get("last_message_id", 0) or 0)
            local_read_id = int(last_read_sent.get(cid, 0) or 0)
            raw_unread = (
                (
                    int(c.get("unread_count", 0) or 0) > 0
                    or bool(c.get("force_unread"))
                )
                and not bool(c.get("muted"))
            )
            clear_stale_unread = False
            if raw_unread and cid == active:
                pending_read.add(cid)
                clear_stale_unread = True
            elif raw_unread and last_message_id > 0 and local_read_id >= last_message_id:
                clear_stale_unread = True
            if clear_stale_unread:
                c["unread_count"] = 0
                c["force_unread"] = False
            is_unread = raw_unread and not clear_stale_unread
            if is_unread:
                unread_convs.add(cid)
        self._unread_convs.intersection_update(current_conv_ids)
        self._unread_convs.difference_update(current_conv_ids - unread_convs)
        self._unread_convs.update(unread_convs)

        self._refresh_dm_list()
        self._refresh_group_list()
        self._sync_active_conversation_header()
        self._update_chat_badge()
        active = int(self.active_conv_id or 0)
        if (active in self.__dict__.get("_pending_read_clear_convs", set())
                and active in self._history_loaded_set()):
            QTimer.singleShot(0, self._mark_active_conversation_read)

    def _presence_text_for_dm(self, conv: dict) -> str:
        """Chuỗi trạng thái (online/last seen) cho một DM."""
        if conv.get("status") == "online":
            return "Online"
        last_seen = str(conv.get("last_seen", "") or "").strip()
        if last_seen:
            return f"Last seen {last_seen}"
        return "Offline"

    def _conversation_record(self, conv_id: int) -> dict:
        """Tìm record sidebar hiện tại của một conversation."""
        conv_id = int(conv_id or 0)
        for c in list(self.dm_convs) + list(self.group_convs):
            if int(c.get("conversation_id", 0) or 0) == conv_id:
                return c
        return {}

    def _is_conversation_muted(self, conv_id: int) -> bool:
        """Kiểm tra hội thoại có đang tắt thông báo không."""
        return bool(self._conversation_record(conv_id).get("muted"))

    def _conversation_has_unread_record(self, conv_id: int) -> bool:
        """Kiểm tra hội thoại có tin chưa đọc không."""
        conv_id = int(conv_id or 0)
        rec = self._conversation_record(conv_id)
        unread_count = int(rec.get("unread_count", 0) or 0)
        return (
            conv_id in self.__dict__.get("_unread_convs", set())
            or unread_count > 0
            or bool(rec.get("force_unread"))
        )

    def _sync_active_conversation_header(self):
        """Đồng bộ header với hội thoại đang mở."""
        conv_id = int(self.active_conv_id or 0)
        if conv_id <= 0 or "lbl_chat_presence" not in self.__dict__:
            return
        self.lbl_chat_presence.setText("")
        if conv_id in self._disbanded_convs:
            self.lbl_chat_presence.setText("Group disbanded")
            return
        for g in self.group_convs:
            if int(g.get("conversation_id", 0) or 0) == conv_id:
                self.lbl_chat.setText(f"[G] {g.get('name', 'Unnamed Group')}")
                self.lbl_chat_presence.setText(
                    "Group conversation" if not g.get("is_disbanded") else "Group disbanded")
                return
        for c in self.dm_convs:
            if int(c.get("conversation_id", 0) or 0) == conv_id:
                self.lbl_chat.setText(c.get("username", "Direct message"))
                self.lbl_chat_presence.setText(self._presence_text_for_dm(c))
                return

    def _refresh_dm_list(self):
        """Dựng lại danh sách DM trong sidebar."""
        scroll_state, updates_enabled = self._begin_list_refresh(self.dm_list)
        self._clear_list_item_widgets(self.dm_list)
        for c in sorted(
                self.dm_convs,
                key=lambda item: (
                    bool(item.get("archived")),
                    not bool(item.get("pinned_conversation")),
                    item.get("username", ""))):
            conv_id = int(c.get("conversation_id", 0) or 0)
            preview = str(c.get("last_message", "") or "")
            sec = self._conv_security.get(conv_id, {})
            sec_label = sec.get("label", "")
            badges = []
            unread = conv_id in self._unread_convs
            if unread:
                badges.append("unread")
            if sec_label:
                badges.append(sec_label)
            if c.get("pinned_conversation"):
                badges.append("pinned")
            if c.get("muted"):
                badges.append("muted")
            if c.get("archived"):
                badges.append("archived")
            if c.get("disappear_after_secs"):
                badges.append("timer")
            title = c.get("username", "Direct message")
            subtitle = preview or self._presence_text_for_dm(c)
            label = title
            if badges:
                label += "  " + " ".join(f"[{b}]" for b in badges)
            if preview:
                label += f"\n    {self._clip_text(preview, 38)}"
            tooltip_parts = [title, self._presence_text_for_dm(c)]
            if preview:
                tooltip_parts.append(preview)
            if badges:
                tooltip_parts.append(" | ".join(badges))
            item = QListWidgetItem(label)
            item.setToolTip("\n".join(tooltip_parts))
            item.setData(Qt.UserRole, conv_id)
            self._hide_native_sidebar_text(item, label)
            item.setSizeHint(QSize(0, SIDEBAR_ROW_HEIGHT))
            self.dm_list.addItem(item)
            self.dm_list.setItemWidget(item, self._sidebar_row_widget(
                title=title,
                subtitle=subtitle,
                leading=(title[:1] or "?").upper(),
                presence="online" if c.get("status") == "online" else "offline",
                badges=badges,
                unread=unread,
                active=conv_id == int(self.active_conv_id or 0),
                tooltip="\n".join(tooltip_parts),
                on_left_click=(
                    lambda cid=conv_id: self._switch_to_conv(cid, is_group=False)
                ),
                on_context_menu=(
                    lambda global_pos, lst=self.dm_list:
                    self._dm_context_menu(lst.viewport().mapFromGlobal(global_pos))
                ),
            ))
        self._end_list_refresh(self.dm_list, scroll_state, updates_enabled)

    def _refresh_group_list(self):
        """Dựng lại danh sách nhóm trong sidebar."""
        scroll_state, updates_enabled = self._begin_list_refresh(self.group_list)
        self._clear_list_item_widgets(self.group_list)
        for g in sorted(
                self.group_convs,
                key=lambda item: (
                    bool(item.get("archived")),
                    not bool(item.get("pinned_conversation")),
                    item.get("name", ""))):
            conv_id = int(g.get("conversation_id", 0) or 0)
            preview = str(g.get("last_message", "") or "")
            sec = self._conv_security.get(conv_id, {})
            sec_label = sec.get("label", "")
            if sec.get("status") in IDENTITY_REVIEW_STATUSES + ("verified", "unknown"):
                sec_label = ""
            badges = []
            unread = conv_id in self._unread_convs
            if unread:
                badges.append("unread")
            if g.get("is_disbanded"):
                badges.append("disbanded")
            if sec_label:
                badges.append(sec_label)
            if g.get("pinned_conversation"):
                badges.append("pinned")
            if g.get("muted"):
                badges.append("muted")
            if g.get("archived"):
                badges.append("archived")
            if g.get("disappear_after_secs"):
                badges.append("timer")
            title = g.get("name", "Unnamed Group")
            subtitle = preview or (
                "Group disbanded" if g.get("is_disbanded") else "Group conversation")
            label = f"#  {title}"
            if badges:
                label += "  " + " ".join(f"[{b}]" for b in badges)
            if preview:
                label += f"\n    {self._clip_text(preview, 38)}"
            tooltip_parts = [title, subtitle]
            if badges:
                tooltip_parts.append(" | ".join(badges))
            item = QListWidgetItem(label)
            item.setToolTip("\n".join(tooltip_parts))
            item.setData(Qt.UserRole, conv_id)
            self._hide_native_sidebar_text(item, label)
            item.setSizeHint(QSize(0, SIDEBAR_ROW_HEIGHT))
            self.group_list.addItem(item)
            self.group_list.setItemWidget(item, self._sidebar_row_widget(
                title=title,
                subtitle=subtitle,
                leading="#",
                presence="warn" if g.get("is_disbanded") else "group",
                badges=badges,
                unread=unread,
                active=conv_id == int(self.active_conv_id or 0),
                tooltip="\n".join(tooltip_parts),
                on_left_click=(
                    lambda cid=conv_id: self._switch_to_conv(cid, is_group=True)
                ),
                on_context_menu=(
                    lambda global_pos, lst=self.group_list:
                    self._group_context_menu(lst.viewport().mapFromGlobal(global_pos))
                ),
            ))
        self._end_list_refresh(self.group_list, scroll_state, updates_enabled)

    def update_search_results(self, users: list):
        """Hiển thị kết quả tìm kiếm người dùng."""
        scroll_state, updates_enabled = self._begin_list_refresh(self.search_results)
        self.search_results.clear()
        for u in users:
            is_friend = "  [friend]" if u["id"] in self.friends else ""
            item = QListWidgetItem(f"{u['username']}{is_friend}")
            item.setData(Qt.UserRole,     u["id"])
            item.setData(Qt.UserRole + 1, u["username"])
            self.search_results.addItem(item)
        self._end_list_refresh(self.search_results, scroll_state, updates_enabled)

    def _clear_request_list(self):
        """Xóa danh sách lời mời đang hiển thị."""
        for row in range(self.request_list.count()):
            item = self.request_list.item(row)
            widget = self.request_list.itemWidget(item)
            if widget is not None:
                self.request_list.removeItemWidget(item)
                widget.hide()
                widget.setParent(None)
                widget.deleteLater()
        self.request_list.clear()

    def update_requests(self, requests: list):
        """Cập nhật danh sách lời mời kết bạn."""
        scroll_state, updates_enabled = self._begin_list_refresh(self.request_list)
        self._clear_request_list()
        for r in requests:
            widget = QWidget()
            lay    = QHBoxLayout(widget)
            lay.setContentsMargins(8, 8, 8, 8)
            lay.setSpacing(6)

            lbl = QLabel(r["username"])
            lbl.setStyleSheet("color:#dbdee1; font-size:13px; font-weight:600;")
            lbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            lay.addWidget(lbl)

            btn_accept = QPushButton("Accept")
            btn_accept.setObjectName("small")
            btn_accept.setMinimumSize(60, 28)
            btn_accept.setMaximumHeight(30)
            btn_accept.clicked.connect(
                lambda checked, uid=r["user_id"]: self._accept_request(uid)
            )
            lay.addWidget(btn_accept)

            btn_reject = QPushButton("Reject")
            btn_reject.setObjectName("danger")
            btn_reject.setMinimumSize(60, 28)
            btn_reject.setMaximumHeight(30)
            btn_reject.clicked.connect(
                lambda checked, uid=r["user_id"]: self.sig_friend_reject.emit(uid)
            )
            lay.addWidget(btn_reject)

            widget.adjustSize()
            item = QListWidgetItem()
            item.setSizeHint(QSize(0, 52))
            self.request_list.addItem(item)
            self.request_list.setItemWidget(item, widget)
        count = 0 if self.current_view == "requests" else len(requests)
        self._set_request_badge(count)
        self._end_list_refresh(self.request_list, scroll_state, updates_enabled)

    def notify_friend_request(self, from_username: str):
        """Hiển thị thông báo có lời mời kết bạn mới."""
        if not self.__dict__.get("_notifications_enabled", True):
            return
        if self.current_view == "requests":
            return
        self._set_request_badge(self._pending_requests_count + 1)

    def _set_request_badge(self, count: int):
        """Cập nhật badge số lời mời đang chờ."""
        count = max(0, int(count or 0))
        if not self.__dict__.get("_notifications_enabled", True):
            count = 0
        self._pending_requests_count = count
        if count <= 0:
            self.btn_requests.setText("Requests")
            self.btn_requests.setStyleSheet("")
            return
        self.btn_requests.setText(f"Requests ({count})")
        self.btn_requests.setStyleSheet(
            "QPushButton { background:#ed4245; color:#fff; text-align:left;"
            " padding:10px 14px; border:none; border-radius:8px;"
            " margin:4px 8px; font-weight:600; font-size:13px; }"
            "QPushButton:hover { background:#c03537; }"
        )

    # Message history
    #
    # ``hist`` là state render tạm thời của UI, không phải nguồn sự thật duy
    # nhất. Một conversation chỉ được coi là đã load đầy đủ khi nhận response
    # history từ server; live/offline message đến trước đó chỉ được merge sau.

    def _history_loaded_set(self):
        """Lazy-init tập conversation đã nhận full history."""
        if "_history_loaded_convs" not in self.__dict__:
            self._history_loaded_convs = set()
        return self._history_loaded_convs

    def invalidate_history(self, conv_id: int, clear_messages: bool = False):
        """Buộc lần mở conversation tiếp theo fetch lại full history."""
        conv_id = int(conv_id)
        self._history_loaded_set().discard(conv_id)
        if clear_messages:
            self.hist.pop(conv_id, None)

    def add_msg(self, conv_id: int, sender_id: int, body: str, ts: str,
                msg_id: int = 0, pinned: bool = False, reactions=None,
                forwarded_from_id: int = 0, reply_to_message_id: int = 0):
        """Thêm live/offline message vào UI mà không đánh dấu history đã đầy đủ."""
        conv_id = int(conv_id)
        entry = {
            "sender_id": sender_id,
            "body":      body,
            "ts":        ts,
            "msg_id":    msg_id,
            "edited":    False,
            "deleted":   False,
            "pinned":    bool(pinned),
            "reactions": self._normalize_reactions(reactions or []),
            "forwarded_from_id": int(forwarded_from_id or 0),
            "reply_to_message_id": int(reply_to_message_id or 0),
        }
        self.hist.setdefault(conv_id, []).append(entry)
        self._apply_pending_edit_events(conv_id)
        if conv_id == self.active_conv_id and self.current_view == "chat":
            self._redraw()
            self._mark_active_conversation_read()
        elif (sender_id != self.my_id
              and body
              and body not in ("__KEM_INIT__", "__S2_CONTROL__", "__S3_INIT__")
              and not self._is_unavailable_history_body(body)
              and self.__dict__.get("_notifications_enabled", True)
              and not self._is_conversation_muted(conv_id)):
            self._unread_convs.add(conv_id)
            self._update_chat_badge()

    def _system_event_keys_for(self, conv_id: int, system_event_id: int = 0,
                               event_key=None) -> list[tuple]:
        """Khóa nhận diện các system event của một hội thoại."""
        keys: list[tuple] = []
        conv_id = int(conv_id)
        try:
            sid = int(system_event_id or 0)
        except Exception:
            sid = 0
        if sid > 0:
            keys.append((conv_id, "system_event_id", str(sid)))
        if event_key is not None:
            if isinstance(event_key, (tuple, list)):
                keys.append((conv_id,) + tuple(str(x) for x in event_key))
            else:
                keys.append((conv_id, str(event_key)))
        return keys

    def _system_event_anchor_from_entry(self, entry: dict, fallback: int = 0) -> int:
        """Vị trí chèn một system event vào dòng thời gian."""
        for key in ("after_message_id", "sort_after_message_id"):
            try:
                value = int(entry.get(key, 0) or 0)
            except Exception:
                value = 0
            if value > 0:
                return value
        return int(fallback or 0)

    def add_system_event(self, conv_id: int, text: str, ts: str = "",
                         event_key=None, system_event_id: int = 0,
                         after_message_id: int | None = None):
        """Thêm dòng sự kiện nhỏ trong group như member joined/left."""
        conv_id = int(conv_id)
        if not text:
            return
        event_keys = self._system_event_keys_for(
            conv_id, system_event_id=system_event_id, event_key=event_key)
        if event_keys:
            seen = self.__dict__.setdefault("_system_event_keys", set())
            if any(key in seen for key in event_keys):
                return
            for key in event_keys:
                seen.add(key)
        if after_message_id is None:
            after_message_id = max(self._visible_message_ids(conv_id) or [0])
        try:
            after_id = int(after_message_id or 0)
        except Exception:
            after_id = 0
        try:
            sid = int(system_event_id or 0)
        except Exception:
            sid = 0
        self._failed_send_counter += 1
        msg_id = -(1_000_000_000 + sid) if sid > 0 else -self._failed_send_counter
        self.hist.setdefault(conv_id, []).append({
            "sender_id": 0,
            "body": f"__SYSTEM__:{text}",
            "ts": ts,
            "msg_id": msg_id,
            "event_key": event_keys[0] if event_keys else None,
            "event_keys": event_keys,
            "system_event_id": sid,
            "after_message_id": after_id,
            "sort_after_message_id": after_id,
            "edited": False,
            "deleted": False,
            "pinned": False,
            "reactions": {},
            "forwarded_from_id": 0,
            "reply_to_message_id": 0,
            "system": True,
        })
        if conv_id == self.active_conv_id and self.current_view == "chat":
            self._redraw()

    def show_send_failed(self, conv_id: int, body: str, reason: str,
                         file_path: str = ""):
        """Render message gửi thất bại với nút Retry/Dismiss."""
        conv_id = int(conv_id)
        self._failed_send_counter += 1
        msg_id = -self._failed_send_counter
        entry = {
            "sender_id": self.my_id,
            "body": body,
            "ts": "not sent",
            "msg_id": msg_id,
            "edited": False,
            "deleted": False,
            "pinned": False,
            "reactions": {},
            "forwarded_from_id": 0,
            "reply_to_message_id": 0,
            "failed": True,
            "failure_reason": reason or "Message was not sent.",
            "retry_body": body,
            "retry_file": file_path or "",
        }
        self.hist.setdefault(conv_id, []).append(entry)
        if conv_id == self.active_conv_id:
            self._redraw()

    def show_send_pending(self, conv_id: int, body: str,
                          file_path: str = "", reply_to_message_id: int = 0) -> int:
        """Render bubble tạm thời trong lúc chờ server accept ciphertext."""
        conv_id = int(conv_id)
        self._failed_send_counter += 1
        msg_id = -self._failed_send_counter
        entry = {
            "sender_id": self.my_id,
            "body": body,
            "ts": "sending",
            "msg_id": msg_id,
            "edited": False,
            "deleted": False,
            "pinned": False,
            "reactions": {},
            "forwarded_from_id": 0,
            "reply_to_message_id": int(reply_to_message_id or 0),
            "sending": True,
            "retry_body": body,
            "retry_file": file_path or "",
        }
        self.hist.setdefault(conv_id, []).append(entry)
        if conv_id == self.active_conv_id:
            self._redraw()
        return msg_id

    def remove_pending_send(self, conv_id: int, body: str = "",
                            pending_id: int = 0):
        """Xóa bubble pending khi server echo lại message thật có id."""
        conv_id = int(conv_id)
        removed = False
        kept = []
        for msg in self.hist.get(conv_id, []):
            mid = int(msg.get("msg_id", 0) or 0)
            is_pending = bool(msg.get("sending"))
            same_id = pending_id and mid == int(pending_id)
            same_body = body and str(msg.get("retry_body", msg.get("body", ""))) == body
            if is_pending and (same_id or (not pending_id and same_body)) and not removed:
                removed = True
                continue
            kept.append(msg)
        if removed:
            self.hist[conv_id] = kept
            if conv_id == self.active_conv_id:
                self._redraw()

    def mark_pending_sends_failed(self, reason: str):
        """Turn all local pending bubbles into retryable failed messages."""
        changed = False
        for msgs in self.hist.values():
            for msg in msgs:
                if not msg.get("sending"):
                    continue
                msg["sending"] = False
                msg["failed"] = True
                msg["ts"] = "not sent"
                msg["failure_reason"] = reason or "Connection was interrupted."
                changed = True
        if changed and self.active_conv_id > 0:
            self._redraw()

    def _remove_failed_message(self, msg_id: int):
        """Gỡ một bong bóng tin gửi thất bại khỏi UI."""
        conv_id = int(self.active_conv_id or 0)
        if conv_id <= 0:
            return
        self.hist[conv_id] = [
            m for m in self.hist.get(conv_id, [])
            if int(m.get("msg_id", 0) or 0) != int(msg_id)
        ]
        self._redraw()

    def _retry_failed_message(self, msg_id: int):
        """Gửi lại message/file thất bại bằng signal UI tương ứng."""
        conv_id = int(self.active_conv_id or 0)
        msg = self._find_message(conv_id, msg_id)
        if not msg:
            return
        retry_file = str(msg.get("retry_file", "") or "")
        retry_body = str(msg.get("retry_body", "") or msg.get("body", ""))
        self._remove_failed_message(msg_id)
        if retry_file:
            self.sig_send_file.emit(conv_id, retry_file)
        else:
            self.sig_send.emit(conv_id, retry_body)

    def load_history(self, conv_id: int, msgs: list, system_events: list | None = None):
        """Merge full history từ server vào ``hist`` theo message id.

        Hàm này giữ lại pending/failed local message, merge metadata như pin và
        reactions, apply edit event vào message gốc, rồi mới đánh dấu history đã
        load. Nhờ vậy tin offline đến trước history không làm mất lịch sử cũ.
        """
        if "_history_loading_convs" in self.__dict__:
            self._history_loading_convs.discard(int(conv_id))
        if int(conv_id) == int(self.active_conv_id or 0):
            self._update_security_guidance_label()
        old_hist = [dict(m) for m in self.hist.get(conv_id, [])]
        local_system_events = []
        local_transient = []
        previous_positive_id = 0
        for m in old_hist:
            msg_id_old = int(m.get("msg_id", 0) or 0)
            is_system = (
                m.get("system")
                or str(m.get("body", "")).startswith("__SYSTEM__:")
            )
            if msg_id_old > 0:
                previous_positive_id = msg_id_old
            elif is_system:
                entry = dict(m)
                anchor = self._system_event_anchor_from_entry(
                    entry, previous_positive_id)
                entry["after_message_id"] = anchor
                entry["sort_after_message_id"] = anchor
                event_keys = entry.get("event_keys")
                if not event_keys:
                    event_keys = self._system_event_keys_for(
                        conv_id,
                        system_event_id=int(entry.get("system_event_id", 0) or 0),
                        event_key=entry.get("event_key"),
                    )
                    entry["event_keys"] = event_keys
                local_system_events.append(entry)
            elif msg_id_old <= 0:
                local_transient.append(dict(m))
        existing_by_id = {
            int(m.get("msg_id", 0)): dict(m)
            for m in old_hist
            if int(m.get("msg_id", 0) or 0) > 0
        }
        incoming_by_id = {}
        pending_edits = []
        for m in msgs:
            body    = m.get("body", "")
            deleted = bool(m.get("deleted", False))
            # Bỏ qua control message của protocol vì chúng chỉ cập nhật state
            # crypto/group, không phải message người dùng cần đọc.
            if body in ("__KEM_INIT__", "__S2_CONTROL__", "__S3_INIT__") and not deleted:
                continue
            edit_target = int(m.get("edit_target_message_id", 0) or 0)
            if edit_target > 0:
                if self._is_unavailable_history_body(body):
                    continue
                pending_edits.append({
                    "target_msg_id": edit_target,
                    "body": body,
                    "sender_id": int(m.get("sender_id", 0)),
                    "ts": ts_short(m.get("time", "")),
                })
                continue

            msg_id = int(m.get("id", 0))
            entry = {
                "sender_id": int(m.get("sender_id", 0)),
                "body":      body,
                "ts":        ts_short(m.get("time", "")),
                "msg_id":    msg_id,
                "edited":    bool(m.get("edited", False)),
                "deleted":   deleted,
                "pinned":    bool(m.get("pinned", False)),
                "reactions": self._normalize_reactions(m.get("reactions", [])),
                "forwarded_from_id": int(m.get("forwarded_from_id", 0) or 0),
                "reply_to_message_id": int(m.get("reply_to_message_id", 0) or 0),
                "hidden":    bool(m.get("hidden", False)),
            }
            previous = existing_by_id.get(msg_id)
            if (previous
                    and self._is_unavailable_history_body(body)
                    and not self._is_unavailable_history_body(previous.get("body", ""))):
                entry["body"] = previous.get("body", "")
                entry["edited"] = bool(entry["edited"] or previous.get("edited", False))
                entry["hidden"] = False
            if msg_id > 0:
                incoming_by_id[msg_id] = entry

        merged = dict(existing_by_id)
        merged.update(incoming_by_id)
        merged_messages = [
            merged[mid] for mid in sorted(merged)
            if mid > 0 and not (
                merged[mid].get("body") in ("__KEM_INIT__", "__S2_CONTROL__", "__S3_INIT__")
                and not merged[mid].get("deleted")
            )
        ]

        persisted_system_events = []
        persisted_keys: set[tuple] = set()
        seen = self.__dict__.setdefault("_system_event_keys", set())
        for ev in system_events or []:
            text = str(
                ev.get("text", "")
                or ev.get("body", "")
                or ev.get("message", "")
                or ""
            )
            if text.startswith("__SYSTEM__:"):
                text = text[len("__SYSTEM__:"):]
            if not text:
                continue
            try:
                sid = int(ev.get("system_event_id", ev.get("id", 0)) or 0)
            except Exception:
                sid = 0
            try:
                after_id = int(ev.get("after_message_id", 0) or 0)
            except Exception:
                after_id = 0
            event_key = ev.get("event_key")
            event_keys = self._system_event_keys_for(
                conv_id, system_event_id=sid, event_key=event_key)
            if event_keys and any(key in persisted_keys for key in event_keys):
                continue
            for key in event_keys:
                persisted_keys.add(key)
                seen.add(key)
            msg_id = -(1_000_000_000 + sid) if sid > 0 else -self._failed_send_counter - 1
            if sid <= 0:
                self._failed_send_counter += 1
                msg_id = -self._failed_send_counter
            persisted_system_events.append({
                "sender_id": 0,
                "body": f"__SYSTEM__:{text}",
                "ts": ts_short(ev.get("time", ev.get("event_time", ""))),
                "msg_id": msg_id,
                "event_key": event_keys[0] if event_keys else None,
                "event_keys": event_keys,
                "system_event_id": sid,
                "after_message_id": after_id,
                "sort_after_message_id": after_id,
                "edited": False,
                "deleted": False,
                "pinned": False,
                "reactions": {},
                "forwarded_from_id": 0,
                "reply_to_message_id": 0,
                "system": True,
                "persisted": True,
            })

        kept_local_system_events = []
        for entry in local_system_events:
            event_keys = entry.get("event_keys") or []
            if event_keys and any(key in persisted_keys for key in event_keys):
                continue
            for key in event_keys:
                seen.add(key)
            kept_local_system_events.append(entry)

        timeline = []
        for msg in merged_messages:
            mid = int(msg.get("msg_id", 0) or 0)
            timeline.append((mid, 0, mid, msg))
        for seq, event in enumerate(persisted_system_events + kept_local_system_events):
            anchor = self._system_event_anchor_from_entry(event, 0)
            try:
                sid = int(event.get("system_event_id", 0) or 0)
            except Exception:
                sid = 0
            order = sid if sid > 0 else 100_000_000 + seq
            timeline.append((anchor, 1, order, event))
        timeline.sort(key=lambda item: (item[0], item[1], item[2]))
        self.hist[conv_id] = [item[3] for item in timeline] + local_transient
        for ev in pending_edits:
            self.apply_edit_event(
                conv_id, ev["target_msg_id"], ev["body"],
                ev["sender_id"], ev["ts"], redraw=False)
        self._apply_pending_edit_events(conv_id, redraw=False)
        self._history_loaded_set().add(int(conv_id))
        self._update_pin_button()
        if conv_id == self.active_conv_id:
            open_bottom = int(conv_id) in self.__dict__.get(
                "_scroll_to_latest_after_history", set())
            self.__dict__.setdefault(
                "_scroll_to_latest_after_history", set()).discard(int(conv_id))
            self._redraw(scroll_mode="bottom" if open_bottom else "preserve")
            self._mark_active_conversation_read()

    def _visible_message_ids(self, conv_id: int) -> list[int]:
        """Danh sách id các tin đang hiển thị trong khung."""
        ids = []
        for msg in self.hist.get(int(conv_id), []):
            msg_id = int(msg.get("msg_id", 0) or 0)
            if msg_id > 0 and not msg.get("deleted") and not msg.get("hidden"):
                ids.append(msg_id)
        return ids

    def _mark_active_conversation_read(self):
        """Đánh dấu hội thoại đang mở là đã đọc."""
        conv_id = int(self.active_conv_id or 0)
        if conv_id <= 0:
            return
        last_id = max(self._visible_message_ids(conv_id) or [0])
        pending = self.__dict__.setdefault("_pending_read_clear_convs", set())
        needs_server_clear = (
            conv_id in pending
            or self._conversation_has_unread_record(conv_id)
        )
        if last_id <= 0 and not needs_server_clear:
            return
        if self.__dict__.get("_metadata_protection_enabled", False):
            self._update_conversation_pref(conv_id, unread=False)
            pending.discard(conv_id)
            return
        last_read_sent = self.__dict__.setdefault("_last_read_sent", {})
        if last_id > 0 and int(last_read_sent.get(conv_id, 0) or 0) >= last_id:
            self._update_conversation_pref(conv_id, unread=False)
            pending.discard(conv_id)
            return
        if last_id > 0:
            last_read_sent[conv_id] = last_id
        self._update_conversation_pref(conv_id, unread=False)
        try:
            self.sig_command.emit({
                "type": "mark_read",
                "conversation_id": conv_id,
                "last_message_id": last_id,
            })
            pending.discard(conv_id)
        except RuntimeError:
            pass

    def _on_input_changed(self):
        """Xử lý khi nội dung ô soạn tin thay đổi (gửi tín hiệu typing)."""
        if not self.__dict__.get("_typing_indicators_enabled", False):
            self._typing_active_sent = False
            self._typing_conv_id = 0
            if "_typing_idle_timer" in self.__dict__:
                self._typing_idle_timer.stop()
            return
        if self.active_conv_id <= 0 or not self.inp.isEnabled():
            return
        if not self.inp.toPlainText().strip():
            self._send_typing_stop()
            return
        if (not self._typing_active_sent
                or self._typing_conv_id != self.active_conv_id):
            self._send_typing_stop()
            self.sig_command.emit({
                "type": "typing_start",
                "conversation_id": int(self.active_conv_id),
            })
            self._typing_active_sent = True
            self._typing_conv_id = int(self.active_conv_id)
        self._typing_idle_timer.start()

    def _send_typing_stop(self):
        """Gửi tín hiệu ngừng gõ."""
        if not self.__dict__.get("_typing_indicators_enabled", False):
            self._typing_active_sent = False
            self._typing_conv_id = 0
            if "_typing_idle_timer" in self.__dict__:
                self._typing_idle_timer.stop()
            return
        if (self.__dict__.get("_typing_active_sent", False)
                and self.__dict__.get("_typing_conv_id", 0) > 0):
            try:
                self.sig_command.emit({
                    "type": "typing_stop",
                    "conversation_id": int(self._typing_conv_id),
                })
            except Exception:
                pass
        self._typing_active_sent = False
        self._typing_conv_id = 0
        if "_typing_idle_timer" in self.__dict__:
            self._typing_idle_timer.stop()

    def set_typing(self, conv_id: int, user_id: int, username: str, active: bool):
        """Hiển thị trạng thái đang gõ của đối phương."""
        conv_id = int(conv_id)
        user_id = int(user_id)
        if conv_id <= 0 or user_id <= 0 or user_id == self.my_id:
            return
        key = (conv_id, user_id)
        timer = self._typing_timers.pop(key, None)
        if timer:
            timer.stop()
            timer.deleteLater()
        if active:
            self._typing_convs.setdefault(conv_id, {})[user_id] = (
                username or self.friends.get(user_id, {}).get("username")
                or f"User#{user_id}"
            )
            timer = QTimer(self)
            timer.setSingleShot(True)
            timer.setInterval(4500)
            timer.timeout.connect(
                lambda cid=conv_id, uid=user_id: self._clear_typing(cid, uid)
            )
            self._typing_timers[key] = timer
            timer.start()
        else:
            self._typing_convs.get(conv_id, {}).pop(user_id, None)
            if not self._typing_convs.get(conv_id):
                self._typing_convs.pop(conv_id, None)
        self._update_typing_label()

    def _clear_typing(self, conv_id: int, user_id: int):
        """Xóa hiển thị trạng thái đang gõ."""
        key = (int(conv_id), int(user_id))
        timer = self._typing_timers.pop(key, None)
        if timer:
            timer.deleteLater()
        users = self._typing_convs.get(int(conv_id), {})
        users.pop(int(user_id), None)
        if not users:
            self._typing_convs.pop(int(conv_id), None)
        self._update_typing_label()

    def _update_typing_label(self):
        """Cập nhật nhãn đang gõ."""
        if "lbl_typing" not in self.__dict__:
            return
        if "_typing_convs" not in self.__dict__:
            self._typing_convs = {}
        users = list(self._typing_convs.get(int(self.active_conv_id), {}).values())
        if not users:
            self.lbl_typing.setText("")
        elif len(users) == 1:
            self.lbl_typing.setText(f"{users[0]} is typing...")
        elif len(users) == 2:
            self.lbl_typing.setText(f"{users[0]} and {users[1]} are typing...")
        else:
            self.lbl_typing.setText("Several people are typing...")

    @staticmethod
    def _is_unavailable_history_body(body) -> bool:
        """Kiểm tra body có phải tin không giải mã được không."""
        if not isinstance(body, str):
            return False
        return (
            "Forward-secret" in body
            or "Cannot decrypt" in body
            or body.startswith("[Cannot")
            or body.startswith("[Encrypted")
        )

    def update_message(self, conv_id: int, msg_id: int, new_body: str,
                       edited: bool, deleted: bool):
        """Update a message in the local history and redraw if visible."""
        updated = None
        for m in self.hist.get(conv_id, []):
            if m["msg_id"] == msg_id:
                m["body"]    = new_body
                m["edited"]  = edited
                m["deleted"] = deleted
                updated = m
                break
        if conv_id == self.active_conv_id:
            self._redraw()
        return updated

    def apply_edit_event(self, conv_id: int, target_msg_id: int, new_body: str,
                         sender_id: int, ts: str, redraw: bool = True):
        """Áp một sự kiện chỉnh sửa lên tin tương ứng."""
        updated = self.update_message(
            conv_id, target_msg_id, new_body, edited=True, deleted=False)
        if not updated:
            self._pending_edit_events.setdefault(conv_id, []).append({
                "target_msg_id": target_msg_id,
                "body": new_body,
                "sender_id": sender_id,
                "ts": ts,
            })
            return None
        if redraw and conv_id == self.active_conv_id:
            self._redraw()
        return updated

    def _apply_pending_edit_events(self, conv_id: int, redraw: bool = True):
        """Áp các sự kiện chỉnh sửa còn chờ (đến trước tin gốc)."""
        pending = self._pending_edit_events.get(conv_id, [])
        if not pending:
            return
        remaining = []
        for ev in pending:
            updated = self.update_message(
                conv_id, ev["target_msg_id"], ev["body"],
                edited=True, deleted=False)
            if not updated:
                remaining.append(ev)
        if remaining:
            self._pending_edit_events[conv_id] = remaining
        else:
            self._pending_edit_events.pop(conv_id, None)
        if redraw and conv_id == self.active_conv_id:
            self._redraw()

    @staticmethod
    def _normalize_reactions(reactions):
        """Chuẩn hóa cấu trúc dữ liệu reaction."""
        out = {}
        if isinstance(reactions, dict):
            iterable = reactions.values()
        else:
            iterable = reactions or []
        for r in iterable:
            emoji = str(r.get("emoji", "") if isinstance(r, dict) else "")
            if not emoji:
                continue
            out[emoji] = {
                "emoji": emoji,
                "count": int(r.get("count", 0) or 0),
                "me": bool(r.get("me", False)),
            }
        return out

    def _update_pin_button(self):
        """Cập nhật nút ghim theo trạng thái tin."""
        if not hasattr(self, "btn_pins"):
            return
        count = sum(1 for m in self.hist.get(self.active_conv_id, [])
                    if m.get("pinned") and not m.get("deleted"))
        self.btn_pins.setText(f"Pins ({count})" if count else "Pins")

    def set_message_pinned(self, conv_id: int, msg_id: int, pinned: bool):
        """Đánh dấu một tin đã ghim/bỏ ghim trên UI."""
        for m in self.hist.get(conv_id, []):
            if m.get("msg_id") == msg_id:
                m["pinned"] = bool(pinned)
                break
        if conv_id == self.active_conv_id:
            self._update_pin_button()
            self._redraw()

    def update_reaction(self, conv_id: int, msg_id: int, emoji: str,
                        user_id: int, added: bool):
        """Cập nhật hiển thị reaction của một tin."""
        if not emoji:
            return
        for m in self.hist.get(conv_id, []):
            if m.get("msg_id") != msg_id:
                continue
            reactions = m.setdefault("reactions", {})
            cur = reactions.setdefault(
                emoji, {"emoji": emoji, "count": 0, "me": False})
            if added:
                if user_id == self.my_id and cur.get("me"):
                    break
                cur["count"] = int(cur.get("count", 0)) + 1
                if user_id == self.my_id:
                    cur["me"] = True
            else:
                if user_id == self.my_id and not cur.get("me"):
                    break
                cur["count"] = max(0, int(cur.get("count", 0)) - 1)
                if user_id == self.my_id:
                    cur["me"] = False
                if cur["count"] <= 0:
                    reactions.pop(emoji, None)
            break
        if conv_id == self.active_conv_id:
            self._redraw()

    def remove_conversation(self, conv_id: int):
        """Hide a conversation from both lists (server-side hidden_at set)."""
        self.invalidate_history(conv_id, clear_messages=True)
        self.dm_convs    = [c for c in self.dm_convs
                            if c["conversation_id"] != conv_id]
        self.group_convs = [g for g in self.group_convs
                            if g["conversation_id"] != conv_id]
        self._refresh_dm_list()
        self._refresh_group_list()
        if self.active_conv_id == conv_id:
            self.active_conv_id = 0
            self._active_is_group = False
            self.view.clear()
            self.lbl_chat.setText("Select a conversation")
            if "lbl_chat_presence" in self.__dict__:
                self.lbl_chat_presence.setText("")
            self._set_input_enabled(True)

    def mark_group_disbanded(self, conv_id: int):
        """Mark a group as disbanded locally."""
        self._disbanded_convs.add(conv_id)
        for g in self.group_convs:
            if g["conversation_id"] == conv_id:
                g["is_disbanded"] = True
                break
        self._refresh_group_list()
        if self.active_conv_id == conv_id:
            self._set_input_enabled(False)
            self.inp.setPlaceholderText("This group has been disbanded.")

    def show_profile(self, profile: dict):
        """Show a read-only profile view dialog."""
        from client.dialogs import ProfileViewDialog
        dlg = ProfileViewDialog(profile, self)
        dlg.exec_()

    def show_privacy_settings(self, settings: dict):
        """Mở dialog thiết lập quyền riêng tư."""
        dlg = QDialog(self)
        dlg.setWindowTitle("Privacy Settings")
        dlg.setMinimumWidth(360)
        lay = QVBoxLayout(dlg)
        lay.setSpacing(10)
        options = ["everyone", "friends", "nobody"]

        combos = {}
        for key, label in [
            ("privacy_online", "Online status"),
            ("privacy_last_seen", "Last seen"),
        ]:
            lay.addWidget(QLabel(label))
            cb = QComboBox()
            cb.setObjectName(key)
            cb.setProperty("testid", key)
            cb.addItems(options)
            value = settings.get(key, "everyone")
            cb.setCurrentText(value if value in options else "everyone")
            lay.addWidget(cb)
            combos[key] = cb

        protect_meta = QCheckBox("Protect message metadata on this device")
        protect_meta.setObjectName("privacy.metadata_protection")
        protect_meta.setProperty("testid", "privacy.metadata_protection")
        protect_meta.setChecked(self.__dict__.get("_metadata_protection_enabled", False))
        protect_meta.setToolTip(
            "When enabled, SecChat stops sending typing status from this device. "
            "Read/unread is kept local and is never shown to the other side."
        )
        lay.addWidget(protect_meta)

        notifications = QCheckBox("Show unread and request badges on this device")
        notifications.setObjectName("privacy.notifications")
        notifications.setProperty("testid", "privacy.notifications")
        notifications.setChecked(self.__dict__.get("_notifications_enabled", True))
        lay.addWidget(notifications)

        lay.addWidget(QLabel("Local plaintext cache:"))
        cache_note = QLabel(
            "Cache is encrypted on this device and is used for readable "
            "previews and history after relogin. Clearing or disabling it can "
            "make old forward-secret messages unavailable locally."
        )
        cache_note.setWordWrap(True)
        cache_note.setStyleSheet("color:#949ba4; font-size:12px;")
        lay.addWidget(cache_note)
        cache_enabled = QCheckBox("Store decrypted previews and history cache on this device")
        cache_enabled.setObjectName("privacy.cache.enabled")
        cache_enabled.setProperty("testid", "privacy.cache.enabled")
        cache_enabled.setChecked(
            bool(self._local_cache_policy.get("enabled", True)))
        lay.addWidget(cache_enabled)

        lay.addWidget(QLabel("Cache retention:"))
        cache_ttl = QComboBox()
        cache_ttl.setObjectName("privacy.cache.ttl")
        cache_ttl.setProperty("testid", "privacy.cache.ttl")
        ttl_options = [
            ("1 day", 1),
            ("7 days", 7),
            ("30 days", 30),
            ("90 days", 90),
            ("Never expire", -1),
        ]
        for label, value in ttl_options:
            cache_ttl.addItem(label, value)
        current_ttl = int(self._local_cache_policy.get("ttl_days", 30))
        idx = next((i for i, (_label, val) in enumerate(ttl_options)
                    if val == current_ttl), 2)
        cache_ttl.setCurrentIndex(idx)
        lay.addWidget(cache_ttl)

        clear_on_logout = QCheckBox("Clear local message cache on logout")
        clear_on_logout.setObjectName("privacy.cache.clear_on_logout")
        clear_on_logout.setProperty("testid", "privacy.cache.clear_on_logout")
        clear_on_logout.setChecked(
            bool(self._local_cache_policy.get("clear_on_logout", False)))
        lay.addWidget(clear_on_logout)

        btn_clear_cache = QPushButton("Clear local message cache")
        btn_clear_cache.setObjectName("ghost")
        btn_clear_cache.setProperty("testid", "privacy.cache.clear_now")
        btn_clear_cache.setToolTip(
            "Deletes the local plaintext cache used for previews and history recovery. "
            "Encrypted messages and protocol state are not removed."
        )
        btn_clear_cache.clicked.connect(self._confirm_clear_local_cache)
        lay.addWidget(btn_clear_cache)

        btns = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        lay.addWidget(btns)

        def save():
            self.set_metadata_protection(protect_meta.isChecked())
            self._notifications_enabled = bool(notifications.isChecked())
            policy = {
                "enabled": bool(cache_enabled.isChecked()),
                "ttl_days": int(cache_ttl.currentData()),
                "clear_on_logout": bool(clear_on_logout.isChecked()),
                "disabled_conversation_ids": sorted(self._cache_disabled_ids()),
            }
            self.set_cache_policy(policy)
            self.sig_update_cache_policy.emit(policy)
            if not self._notifications_enabled:
                self._unread_convs.clear()
                self._pending_requests_count = 0
                self._update_chat_badge()
                self.btn_requests.setText("Requests")
                self.btn_requests.setStyleSheet("")
            self.sig_command.emit({
                "type": "update_privacy",
                "privacy_online": combos["privacy_online"].currentText(),
                "privacy_last_seen": combos["privacy_last_seen"].currentText(),
            })
            dlg.accept()

        btns.accepted.connect(save)
        btns.rejected.connect(dlg.reject)
        dlg.exec_()

    def _confirm_clear_local_cache(self):
        """Hỏi xác nhận trước khi xóa toàn bộ cache cục bộ."""
        reply = QMessageBox.question(
            self,
            "Clear Local Cache",
            "Delete locally cached plaintext message previews on this device?\n"
            "Encrypted messages and keys are kept.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.sig_clear_local_cache.emit()

    def _confirm_clear_conversation_cache(self, conv_id: int):
        """Hỏi xác nhận trước khi xóa cache một hội thoại."""
        reply = QMessageBox.question(
            self,
            "Clear Conversation Cache",
            "Delete the local plaintext cache for this conversation on this device?\n"
            "Encrypted messages and keys are kept.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.sig_clear_conversation_cache.emit(int(conv_id))

    def show_blocked_list(self, users: list):
        """Hiển thị danh sách người bị chặn."""
        dlg = QDialog(self)
        dlg.setWindowTitle("Blocked Users")
        dlg.setMinimumWidth(320)
        lay = QVBoxLayout(dlg)
        lay.setSpacing(10)

        lst = QListWidget()
        lst.setObjectName("blocked.list")
        lst.setProperty("testid", "blocked.list")
        for uid in users:
            item = QListWidgetItem(f"User #{uid}")
            item.setData(Qt.UserRole, int(uid))
            lst.addItem(item)
        lay.addWidget(lst)

        row = QHBoxLayout()
        btn_unblock = QPushButton("Unblock")
        btn_unblock.setObjectName("small")
        btn_unblock.setProperty("testid", "blocked.unblock")
        row.addWidget(btn_unblock)
        row.addStretch()
        lay.addLayout(row)

        btns = QDialogButtonBox(QDialogButtonBox.Close)
        lay.addWidget(btns)

        def unblock():
            item = lst.currentItem()
            if not item:
                return
            uid = int(item.data(Qt.UserRole))
            self.sig_command.emit({"type": "unblock_user", "user_id": uid})
            lst.takeItem(lst.row(item))

        btn_unblock.clicked.connect(unblock)
        btns.rejected.connect(dlg.reject)
        dlg.exec_()

    def show_group_info(self, info: dict):
        """Hiển thị thông tin nhóm (thành viên/vai trò)."""
        group_id = int(info.get("group_id", 0))
        dlg = QDialog(self)
        dlg.setWindowTitle("Group Info")
        dlg.setMinimumWidth(440)
        lay = QVBoxLayout(dlg)
        lay.setSpacing(10)

        lay.addWidget(QLabel("Name:"))
        name = QLineEdit(info.get("name", ""))
        name.setObjectName("group.info.name")
        name.setProperty("testid", "group.info.name")
        lay.addWidget(name)

        lay.addWidget(QLabel("Description:"))
        desc = QLineEdit(info.get("description", ""))
        desc.setObjectName("group.info.description")
        desc.setProperty("testid", "group.info.description")
        lay.addWidget(desc)

        lay.addWidget(QLabel("Members:"))
        members = QListWidget()
        members.setObjectName("group.info.members")
        members.setProperty("testid", "group.info.members")
        for m in info.get("members", []):
            uid = int(m.get("user_id", 0))
            username = m.get("username", f"User#{uid}")
            role = m.get("role", "member")
            item = QListWidgetItem(f"{username} (#{uid}) - {role}")
            item.setData(Qt.UserRole, uid)
            item.setData(Qt.UserRole + 1, role)
            members.addItem(item)
        lay.addWidget(members)

        group_row = QHBoxLayout()
        group_row.addStretch()
        btn_add = QPushButton("Add Member")
        btn_add.setObjectName("small")
        btn_add.setProperty("testid", "group.info.add_member")
        btn_add.setMinimumSize(112, 32)
        btn_leave = QPushButton("Leave Group")
        btn_leave.setObjectName("danger")
        btn_leave.setProperty("testid", "group.info.leave")
        btn_leave.setMinimumSize(112, 32)
        group_row.addWidget(btn_add)
        group_row.addWidget(btn_leave)
        lay.addLayout(group_row)

        btns = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Close)
        lay.addWidget(btns)

        def selected_uid():
            item = members.currentItem()
            return int(item.data(Qt.UserRole)) if item else 0

        def set_role(role: str):
            item = members.currentItem()
            uid = int(item.data(Qt.UserRole)) if item else 0
            if uid:
                self.sig_command.emit({
                    "type": "set_member_role",
                    "group_id": group_id,
                    "user_id": uid,
                    "role": role,
                })
                username = item.text().split(" (#", 1)[0]
                item.setData(Qt.UserRole + 1, role)
                item.setText(f"{username} (#{uid}) - {role}")

        def remove_member():
            item = members.currentItem()
            uid = int(item.data(Qt.UserRole)) if item else 0
            if uid and QMessageBox.question(
                    self, "Remove Member", "Remove this member from the group?",
                    QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
                self.sig_command.emit({
                    "type": "remove_member",
                    "group_id": group_id,
                    "user_id": uid,
                })
                members.takeItem(members.row(item))

        def member_context_menu(pos):
            item = members.itemAt(pos)
            if not item:
                return
            members.setCurrentItem(item)
            self._show_context_popover(members, members.viewport().mapToGlobal(pos), [
                self._context_action("Make Admin", lambda: set_role("admin")),
                self._context_action("Make Member", lambda: set_role("member")),
                None,
                self._context_action("Remove Member", remove_member),
            ])

        def save_group():
            self.sig_command.emit({
                "type": "update_group_info",
                "group_id": group_id,
                "name": name.text().strip(),
                "description": desc.text().strip(),
            })
            dlg.accept()

        members.setContextMenuPolicy(Qt.CustomContextMenu)
        members.customContextMenuRequested.connect(member_context_menu)
        btn_add.clicked.connect(lambda: self._show_add_member_to_group(group_id))
        btn_leave.clicked.connect(
            lambda: dlg.accept() if self._confirm_leave_group(group_id) else None)
        btns.accepted.connect(save_group)
        btns.rejected.connect(dlg.reject)
        dlg.exec_()

    def show_pinned_messages(self, conv_id: int, messages: list):
        """Hiển thị danh sách tin đã ghim."""
        dlg = QDialog(self)
        dlg.setWindowTitle("Pinned Messages")
        dlg.setMinimumWidth(460)
        lay = QVBoxLayout(dlg)
        lay.setSpacing(8)

        lst = QListWidget()
        lst.setObjectName("pinned.list")
        lst.setProperty("testid", "pinned.list")
        for m in messages:
            body = m.get("body", "")
            sender = m.get("sender", f"User#{m.get('sender_id', 0)}")
            item = QListWidgetItem(f"{sender}: {body[:100]}")
            item.setData(Qt.UserRole, int(m.get("message_id", 0)))
            lst.addItem(item)
        lay.addWidget(lst)

        row = QHBoxLayout()
        btn_unpin = QPushButton("Unpin Selected")
        btn_unpin.setObjectName("small")
        btn_unpin.setProperty("testid", "pinned.unpin")
        row.addWidget(btn_unpin)
        row.addStretch()
        lay.addLayout(row)

        btns = QDialogButtonBox(QDialogButtonBox.Close)
        lay.addWidget(btns)

        def unpin():
            item = lst.currentItem()
            if not item:
                return
            msg_id = int(item.data(Qt.UserRole))
            self.sig_command.emit({"type": "unpin_message", "message_id": msg_id})
            lst.takeItem(lst.row(item))

        btn_unpin.clicked.connect(unpin)
        btns.rejected.connect(dlg.reject)
        dlg.exec_()

    # ── avatar cache ──────────────────────────────────────────────────────────

    def _get_avatar_path(self, user_id: int, username: str) -> str:
        """Return a local PNG path for user_id (initials fallback). Returns '' on failure."""
        if user_id in self._avatar_paths:
            return self._avatar_paths[user_id]
        can_fetch_avatar = int(user_id or 0) > 0
        try:
            from client.utils import initials_pixmap
            pm   = initials_pixmap(username or f"User{user_id}", 40)
            path = os.path.join(self._temp_dir, f"avatar_{user_id}.png")
            if not pm.save(path, "PNG"):
                raise RuntimeError("QPixmap.save returned False")
            self._avatar_paths[user_id] = path
            if can_fetch_avatar and user_id > 0 and user_id not in self._avatar_pending:
                self._avatar_pending.add(user_id)
                self.sig_get_avatar.emit(user_id)
            return path
        except Exception:
            return ""

    def set_user_avatar(self, user_id: int, b64: str, username: str = ""):
        """Called by App when a real avatar arrives from the server."""
        import time
        self._avatar_pending.discard(user_id)
        # Use timestamp in filename so Qt loads a fresh image (no cache invalidation needed)
        filename = f"avatar_{user_id}_{int(time.time() * 1000)}.png"
        path = os.path.join(self._temp_dir, filename)
        saved = False
        if not b64:
            # Server returns an empty avatar when the user removed it. Drop any
            # cached file path so message rows and the user bar fall back to
            # initials immediately instead of continuing to show the stale PNG.
            self._avatar_paths.pop(user_id, None)
        if b64:
            try:
                from client.utils import avatar_from_b64
                pm = avatar_from_b64(b64, 40)
                if pm and pm.save(path, "PNG"):
                    self._avatar_paths[user_id] = path
                    saved = True
            except Exception:
                pass
        if not saved and user_id not in self._avatar_paths:
            try:
                from client.utils import initials_pixmap
                pm = initials_pixmap(username or f"User{user_id}", 40)
                if pm.save(path, "PNG"):
                    self._avatar_paths[user_id] = path
            except Exception:
                return

        # Update user-bar own avatar if this is ourselves
        if user_id == self.my_id and user_id in self._avatar_paths:
            try:
                from PyQt5.QtGui import QPixmap
                pm_bar = QPixmap(self._avatar_paths[user_id]).scaled(
                    36, 36, Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation)
                self.lbl_my_avatar.setPixmap(pm_bar)
            except Exception:
                pass

        # Redraw active conversation if this user has messages there
        if self.active_conv_id in self.hist:
            if any(m["sender_id"] == user_id
                   for m in self.hist[self.active_conv_id]):
                self._redraw()

    def reset(self):
        """Đặt lại trang chat về trạng thái trống (khi đăng xuất)."""
        self._cancel_inline_edit()
        self._clear_reply_target()
        self._send_typing_stop()
        self.hist.clear()
        self._history_loaded_set().clear()
        if "_history_loading_convs" in self.__dict__:
            self._history_loading_convs.clear()
        if "_message_widgets" in self.__dict__:
            self._message_widgets.clear()
        if "_security_warnings" in self.__dict__:
            self._security_warnings.clear()
        if "_conv_security" in self.__dict__:
            self._conv_security.clear()
        if "_security_blocked_convs" in self.__dict__:
            self._security_blocked_convs.clear()
        self._fingerprint_present = False
        self._fingerprint_verified = False
        if "lbl_consistency" in self.__dict__:
            self._update_security_warning_label()
        if "lbl_security_guide" in self.__dict__:
            self._update_security_guidance_label()
        self._message_search_query = ""
        if "e_msg_search" in self.__dict__:
            self.e_msg_search.clear()
        self.friends.clear()
        self.dm_convs.clear()
        self.group_convs.clear()
        self._pending_open_conv = None
        self._pending_open_is_group = False
        self._active_is_group = False
        self._disbanded_convs.clear()
        self._avatar_paths.clear()
        self._avatar_pending.clear()
        self._unread_convs.clear()
        self._pending_edit_events.clear()
        for timer in self._typing_timers.values():
            timer.stop()
            timer.deleteLater()
        self._typing_timers.clear()
        for timer in self._request_refresh_timers:
            timer.stop()
            timer.deleteLater()
        self._request_refresh_timers.clear()
        self._typing_convs.clear()
        self._last_read_sent.clear()
        self._scroll_to_latest_after_history.clear()
        if "_system_event_keys" in self.__dict__:
            self._system_event_keys.clear()
        self.view.clear()
        self.lbl_typing.setText("")
        self.lbl_chat.setText("Select a conversation")
        if "lbl_chat_presence" in self.__dict__:
            self.lbl_chat_presence.setText("")
        self.lbl_fingerprint.setText("")
        self.lbl_cache_state.hide()
        self.lbl_consistency.hide()
        self.btn_warning_details.hide()
        self.btn_review_identity.hide()
        self.lbl_security_guide.hide()
        self.inp.clear()
        self.content_stack.setCurrentIndex(0)
        self.current_view = "chat"
        self.active_conv_id = 0
        self._active_is_group = False
        self._clear_list_item_widgets(self.friend_list)
        self._clear_list_item_widgets(self.dm_list)
        self._clear_list_item_widgets(self.group_list)
        self._clear_list_item_widgets(self.search_results)
        self._clear_request_list()
        self._set_request_badge(0)
        self._set_input_enabled(True)
        self._update_chat_badge()
        self._update_pin_button()

    # ================================================================ file attach

    def _attach_file(self):
        """Mở hộp thoại chọn tệp để gửi."""
        if self.active_conv_id == 0:
            QMessageBox.warning(self, "No conversation",
                                "Select a conversation first.")
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Attach file", "",
            "All Files (*);;Images (*.png *.jpg *.jpeg *.gif *.bmp *.webp)"
            ";;Videos (*.mp4 *.webm *.avi *.mov *.mkv)")
        if not path:
            return
        self._send_file_path(path)

    def _send_dropped_file(self, path: str):
        """Gửi tệp được kéo-thả vào khung chat."""
        if self.active_conv_id == 0:
            QMessageBox.warning(self, "No conversation",
                                "Select a conversation first.")
            return
        self._send_file_path(path)

    def _send_file_path(self, path: str):
        """Phát signal gửi tệp theo đường dẫn."""
        if not os.path.isfile(path):
            QMessageBox.warning(self, "File not found", "The dropped file is not available.")
            return
        size = os.path.getsize(path)
        if size > MAX_FILE_SIZE:
            QMessageBox.warning(self, "File too large",
                                f"Max file size is {MAX_FILE_SIZE // 1024} KB.\n"
                                f"Selected file: {size / 1024:.1f} KB")
            return
        self.sig_send_file.emit(self.active_conv_id, path)

    def _find_message(self, conv_id: int, msg_id: int) -> dict | None:
        """Tìm widget tin theo msg_id."""
        for msg in self.hist.get(int(conv_id), []):
            if int(msg.get("msg_id", 0) or 0) == int(msg_id):
                return msg
        return None

    def _forwardable_body(self, msg: dict | None) -> str:
        """Trích nội dung có thể chuyển tiếp của một tin."""
        if not msg or msg.get("deleted"):
            return ""
        body, _meta = self._decode_body_meta(str(msg.get("body", "")))
        if (not body or body.startswith("[") or body.startswith("FILE:")
                or body in ("__KEM_INIT__", "__S2_CONTROL__", "__S3_INIT__")):
            return ""
        return body

    def _on_link_clicked(self, anchor: str):
        """Handle clicks on links in the chat view. Parse anchor string directly."""
        if anchor.startswith("secchat-actions://"):
            parts = anchor[len("secchat-actions://"):].split("/", 1)
            if len(parts) == 2:
                try:
                    self._show_message_actions(int(parts[0]), int(parts[1]))
                except ValueError:
                    pass
        elif anchor.startswith("secchat-react-toggle://"):
            parts = anchor[len("secchat-react-toggle://"):].split("/", 1)
            if len(parts) == 2:
                try:
                    msg_id = int(parts[0])
                    raw = parts[1]
                    pad = "=" * (-len(raw) % 4)
                    emoji = base64.urlsafe_b64decode(
                        (raw + pad).encode("ascii")).decode("utf-8")
                    msg = self._find_message(self.active_conv_id, msg_id)
                    cur = (msg or {}).get("reactions", {}).get(emoji, {})
                    self.sig_command.emit({
                        "type": "remove_reaction" if cur.get("me") else "add_reaction",
                        "message_id": msg_id,
                        "emoji": emoji,
                    })
                except Exception:
                    pass
        elif anchor.startswith("secchat-edit://"):
            parts = anchor[len("secchat-edit://"):].split("/", 1)
            if len(parts) == 2:
                try:
                    self._start_inline_edit(int(parts[0]), int(parts[1]))
                except ValueError:
                    pass
        elif anchor.startswith("secchat-del://"):
            parts = anchor[len("secchat-del://"):].split("/", 1)
            if len(parts) == 2:
                try:
                    self._do_delete_message(int(parts[0]), int(parts[1]))
                except ValueError:
                    pass
        elif anchor.startswith("secchat-profile://"):
            try:
                self.sig_view_profile.emit(int(anchor[len("secchat-profile://"):]))
            except ValueError:
                pass
        elif anchor.startswith("secchat-react://"):
            try:
                self._react_to_message(int(anchor[len("secchat-react://"):]), remove=False)
            except ValueError:
                pass
        elif anchor.startswith("secchat-unreact://"):
            try:
                self._react_to_message(int(anchor[len("secchat-unreact://"):]), remove=True)
            except ValueError:
                pass
        elif anchor.startswith("secchat-pin://"):
            try:
                self.sig_command.emit({
                    "type": "pin_message",
                    "message_id": int(anchor[len("secchat-pin://"):]),
                })
            except ValueError:
                pass
        elif anchor.startswith("secchat-unpin://"):
            try:
                self.sig_command.emit({
                    "type": "unpin_message",
                    "message_id": int(anchor[len("secchat-unpin://"):]),
                })
            except ValueError:
                pass
        elif anchor.startswith("secchat-forward://"):
            parts = anchor[len("secchat-forward://"):].split("/", 1)
            if len(parts) == 2:
                try:
                    self._forward_message(int(parts[0]), int(parts[1]))
                except ValueError:
                    pass
        elif anchor.startswith("secchat-save:"):
            src  = anchor[len("secchat-save:"):]
            name = os.path.basename(src)
            dst, _ = QFileDialog.getSaveFileName(self, "Save file", name)
            if dst:
                import shutil
                shutil.copy2(src, dst)

    def _show_message_actions(self, conv_id: int, msg_id: int):
        """Mở menu hành động trên một tin (sửa/xóa/reply...)."""
        msg = self._find_message(conv_id, msg_id)
        if not msg or msg.get("deleted"):
            return
        body = str(msg.get("body", ""))
        display_body, _meta = self._decode_body_meta(body)
        is_mine = int(msg.get("sender_id", 0) or 0) == self.my_id
        is_file = display_body.startswith("FILE:")

        forwardable = bool(self._forwardable_body(msg))
        actions = [
            self._context_action(
                "Reply",
                lambda cid=conv_id, mid=msg_id: self._start_reply(cid, mid),
                enabled=forwardable,
            ),
            self._context_action(
                "React",
                lambda mid=msg_id: self._react_to_message(mid, False),
            ),
            self._context_action(
                "Forward",
                lambda cid=conv_id, mid=msg_id: self._forward_message(cid, mid),
                enabled=forwardable,
            ),
        ]
        if msg.get("pinned"):
            actions.append(self._context_action(
                "Unpin",
                lambda mid=msg_id: self.sig_command.emit({
                    "type": "unpin_message",
                    "message_id": int(mid),
                }),
            ))
        else:
            actions.append(self._context_action(
                "Pin",
                lambda mid=msg_id: self.sig_command.emit({
                    "type": "pin_message",
                    "message_id": int(mid),
                }),
            ))
        actions.append(None)

        if is_mine:
            if not is_file:
                actions.append(self._context_action(
                    "Edit",
                    lambda cid=conv_id, mid=msg_id:
                    self._start_inline_edit(cid, mid),
                ))
            actions.append(self._context_action(
                "Delete",
                lambda cid=conv_id, mid=msg_id:
                self._do_delete_message(cid, mid),
            ))

        self._show_context_popover(self, QCursor.pos(), actions)

    def _message_preview(self, msg: dict | None, limit: int = 96) -> str:
        """Dựng đoạn xem trước ngắn của một tin."""
        body = self._forwardable_body(msg)
        if not body:
            return "message"
        body = " ".join(body.split())
        if len(body) > limit:
            body = body[:limit - 3].rstrip() + "..."
        return body

    def _reply_preview_for(self, conv_id: int, reply_to_msg_id: int) -> str:
        """Dựng xem trước cho tin được trả lời."""
        target = self._find_message(int(conv_id), int(reply_to_msg_id))
        preview = self._message_preview(target, limit=110)
        if preview and preview != "message":
            return preview
        return f"message #{int(reply_to_msg_id)}"

    def _start_reply(self, conv_id: int, msg_id: int):
        """Bắt đầu soạn trả lời một tin."""
        msg = self._find_message(conv_id, msg_id)
        if not msg or msg.get("deleted") or not self._forwardable_body(msg):
            return
        preview = self._message_preview(msg)
        self._reply_target = {
            "conv_id": int(conv_id),
            "msg_id": int(msg_id),
            "preview": preview,
        }
        self.lbl_reply.setText(f"Replying to {preview}")
        self.reply_bar.show()
        self.inp.setFocus()

    def _clear_reply_target(self):
        """Hủy trạng thái đang trả lời."""
        self._reply_target = None
        reply_bar = self.__dict__.get("reply_bar")
        if reply_bar is not None:
            reply_bar.hide()
        lbl_reply = self.__dict__.get("lbl_reply")
        if lbl_reply is not None:
            lbl_reply.setText("")

    def _react_to_message(self, msg_id: int, remove: bool):
        """Thêm/đổi reaction cho một tin."""
        if remove:
            msg = self._find_message(self.active_conv_id, msg_id)
            for emoji, reaction in (msg or {}).get("reactions", {}).items():
                if reaction.get("me"):
                    self.sig_command.emit({
                        "type": "remove_reaction",
                        "message_id": int(msg_id),
                        "emoji": emoji,
                    })
                    return
        emoji = self._choose_reaction_emoji()
        if not emoji:
            return
        self.sig_command.emit({
            "type": "remove_reaction" if remove else "add_reaction",
            "message_id": int(msg_id),
            "emoji": emoji,
        })

    def _choose_reaction_emoji(self) -> str:
        """Mở bộ chọn emoji để reaction."""
        dlg = QDialog(self)
        dlg.setWindowTitle("React")
        dlg.setObjectName("reaction.dialog")
        dlg.setModal(True)
        dlg.setMinimumSize(392, 340)
        dlg.setMaximumWidth(440)
        lay = QVBoxLayout(dlg)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)
        selected = {"emoji": ""}

        title = QLabel("Add reaction")
        title.setStyleSheet("color:#f2f3f5; font-size:14px; font-weight:700;")
        lay.addWidget(title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setMinimumHeight(250)
        scroll.setStyleSheet(
            "QScrollArea { background:#2b2d31; border:1px solid #232428;"
            " border-radius:8px; }"
        )
        panel = QWidget()
        panel.setStyleSheet("QWidget { background:#2b2d31; }")
        grid = QGridLayout(panel)
        grid.setContentsMargins(8, 8, 8, 8)
        grid.setHorizontalSpacing(4)
        grid.setVerticalSpacing(4)

        columns = 8
        for idx, emoji in enumerate(REACTION_EMOJIS):
            btn = QPushButton(emoji)
            btn.setObjectName(f"reaction.emoji.{idx}")
            btn.setProperty("testid", f"reaction.emoji.{idx}")
            btn.setFixedSize(40, 40)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setToolTip(emoji)
            btn.setStyleSheet(
                "QPushButton { background:transparent; border:none; border-radius:4px;"
                " padding:0px; font-size:20px; font-weight:400; color:#dbdee1; }"
                "QPushButton:hover { background:#404249; }"
                "QPushButton:pressed { background:#5865f2; }"
            )
            btn.clicked.connect(
                lambda _checked=False, e=emoji: (
                    selected.__setitem__("emoji", e), dlg.accept()))
            grid.addWidget(btn, idx // columns, idx % columns)

        scroll.setWidget(panel)
        lay.addWidget(scroll)
        btns = QDialogButtonBox(QDialogButtonBox.Cancel)
        btns.rejected.connect(dlg.reject)
        lay.addWidget(btns)
        return selected["emoji"] if dlg.exec_() == QDialog.Accepted else ""

    def _forward_message(self, conv_id: int, msg_id: int):
        """Chuyển tiếp một tin tới hội thoại khác."""
        msg = None
        for m in self.hist.get(conv_id, []):
            if m.get("msg_id") == msg_id:
                msg = m
                break
        body = self._forwardable_body(msg)
        if not body or body.startswith("[") or body.startswith("FILE:"):
            QMessageBox.warning(self, "Forward Message",
                                "This message is not available for forwarding.")
            return

        targets = []
        target_ids = []
        for c in self.dm_convs:
            cid = int(c.get("conversation_id", 0))
            if cid != conv_id:
                targets.append(f"DM: {c.get('username', cid)}")
                target_ids.append(cid)
        for g in self.group_convs:
            cid = int(g.get("conversation_id", 0))
            if cid != conv_id and not g.get("is_disbanded"):
                targets.append(f"Group: {g.get('name', cid)}")
                target_ids.append(cid)
        if not targets:
            QMessageBox.warning(self, "Forward Message",
                                "No other conversation is available.")
            return
        choice, ok = QInputDialog.getItem(
            self, "Forward Message", "Send to:", targets, 0, False)
        if not ok or choice not in targets:
            return
        target_id = target_ids[targets.index(choice)]
        meta = {
            "kind": "forward",
            "source_message_id": int(msg_id),
            "body": body,
        }
        encoded = base64.urlsafe_b64encode(
            json.dumps(meta, ensure_ascii=False, separators=(",", ":"))
            .encode("utf-8")
        ).decode("ascii").rstrip("=")
        self.sig_send.emit(target_id, f"SCMSG:1:{encoded}")

    # ── inline edit (Discord-style) ───────────────────────────────────────────

    def _find_msg_y(self, msg_id: int) -> int:
        """Return viewport Y coordinate of the anchor for msg_id, or -1."""
        row = self.__dict__.get("_message_widgets", {}).get(int(msg_id))
        if row is None and hasattr(self.view, "row_for_msg"):
            row = self.view.row_for_msg(int(msg_id))
        if row is not None:
            return row.mapTo(self.view.viewport(), QPoint(0, 0)).y()
        return -1

    def _build_edit_widget(self):
        """Dựng widget chỉnh sửa tin tại chỗ (inline)."""
        w = QFrame(self.view.viewport())
        w.setStyleSheet(
            "QFrame { background:#2b2d31; border:1px solid #5865f2;"
            " border-radius:8px; }"
        )
        lay = QHBoxLayout(w)
        lay.setContentsMargins(8, 6, 8, 6)
        lay.setSpacing(6)

        self._edit_input = QLineEdit(w)
        self._edit_input.setObjectName("message.edit.input")
        self._edit_input.setProperty("testid", "message.edit.input")
        self._edit_input.setStyleSheet(
            "QLineEdit { background:#383a40; color:#dbdee1; border:none;"
            " border-radius:4px; padding:6px; font-size:13px; }"
        )
        self._edit_input.returnPressed.connect(self._finish_inline_edit)
        lay.addWidget(self._edit_input)

        btn_save = QPushButton("Save", w)
        btn_save.setObjectName("small")
        btn_save.setProperty("testid", "message.edit.save")
        btn_save.clicked.connect(self._finish_inline_edit)
        lay.addWidget(btn_save)

        btn_cancel = QPushButton("Cancel", w)
        btn_cancel.setObjectName("ghost")
        btn_cancel.setProperty("testid", "message.edit.cancel")
        btn_cancel.clicked.connect(self._cancel_inline_edit)
        lay.addWidget(btn_cancel)

        QShortcut(QKeySequence("Escape"), self._edit_input,
                  activated=self._cancel_inline_edit)
        self._edit_widget = w
        w.hide()

    def _start_inline_edit(self, conv_id: int, msg_id: int):
        """Bắt đầu chỉnh sửa tin tại chỗ."""
        body = ""
        for m in self.hist.get(conv_id, []):
            if m["msg_id"] == msg_id:
                body = m["body"]
                break
        body, _meta = self._decode_body_meta(str(body))
        if body.startswith("FILE:"):
            return
        self._editing_msg = (conv_id, msg_id)
        if self._edit_widget is None:
            self._build_edit_widget()
        self._edit_input.setText(body)
        self._edit_input.selectAll()
        y = self._find_msg_y(msg_id)
        if y < 0:
            y = 20
        vw = self.view.viewport()
        self._edit_widget.setGeometry(4, y, vw.width() - 8, 52)
        self._edit_widget.show()
        self._edit_widget.raise_()
        self._edit_input.setFocus()

    def _finish_inline_edit(self):
        """Xác nhận và gửi chỉnh sửa tin tại chỗ."""
        if not self._editing_msg:
            return
        conv_id, msg_id = self._editing_msg
        new_body = self._edit_input.text().strip()
        if new_body:
            self.sig_edit_message.emit(conv_id, msg_id, new_body)
        self._cancel_inline_edit()

    def _cancel_inline_edit(self):
        """Hủy chỉnh sửa tin tại chỗ."""
        if self._edit_widget:
            self._edit_widget.hide()
        self._editing_msg = None

    def _reposition_edit(self):
        """Định lại vị trí ô chỉnh sửa inline."""
        if not self._editing_msg or not self._edit_widget or not self._edit_widget.isVisible():
            return
        _, msg_id = self._editing_msg
        y = self._find_msg_y(msg_id)
        if y < 0:
            self._edit_widget.hide()
            return
        vw = self.view.viewport()
        self._edit_widget.setGeometry(4, y, vw.width() - 8, 52)

    def _update_chat_badge(self):
        """Cập nhật badge số tin chưa đọc trên sidebar."""
        count = len(self._unread_convs)
        if count > 0:
            self.btn_chat.setText(f"Chats ({count})")
            self.btn_chat.setStyleSheet(
                "QPushButton { background:#ed4245; color:#fff; text-align:left;"
                " padding:10px 14px; border:none; border-radius:8px;"
                " margin:4px 8px; font-weight:600; font-size:13px; }"
                "QPushButton:hover { background:#c03537; }"
            )
        else:
            self.btn_chat.setText("Chats")
            self.btn_chat.setStyleSheet("")
            self.btn_chat.setObjectName(
                "nav_active" if self.current_view == "chat" else "nav")
            self.btn_chat.setStyle(self.btn_chat.style())

    # ================================================================ internal

    def _set_input_enabled(self, enabled: bool):
        """Bật/tắt ô soạn tin."""
        actual = bool(enabled)
        self.inp.setEnabled(actual)
        self._btn_send.setEnabled(actual)
        if not enabled:
            self.inp.setPlaceholderText("This group has been disbanded.")
        else:
            self.inp.setPlaceholderText("Message...")

    def _on_dm_click(self, item):
        """Mở một hội thoại DM khi click."""
        self._switch_to_conv(item.data(Qt.UserRole), is_group=False)

    def _on_group_click(self, item):
        """Mở một nhóm khi click."""
        self._switch_to_conv(item.data(Qt.UserRole), is_group=True)

    def _switch_to_conv(self, conv_id: int, is_group: bool):
        """Chuyển khung chat sang một hội thoại."""
        self._cancel_inline_edit()
        self._clear_reply_target()
        self._send_typing_stop()
        if self.current_view != "chat":
            self._switch_view("chat")
        conv_id = int(conv_id or 0)
        self.active_conv_id = conv_id
        self._active_is_group = bool(is_group)
        if self._conversation_has_unread_record(conv_id):
            self.__dict__.setdefault("_pending_read_clear_convs", set()).add(conv_id)
        self._clear_unread_without_sidebar_refresh(conv_id)
        self._update_typing_label()
        # Clear fingerprint; App will repopulate it via set_fingerprint() if available
        self.lbl_fingerprint.setText("")
        self._fingerprint_present = False
        self._fingerprint_verified = False
        self._update_security_warning_label()
        self._update_cache_status_label()
        is_disbanded = conv_id in self._disbanded_convs

        if is_group:
            for g in self.group_convs:
                if g["conversation_id"] == conv_id:
                    self.lbl_chat.setText(f"[G] {g['name']}")
                    self.lbl_chat_presence.setText(
                        "Group conversation" if not g.get("is_disbanded") else "Group disbanded")
                    if g.get("is_disbanded"):
                        is_disbanded = True
                        self._disbanded_convs.add(conv_id)
                    break
        else:
            for c in self.dm_convs:
                if c["conversation_id"] == conv_id:
                    self.lbl_chat.setText(c["username"])
                    self.lbl_chat_presence.setText(self._presence_text_for_dm(c))
                    break

        self._set_input_enabled(not is_disbanded)
        self._update_pin_button()
        self._update_cache_status_label()
        self._refresh_dm_list()
        self._refresh_group_list()

        if conv_id not in self._history_loaded_set():
            if "_history_loading_convs" not in self.__dict__:
                self._history_loading_convs = set()
            self._history_loading_convs.add(int(conv_id))
            self.__dict__.setdefault(
                "_scroll_to_latest_after_history", set()).add(int(conv_id))
            self._redraw(scroll_mode="bottom")
            self.sig_history.emit(conv_id)
            self._update_security_guidance_label()
        else:
            self.__dict__.setdefault(
                "_scroll_to_latest_after_history", set()).discard(int(conv_id))
            self._redraw(scroll_mode="bottom")
            self._mark_active_conversation_read()

    def _redraw(self, scroll_mode: str = "preserve"):
        """Vẽ lại toàn bộ danh sách tin của hội thoại hiện tại."""
        self._cancel_inline_edit()
        scroll_state = self.view.capture_scroll() if hasattr(
            self.view, "capture_scroll") else capture_vertical_scroll(self.view)
        updates_enabled = self.view.updatesEnabled()
        self.view.setUpdatesEnabled(False)
        self.view.clear()
        self._message_widgets = {}
        conv_id = int(self.active_conv_id or 0)
        try:
            if conv_id <= 0:
                self.view.add_info("Select a conversation to start messaging.")
                return

            loading = conv_id in self.__dict__.get("_history_loading_convs", set())
            msgs = list(self.hist.get(conv_id, []))
            query = self.__dict__.get("_message_search_query", "")
            self._update_security_guidance_label()

            if loading:
                self.view.add_info("Loading message history...")

            rendered = 0
            for msg in msgs:
                if msg.get("hidden"):
                    continue
                if query and not self._message_matches_search(msg, query):
                    continue
                self._render(msg)
                rendered += 1

            if query and rendered == 0 and not loading:
                self.view.add_info("No messages match this search.")
            elif not msgs and not loading:
                self.view.add_info("No messages yet.")
        finally:
            force_bottom = str(scroll_mode or "preserve") == "bottom"
            if hasattr(self.view, "restore_scroll"):
                self.view.restore_scroll(scroll_state, force_bottom=force_bottom)
            elif force_bottom and hasattr(self.view, "scroll_to_bottom"):
                self.view.scroll_to_bottom()
            else:
                restore_vertical_scroll(self.view, scroll_state)
            self.view.setUpdatesEnabled(updates_enabled)

    def _message_matches_search(self, msg: dict, query: str) -> bool:
        """Kiểm tra một tin có khớp từ khóa tìm trong hội thoại."""
        body, meta = self._decode_body_meta(str(msg.get("body", "")))
        sender_id = int(msg.get("sender_id", 0) or 0)
        sender = self.me if sender_id == self.my_id else (
            self.friends.get(sender_id, {}).get("username") or f"User#{sender_id}"
        )
        haystack = " ".join([
            body,
            str(meta.get("body", "")),
            str(meta.get("kind", "")),
            sender,
            str(msg.get("ts", "")),
        ]).lower()
        return query in haystack

    def _format_size(self, size: int) -> str:
        """Định dạng kích thước tệp (B/KB/MB)."""
        if size < 1024:
            return f"{size} B"
        if size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        return f"{size / (1024 * 1024):.1f} MB"

    def _parse_file_payload(self, body: str) -> dict | None:
        """Phân tích metadata của một tin tệp."""
        try:
            rest = body[5:]
            brace_end = rest.index("}") + 1
            meta = json.loads(rest[:brace_end])
            raw = base64.b64decode(rest[brace_end + 1:])
            name = str(meta.get("name", "file"))
            mime = str(meta.get("mime", "application/octet-stream"))
            size = int(meta.get("size", len(raw)) or len(raw))
            ext = os.path.splitext(name)[1] or ".bin"
            tmp = self._next_temp_path(ext)
            with open(tmp, "wb") as fh:
                fh.write(raw)
            return {
                "name": name,
                "mime": mime,
                "size": size,
                "path": tmp,
            }
        except Exception:
            return None

    def _avatar_widget(self, sender_id: int, sender_name: str) -> QLabel:
        """Tạo widget avatar tròn cho một người dùng."""
        avatar = _ClickableLabel("")
        avatar.setFixedSize(40, 40)
        avatar.setAlignment(Qt.AlignCenter)
        can_view_profile = int(sender_id or 0) > 0
        avatar.setToolTip("View profile" if can_view_profile else sender_name)
        path = self._get_avatar_path(sender_id, sender_name)
        if path:
            pm = QPixmap(path)
            if not pm.isNull():
                avatar.setPixmap(pm.scaled(
                    40, 40, Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation))
        if avatar.pixmap() is None:
            initial = (sender_name or "?")[0].upper()
            avatar.setText(initial)
            avatar.setStyleSheet(
                "QLabel { background:#5865f2; color:#fff; border-radius:20px;"
                " font-weight:700; font-size:15px; }"
            )
        if can_view_profile:
            avatar.clicked.connect(lambda uid=sender_id: self.sig_view_profile.emit(int(uid)))
        return avatar

    def _build_file_widget(self, display_body: str) -> QWidget:
        """Dựng widget hiển thị tệp đính kèm."""
        info = self._parse_file_payload(display_body)
        box = QFrame()
        box.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)
        box.setMaximumWidth(430)
        box.setStyleSheet(
            "QFrame { background:#2b2d31; border:1px solid #3f4147;"
            " border-radius:8px; }"
        )
        lay = QVBoxLayout(box)
        lay.setContentsMargins(10, 8, 10, 8)
        lay.setSpacing(6)
        if not info:
            err = QLabel("[File error]")
            err.setStyleSheet("color:#ed4245;")
            lay.addWidget(err)
            return box

        if info["mime"] in IMAGE_MIMES:
            pm = QPixmap(info["path"])
            if not pm.isNull():
                img = QLabel()
                scaled = pm.scaled(
                    360, 240, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                img.setPixmap(scaled)
                img.setFixedSize(scaled.size())
                img.setAlignment(Qt.AlignCenter)
                lay.addWidget(img)
        elif info["mime"] in VIDEO_MIMES:
            kind = QLabel("Video file")
            kind.setStyleSheet("color:#b5bac1; font-size:12px; font-weight:600;")
            lay.addWidget(kind)

        row = QHBoxLayout()
        name = QLabel(info["name"])
        name.setWordWrap(True)
        name.setStyleSheet("color:#dbdee1; font-weight:600;")
        row.addWidget(name, 1)
        meta = QLabel(self._format_size(info["size"]))
        meta.setStyleSheet("color:#949ba4; font-size:12px;")
        row.addWidget(meta)
        btn_save = QPushButton("Save")
        btn_save.setObjectName("small")
        btn_save.setProperty("testid", "file.save")
        btn_save.clicked.connect(
            lambda _checked=False, src=info["path"]: self._save_file_from_temp(src))
        row.addWidget(btn_save)
        lay.addLayout(row)
        return box

    def _save_file_from_temp(self, src: str):
        """Lưu tệp nhận được từ thư mục tạm ra nơi người dùng chọn."""
        name = os.path.basename(src)
        dst, _ = QFileDialog.getSaveFileName(self, "Save file", name)
        if dst:
            import shutil
            shutil.copy2(src, dst)

    def _reaction_chip(self, msg_id: int, emoji: str, count: int, mine: bool) -> QPushButton:
        """Tạo chip hiển thị một loại reaction và số lượng."""
        chip = QPushButton(f"{emoji} {count}")
        chip.setObjectName("reactionChip")
        chip.setProperty("testid", f"reaction.chip.{msg_id}.{emoji}")
        chip.setCursor(Qt.PointingHandCursor)
        chip.setMinimumHeight(28)
        chip.setMaximumHeight(28)
        chip.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
        chip.setStyleSheet(
            "QPushButton { background:%s; border:1px solid %s;"
            " color:#dbdee1; border-radius:14px; padding:3px 9px;"
            " font-size:12px; font-weight:600; }"
            "QPushButton:hover { border-color:#5865f2; }"
            % ("#3b4170" if mine else "#2b2d31",
               "#5865f2" if mine else "#3f4147")
        )
        chip.clicked.connect(
            lambda _checked=False, mid=msg_id, e=emoji, me=mine:
            self.sig_command.emit({
                "type": "remove_reaction" if me else "add_reaction",
                "message_id": int(mid),
                "emoji": e,
            })
        )
        return chip

    def _render_widget_inner(self, msg: dict):
        """Dựng phần nội dung bên trong của một bong bóng tin."""
        sender_id = int(msg.get("sender_id", 0) or 0)
        body = str(msg.get("body", ""))
        display_body, body_meta = self._decode_body_meta(body)
        if bool(msg.get("system")) or display_body.startswith("__SYSTEM__:"):
            text = display_body[len("__SYSTEM__:"):] if display_body.startswith("__SYSTEM__:") else display_body
            line = QLabel(text)
            line.setAlignment(Qt.AlignCenter)
            line.setWordWrap(True)
            line.setStyleSheet(
                "QLabel { color:#949ba4; font-size:12px; padding:8px 12px; }")
            self.view.add_row(0, line)
            return
        msg_id = int(msg.get("msg_id", 0) or 0)
        is_mine = sender_id == self.my_id
        deleted = bool(msg.get("deleted", False))
        edited = bool(msg.get("edited", False))
        failed = bool(msg.get("failed", False))
        sending = bool(msg.get("sending", False))
        unavailable = self._is_unavailable_history_body(display_body)
        is_file = display_body.startswith("FILE:") and not deleted
        is_forwarded = (
            body_meta.get("kind") == "forward"
            or int(msg.get("forwarded_from_id", 0) or 0) > 0
        )
        sender_name = self.me if is_mine else (
            self.friends.get(sender_id, {}).get("username") or f"User#{sender_id}"
        )

        row = QFrame()
        row.setObjectName("messageRow")
        row.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        row.setStyleSheet(
            "QFrame#messageRow { background:transparent; border:none;"
            " border-radius:6px; }"
            "QFrame#messageRow:hover { background:#32353b; }"
        )
        outer = QHBoxLayout(row)
        outer.setContentsMargins(4, 4, 4, 4)
        outer.setSpacing(10)
        outer.setAlignment(Qt.AlignTop)
        outer.addWidget(self._avatar_widget(sender_id, sender_name), 0, Qt.AlignTop)

        content = QVBoxLayout()
        content.setContentsMargins(0, 0, 0, 0)
        content.setSpacing(3)
        content.setAlignment(Qt.AlignTop)

        header = QHBoxLayout()
        header.setSpacing(6)
        name = QLabel(sender_name)
        name.setStyleSheet(
            "color:%s; font-weight:700; font-size:13px;"
            % ("#5865f2" if is_mine else "#f2f3f5")
        )
        header.addWidget(name, 0)
        ts = QLabel(str(msg.get("ts", "")))
        ts.setStyleSheet("color:#72767d; font-size:11px;")
        header.addWidget(ts, 0)
        if edited and not deleted:
            edited_lbl = QLabel("(edited)")
            edited_lbl.setStyleSheet("color:#72767d; font-size:11px;")
            header.addWidget(edited_lbl, 0)
        if msg.get("pinned") and not deleted:
            pinned = QLabel("Pinned")
            pinned.setStyleSheet(
                "color:#faa61a; font-size:11px; font-weight:600;")
            header.addWidget(pinned, 0)
        if failed:
            failed_lbl = QLabel("Failed")
            failed_lbl.setStyleSheet(
                "color:#ed4245; font-size:11px; font-weight:600;")
            header.addWidget(failed_lbl, 0)
        elif sending:
            sending_lbl = QLabel("Sending")
            sending_lbl.setStyleSheet(
                "color:#949ba4; font-size:11px; font-weight:600;")
            header.addWidget(sending_lbl, 0)
        header.addStretch()
        content.addLayout(header)

        if is_forwarded and not deleted:
            fwd = QLabel("Forwarded")
            fwd.setStyleSheet("color:#949ba4; font-size:11px;")
            content.addWidget(fwd)

        reply_to = int(msg.get("reply_to_message_id", 0) or 0)
        if reply_to > 0 and not deleted:
            reply = QLabel(f"Replying to {self._reply_preview_for(self.active_conv_id, reply_to)}")
            reply.setWordWrap(True)
            reply.setStyleSheet(
                "QLabel { color:#b5bac1; background:#2b2d31;"
                " border-left:3px solid #5865f2; padding:5px 8px;"
                " font-size:12px; border-radius:3px; }"
            )
            content.addWidget(reply)

        if deleted:
            body_widget = QLabel("[Message deleted]")
            body_widget.setStyleSheet("color:#949ba4; font-style:italic;")
            content.addWidget(body_widget)
        elif is_file:
            content.addWidget(self._build_file_widget(display_body))
        else:
            body_lbl = QLabel(display_body)
            body_lbl.setTextFormat(Qt.PlainText)
            body_lbl.setWordWrap(True)
            body_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            if unavailable:
                body_lbl.setStyleSheet(
                    "QLabel { color:#faa61a; font-size:14px; line-height:1.5; }")
                body_lbl.setToolTip(
                    "This ciphertext could not be decrypted with the local state "
                    "available on this device."
                )
            else:
                body_lbl.setStyleSheet(
                    "QLabel { color:#dcddde; font-size:14px; line-height:1.5; }")
            content.addWidget(body_lbl)
            if unavailable:
                explain = QLabel(
                    "Encryption state for this message is unavailable on this device. "
                    "This can happen after MLS group changes, missing local state, "
                    "or cache being disabled."
                )
                explain.setWordWrap(True)
                explain.setStyleSheet("color:#949ba4; font-size:11px;")
                content.addWidget(explain)

        reactions = msg.get("reactions", {}) or {}
        reaction_wrap = QWidget()
        reaction_wrap.setStyleSheet("QWidget { background:transparent; }")
        reaction_grid = QGridLayout(reaction_wrap)
        reaction_grid.setContentsMargins(0, 2, 0, 0)
        reaction_grid.setHorizontalSpacing(4)
        reaction_grid.setVerticalSpacing(4)
        reaction_count = 0
        for emoji, reaction in sorted(reactions.items(), key=lambda item: item[0]):
            count = int(reaction.get("count", 0) or 0)
            if count <= 0:
                continue
            reaction_grid.addWidget(
                self._reaction_chip(msg_id, emoji, count, bool(reaction.get("me"))),
                reaction_count // 5,
                reaction_count % 5,
            )
            reaction_count += 1
        if reaction_count:
            content.addWidget(reaction_wrap)

        if sending:
            pending = QLabel(
                "Waiting for the encrypted message to be accepted by the server."
            )
            pending.setStyleSheet("color:#949ba4; font-size:12px;")
            content.addWidget(pending)
        elif failed:
            fail_row = QHBoxLayout()
            reason = QLabel(str(msg.get("failure_reason", "Message was not sent.")))
            reason.setStyleSheet("color:#ed4245; font-size:12px;")
            fail_row.addWidget(reason, 1)
            retry = QPushButton("Retry")
            retry.setObjectName("small")
            retry.setProperty("testid", "message.retry")
            retry.setFixedSize(84, 32)
            retry.clicked.connect(
                lambda _checked=False, mid=msg_id: self._retry_failed_message(mid))
            fail_row.addWidget(retry)
            dismiss = QPushButton("Dismiss")
            dismiss.setObjectName("ghost")
            dismiss.setProperty("testid", "message.dismiss")
            dismiss.setFixedSize(84, 32)
            dismiss.clicked.connect(
                lambda _checked=False, mid=msg_id: self._remove_failed_message(mid))
            fail_row.addWidget(dismiss)
            content.addLayout(fail_row)
        outer.addLayout(content, 1)
        if not deleted and msg_id > 0:
            action_col = QVBoxLayout()
            action_col.setContentsMargins(0, 0, 0, 0)
            action_col.addStretch()
            btn_actions = QPushButton("...")
            btn_actions.setObjectName(f"message.actions.{msg_id}")
            btn_actions.setProperty("testid", f"message.actions.{msg_id}")
            btn_actions.setFixedSize(32, 32)
            btn_actions.setCursor(Qt.PointingHandCursor)
            btn_actions.setToolTip("Message actions")
            btn_actions.setStyleSheet(
                "QPushButton { background:transparent; border:none; color:#72767d;"
                " font-size:18px; padding:0; }"
                "QPushButton:hover { color:#dbdee1; background:transparent; }"
            )
            btn_actions.clicked.connect(
                lambda _checked=False, cid=int(self.active_conv_id), mid=msg_id:
                self._show_message_actions(cid, mid))
            action_col.addWidget(btn_actions, 0, Qt.AlignCenter)
            action_col.addStretch()
            outer.addLayout(action_col)

        self.view.add_row(msg_id, row)
        if msg_id:
            self._message_widgets[msg_id] = row

    def _next_temp_path(self, ext: str) -> str:
        """Sinh đường dẫn tệp tạm kế tiếp."""
        self._temp_counter += 1
        return os.path.join(self._temp_dir,
                            f"file_{self._temp_counter}{ext}")

    def _render(self, msg: dict):
        """Wrapper: render with fallback on error."""
        try:
            self._render_widget_inner(msg)
        except Exception as e:
            safe = str(msg.get("body", "")).replace("&", "&amp;").replace("<", "&lt;")
            self.view.add_info(f"[render error: {e}] {safe}")

    def _decode_body_meta(self, body: str) -> tuple[str, dict]:
        """Tách phần metadata khỏi body của tin."""
        if not body.startswith("SCMSG:1:"):
            return body, {}
        try:
            raw = body[len("SCMSG:1:"):]
            pad = "=" * (-len(raw) % 4)
            data = base64.urlsafe_b64decode((raw + pad).encode("ascii"))
            meta = json.loads(data.decode("utf-8"))
            return str(meta.get("body", "")), meta
        except Exception:
            return body, {}

    def _send(self):
        """Phát signal gửi tin nhắn văn bản đang soạn."""
        body = self.inp.toPlainText().strip()
        if not body or self.active_conv_id == 0:
            return
        reply_target = self._reply_target
        reply_to = 0
        if (reply_target
                and int(reply_target.get("conv_id", 0) or 0) == int(self.active_conv_id)):
            reply_to = int(reply_target.get("msg_id", 0) or 0)
        self.inp.clear()
        self._send_typing_stop()
        if reply_to > 0:
            self.sig_send_reply.emit(self.active_conv_id, reply_to, body)
            self._clear_reply_target()
        else:
            self.sig_send.emit(self.active_conv_id, body)

    def _do_search(self):
        """Phát signal tìm kiếm người dùng."""
        q = self.e_search.text().strip()
        if q:
            self.sig_search.emit(q)

    def _accept_request(self, uid: int):
        """Phát signal chấp nhận một lời mời kết bạn."""
        self.sig_friend_accept.emit(uid)
        self._schedule_request_refresh(self.sig_get_friends.emit)
        self._schedule_request_refresh(self.sig_get_requests.emit)

    def _schedule_request_refresh(self, callback):
        """Lên lịch làm mới danh sách lời mời."""
        timer = QTimer(self)
        timer.setSingleShot(True)

        def fire():
            try:
                callback()
            finally:
                if timer in self._request_refresh_timers:
                    self._request_refresh_timers.remove(timer)
                timer.deleteLater()

        timer.timeout.connect(fire)
        self._request_refresh_timers.append(timer)
        timer.start(500)

    def _confirm_unfriend(self, uid: int):
        """Hỏi xác nhận trước khi hủy kết bạn."""
        name = self.friends.get(uid, {}).get("username", f"User#{uid}")
        reply = QMessageBox.question(
            self, "Confirm Unfriend",
            f"Are you sure you want to remove {name} from your friends?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.sig_unfriend.emit(uid)
