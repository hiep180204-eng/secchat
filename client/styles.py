"""Bảng kiểu (stylesheet) Qt dùng chung cho toàn bộ client SecChat.

Chọn font theo hệ điều hành (Windows vs Linux/Docker) để hiển thị đúng tiếng Việt
và emoji, rồi ghép vào một chuỗi CSS lớn (``CSS``) áp cho mọi widget. Giao diện
theo tông tối kiểu Discord.
"""
import platform as _plat

if _plat.system() == "Windows":
    _FONT = '"Segoe UI", "Microsoft YaHei", "Yu Gothic UI", "Malgun Gothic", sans-serif'
else:
    _FONT = ('"Noto Sans CJK SC", "Noto Sans", "Liberation Sans", '
             '"DejaVu Sans", "Noto Color Emoji", sans-serif')

CSS = (
"* { font-family: " + _FONT + "; font-size: 13px; }\n"
"""
/* Base */
QMainWindow, QWidget {
    background: #313338;
    color: #dbdee1;
}
QDialog, QMessageBox, QInputDialog {
    background: #313338;
    color: #dbdee1;
}
QToolTip {
    background: #111214;
    color: #f2f3f5;
    border: 1px solid #232428;
    border-radius: 4px;
    padding: 5px 7px;
}

/* Sidebar */
QFrame#sidebar {
    background: #2b2d31;
    border-right: 1px solid #1f2023;
}
QFrame#topbar {
    background: #1e1f22;
    border-bottom: 1px solid #111214;
}

/* Chat area */
QFrame#header {
    background: #313338;
    border-bottom: 1px solid #232428;
}
QFrame#inputbar {
    background: #383a40;
    border-top: 1px solid #232428;
}

/* Lists */
QListWidget {
    background: #2b2d31;
    border: none;
    color: #949ba4;
    font-size: 13px;
    outline: none;
    padding: 4px 6px;
}
QListWidget::item {
    padding: 0;
    border-radius: 6px;
    margin: 2px 2px;
    min-height: 28px;
}
QListWidget::item:selected {
    background: #404249;
    color: #ffffff;
}
QListWidget::item:hover {
    background: #35373c;
    color: #dbdee1;
}

/* Input */
QLineEdit, QPlainTextEdit {
    background: #383a40;
    border: none;
    border-radius: 8px;
    padding: 9px 12px;
    color: #dbdee1;
    font-size: 14px;
    selection-background-color: #5865f2;
}
QLineEdit:focus, QPlainTextEdit:focus {
    background: #404249;
}
QLineEdit:placeholder, QPlainTextEdit:placeholder {
    color: #6d6f78;
}

/* Buttons */
QPushButton {
    background: #5865f2;
    color: #ffffff;
    border: none;
    border-radius: 6px;
    padding: 8px 14px;
    font-weight: 600;
    font-size: 13px;
}
QPushButton:hover {
    background: #4752c4;
}
QPushButton:pressed {
    background: #3c45a5;
}
QPushButton:disabled {
    background: #3a3c42;
    color: #72767d;
}
QPushButton#ghost {
    background: #4e505a;
    color: #f2f3f5;
}
QPushButton#ghost:hover {
    background: #5d6068;
}
QPushButton#danger {
    background: #da373c;
    color: #ffffff;
}
QPushButton#danger:hover {
    background: #a12828;
}
QPushButton#small {
    padding: 4px 10px;
    font-size: 12px;
    border-radius: 4px;
}

/* Nav buttons */
QPushButton#nav {
    background: transparent;
    color: #949ba4;
    text-align: left;
    padding: 10px 14px;
    border: none;
    border-radius: 6px;
    margin: 1px 8px;
    font-weight: 500;
}
QPushButton#nav:hover {
    background: #35373c;
    color: #dbdee1;
}
QPushButton#nav_active {
    background: #404249;
    color: #ffffff;
    text-align: left;
    padding: 10px 14px;
    border: none;
    border-radius: 6px;
    margin: 1px 8px;
    font-weight: 600;
}

/* Section labels */
QLabel#section {
    color: #7d828a;
    font-size: 11px;
    font-weight: 700;
    padding: 16px 16px 4px;
    letter-spacing: 0;
    text-transform: uppercase;
}

/* Scrollbar */
QScrollBar:vertical {
    background: transparent;
    width: 8px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #1a1b1e;
    border-radius: 4px;
    min-height: 30px;
}
QScrollBar::handle:vertical:hover {
    background: #2f3136;
}
QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {
    height: 0;
}
QScrollBar::add-page:vertical,
QScrollBar::sub-page:vertical {
    background: none;
}
QScrollBar:horizontal {
    background: transparent;
    height: 8px;
    margin: 0;
}
QScrollBar::handle:horizontal {
    background: #1a1b1e;
    border-radius: 4px;
    min-width: 30px;
}
QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal {
    width: 0;
}

/* Misc */
QScrollArea {
    border: none;
    background: transparent;
}
QCheckBox {
    color: #dbdee1;
    spacing: 8px;
}
QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border: 2px solid #4e505a;
    border-radius: 4px;
    background: #383a40;
}
QCheckBox::indicator:checked {
    background: #5865f2;
    border-color: #5865f2;
}
QMenu {
    background: #1e1f22;
    border: 1px solid #111214;
    border-radius: 6px;
    padding: 6px 4px;
}
QMenu::item {
    padding: 8px 28px;
    color: #dbdee1;
    border-radius: 4px;
}
QMenu::item:selected {
    background: #5865f2;
    color: #ffffff;
}
""")
