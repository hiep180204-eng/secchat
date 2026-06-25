"""Khung hiển thị dòng thời gian tin nhắn (mỗi tin là một widget row).

``MessageListView`` là một QScrollArea chứa một QVBoxLayout; mỗi tin nhắn được
thêm vào dưới dạng một widget riêng (tra cứu nhanh theo msg_id qua ``_rows``).
Có hỗ trợ kéo-thả tệp vào khung và các tiện ích giữ/khôi phục vị trí cuộn.
"""
from __future__ import annotations

from PyQt5.QtCore import QTimer, Qt, pyqtSignal
from PyQt5.QtWidgets import QLabel, QScrollArea, QVBoxLayout, QWidget

from client.components.scrolling import (
    capture_vertical_scroll,
    is_near_bottom,
    restore_vertical_scroll,
)


class MessageListView(QScrollArea):
    """Dòng thời gian tin nhắn dựng bằng widget (mỗi tin một row)."""

    file_dropped = pyqtSignal(str)

    def __init__(self, parent=None):
        """Khởi tạo vùng cuộn, layout dọc và bảng tra row theo msg_id."""
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setAcceptDrops(True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setStyleSheet("QScrollArea { background:#313338; border:none; }")

        self._content = QWidget()
        self._content.setObjectName("messageListContent")
        self._content.setStyleSheet("QWidget#messageListContent { background:#313338; }")
        self._layout = QVBoxLayout(self._content)
        self._layout.setContentsMargins(16, 12, 16, 12)
        self._layout.setSpacing(2)
        self._layout.setAlignment(Qt.AlignTop)
        self._rows = {}
        self.setWidget(self._content)

    def clear(self):
        """Gỡ và hủy toàn bộ row khi đổi hội thoại hoặc nạp lại lịch sử."""
        while self._layout.count():
            item = self._layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.hide()
                w.setParent(None)
                w.deleteLater()
        self._rows.clear()

    def add_row(self, msg_id: int, widget: QWidget):
        """Thêm một widget tin vào cuối danh sách (đăng ký theo msg_id nếu có)."""
        self._layout.addWidget(widget)
        if msg_id:
            self._rows[int(msg_id)] = widget

    def row_for_msg(self, msg_id: int):
        """Tra widget tin theo msg_id (None nếu không có)."""
        return self._rows.get(int(msg_id))

    def add_info(self, text: str):
        """Thêm một dòng thông tin căn giữa (vd: ngày, thông báo hệ thống)."""
        lbl = QLabel(text)
        lbl.setWordWrap(True)
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setStyleSheet(
            "QLabel { color:#949ba4; padding:18px 12px; font-size:13px; }")
        self._layout.addWidget(lbl)

    def capture_scroll(self):
        """Chụp lại vị trí cuộn hiện tại (để khôi phục sau khi dựng lại)."""
        return capture_vertical_scroll(self)

    def restore_scroll(self, state, *, force_bottom: bool = False):
        """Khôi phục vị trí cuộn đã chụp; ép xuống đáy nếu force_bottom."""
        try:
            self._content.adjustSize()
            self._content.updateGeometry()
        except RuntimeError:
            pass
        restore_vertical_scroll(
            self, state, force_bottom=force_bottom, delays=(0, 1, 20, 60, 100))
        if force_bottom:
            QTimer.singleShot(0, self.scroll_to_bottom)

    def is_near_bottom(self, margin: int = 24) -> bool:
        """Kiểm tra người dùng có đang xem gần tin mới nhất (gần đáy) không."""
        return is_near_bottom(self, margin=margin)

    def scroll_to_bottom(self):
        """Cuộn xuống tin mới nhất."""
        restore_vertical_scroll(self, self.capture_scroll(), force_bottom=True)

    def dragEnterEvent(self, event):
        """Override Qt: chấp nhận thao tác kéo tệp (URL) vào khung."""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            return
        super().dragEnterEvent(event)

    def dropEvent(self, event):
        """Override Qt: khi thả tệp, phát signal file_dropped cho từng đường dẫn."""
        if not event.mimeData().hasUrls():
            super().dropEvent(event)
            return
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if path:
                self.file_dropped.emit(path)
        event.acceptProposedAction()
