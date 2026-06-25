"""Tiện ích giữ và khôi phục vị trí cuộn dọc cho danh sách tin nhắn.

Khi nạp lại/đổi nội dung khung chat, ta muốn người dùng không bị 'nhảy' vị trí:
chụp lại trạng thái cuộn trước, rồi khôi phục — hoặc dính xuống đáy nếu trước đó
họ đang xem tin mới nhất.
"""
from __future__ import annotations

from dataclasses import dataclass

from PyQt5 import sip
from PyQt5.QtCore import QTimer


@dataclass(frozen=True)
class VerticalScrollState:
    """Ảnh chụp trạng thái thanh cuộn dọc (giá trị hiện tại, cực đại, có ở đáy không)."""
    value: int = 0
    maximum: int = 0
    at_bottom: bool = True


def _vertical_bar(widget):
    """Lấy thanh cuộn dọc của widget (None nếu widget đã bị hủy)."""
    try:
        if widget is None or sip.isdeleted(widget):
            return None
        return widget.verticalScrollBar()
    except Exception:
        return None


def capture_vertical_scroll(widget, bottom_margin: int = 4) -> VerticalScrollState:
    """Chụp lại vị trí cuộn dọc hiện tại của widget."""
    bar = _vertical_bar(widget)
    if bar is None:
        return VerticalScrollState()
    value = int(bar.value())
    maximum = int(bar.maximum())
    return VerticalScrollState(
        value=value,
        maximum=maximum,
        at_bottom=value >= max(0, maximum - int(bottom_margin or 0)),
    )


def restore_vertical_scroll(
        widget,
        state: VerticalScrollState | None,
        *,
        force_bottom: bool = False,
        stick_to_bottom_if_was_bottom: bool = True,
        delays: tuple[int, ...] = (0, 20, 80)) -> None:
    """Khôi phục vị trí cuộn (hoặc dính đáy nếu trước đó đang ở đáy).

    Áp lại nhiều lần theo ``delays`` vì chiều cao nội dung có thể thay đổi sau khi
    Qt bố trí lại layout, nên một lần đặt giá trị là chưa đủ chắc.
    """
    snapshot = state or VerticalScrollState()

    def apply() -> None:
        bar = _vertical_bar(widget)
        if bar is None:
            return
        maximum = int(bar.maximum())
        if force_bottom or (stick_to_bottom_if_was_bottom and snapshot.at_bottom):
            target = maximum
        else:
            target = min(maximum, max(0, int(snapshot.value)))
        bar.setValue(target)

    apply()
    for delay in delays:
        QTimer.singleShot(int(delay), apply)


def is_near_bottom(widget, margin: int = 24) -> bool:
    """Kiểm tra widget có đang cuộn gần đáy không (trong khoảng margin px)."""
    return capture_vertical_scroll(widget, bottom_margin=margin).at_bottom


def set_plain_text_preserve_scroll(view, text: str) -> None:
    """Đặt text mới cho view nhưng giữ nguyên vị trí cuộn tương đối."""
    state = capture_vertical_scroll(view)
    ratio = state.value / max(1, state.maximum)
    try:
        view.setPlainText(text)
    finally:
        bar = _vertical_bar(view)
        if bar is None:
            return
        maximum = int(bar.maximum())
        if state.at_bottom:
            bar.setValue(maximum)
        else:
            bar.setValue(min(maximum, max(0, int(maximum * ratio))))
