#!/usr/bin/env python3
"""Test hồi quy UI theo checklist kiểm thử thủ công của SecChat.

Bộ test này bám theo ``docs/manual_system_test_plan_vi.md``. Test điều khiển
widget PyQt thật: bấm nút, mở context menu, nhập ô text, chọn dialog và kiểm tra
trạng thái đang hiển thị trên màn hình.

Tính đúng của mạng, database và crypto được kiểm tra ở các test tích hợp/crypto.
Mục tiêu của file này hẹp hơn: khi người dùng thao tác qua UI, màn hình phải đổi
đúng như mong muốn và UI phải phát ra intent cấp cao phù hợp cho ``App``.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from PyQt5 import sip  # noqa: E402
from PyQt5.QtCore import QMimeData, QPointF, Qt, QUrl  # noqa: E402
from PyQt5.QtGui import QDropEvent, QPixmap  # noqa: E402
from PyQt5.QtTest import QTest  # noqa: E402
from PyQt5.QtWidgets import (  # noqa: E402
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QScrollArea,
)

from client.app import App  # noqa: E402
from client.dialogs import AvatarCropDialog, ProfileEditDialog  # noqa: E402
from client.pages.chat_page import ChatPage, MAX_FILE_SIZE  # noqa: E402
from client.pages.login_page import LoginPage  # noqa: E402
from client.pages.register_page import RegisterPage  # noqa: E402
from server_gui import ServerGUI  # noqa: E402


def _sidebar_text(item) -> str:
    return ChatPage.sidebar_item_text(item)


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _pump(ms: int = 20) -> None:
    app = _app()
    app.processEvents()
    app.processEvents()


def _click(widget) -> None:
    if hasattr(widget, "click"):
        widget.click()
        return
    QTest.mouseClick(widget, Qt.LeftButton)
    _pump()


def _key_text(widget, text: str) -> None:
    widget.setFocus()
    if hasattr(widget, "setPlainText"):
        current = widget.toPlainText() if hasattr(widget, "toPlainText") else ""
        widget.setPlainText(f"{current}{text}")
        return
    if hasattr(widget, "setText"):
        current = widget.text() if hasattr(widget, "text") else ""
        widget.setText(f"{current}{text}")
        return
    QTest.keyClicks(widget, text)
    _pump()


def _button(parent, text: str) -> QPushButton:
    for btn in parent.findChildren(QPushButton):
        if btn.text() == text:
            return btn
    raise AssertionError(f"button not found: {text}")


def _line_by_placeholder(parent, placeholder: str) -> QLineEdit:
    for line in parent.findChildren(QLineEdit):
        if line.placeholderText() == placeholder:
            return line
    raise AssertionError(f"line edit not found: {placeholder}")


def _labels(parent) -> list[str]:
    return [lbl.text() for lbl in parent.findChildren(QLabel)]


def _click_list_row(list_widget: QListWidget, row: int) -> None:
    item = list_widget.item(row)
    if item is None:
        raise AssertionError(f"list row not found: {row}")
    list_widget.setCurrentItem(item)
    list_widget.itemClicked.emit(item)


@contextmanager
def _auto_question(answer=QMessageBox.Yes):
    original = QMessageBox.question
    QMessageBox.question = staticmethod(lambda *args, **kwargs: answer)
    try:
        yield
    finally:
        QMessageBox.question = original


@contextmanager
def _capture_messagebox(kind: str = "information"):
    original = getattr(QMessageBox, kind)
    captured: dict[str, str] = {}

    def fake(_parent, title, text, *args, **kwargs):
        captured["title"] = str(title)
        captured["text"] = str(text)
        return QMessageBox.Ok

    setattr(QMessageBox, kind, staticmethod(fake))
    try:
        yield captured
    finally:
        setattr(QMessageBox, kind, original)


@contextmanager
def _auto_item(choice: str, ok: bool = True):
    from PyQt5.QtWidgets import QInputDialog

    original = QInputDialog.getItem
    QInputDialog.getItem = staticmethod(lambda *args, **kwargs: (choice, ok))
    try:
        yield
    finally:
        QInputDialog.getItem = original


@contextmanager
def _choose_menu_action(action_text: str):
    original = ChatPage._show_context_popover

    def fake_show(self, anchor, global_pos, actions):
        for action in actions:
            if action and action.get("text") == action_text:
                if not action.get("enabled", True):
                    raise AssertionError(f"menu action disabled: {action_text}")
                action["callback"]()
                return
        available = [a.get("text") for a in actions if a]
        raise AssertionError(
            f"menu action not found: {action_text}; available={available}"
        )

    ChatPage._show_context_popover = fake_show
    try:
        yield
    finally:
        ChatPage._show_context_popover = original


@contextmanager
def _auto_open_file(path: str):
    original = QFileDialog.getOpenFileName
    QFileDialog.getOpenFileName = staticmethod(
        lambda *args, **kwargs: (path, ""))
    try:
        yield
    finally:
        QFileDialog.getOpenFileName = original


class _FakeAvatarCropDialog:
    def __init__(self, path: str, parent=None):
        self.path = path

    def exec_(self):
        return QDialog.Accepted

    def get_result(self):
        with open(self.path, "rb") as fh:
            return fh.read(), "image/png"


class _FakeCryptoSession:
    def __init__(self) -> None:
        self.reviewed: list[tuple[int, bool]] = []

    def load_identity_audit(self, peer_uid: int) -> dict:
        return {
            "status": "ok",
            "identity_version": 0,
            "checkpoint": {"tree_size": 3, "root_hash": "ab" * 32},
            "history": [{
                "identity_version": 0,
                "event_type": "initial",
                "created_at": "2026-05-28 09:00:00",
                "device_label": "primary device",
                "safety_number": "123456 789012 345678 901234",
            }],
        }

    def load_auditor_state(self) -> dict:
        return {"checkpoint": {"tree_size": 3, "root_hash": "ab" * 32}}

    def mark_identity_reviewed(self, peer_uid: int, verified: bool) -> None:
        self.reviewed.append((int(peer_uid), bool(verified)))


class ManualChecklistUiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.qt = _app()

    def setUp(self) -> None:
        self.page = ChatPage()
        self.page.resize(1000, 700)
        self.page.set_me("alice@example.test", 101)
        self.page.friends = {
            202: {"id": 202, "username": "bob@example.test", "status": "online"},
            303: {
                "id": 303,
                "username": "carol@example.test",
                "status": "offline",
                "last_seen": "2026-05-28 08:00:00",
            },
        }
        self.page.update_friends(list(self.page.friends.values()))
        self.page.update_inbox(
            [{
                "conversation_id": 50,
                "username": "bob@example.test",
                "status": "online",
                "with_user_id": 202,
                "last_message": "cached preview",
            }],
            [{
                "conversation_id": 70,
                "name": "project room",
                "creator_id": 101,
                "last_message": "group preview",
            }],
        )
        self.page._history_loaded_convs.add(50)
        self.page.hist[50] = []
        self.page.hist[70] = []
        self.sent: list[tuple[int, str]] = []
        self.replies: list[tuple[int, int, str]] = []
        self.files: list[tuple[int, str]] = []
        self.commands: list[dict] = []
        self.history_requests: list[int] = []
        self.searches: list[str] = []
        self.friend_requests: list[int] = []
        self.accepts: list[int] = []
        self.rejects: list[int] = []
        self.unfriends: list[int] = []
        self.groups: list[tuple[str, list[int]]] = []
        self.add_to_groups: list[tuple[int, int]] = []
        self.started_dms: list[int] = []
        self.edits: list[tuple[int, int, str]] = []
        self.deletes: list[tuple[int, int]] = []
        self.verify_requests: list[int] = []
        self.cache_policies: list[dict] = []
        self.conv_cache_policies: list[tuple[int, bool]] = []
        self.clear_cache_count = 0
        self.clear_conv_cache: list[int] = []
        self.logout_count = 0
        self.change_passwords: list[tuple[str, str]] = []

        self.page.sig_send.connect(lambda cid, body: self.sent.append((cid, body)))
        self.page.sig_send_reply.connect(
            lambda cid, mid, body: self.replies.append((cid, mid, body)))
        self.page.sig_send_file.connect(
            lambda cid, path: self.files.append((cid, path)))
        self.page.sig_command.connect(lambda obj: self.commands.append(dict(obj)))
        self.page.sig_history.connect(lambda cid: self.history_requests.append(int(cid)))
        self.page.sig_search.connect(lambda q: self.searches.append(q))
        self.page.sig_friend_request.connect(
            lambda uid: self.friend_requests.append(int(uid)))
        self.page.sig_friend_accept.connect(lambda uid: self.accepts.append(int(uid)))
        self.page.sig_friend_reject.connect(lambda uid: self.rejects.append(int(uid)))
        self.page.sig_unfriend.connect(lambda uid: self.unfriends.append(int(uid)))
        self.page.sig_create_group.connect(
            lambda name, members: self.groups.append((name, list(members))))
        self.page.sig_add_to_group.connect(
            lambda gid, uid: self.add_to_groups.append((int(gid), int(uid))))
        self.page.sig_start_dm.connect(lambda uid: self.started_dms.append(int(uid)))
        self.page.sig_edit_message.connect(
            lambda cid, mid, body: self.edits.append((int(cid), int(mid), body)))
        self.page.sig_delete_message.connect(
            lambda cid, mid: self.deletes.append((int(cid), int(mid))))
        self.page.sig_verify_identity.connect(
            lambda cid: self.verify_requests.append(int(cid)))
        self.page.sig_update_cache_policy.connect(
            lambda policy: self.cache_policies.append(dict(policy)))
        self.page.sig_update_conversation_cache_policy.connect(
            lambda cid, enabled: self.conv_cache_policies.append((int(cid), bool(enabled))))
        self.page.sig_clear_local_cache.connect(
            lambda: setattr(self, "clear_cache_count", self.clear_cache_count + 1))
        self.page.sig_clear_conversation_cache.connect(
            lambda cid: self.clear_conv_cache.append(int(cid)))
        self.page.sig_logout.connect(
            lambda: setattr(self, "logout_count", self.logout_count + 1))
        self.page.sig_change_password.connect(
            lambda cur, new: self.change_passwords.append((cur, new)))

    def tearDown(self) -> None:
        if self.page is not None and not sip.isdeleted(self.page):
            self.page.close()
            sip.delete(self.page)
        self.page = None

    def _dm_point(self, row: int = 0):
        item = self.page.dm_list.item(row)
        return self.page.dm_list.visualItemRect(item).center()

    def _group_point(self, row: int = 0):
        item = self.page.group_list.item(row)
        return self.page.group_list.visualItemRect(item).center()

    def _message_action(self, msg_id: int, action_text: str) -> None:
        row = self.page.view.row_for_msg(msg_id)
        self.assertIsNotNone(row, f"message row not found: {msg_id}")
        btn = next(
            b for b in row.findChildren(QPushButton)
            if b.text() == "..."
        )
        with _choose_menu_action(action_text):
            btn.click()

    def test_01_auth_register_logout_manual_ui(self) -> None:
        login = LoginPage()
        register = RegisterPage()
        try:
            logins: list[tuple[str, int, str, str]] = []
            registrations: list[tuple[str, int, str, str, str]] = []
            go_register = []
            back_to_login = []
            login.sig_login.connect(lambda *args: logins.append(args))
            login.sig_go_register.connect(lambda: go_register.append(True))
            register.sig_register.connect(lambda *args: registrations.append(args))
            register.sig_back.connect(lambda: back_to_login.append(True))

            _click(_button(login, "Log in"))
            self.assertEqual(login.lbl_status.text(), "Enter email!")

            login.set_status("Email or password is incorrect")
            self.assertEqual(login.lbl_status.text(), "Email or password is incorrect")

            _key_text(login.e_email, "234@gmail.com")
            _key_text(login.e_pw, "123456")
            _click(_button(login, "Log in"))
            self.assertEqual(logins[0][2], "234@gmail.com")
            self.assertEqual(len(logins[0][3]), 64)
            self.assertEqual(login.lbl_status.text(), "Connecting...")

            _click(_button(login, "Register"))
            self.assertEqual(go_register, [True])

            _key_text(register.e_user, "ab")
            _key_text(register.e_email, "bad")
            _key_text(register.e_pw, "123")
            _key_text(register.e_pw2, "456")
            _click(_button(register, "Register"))
            self.assertIn("at least 3", register.lbl_status.text())

            register.e_user.setText("alice")
            _click(_button(register, "Register"))
            self.assertIn("valid email", register.lbl_status.text())

            register.e_email.setText("alice@example.test")
            register.e_pw.setText("123456")
            register.e_pw2.setText("654321")
            _click(_button(register, "Register"))
            self.assertIn("do not match", register.lbl_status.text())

            register.e_pw2.setText("123456")
            _click(_button(register, "Register"))
            self.assertEqual(registrations[0][2], "alice")
            self.assertEqual(registrations[0][3], "alice@example.test")
            self.assertEqual(len(registrations[0][4]), 64)
            self.assertEqual(register.lbl_status.text(), "Registering...")

            register.set_status("Email already exists")
            self.assertEqual(register.lbl_status.text(), "Email already exists")
            _click(_button(register, "Back to Login"))
            self.assertEqual(back_to_login, [True])

            _click(_button(self.page, "Exit"))
            self.assertEqual(self.logout_count, 1)
        finally:
            login.deleteLater()
            register.deleteLater()

    def test_02_sidebar_friends_requests_and_blocking_ui(self) -> None:
        _click(self.page.btn_search)
        _key_text(self.page.e_search, "bob")
        _click(_button(self.page, "Go"))
        self.assertEqual(self.searches, ["bob"])

        self.page.update_search_results([
            {"id": 404, "username": "dave@example.test"},
            {"id": 202, "username": "bob@example.test"},
        ])
        self.assertEqual(self.page.search_results.count(), 2)

        search_item = self.page.search_results.item(0)
        search_pos = self.page.search_results.visualItemRect(search_item).center()
        with _capture_messagebox("information"):
            with _choose_menu_action("Send Friend Request"):
                self.page._search_context_menu(search_pos)
        self.assertEqual(self.friend_requests, [404])

        self.page.notify_friend_request("dave@example.test")
        self.assertIn("Requests (1)", self.page.btn_requests.text())
        _click(self.page.btn_requests)
        self.assertEqual(self.page.btn_requests.text(), "Requests")

        self.page.update_requests([
            {"user_id": 404, "username": "dave@example.test"},
            {"user_id": 505, "username": "erin@example.test"},
        ])
        first = self.page.request_list.itemWidget(self.page.request_list.item(0))
        second = self.page.request_list.itemWidget(self.page.request_list.item(1))
        _click(_button(first, "Accept"))
        _click(_button(second, "Reject"))
        self.assertEqual(self.accepts, [404])
        self.assertEqual(self.rejects, [505])

        with _choose_menu_action("Start Conversation"):
            self.page._friend_context_menu(self.page.friend_list.visualItemRect(
                self.page.friend_list.item(0)).center())
        self.assertEqual(self.started_dms, [202])

        with _auto_question(QMessageBox.Yes), _choose_menu_action("Remove Friend"):
            self.page._friend_context_menu(self.page.friend_list.visualItemRect(
                self.page.friend_list.item(0)).center())
        self.assertEqual(self.unfriends, [202])

        with _auto_question(QMessageBox.Yes), _choose_menu_action("Block User"):
            self.page._friend_context_menu(self.page.friend_list.visualItemRect(
                self.page.friend_list.item(0)).center())
        self.assertIn({"type": "block_user", "user_id": 202}, self.commands)

        self.assertFalse(hasattr(self.page, "btn_saved"))

    def test_03_dm_history_offline_unread_preview_and_typing_ui(self) -> None:
        _click_list_row(self.page.dm_list, 0)
        self.assertEqual(self.page.active_conv_id, 50)
        self.assertEqual(self.page.lbl_chat.text(), "bob@example.test")
        self.assertEqual(self.page.lbl_chat_presence.text(), "Online")

        _key_text(self.page.inp, "hello dm")
        _click(self.page._btn_send)
        self.assertEqual(self.sent[-1], (50, "hello dm"))
        self.assertEqual(self.page.inp.toPlainText(), "")

        self.page.add_msg(50, 202, "live reply", "10:00", msg_id=2)
        self.assertIn("live reply", _labels(self.page))
        self.page.update_inbox([{
            "conversation_id": 50,
            "username": "bob@example.test",
            "status": "online",
            "with_user_id": 202,
            "last_message": "live reply",
        }], [])
        self.assertIn("live reply", _sidebar_text(self.page.dm_list.item(0)))

        self.page._switch_view("search")
        self.page.add_msg(50, 202, "unread while away", "10:01", msg_id=3)
        self.assertIn("Chats (1)", self.page.btn_chat.text())
        self.page._switch_view("chat")
        self.page._refresh_dm_list()
        self.assertNotIn("[unread]", _sidebar_text(self.page.dm_list.item(0)))

        self.page.invalidate_history(50, clear_messages=True)
        self.page.add_msg(50, 202, "offline message", "10:02", msg_id=5)
        self.page._switch_to_conv(50, is_group=False)
        self.assertIn(50, self.history_requests)
        self.page.load_history(50, [
            {"id": 1, "sender_id": 101, "body": "old before logout", "time": "2026-05-28 10:00:00"},
            {"id": 5, "sender_id": 202, "body": "offline message", "time": "2026-05-28 10:02:00"},
        ])
        bodies = [m["body"] for m in self.page.hist[50]]
        self.assertEqual(bodies, ["old before logout", "offline message"])
        self.assertEqual(len(bodies), len(set(bodies)))

        self.page.set_typing(50, 202, "bob@example.test", True)
        self.assertEqual(self.page.lbl_typing.text(), "bob@example.test is typing...")
        self.page.set_metadata_protection(True)
        self.commands.clear()
        self.page.inp.setPlainText("typing is private")
        self.page._on_input_changed()
        self.assertNotIn("typing_start", [c.get("type") for c in self.commands])

    def test_04_identity_verify_dialog_and_nonblocking_warnings_ui(self) -> None:
        fp = "123456 234567 345678 456789 567890"
        self.page._switch_to_conv(50, is_group=False)
        self.page.set_fingerprint(fp, verified=False)
        self.page.lbl_fingerprint.clicked.emit()
        self.assertEqual(self.verify_requests[-1], 50)

        for status in ("reviewed_unverified", "key_changed",
                       "audit_mismatch", "audit_unavailable"):
            self.page.set_conversation_security(
                50, status, status.replace("_", " "), "manual warning", blocked=False)
            self.assertTrue(self.page.inp.isEnabled())
            _key_text(self.page.inp, f"msg under {status}")
            _click(self.page._btn_send)
            self.assertEqual(self.sent[-1][0], 50)
            guide = self.page.lbl_security_guide.text().lower()
            self.assertTrue("not verified" in guide or "you can" in guide)

        fake = _FakeCryptoSession()
        class Harness:
            pass

        harness = Harness()
        harness._chat = self.page
        harness._conv_verified = {}
        harness._is_saved_message_conv = lambda conv_id: False
        harness._safety_fingerprint_for_conv = lambda conv_id: fp
        harness._safety_short_code = App._safety_short_code
        harness._safety_visual_code = App._safety_visual_code
        harness._peer_uid_for_conv = lambda conv_id: 202
        harness._crypto_session = lambda: fake
        harness._save_verified = lambda conv_id, verified: harness._conv_verified.__setitem__(conv_id, verified)
        harness._refresh_security_ui = lambda conv_id: self.page.set_conversation_security(
            conv_id,
            "verified" if harness._conv_verified.get(conv_id) else "reviewed_unverified",
            "verified" if harness._conv_verified.get(conv_id) else "unverified",
            "",
            False,
        )
        harness._retry_identity_blocked_key_work = lambda peer_uid: None

        original_exec = QDialog.exec_

        def accept_verify_dialog(dlg) -> int:
            texts = _labels(dlg)
            self.assertIn("Short check code", texts)
            self.assertIn("Full safety number", texts)
            self.assertTrue(any("Identity transparency" in text for text in texts))
            self.assertTrue(any("123 456 234 567" in text for text in texts))
            scrolls = dlg.findChildren(QScrollArea)
            self.assertTrue(scrolls)
            self.assertEqual(
                scrolls[0].horizontalScrollBarPolicy(),
                Qt.ScrollBarAlwaysOff,
            )
            chk = next(cb for cb in dlg.findChildren(QCheckBox)
                       if cb.text().startswith("The code matches"))
            chk.setChecked(True)
            self.assertTrue(_button(dlg, "Mark Verified").isEnabled())
            return QDialog.Accepted

        try:
            QDialog.exec_ = accept_verify_dialog
            App._show_verify_dialog(harness, 50)
            self.assertTrue(harness._conv_verified[50])
            self.assertEqual(fake.reviewed[-1], (202, True))
            self.assertIn("Verified", self.page.lbl_fingerprint.text())

            QDialog.exec_ = lambda _dlg: 2
            App._show_verify_dialog(harness, 50)
            self.assertFalse(harness._conv_verified[50])
            self.assertEqual(fake.reviewed[-1], (202, False))
            self.assertIn("Verify safety", self.page.lbl_fingerprint.text())
        finally:
            QDialog.exec_ = original_exec

    def test_05_message_actions_metadata_and_relogin_render_ui(self) -> None:
        self.page._switch_to_conv(50, is_group=False)
        self.page.load_history(50, [{
            "id": 11,
            "sender_id": 101,
            "body": "message to operate",
            "time": "2026-05-28 10:00:00",
            "pinned": False,
            "reactions": [],
        }])

        original_exec = QDialog.exec_

        def choose_first_reaction(dlg) -> int:
            btn = next(b for b in dlg.findChildren(QPushButton)
                       if b.text() and b.text() != "Cancel")
            btn.click()
            return QDialog.Accepted

        try:
            QDialog.exec_ = choose_first_reaction
            self._message_action(11, "React")
        finally:
            QDialog.exec_ = original_exec
        self.assertEqual(self.commands[-1]["type"], "add_reaction")
        self.page.update_reaction(50, 11, self.commands[-1]["emoji"], self.page.my_id, True)
        reaction_buttons = [b.text() for b in self.page.findChildren(QPushButton)]
        self.assertTrue(any(self.commands[-1]["emoji"] in text for text in reaction_buttons))

        self._message_action(11, "Pin")
        self.assertEqual(self.commands[-1], {"type": "pin_message", "message_id": 11})
        self.page.set_message_pinned(50, 11, True)
        self.assertIn("Pins (1)", self.page.btn_pins.text())
        self.assertIn("Pinned", _labels(self.page))

        self._message_action(11, "Reply")
        self.assertFalse(self.page.reply_bar.isHidden())
        _key_text(self.page.inp, "reply body")
        _click(self.page._btn_send)
        self.assertEqual(self.replies[-1], (50, 11, "reply body"))
        self.page.add_msg(50, 202, "reply from peer", "10:01", msg_id=12,
                          reply_to_message_id=11)
        self.assertTrue(any("Replying to message to operate" in text
                            for text in _labels(self.page)))

        self._message_action(11, "Edit")
        self.page._edit_input.clear()
        self.page._edit_input.setText("edited text")
        _click(_button(self.page._edit_widget, "Save"))
        self.assertEqual(self.edits[-1], (50, 11, "edited text"))
        self.page.update_message(50, 11, "edited text", edited=True, deleted=False)
        self.assertIn("(edited)", _labels(self.page))
        self.assertIn("edited text", _labels(self.page))

        self.page.dm_convs.append({
            "conversation_id": 60,
            "username": "carol@example.test",
            "status": "offline",
            "last_message": "",
        })
        with _auto_item("DM: carol@example.test", True):
            self._message_action(11, "Forward")
        self.assertEqual(self.sent[-1][0], 60)
        self.assertTrue(self.sent[-1][1].startswith("SCMSG:1:"))

        self.page.add_msg(50, 101, self.sent[-1][1], "10:03", msg_id=13,
                          forwarded_from_id=11)
        self.assertIn("Forwarded", _labels(self.page))

        with _auto_question(QMessageBox.Yes):
            self._message_action(11, "Delete")
        self.assertEqual(self.deletes[-1], (50, 11))
        self.page.update_message(50, 11, "", edited=False, deleted=True)
        self.assertIn("[Message deleted]", _labels(self.page))

        self.page.load_history(50, [{
            "id": 11,
            "sender_id": 101,
            "body": "edited text",
            "time": "2026-05-28 10:00:00",
            "edited": True,
            "pinned": True,
            "reactions": [{"emoji": "ok", "count": 1, "me": True}],
        }])
        labels = _labels(self.page)
        self.assertIn("edited text", labels)
        self.assertIn("(edited)", labels)
        self.assertIn("Pinned", labels)
        self.assertTrue(any("ok" in b.text() for b in self.page.findChildren(QPushButton)))

    def test_06_file_attach_drag_drop_preview_and_errors_ui(self) -> None:
        self.page._switch_to_conv(50, is_group=False)
        with tempfile.TemporaryDirectory() as td:
            small = os.path.join(td, "note.txt")
            with open(small, "w", encoding="utf-8") as fh:
                fh.write("hello file")

            with _auto_open_file(small):
                _click(_button(self.page, "+"))
            self.assertEqual(self.files[-1][0], 50)
            self.assertEqual(
                os.path.normcase(os.path.normpath(self.files[-1][1])),
                os.path.normcase(os.path.normpath(small)),
            )

            mime = QMimeData()
            mime.setUrls([QUrl.fromLocalFile(small)])
            event = QDropEvent(
                QPointF(8, 8), Qt.CopyAction, mime, Qt.LeftButton, Qt.NoModifier)
            self.page.view.dropEvent(event)
            self.assertEqual(self.files[-1][0], 50)
            self.assertEqual(
                os.path.normcase(os.path.normpath(self.files[-1][1])),
                os.path.normcase(os.path.normpath(small)),
            )

            payload = "FILE:%s:%s" % (
                json.dumps({"name": "note.txt", "mime": "text/plain", "size": 10}),
                base64.b64encode(b"hello file").decode("ascii"),
            )
            self.page.add_msg(50, 101, payload, "10:04", msg_id=21)
            labels = _labels(self.page)
            self.assertIn("note.txt", labels)
            self.assertIn("10 B", labels)
            self.assertIn("Save", [b.text() for b in self.page.findChildren(QPushButton)])

            large = os.path.join(td, "large.bin")
            with open(large, "wb") as fh:
                fh.truncate(MAX_FILE_SIZE + 1)
            with _capture_messagebox("warning") as box:
                self.page._send_dropped_file(large)
            self.assertEqual(box["title"], "File too large")
            self.assertIn("Max file size", box["text"])

            missing = os.path.join(td, "missing.txt")
            with _capture_messagebox("warning") as missing_box:
                self.page._send_dropped_file(missing)
            self.assertEqual(missing_box["title"], "File not found")

    def test_07_group_create_membership_sending_consistency_and_leave_ui(self) -> None:
        original_exec = QDialog.exec_

        def create_group_exec(dlg) -> int:
            _line_by_placeholder(dlg, "Enter group name...").setText("manual group")
            for cb in dlg.findChildren(QCheckBox):
                if cb.text() == "bob@example.test":
                    cb.setChecked(True)
            box = dlg.findChild(QDialogButtonBox)
            box.button(QDialogButtonBox.Ok).click()
            return QDialog.Accepted

        try:
            QDialog.exec_ = create_group_exec
            _click(_button(self.page, "+ New Group"))
        finally:
            QDialog.exec_ = original_exec
        self.assertEqual(self.groups[-1], ("manual group", [202]))

        self.page.update_inbox([], [{
            "conversation_id": 70,
            "name": "manual group",
            "creator_id": 101,
            "last_message": "",
        }])
        _click_list_row(self.page.group_list, 0)
        self.assertEqual(self.page.lbl_chat.text(), "[G] manual group")
        _key_text(self.page.inp, "group message")
        _click(self.page._btn_send)
        self.assertEqual(self.sent[-1], (70, "group message"))

        pending_id = self.page.show_send_pending(70, "waiting server")
        self.assertIsNotNone(self.page.view.row_for_msg(pending_id))
        self.page.remove_pending_send(70, "waiting server", pending_id=pending_id)
        self.assertIsNone(self.page.view.row_for_msg(pending_id))

        self.page.add_system_event(70, "bob@example.test joined the group.")
        self.page.add_system_event(70, "carol@example.test left the group.")
        labels = _labels(self.page)
        self.assertIn("bob@example.test joined the group.", labels)
        self.assertIn("carol@example.test left the group.", labels)

        self.page.show_security_warning(70, [
            "Group commit chain mismatch.",
            "Server history may be missing a membership event.",
        ])
        self.assertFalse(self.page.btn_warning_details.isHidden())
        with _capture_messagebox("warning") as box:
            _click(self.page.btn_warning_details)
        self.assertEqual(box["title"], "Warning Details")
        self.assertIn("Group commit chain mismatch", box["text"])

        def group_info_exec(dlg) -> int:
            members = dlg.findChild(QListWidget)
            members.setCurrentRow(0)
            pos = members.visualItemRect(members.item(0)).center()
            with _choose_menu_action("Make Admin"):
                members.customContextMenuRequested.emit(pos)
            with _choose_menu_action("Make Member"):
                members.customContextMenuRequested.emit(pos)
            with _auto_question(QMessageBox.Yes):
                with _choose_menu_action("Remove Member"):
                    members.customContextMenuRequested.emit(pos)
            with _auto_item("carol@example.test (#303)", True):
                _button(dlg, "Add Member").click()
            box_buttons = dlg.findChild(QDialogButtonBox)
            box_buttons.button(QDialogButtonBox.Save).click()
            return QDialog.Accepted

        try:
            QDialog.exec_ = group_info_exec
            self.page.show_group_info({
                "group_id": 70,
                "name": "manual group",
                "description": "old",
                "members": [
                    {"user_id": 202, "username": "bob@example.test", "role": "member"},
                    {"user_id": 101, "username": "alice@example.test", "role": "admin"},
                ],
            })
        finally:
            QDialog.exec_ = original_exec
        self.assertIn({"type": "set_member_role", "group_id": 70,
                       "user_id": 202, "role": "admin"}, self.commands)
        self.assertIn({"type": "set_member_role", "group_id": 70,
                       "user_id": 202, "role": "member"}, self.commands)
        self.assertIn({"type": "remove_member", "group_id": 70,
                       "user_id": 202}, self.commands)
        self.assertIn((70, 303), self.add_to_groups)

        def leave_group_exec(dlg) -> int:
            with _auto_question(QMessageBox.Yes):
                _button(dlg, "Leave Group").click()
            return QDialog.Rejected

        try:
            QDialog.exec_ = leave_group_exec
            self.page.show_group_info({
                "group_id": 70,
                "name": "manual group",
                "description": "old",
                "members": [
                    {"user_id": 101, "username": "alice@example.test", "role": "admin"},
                ],
            })
        finally:
            QDialog.exec_ = original_exec
        self.assertIn({"type": "leave_group", "group_id": 70}, self.commands)
        self.assertEqual(self.page.active_conv_id, 0)
        self.assertEqual(self.page.lbl_chat.text(), "Select a conversation")

    def test_08_cache_password_backup_profile_avatar_privacy_ui(self) -> None:
        self.page._switch_to_conv(50, is_group=False)
        self.page.set_cache_policy({
            "enabled": True,
            "ttl_days": 30,
            "clear_on_logout": False,
            "disabled_conversation_ids": [],
        })
        self.assertEqual(self.page.lbl_cache_state.text(), "Cache 30 days")

        original_exec = QDialog.exec_

        def privacy_exec(dlg) -> int:
            for combo in dlg.findChildren(QComboBox):
                if combo.findText("nobody") >= 0:
                    combo.setCurrentText("nobody")
                if combo.findData(7) >= 0:
                    combo.setCurrentIndex(combo.findData(7))
            for cb in dlg.findChildren(QCheckBox):
                if cb.text().startswith("Store decrypted"):
                    cb.setChecked(False)
                if cb.text().startswith("Clear local message cache"):
                    cb.setChecked(True)
            box = dlg.findChild(QDialogButtonBox)
            box.button(QDialogButtonBox.Save).click()
            return QDialog.Accepted

        try:
            QDialog.exec_ = privacy_exec
            self.page.show_privacy_settings({
                "privacy_online": "everyone",
                "privacy_last_seen": "friends",
            })
        finally:
            QDialog.exec_ = original_exec
        self.assertFalse(self.cache_policies[-1]["enabled"])
        self.assertEqual(self.cache_policies[-1]["ttl_days"], 7)
        self.assertTrue(self.cache_policies[-1]["clear_on_logout"])
        self.assertEqual(self.commands[-1]["type"], "update_privacy")
        self.assertNotIn("privacy_read_receipt", self.commands[-1])

        with _auto_question(QMessageBox.Yes), _choose_menu_action("Clear This Conversation Cache"):
            self.page._dm_context_menu(self._dm_point())
        self.assertEqual(self.clear_conv_cache[-1], 50)
        with _auto_question(QMessageBox.Yes):
            self.page._confirm_clear_local_cache()
        self.assertEqual(self.clear_cache_count, 1)

        self.page.set_cache_policy({
            "enabled": True,
            "ttl_days": 7,
            "clear_on_logout": False,
            "disabled_conversation_ids": [],
        })
        with _choose_menu_action("Disable Local Cache"):
            self.page._dm_context_menu(self._dm_point())
        self.assertEqual(self.conv_cache_policies[-1], (50, False))
        self.page.set_cache_policy({
            "enabled": True,
            "ttl_days": 7,
            "clear_on_logout": False,
            "disabled_conversation_ids": [50],
        })
        self.assertEqual(self.page.lbl_cache_state.text(), "No local cache")

        password_errors: list[str] = []

        def change_password_exec(dlg) -> int:
            dlg.findChild(QDialogButtonBox).button(QDialogButtonBox.Ok).click()
            password_errors.extend(text for text in _labels(dlg) if "required" in text)
            _line_by_placeholder(dlg, "Current password").setText("old")
            _line_by_placeholder(dlg, "New password").setText("newpass")
            _line_by_placeholder(dlg, "Confirm new password").setText("newpass")
            dlg.findChild(QDialogButtonBox).button(QDialogButtonBox.Ok).click()
            return QDialog.Accepted

        try:
            QDialog.exec_ = change_password_exec
            self.page._show_change_password()
        finally:
            QDialog.exec_ = original_exec
        self.assertTrue(any("Current password is required" in text for text in password_errors))
        self.assertEqual(self.change_passwords[-1], ("old", "newpass"))

        with tempfile.TemporaryDirectory() as td:
            avatar = os.path.join(td, "avatar.png")
            pm = QPixmap(4, 4)
            pm.fill(Qt.red)
            self.assertTrue(pm.save(avatar, "PNG"))

            original_crop = AvatarCropDialog
            import client.dialogs as dialogs_mod
            dialogs_mod.AvatarCropDialog = _FakeAvatarCropDialog
            try:
                dlg = ProfileEditDialog({
                    "username": "alice@example.test",
                    "backup_status": {
                        "latest_generation": 2,
                        "latest_created_at": int(time.time()),
                        "latest_include_cache": True,
                    },
                }, self.page)
                try:
                    with _auto_open_file(avatar):
                        _click(_button(dlg, "Upload Avatar"))
                    display, bio, data, mime, remove = dlg.get_result()
                    self.assertEqual(mime, "image/png")
                    self.assertTrue(data)
                    self.assertFalse(remove)
                    _click(_button(dlg, "Remove Avatar"))
                    self.assertTrue(dlg.get_result()[4])

                    for action, text in [
                        ("change_password", "Change Password"),
                        ("privacy", "Privacy"),
                        ("blocked", "Blocked Users"),
                        ("rotate_identity", "Rotate Safety Key"),
                        ("export_backup", "Export E2EE Backup"),
                        ("restore_backup", "Restore E2EE Backup"),
                        ("backup_status", "Backup Status"),
                        ("revoke_backups", "Revoke Local Backups"),
                    ]:
                        dlg2 = ProfileEditDialog({"username": "alice@example.test"}, self.page)
                        try:
                            _click(_button(dlg2, text))
                            self.assertEqual(dlg2.get_requested_action(), action)
                        finally:
                            dlg2.deleteLater()
                finally:
                    dlg.deleteLater()
            finally:
                dialogs_mod.AvatarCropDialog = original_crop

    def test_09_retry_pending_server_restart_and_layout_ui(self) -> None:
        self.page._switch_to_conv(70, is_group=True)
        first = self.page.show_send_pending(70, "group pending")
        self.assertIsNotNone(self.page.view.row_for_msg(first))
        self.assertIn("Sending", _labels(self.page))
        self.page.remove_pending_send(70, "group pending", pending_id=first)
        self.assertIsNone(self.page.view.row_for_msg(first))

        self.page.show_send_pending(70, "will fail on disconnect")
        self.page.mark_pending_sends_failed("Connection was interrupted.")
        labels = _labels(self.page)
        self.assertIn("Failed", labels)
        self.assertIn("Connection was interrupted.", labels)
        retry = _button(self.page, "Retry")
        dismiss = _button(self.page, "Dismiss")
        self.assertEqual(retry.size(), dismiss.size())
        _click(retry)
        self.assertEqual(self.sent[-1], (70, "will fail on disconnect"))

        self.page.show_send_failed(70, "dismiss me", "server unavailable")
        dismiss_id = int(self.page.hist[70][-1]["msg_id"])
        dismiss_row = self.page.view.row_for_msg(dismiss_id)
        self.assertIsNotNone(dismiss_row)
        _click(_button(dismiss_row, "Dismiss"))
        self.assertFalse(any(m.get("retry_body") == "dismiss me"
                             for m in self.page.hist[70]))

        for idx in range(30):
            self.page.add_msg(70, 101 if idx % 2 else 202, f"group line {idx}", "10:00", msg_id=100 + idx)
        bar = self.page.view.verticalScrollBar()
        self.assertEqual(bar.value(), bar.maximum())
        for msg in self.page.hist[70]:
            row = self.page.view.row_for_msg(msg["msg_id"])
            self.assertIsNotNone(row)
            self.assertLess(row.sizeHint().height(), 180)

    def test_10_server_gui_logs_metrics_manual_ui(self) -> None:
        original_start = ServerGUI._start
        ServerGUI._start = lambda self: None
        try:
            gui = ServerGUI()
        finally:
            ServerGUI._start = original_start
        try:
            tabs = [gui._tabs.tabText(i) for i in range(gui._tabs.count())]
            self.assertEqual(tabs, ["Logs", "Metrics"])
            self.assertNotIn("API Coverage", tabs)

            gui._log("login failed for invalid credentials")
            self.assertIn("login failed", gui.log.toPlainText())
            self.assertNotIn("secret", gui.log.toPlainText().lower())

            long_old = "\n".join(f"old metric line {i}" for i in range(200))
            long_new = "\n".join(f"new metric line {i}" for i in range(240))
            gui.metrics_view.setPlainText(long_old)
            bar = gui.metrics_view.verticalScrollBar()
            bar.setValue(bar.maximum() // 2)
            old_ratio = bar.value() / max(1, bar.maximum())
            gui._set_plain_preserve_scroll(gui.metrics_view, long_new)
            new_bar = gui.metrics_view.verticalScrollBar()
            new_ratio = new_bar.value() / max(1, new_bar.maximum())
            self.assertAlmostEqual(new_ratio, old_ratio, delta=0.12)

            metrics_text = gui._format_metrics({
                "uptime_s": 1,
                "system": {},
                "connections": {"accepted": 1, "active": 0},
                "auth": {"ok": 1, "fail": 1},
                "messages": {"sent": 2},
                "io": {},
                "database": {"queries": 3},
                "security": {},
                "latency": {},
            })
            self.assertIn("SecChat Performance Dashboard", metrics_text)
            self.assertIn("AUTHENTICATION", metrics_text)
        finally:
            gui.close()
            gui.deleteLater()


if __name__ == "__main__":
    unittest.main(verbosity=2)
