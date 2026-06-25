#!/usr/bin/env python3
"""User-flow UI tests for SecChat.

These tests drive real PyQt widgets with QTest.  They are intentionally
controller-light: the goal is to verify that a user can operate the UI and see
the expected visual state, while commands/signals emitted to the controller are
captured for assertions.
"""

from __future__ import annotations

import os
import sys
import unittest
from contextlib import contextmanager

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from PyQt5.QtCore import Qt, QTimer, QCoreApplication, QEvent  # noqa: E402
from PyQt5.QtTest import QTest  # noqa: E402
from PyQt5.QtWidgets import (  # noqa: E402
    QApplication,
    QCheckBox,
    QComboBox,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QInputDialog,
)

from client.pages.chat_page import ChatPage  # noqa: E402
from client.pages.login_page import LoginPage  # noqa: E402
from client.pages.register_page import RegisterPage  # noqa: E402
from client.dialogs import ProfileEditDialog  # noqa: E402


def _sidebar_text(item) -> str:
    return ChatPage.sidebar_item_text(item)


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _click(widget) -> None:
    QTest.mouseClick(widget, Qt.LeftButton)
    _app().processEvents()


def _key_text(widget, text: str) -> None:
    widget.setFocus()
    QTest.keyClicks(widget, text)
    _app().processEvents()


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
    texts: list[str] = []
    for lbl in parent.findChildren(QLabel):
        try:
            texts.append(lbl.text())
        except RuntimeError:
            continue
    return texts


@contextmanager
def _auto_question(answer=QMessageBox.Yes):
    original = QMessageBox.question
    QMessageBox.question = staticmethod(lambda *args, **kwargs: answer)
    try:
        yield
    finally:
        QMessageBox.question = original


@contextmanager
def _auto_information(answer=QMessageBox.Ok):
    original = QMessageBox.information
    QMessageBox.information = staticmethod(lambda *args, **kwargs: answer)
    try:
        yield
    finally:
        QMessageBox.information = original


@contextmanager
def _auto_item(choice: str, ok: bool = True):
    original = QInputDialog.getItem
    QInputDialog.getItem = staticmethod(
        lambda *args, **kwargs: (choice, ok)
    )
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


class ClientUiUserFlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.qt = _app()

    def setUp(self) -> None:
        self.page = ChatPage()
        self.page.resize(1000, 700)
        self.page.show()
        self.qt.processEvents()
        self.page.set_me("alice@example.test", 101)
        self.page.friends = {
            202: {"id": 202, "username": "bob@example.test", "status": "online"},
            303: {"id": 303, "username": "carol@example.test", "status": "offline"},
        }
        self.page.update_friends(list(self.page.friends.values()))
        self.page.update_inbox(
            [{
                "conversation_id": 50,
                "username": "bob@example.test",
                "status": "online",
                "last_message": "hello from bob",
            }, {
                "conversation_id": 60,
                "username": "carol@example.test",
                "status": "offline",
                "last_message": "other dm",
            }],
            [{
                "conversation_id": 70,
                "name": "project room",
                "last_message": "group note",
                "creator_id": 101,
            }],
        )
        self.page._history_loaded_convs.add(50)
        self.page.hist[50] = []
        self.sent: list[tuple[int, str]] = []
        self.sent_replies: list[tuple[int, int, str]] = []
        self.sent_files: list[tuple[int, str]] = []
        self.history_requests: list[int] = []
        self.searches: list[str] = []
        self.friend_requests: list[int] = []
        self.accepts: list[int] = []
        self.rejects: list[int] = []
        self.create_groups: list[tuple[str, list[int]]] = []
        self.add_to_groups: list[tuple[int, int]] = []
        self.edits: list[tuple[int, int, str]] = []
        self.deletes: list[tuple[int, int]] = []
        self.commands: list[dict] = []
        self.verify: list[int] = []
        self.logout_count = 0
        self.change_passwords: list[tuple[str, str]] = []

        self.page.sig_send.connect(lambda cid, body: self.sent.append((cid, body)))
        self.page.sig_send_reply.connect(
            lambda cid, mid, body: self.sent_replies.append((cid, mid, body)))
        self.page.sig_send_file.connect(lambda cid, path: self.sent_files.append((cid, path)))
        self.page.sig_history.connect(lambda cid: self.history_requests.append(int(cid)))
        self.page.sig_search.connect(lambda q: self.searches.append(q))
        self.page.sig_friend_request.connect(lambda uid: self.friend_requests.append(int(uid)))
        self.page.sig_friend_accept.connect(lambda uid: self.accepts.append(int(uid)))
        self.page.sig_friend_reject.connect(lambda uid: self.rejects.append(int(uid)))
        self.page.sig_create_group.connect(
            lambda name, members: self.create_groups.append((name, list(members))))
        self.page.sig_add_to_group.connect(
            lambda gid, uid: self.add_to_groups.append((int(gid), int(uid))))
        self.page.sig_edit_message.connect(
            lambda cid, mid, body: self.edits.append((int(cid), int(mid), body)))
        self.page.sig_delete_message.connect(
            lambda cid, mid: self.deletes.append((int(cid), int(mid))))
        self.page.sig_command.connect(lambda obj: self.commands.append(dict(obj)))
        self.page.sig_verify_identity.connect(lambda cid: self.verify.append(int(cid)))
        self.page.sig_logout.connect(lambda: setattr(self, "logout_count", self.logout_count + 1))
        self.page.sig_change_password.connect(
            lambda cur, new: self.change_passwords.append((cur, new)))

    def tearDown(self) -> None:
        self.page.reset()
        self.page.close()
        self.page.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        for _ in range(3):
            QTest.qWait(10)
            self.qt.processEvents()

    def _click_message_action(self, msg_id: int, action_text: str) -> None:
        row = self.page.view.row_for_msg(msg_id)
        self.assertIsNotNone(row, f"message row not found: {msg_id}")
        action_btn = next(
            (btn for btn in row.findChildren(QPushButton) if btn.text() == "..."),
            None,
        )
        self.assertIsNotNone(action_btn, "message action button missing")
        with _choose_menu_action(action_text):
            _click(action_btn)

    def test_login_and_register_forms_are_real_user_flows(self) -> None:
        register = RegisterPage()
        login = LoginPage()
        try:
            registered = []
            logged_in = []
            register.sig_register.connect(
                lambda host, port, username, email, pw:
                registered.append((host, port, username, email, pw)))
            login.sig_login.connect(
                lambda host, port, email, pw: logged_in.append((host, port, email, pw)))

            _key_text(register.e_user, "alice")
            _key_text(register.e_email, "alice@example.test")
            _key_text(register.e_pw, "123456")
            _key_text(register.e_pw2, "123456")
            _click(_button(register, "Register"))

            self.assertEqual(registered[0][2], "alice")
            self.assertEqual(registered[0][3], "alice@example.test")
            self.assertEqual(len(registered[0][4]), 64)
            self.assertEqual(register.lbl_status.text(), "Registering...")

            _click(_button(login, "Log in"))
            self.assertEqual(login.lbl_status.text(), "Enter email!")
            _key_text(login.e_email, "alice@example.test")
            _key_text(login.e_pw, "123456")
            _click(_button(login, "Log in"))

            self.assertEqual(logged_in[0][2], "alice@example.test")
            self.assertEqual(len(logged_in[0][3]), 64)
            self.assertEqual(login.lbl_status.text(), "Connecting...")
        finally:
            register.deleteLater()
            login.deleteLater()

    def test_navigation_search_requests_and_sidebar_actions(self) -> None:
        _click(self.page.btn_search)
        self.assertEqual(self.page.current_view, "search")
        _key_text(self.page.e_search, "bob")
        _click(_button(self.page, "Go"))
        self.assertEqual(self.searches, ["bob"])

        self.page.update_search_results([{"id": 404, "username": "dave@example.test"}])
        self.assertEqual(self.page.search_results.count(), 1)
        self.page.search_results.setCurrentRow(0)
        item_pos = self.page.search_results.visualItemRect(
            self.page.search_results.item(0)).center()
        with _auto_information(), _choose_menu_action("Send Friend Request"):
            self.page._search_context_menu(item_pos)
        self.assertEqual(self.friend_requests, [404])

        _click(self.page.btn_requests)
        self.assertEqual(self.page.current_view, "requests")
        self.page.update_requests([
            {"user_id": 202, "username": "bob@example.test"},
            {"user_id": 303, "username": "carol@example.test"},
        ])
        self.assertEqual(self.page.request_list.count(), 2)
        first = self.page.request_list.itemWidget(self.page.request_list.item(0))
        second = self.page.request_list.itemWidget(self.page.request_list.item(1))
        _click(_button(first, "Accept"))
        _click(_button(second, "Reject"))

        self.assertEqual(self.accepts, [202])
        self.assertEqual(self.rejects, [303])

        self.assertNotIn(
            "Saved Messages",
            [btn.text() for btn in self.page.findChildren(QPushButton)],
        )
        _click(_button(self.page, "Exit"))
        self.assertEqual(self.logout_count, 1)

    def test_conversation_context_actions_show_state_in_sidebar(self) -> None:
        def dm_point():
            item = None
            for i in range(self.page.dm_list.count()):
                candidate = self.page.dm_list.item(i)
                if int(candidate.data(Qt.UserRole) or 0) == 50:
                    item = candidate
                    break
            self.assertIsNotNone(item)
            return self.page.dm_list.visualItemRect(item).center()

        with _choose_menu_action("Mute 1 Hour"):
            self.page._dm_context_menu(dm_point())
        self.assertEqual(self.commands[-1], {
            "type": "mute_conversation",
            "conversation_id": 50,
            "mute_secs": 3600,
        })
        self.assertIn("[muted]", _sidebar_text(self.page.dm_list.item(0)))

        with _choose_menu_action("Unmute"):
            self.page._dm_context_menu(dm_point())
        self.assertEqual(self.commands[-1], {
            "type": "mute_conversation",
            "conversation_id": 50,
            "mute_secs": 0,
        })
        self.assertNotIn("[muted]", _sidebar_text(self.page.dm_list.item(0)))

        with _choose_menu_action("Toggle Archive"):
            self.page._dm_context_menu(dm_point())
        self.assertEqual(self.commands[-1], {
            "type": "archive_conversation",
            "conversation_id": 50,
        })
        self.assertTrue(any(
            "[archived]" in _sidebar_text(self.page.dm_list.item(i))
            for i in range(self.page.dm_list.count())
        ))

        with _choose_menu_action("Toggle Archive"):
            self.page._dm_context_menu(dm_point())
        self.assertEqual(self.commands[-1], {
            "type": "archive_conversation",
            "conversation_id": 50,
        })
        self.assertNotIn("[archived]", _sidebar_text(self.page.dm_list.item(0)))

        with _choose_menu_action("Toggle Pin Conversation"):
            self.page._dm_context_menu(dm_point())
        self.assertEqual(self.commands[-1], {
            "type": "pin_conversation",
            "conversation_id": 50,
        })
        self.assertIn("[pinned]", _sidebar_text(self.page.dm_list.item(0)))

        with _choose_menu_action("Toggle Pin Conversation"):
            self.page._dm_context_menu(dm_point())
        self.assertEqual(self.commands[-1], {
            "type": "pin_conversation",
            "conversation_id": 50,
        })
        self.assertNotIn("[pinned]", _sidebar_text(self.page.dm_list.item(0)))

        with _choose_menu_action("Mark Unread"):
            self.page._dm_context_menu(dm_point())
        self.assertEqual(self.commands[-1], {
            "type": "mark_unread",
            "conversation_id": 50,
        })
        self.assertIn("[unread]", _sidebar_text(self.page.dm_list.item(0)))

        with _auto_item("1 hour", True), _auto_question(QMessageBox.Yes), \
                _choose_menu_action("Disappearing Timer..."):
            self.page._dm_context_menu(dm_point())
        self.assertEqual(self.commands[-1], {
            "type": "set_disappearing",
            "conversation_id": 50,
            "disappear_after_secs": 3600,
        })
        self.assertIn("[timer]", _sidebar_text(self.page.dm_list.item(0)))

        with _auto_item("Off", True), _choose_menu_action("Disappearing Timer..."):
            self.page._dm_context_menu(dm_point())
        self.assertEqual(self.commands[-1], {
            "type": "set_disappearing",
            "conversation_id": 50,
            "disappear_after_secs": 0,
        })
        self.assertNotIn("[timer]", _sidebar_text(self.page.dm_list.item(0)))

        self.page.update_inbox(
            [{
                "conversation_id": 50,
                "username": "bob@example.test",
                "status": "online",
                "last_message": "",
                "unread_count": 1,
                "muted": True,
                "archived": True,
                "pinned_conversation": True,
                "disappear_after_secs": 3600,
            }],
            [],
        )
        text = _sidebar_text(self.page.dm_list.item(0))
        self.assertNotIn("[unread]", text)
        self.assertIn("[pinned]", text)
        self.assertIn("[muted]", text)
        self.assertIn("[archived]", text)
        self.assertIn("[timer]", text)
        self.assertNotIn("\n", text, "empty preview should not render a blank line")

    def test_group_context_actions_show_state_in_sidebar(self) -> None:
        def group_point():
            item = self.page.group_list.item(0)
            return self.page.group_list.visualItemRect(item).center()

        with _choose_menu_action("Mute 1 Hour"):
            self.page._group_context_menu(group_point())
        self.assertEqual(self.commands[-1], {
            "type": "mute_conversation",
            "conversation_id": 70,
            "mute_secs": 3600,
        })
        self.assertIn("[muted]", _sidebar_text(self.page.group_list.item(0)))

        with _choose_menu_action("Unmute"):
            self.page._group_context_menu(group_point())
        self.assertEqual(self.commands[-1], {
            "type": "mute_conversation",
            "conversation_id": 70,
            "mute_secs": 0,
        })
        self.assertNotIn("[muted]", _sidebar_text(self.page.group_list.item(0)))

        with _choose_menu_action("Toggle Archive"):
            self.page._group_context_menu(group_point())
        self.assertEqual(self.commands[-1], {
            "type": "archive_conversation",
            "conversation_id": 70,
        })
        self.assertIn("[archived]", _sidebar_text(self.page.group_list.item(0)))

        with _choose_menu_action("Toggle Archive"):
            self.page._group_context_menu(group_point())
        self.assertNotIn("[archived]", _sidebar_text(self.page.group_list.item(0)))

        with _choose_menu_action("Toggle Pin Conversation"):
            self.page._group_context_menu(group_point())
        self.assertEqual(self.commands[-1], {
            "type": "pin_conversation",
            "conversation_id": 70,
        })
        self.assertIn("[pinned]", _sidebar_text(self.page.group_list.item(0)))

        with _choose_menu_action("Toggle Pin Conversation"):
            self.page._group_context_menu(group_point())
        self.assertNotIn("[pinned]", _sidebar_text(self.page.group_list.item(0)))

        with _choose_menu_action("Mark Unread"):
            self.page._group_context_menu(group_point())
        self.assertEqual(self.commands[-1], {
            "type": "mark_unread",
            "conversation_id": 70,
        })
        self.assertIn("[unread]", _sidebar_text(self.page.group_list.item(0)))

        with _auto_item("1 hour", True), _auto_question(QMessageBox.Yes), \
                _choose_menu_action("Disappearing Timer..."):
            self.page._group_context_menu(group_point())
        self.assertEqual(self.commands[-1], {
            "type": "set_disappearing",
            "conversation_id": 70,
            "disappear_after_secs": 3600,
        })
        self.assertIn("[timer]", _sidebar_text(self.page.group_list.item(0)))

        with _auto_item("Off", True), _choose_menu_action("Disappearing Timer..."):
            self.page._group_context_menu(group_point())
        self.assertEqual(self.commands[-1], {
            "type": "set_disappearing",
            "conversation_id": 70,
            "disappear_after_secs": 0,
        })
        self.assertNotIn("[timer]", _sidebar_text(self.page.group_list.item(0)))

    def test_open_conversation_scrolls_to_latest_and_reset_clears_stale_header(self) -> None:
        self.page._history_loaded_convs.add(50)
        self.page.hist[50] = [
            {
                "sender_id": 202,
                "body": f"long history message {idx}",
                "ts": "10:00",
                "msg_id": idx,
                "edited": False,
                "deleted": False,
                "pinned": False,
                "reactions": {},
                "forwarded_from_id": 0,
            }
            for idx in range(1, 80)
        ]

        self.page._switch_to_conv(50, is_group=False)
        for _ in range(4):
            QTest.qWait(20)
            self.qt.processEvents()

        bar = self.page.view.verticalScrollBar()
        self.assertGreater(bar.maximum(), 0)
        self.assertEqual(bar.value(), bar.maximum())
        self.assertEqual(self.page.lbl_chat.text(), "bob@example.test")
        self.assertEqual(self.page.lbl_chat_presence.text(), "Online")

        self.page.reset()
        self.qt.processEvents()
        self.assertEqual(self.page.active_conv_id, 0)
        self.assertEqual(self.page.lbl_chat.text(), "Select a conversation")
        self.assertEqual(self.page.lbl_chat_presence.text(), "")
        self.assertEqual(self.page.dm_list.count(), 0)
        self.assertEqual(self.page.group_list.count(), 0)

    def test_active_conversation_keeps_scroll_when_user_reads_old_messages(self) -> None:
        self.page._history_loaded_convs.add(50)
        self.page.hist[50] = [
            {
                "sender_id": 202 if idx % 2 else 101,
                "body": f"old history line {idx} " * 4,
                "ts": "10:00",
                "msg_id": idx,
                "edited": False,
                "deleted": False,
                "pinned": False,
                "reactions": {},
                "forwarded_from_id": 0,
            }
            for idx in range(1, 100)
        ]

        self.page._switch_to_conv(50, is_group=False)
        for _ in range(4):
            QTest.qWait(25)
            self.qt.processEvents()

        bar = self.page.view.verticalScrollBar()
        self.assertGreater(bar.maximum(), 0)
        bar.setValue(max(1, bar.maximum() // 3))
        self.qt.processEvents()
        old_value = bar.value()

        self.page.add_msg(50, 202, "new message while reading old history", "10:30", msg_id=150)
        for _ in range(4):
            QTest.qWait(25)
            self.qt.processEvents()

        self.assertLess(bar.value(), bar.maximum())
        self.assertAlmostEqual(bar.value(), old_value, delta=8)

    def test_sidebar_lists_preserve_scroll_after_refresh(self) -> None:
        friends = [
            {
                "id": 1000 + idx,
                "username": f"friend{idx:02d}@example.test",
                "status": "online" if idx % 2 else "offline",
            }
            for idx in range(45)
        ]
        dms = [
            {
                "conversation_id": 2000 + idx,
                "username": f"dm{idx:02d}@example.test",
                "status": "online" if idx % 2 else "offline",
                "last_message": f"preview {idx}",
            }
            for idx in range(45)
        ]
        groups = [
            {
                "conversation_id": 3000 + idx,
                "name": f"group {idx:02d}",
                "last_message": f"group preview {idx}",
                "creator_id": 101,
            }
            for idx in range(45)
        ]

        self.page.update_friends(friends)
        self.page.update_inbox(dms, groups)
        self.qt.processEvents()

        tracked = [self.page.friend_list, self.page.dm_list, self.page.group_list]
        old_values = {}
        for widget in tracked:
            bar = widget.verticalScrollBar()
            self.assertGreater(bar.maximum(), 0)
            bar.setValue(max(1, bar.maximum() // 2))
            old_values[widget.objectName()] = bar.value()

        refreshed_friends = [dict(item, last_seen="just now") for item in friends]
        refreshed_dms = [dict(item, last_message=f"updated preview {idx}")
                         for idx, item in enumerate(dms)]
        refreshed_groups = [dict(item, last_message=f"updated group preview {idx}")
                            for idx, item in enumerate(groups)]
        self.page.update_friends(refreshed_friends)
        self.page.update_inbox(refreshed_dms, refreshed_groups)
        for _ in range(4):
            QTest.qWait(25)
            self.qt.processEvents()

        for widget in tracked:
            bar = widget.verticalScrollBar()
            self.assertAlmostEqual(
                bar.value(), old_values[widget.objectName()], delta=4)

    def test_group_system_events_render_inline_not_as_popup(self) -> None:
        self.page._switch_to_conv(70, is_group=True)
        self.page.add_system_event(70, "bob@example.test joined the group.")
        self.page.add_system_event(70, "carol@example.test left the group.")
        self.qt.processEvents()

        labels = _labels(self.page)
        self.assertIn("bob@example.test joined the group.", labels)
        self.assertIn("carol@example.test left the group.", labels)
        system_rows = [
            msg for msg in self.page.hist[70]
            if str(msg.get("body", "")).startswith("__SYSTEM__:")
        ]
        self.assertEqual(len(system_rows), 2)

    def test_chat_history_send_search_pin_and_security_state_are_visible(self) -> None:
        item = self.page.dm_list.item(0)
        point = self.page.dm_list.visualItemRect(item).center()
        QTest.mouseClick(self.page.dm_list.viewport(), Qt.LeftButton, pos=point)
        self.qt.processEvents()
        self.assertEqual(self.page.active_conv_id, 50)
        self.assertEqual(self.page.lbl_chat.text(), "bob@example.test")

        self.page.load_history(50, [
            {
                "id": 1,
                "sender_id": 202,
                "body": "hello visible ui",
                "time": "2026-05-19 10:00:00",
                "pinned": True,
                "reactions": [{"emoji": "ok", "count": 2, "me": False}],
            },
            {
                "id": 2,
                "sender_id": 101,
                "body": "SCMSG:1:eyJraW5kIjoiZm9yd2FyZCIsImJvZHkiOiJmb3J3YXJkZWQgdGV4dCJ9",
                "time": "2026-05-19 10:01:00",
                "forwarded_from_id": 1,
            },
        ])
        self.assertIsNotNone(self.page.view.row_for_msg(1))
        self.assertTrue(any(text == "Pinned" for text in _labels(self.page)))
        self.assertTrue(any(text == "Forwarded" for text in _labels(self.page)))
        self.assertEqual(self.page.btn_pins.text(), "Pins (1)")

        _key_text(self.page.e_msg_search, "visible")
        self.assertIsNotNone(self.page.view.row_for_msg(1))
        self.assertIsNone(self.page.view.row_for_msg(2))
        self.page.e_msg_search.clear()

        _key_text(self.page.inp, "typed by user")
        _click(self.page._btn_send)
        self.assertEqual(self.sent[-1], (50, "typed by user"))
        self.assertEqual(self.page.inp.toPlainText(), "")

        self.page.set_conversation_security(
            50,
            "key_changed",
            "key changed",
            "Safety number changed.",
            blocked=True,
        )
        self.assertIn("[key changed]", _sidebar_text(self.page.dm_list.item(0)))
        self.assertTrue(self.page.inp.isEnabled())
        self.assertTrue(self.page.btn_review_identity.isVisible())
        _click(self.page.btn_review_identity)
        self.assertEqual(self.verify[-1], 50)

    def test_message_action_menu_react_pin_edit_forward_and_delete(self) -> None:
        self.page._switch_to_conv(50, is_group=False)
        self.page.load_history(50, [{
            "id": 11,
            "sender_id": 101,
            "body": "message to act on",
            "time": "2026-05-19 10:02:00",
            "pinned": False,
            "reactions": [],
        }])

        def choose_first_emoji() -> None:
            dlg = QApplication.activeModalWidget()
            self.assertIsNotNone(dlg)
            emoji_btn = next(
                btn for btn in dlg.findChildren(QPushButton)
                if btn.text() and btn.text() != "Cancel"
            )
            _click(emoji_btn)

        QTimer.singleShot(0, choose_first_emoji)
        self._click_message_action(11, "React")
        self.assertEqual(self.commands[-1]["type"], "add_reaction")
        self.assertEqual(self.commands[-1]["message_id"], 11)
        self.assertTrue(self.commands[-1]["emoji"])

        self._click_message_action(11, "Pin")
        self.assertEqual(self.commands[-1], {"type": "pin_message", "message_id": 11})
        self.page.set_message_pinned(50, 11, True)
        self.assertTrue(any(text == "Pinned" for text in _labels(self.page)))
        self._click_message_action(11, "Unpin")
        self.assertEqual(self.commands[-1], {"type": "unpin_message", "message_id": 11})

        self._click_message_action(11, "Reply")
        self.assertFalse(self.page.reply_bar.isHidden())
        self.assertIn("message to act on", self.page.lbl_reply.text())
        _key_text(self.page.inp, "reply from ui")
        _click(self.page._btn_send)
        self.assertEqual(self.sent_replies[-1], (50, 11, "reply from ui"))
        self.assertTrue(self.page.reply_bar.isHidden())

        self.page.add_msg(50, 202, "reply body", "10:03", msg_id=12,
                          reply_to_message_id=11)
        self.assertTrue(any("Replying to message to act on" in text
                            for text in _labels(self.page)))

        self._click_message_action(11, "Edit")
        self.assertTrue(self.page._edit_widget.isVisible())
        self.page._edit_input.clear()
        _key_text(self.page._edit_input, "edited from ui")
        _click(_button(self.page._edit_widget, "Save"))
        self.assertEqual(self.edits[-1], (50, 11, "edited from ui"))

        self.page.dm_convs.append({
            "conversation_id": 60,
            "username": "carol@example.test",
            "status": "offline",
            "last_message": "",
        })
        with _auto_item("DM: carol@example.test", True):
            self._click_message_action(11, "Forward")
        self.assertEqual(self.sent[-1][0], 60)
        self.assertTrue(self.sent[-1][1].startswith("SCMSG:1:"))

        with _auto_question(QMessageBox.Yes):
            self._click_message_action(11, "Delete")
        self.assertEqual(self.deletes[-1], (50, 11))

    def test_group_profile_privacy_blocked_and_pinned_dialogs_are_operable(self) -> None:
        def drive_create_group() -> None:
            dlg = QApplication.activeModalWidget()
            self.assertIsNotNone(dlg)
            _key_text(_line_by_placeholder(dlg, "Enter group name..."), "ui group")
            for cb in dlg.findChildren(QCheckBox):
                if cb.text() in ("bob@example.test", "carol@example.test"):
                    cb.setChecked(True)
            box = dlg.findChild(QDialogButtonBox)
            self.assertIsNotNone(box)
            _click(box.button(QDialogButtonBox.Ok))

        QTimer.singleShot(0, drive_create_group)
        _click(_button(self.page, "+ New Group"))
        self.assertEqual(self.create_groups[-1], ("ui group", [202, 303]))

        dlg = ProfileEditDialog({"username": "alice@example.test"}, self.page)
        try:
            _click(_button(dlg, "Change Password"))
            self.assertEqual(dlg.get_requested_action(), "change_password")
        finally:
            dlg.deleteLater()

        def drive_change_password() -> None:
            dlg = QApplication.activeModalWidget()
            self.assertIsNotNone(dlg)
            _key_text(_line_by_placeholder(dlg, "Current password"), "oldpass")
            _key_text(_line_by_placeholder(dlg, "New password"), "newpass")
            _key_text(_line_by_placeholder(dlg, "Confirm new password"), "newpass")
            box = dlg.findChild(QDialogButtonBox)
            _click(box.button(QDialogButtonBox.Ok))

        QTimer.singleShot(0, drive_change_password)
        self.page._show_change_password()
        self.assertEqual(self.change_passwords[-1], ("oldpass", "newpass"))

        def drive_privacy() -> None:
            dlg = QApplication.activeModalWidget()
            self.assertIsNotNone(dlg)
            for combo in dlg.findChildren(QComboBox):
                if combo.findText("nobody") >= 0:
                    combo.setCurrentText("nobody")
            for cb in dlg.findChildren(QCheckBox):
                if cb.text().startswith("Store decrypted"):
                    cb.setChecked(False)
            box = dlg.findChild(QDialogButtonBox)
            _click(box.button(QDialogButtonBox.Save))

        QTimer.singleShot(0, drive_privacy)
        self.page.show_privacy_settings({
            "privacy_online": "everyone",
            "privacy_last_seen": "friends",
        })
        self.assertEqual(self.commands[-1]["type"], "update_privacy")
        self.assertFalse(self.page._local_cache_policy["enabled"])

        def drive_blocked() -> None:
            dlg = QApplication.activeModalWidget()
            self.assertIsNotNone(dlg)
            lst = dlg.findChild(QListWidget)
            lst.setCurrentRow(0)
            _click(_button(dlg, "Unblock"))
            self.assertEqual(lst.count(), 1)
            box = dlg.findChild(QDialogButtonBox)
            _click(box.button(QDialogButtonBox.Close))

        QTimer.singleShot(0, drive_blocked)
        self.page.show_blocked_list([202, 303])
        self.assertIn({"type": "unblock_user", "user_id": 202}, self.commands)

        def drive_pins() -> None:
            dlg = QApplication.activeModalWidget()
            self.assertIsNotNone(dlg)
            lst = dlg.findChild(QListWidget)
            lst.setCurrentRow(0)
            _click(_button(dlg, "Unpin Selected"))
            self.assertEqual(lst.count(), 1)
            box = dlg.findChild(QDialogButtonBox)
            _click(box.button(QDialogButtonBox.Close))

        QTimer.singleShot(0, drive_pins)
        self.page.show_pinned_messages(50, [
            {"message_id": 11, "sender": "alice", "body": "pin one"},
            {"message_id": 12, "sender": "bob", "body": "pin two"},
        ])
        self.assertIn({"type": "unpin_message", "message_id": 11}, self.commands)

    def test_group_info_dialog_exposes_member_and_group_actions(self) -> None:
        def drive_group_info() -> None:
            dlg = QApplication.activeModalWidget()
            self.assertIsNotNone(dlg)
            lines = dlg.findChildren(QLineEdit)
            lines[0].setText("renamed group")
            lines[1].setText("new description")
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
            with _auto_item("bob@example.test (#202)", True):
                _click(_button(dlg, "Add Member"))
            box = dlg.findChild(QDialogButtonBox)
            _click(box.button(QDialogButtonBox.Save))

        QTimer.singleShot(0, drive_group_info)
        self.page.show_group_info({
            "group_id": 70,
            "name": "project room",
            "description": "old",
            "members": [
                {"user_id": 202, "username": "bob@example.test", "role": "member"},
                {"user_id": 101, "username": "alice@example.test", "role": "admin"},
            ],
        })

        self.assertIn({
            "type": "set_member_role",
            "group_id": 70,
            "user_id": 202,
            "role": "admin",
        }, self.commands)
        self.assertIn({
            "type": "set_member_role",
            "group_id": 70,
            "user_id": 202,
            "role": "member",
        }, self.commands)
        self.assertIn({
            "type": "remove_member",
            "group_id": 70,
            "user_id": 202,
        }, self.commands)
        self.assertIn((70, 202), self.add_to_groups)
        self.assertEqual(self.commands[-1], {
            "type": "update_group_info",
            "group_id": 70,
            "name": "renamed group",
            "description": "new description",
        })

    def test_group_info_leave_closes_without_saving_changes(self) -> None:
        def drive_group_info() -> None:
            dlg = QApplication.activeModalWidget()
            self.assertIsNotNone(dlg)
            with _auto_question(QMessageBox.Yes):
                _click(_button(dlg, "Leave Group"))

        QTimer.singleShot(0, drive_group_info)
        self.page.show_group_info({
            "group_id": 70,
            "name": "project room",
            "description": "old",
            "members": [
                {"user_id": 202, "username": "bob@example.test", "role": "member"},
                {"user_id": 101, "username": "alice@example.test", "role": "admin"},
            ],
        })

        self.assertIn({"type": "leave_group", "group_id": 70}, self.commands)
        self.assertNotIn("project room", self.page.lbl_chat.text())


if __name__ == "__main__":
    unittest.main(verbosity=2)
