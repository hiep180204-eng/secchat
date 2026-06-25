#!/usr/bin/env python3
"""Two-user UI flow tests for SecChat.

The goal of this suite is to exercise the chat UI the way a user operates it:
search, friend request, accept, open DM, send messages, create a group, and
send group messages.  A small in-process server model handles only the state
needed by the widgets, so the test verifies UI wiring and visible results
without bypassing ChatPage signals.
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

from PyQt5 import sip  # noqa: E402
from PyQt5.QtCore import Qt  # noqa: E402
from PyQt5.QtTest import QTest  # noqa: E402
from PyQt5.QtWidgets import (  # noqa: E402
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
)

from client.pages.chat_page import ChatPage  # noqa: E402


def _sidebar_text(item) -> str:
    return ChatPage.sidebar_item_text(item)


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _pump() -> None:
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
def _auto_information(answer=QMessageBox.Ok):
    original = QMessageBox.information
    QMessageBox.information = staticmethod(lambda *args, **kwargs: answer)
    try:
        yield
    finally:
        QMessageBox.information = original


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


class UiFlowServer:
    """Tiny state bridge that behaves like the parts of the server the UI sees."""

    def __init__(self, alice: ChatPage, bob: ChatPage) -> None:
        self.pages = {1: alice, 2: bob}
        self.users = {
            1: {"id": 1, "username": "alice@example.test", "status": "online"},
            2: {"id": 2, "username": "bob@example.test", "status": "online"},
        }
        self.requests: dict[int, list[int]] = {1: [], 2: []}
        self.friendships: set[frozenset[int]] = set()
        self.dm_conv_id = 101
        self.group_conv_id = 201
        self.dm_started = False
        self.groups: dict[int, dict] = {}
        self.conv_members: dict[int, list[int]] = {}
        self.messages: dict[int, list[dict]] = {}
        self.next_msg_id = 1
        self.searches: list[tuple[int, str]] = []
        self.friend_requests: list[tuple[int, int]] = []
        self.accepts: list[tuple[int, int]] = []
        self.started_dms: list[tuple[int, int]] = []
        self.created_groups: list[tuple[int, str, list[int]]] = []
        self.sent_messages: list[tuple[int, int, str]] = []

        for uid, page in self.pages.items():
            page.set_me(self.users[uid]["username"], uid)
            page.update_friends([])
            page.update_requests([])
            page.update_inbox([], [])
            page.sig_search.connect(lambda q, uid=uid: self.search(uid, q))
            page.sig_friend_request.connect(
                lambda target_uid, uid=uid: self.friend_request(uid, int(target_uid))
            )
            page.sig_friend_accept.connect(
                lambda requester_uid, uid=uid: self.accept_friend(uid, int(requester_uid))
            )
            page.sig_start_dm.connect(lambda peer_uid, uid=uid: self.start_dm(uid, int(peer_uid)))
            page.sig_create_group.connect(
                lambda name, members, uid=uid: self.create_group(uid, name, list(members))
            )
            page.sig_send.connect(lambda conv_id, body, uid=uid: self.send(uid, int(conv_id), body))
            page.sig_history.connect(lambda conv_id, uid=uid: self.load_history(uid, int(conv_id)))

    def search(self, uid: int, query: str) -> None:
        self.searches.append((uid, query))
        query_l = query.lower()
        results = [
            user for other_uid, user in self.users.items()
            if other_uid != uid and query_l in user["username"].lower()
        ]
        self.pages[uid].update_search_results(results)

    def friend_request(self, from_uid: int, target_uid: int) -> None:
        self.friend_requests.append((from_uid, target_uid))
        if from_uid not in self.requests[target_uid]:
            self.requests[target_uid].append(from_uid)
        self._refresh_requests(target_uid)
        self.pages[target_uid].notify_friend_request(self.users[from_uid]["username"])

    def accept_friend(self, uid: int, requester_uid: int) -> None:
        self.accepts.append((uid, requester_uid))
        self.friendships.add(frozenset((uid, requester_uid)))
        self.requests[uid] = [r for r in self.requests[uid] if r != requester_uid]
        self._refresh_requests(uid)
        self._refresh_friends(uid)
        self._refresh_friends(requester_uid)

    def start_dm(self, uid: int, peer_uid: int) -> None:
        self.started_dms.append((uid, peer_uid))
        self.dm_started = True
        self.conv_members[self.dm_conv_id] = [uid, peer_uid]
        self.messages.setdefault(self.dm_conv_id, [])
        self._refresh_inboxes()

    def create_group(self, creator_uid: int, name: str, members: list[int]) -> None:
        all_members = [creator_uid] + [m for m in members if m != creator_uid]
        self.created_groups.append((creator_uid, name, list(members)))
        self.groups[self.group_conv_id] = {
            "conversation_id": self.group_conv_id,
            "name": name,
            "creator_id": creator_uid,
            "members": all_members,
        }
        self.conv_members[self.group_conv_id] = all_members
        self.messages.setdefault(self.group_conv_id, [])
        self._refresh_inboxes()

    def send(self, uid: int, conv_id: int, body: str) -> None:
        self.sent_messages.append((uid, conv_id, body))
        msg_id = self.next_msg_id
        self.next_msg_id += 1
        msg = {
            "id": msg_id,
            "sender_id": uid,
            "body": body,
            "time": f"2026-05-22 12:{msg_id:02d}:00",
            "pinned": False,
            "reactions": [],
        }
        self.messages.setdefault(conv_id, []).append(msg)
        for member_uid in self.conv_members.get(conv_id, []):
            self.pages[member_uid].add_msg(
                conv_id,
                uid,
                body,
                f"12:{msg_id:02d}",
                msg_id=msg_id,
            )
        self._refresh_inboxes()

    def load_history(self, uid: int, conv_id: int) -> None:
        self.pages[uid].load_history(conv_id, list(self.messages.get(conv_id, [])))

    def _refresh_requests(self, uid: int) -> None:
        self.pages[uid].update_requests([
            {"user_id": requester, "username": self.users[requester]["username"]}
            for requester in self.requests[uid]
        ])

    def _refresh_friends(self, uid: int) -> None:
        friends = []
        for pair in self.friendships:
            if uid in pair:
                peer_uid = next(iter(pair - {uid}))
                friends.append(dict(self.users[peer_uid]))
        self.pages[uid].update_friends(sorted(friends, key=lambda f: f["username"]))

    def _refresh_inboxes(self) -> None:
        for uid, page in self.pages.items():
            dm_convs = []
            if self.dm_started and uid in self.conv_members.get(self.dm_conv_id, []):
                peer_uid = next(m for m in self.conv_members[self.dm_conv_id] if m != uid)
                last = self.messages.get(self.dm_conv_id, [])[-1]["body"] if self.messages.get(self.dm_conv_id) else ""
                dm_convs.append({
                    "conversation_id": self.dm_conv_id,
                    "username": self.users[peer_uid]["username"],
                    "status": self.users[peer_uid]["status"],
                    "with_user_id": peer_uid,
                    "last_message": last,
                })

            group_convs = []
            for group in self.groups.values():
                if uid not in group["members"]:
                    continue
                conv_id = int(group["conversation_id"])
                last = self.messages.get(conv_id, [])[-1]["body"] if self.messages.get(conv_id) else ""
                group_convs.append({
                    "conversation_id": conv_id,
                    "name": group["name"],
                    "creator_id": group["creator_id"],
                    "last_message": last,
                })
            page.update_inbox(dm_convs, group_convs)


class ClientUiTwoUserFlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.qt = _app()

    def setUp(self) -> None:
        self.alice = ChatPage()
        self.bob = ChatPage()
        for page in (self.alice, self.bob):
            page.resize(1000, 700)
        self.qt.processEvents()
        self.server = UiFlowServer(self.alice, self.bob)
        _pump()

    def tearDown(self) -> None:
        for page in (self.alice, self.bob):
            if page is not None and not sip.isdeleted(page):
                page.close()
                sip.delete(page)

    def test_two_users_friend_dm_and_group_messages_through_ui(self) -> None:
        _click(self.alice.btn_search)
        _key_text(self.alice.e_search, "bob")
        _click(_button(self.alice, "Go"))
        self.assertEqual(self.server.searches[-1], (1, "bob"))
        self.assertEqual(self.alice.search_results.count(), 1)

        search_item = self.alice.search_results.item(0)
        search_pos = self.alice.search_results.visualItemRect(search_item).center()
        with _auto_information(), _choose_menu_action("Send Friend Request"):
            self.alice._search_context_menu(search_pos)
        _pump()
        self.assertEqual(self.server.friend_requests, [(1, 2)])
        self.assertIn("Requests", self.bob.btn_requests.text())
        self.assertEqual(self.bob.request_list.count(), 1)

        _click(self.bob.btn_requests)
        request_widget = self.bob.request_list.itemWidget(self.bob.request_list.item(0))
        _click(_button(request_widget, "Accept"))
        self.assertEqual(self.server.accepts, [(2, 1)])
        self.assertEqual(self.alice.friend_list.count(), 1)
        self.assertEqual(self.bob.friend_list.count(), 1)
        self.assertIn("bob@example.test", _sidebar_text(self.alice.friend_list.item(0)))
        self.assertIn("alice@example.test", _sidebar_text(self.bob.friend_list.item(0)))

        friend_item = self.alice.friend_list.item(0)
        friend_pos = self.alice.friend_list.visualItemRect(friend_item).center()
        with _choose_menu_action("Start Conversation"):
            self.alice._friend_context_menu(friend_pos)
        _pump()
        self.assertEqual(self.server.started_dms, [(1, 2)])
        self.assertEqual(self.alice.dm_list.count(), 1)
        self.assertEqual(self.bob.dm_list.count(), 1)

        _click_list_row(self.alice.dm_list, 0)
        self.assertEqual(self.alice.active_conv_id, self.server.dm_conv_id)
        _key_text(self.alice.inp, "hello bob from ui dm")
        _click(self.alice._btn_send)
        self.assertIn((1, self.server.dm_conv_id, "hello bob from ui dm"), self.server.sent_messages)

        _click_list_row(self.bob.dm_list, 0)
        self.assertIn("hello bob from ui dm", _labels(self.bob))
        self.assertEqual(self.bob.lbl_chat.text(), "alice@example.test")
        _key_text(self.bob.inp, "hi alice from ui dm")
        _click(self.bob._btn_send)
        self.assertIn((2, self.server.dm_conv_id, "hi alice from ui dm"), self.server.sent_messages)
        self.assertIn("hi alice from ui dm", _labels(self.alice))

        original_exec = QDialog.exec_

        def create_group_exec(dlg) -> int:
            _line_by_placeholder(dlg, "Enter group name...").setText("ui group room")
            for cb in dlg.findChildren(QCheckBox):
                if cb.text() == "bob@example.test":
                    cb.setChecked(True)
            box = dlg.findChild(QDialogButtonBox)
            self.assertIsNotNone(box)
            box.button(QDialogButtonBox.Ok).click()
            return QDialog.Accepted

        try:
            QDialog.exec_ = create_group_exec
            _click(_button(self.alice, "+ New Group"))
        finally:
            QDialog.exec_ = original_exec
        self.assertEqual(self.server.created_groups, [(1, "ui group room", [2])])
        self.assertEqual(self.alice.group_list.count(), 1)
        self.assertEqual(self.bob.group_list.count(), 1)
        self.assertIn("ui group room", _sidebar_text(self.alice.group_list.item(0)))
        self.assertIn("ui group room", _sidebar_text(self.bob.group_list.item(0)))

        _click_list_row(self.alice.group_list, 0)
        self.assertEqual(self.alice.active_conv_id, self.server.group_conv_id)
        _key_text(self.alice.inp, "hello group from alice ui")
        _click(self.alice._btn_send)
        self.assertIn((1, self.server.group_conv_id, "hello group from alice ui"), self.server.sent_messages)

        _click_list_row(self.bob.group_list, 0)
        self.assertEqual(self.bob.lbl_chat.text(), "[G] ui group room")
        self.assertIn("hello group from alice ui", _labels(self.bob))
        _key_text(self.bob.inp, "group reply from bob ui")
        _click(self.bob._btn_send)
        self.assertIn((2, self.server.group_conv_id, "group reply from bob ui"), self.server.sent_messages)
        self.assertIn("group reply from bob ui", _labels(self.alice))

        self.assertTrue(self.alice.inp.isEnabled())
        self.assertTrue(self.bob.inp.isEnabled())
        self.assertIsNotNone(self.alice.view.row_for_msg(4))
        self.assertIsNotNone(self.bob.view.row_for_msg(3))


if __name__ == "__main__":
    unittest.main(verbosity=2)
