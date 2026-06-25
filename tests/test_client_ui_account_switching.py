#!/usr/bin/env python3
"""App-level UI tests for same-window account switching.

These tests drive the real LoginPage and ChatPage widgets, then inject server
events through a fake WebSocket signal.  They are intentionally above pure API
tests: the assertions look at the visible chat UI after login, logout, inbox,
live message and history events.
"""

from __future__ import annotations

import base64
import os
import random
import sys
import tempfile
import unittest
from contextlib import contextmanager
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from PyQt5 import sip  # noqa: E402
from PyQt5.QtCore import Qt  # noqa: E402
from PyQt5.QtTest import QTest  # noqa: E402
from PyQt5.QtWidgets import (  # noqa: E402
    QApplication,
    QFileDialog,
    QInputDialog,
    QLabel,
    QMessageBox,
    QPushButton,
)

from client.app import App  # noqa: E402
from client.pages.chat_page import ChatPage  # noqa: E402
from client.crypto_engine.audit import same_identity_key  # noqa: E402
from client.crypto_engine.session import CryptoSession  # noqa: E402
from client.crypto_engine.secure_protocol import pqxdh_initiate  # noqa: E402


def _sidebar_text(item) -> str:
    return ChatPage.sidebar_item_text(item)


class _Signal:
    def __init__(self) -> None:
        self._callbacks = []

    def connect(self, callback) -> None:
        self._callbacks.append(callback)

    def disconnect(self, callback=None) -> None:
        if callback is None:
            self._callbacks.clear()
            return
        self._callbacks = [cb for cb in self._callbacks if cb != callback]

    def emit(self, *args, **kwargs) -> None:
        for callback in list(self._callbacks):
            callback(*args, **kwargs)


class _FakeWS:
    def __init__(self) -> None:
        self.on_open = _Signal()
        self.on_close = _Signal()
        self.on_msg = _Signal()
        self.sent: list[dict] = []
        self.connects: list[tuple[str, int]] = []
        self.disconnected = False

    def connect_async(self, host: str, port: int) -> None:
        self.connects.append((host, int(port)))

    def send(self, obj: dict) -> None:
        self.sent.append(dict(obj))

    def disconnect(self) -> None:
        self.disconnected = True


def _qt() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _pump() -> None:
    app = _qt()
    app.processEvents()
    app.processEvents()


def _button(parent, text: str) -> QPushButton:
    for btn in parent.findChildren(QPushButton):
        if btn.text() == text:
            return btn
    raise AssertionError(f"button not found: {text}")


def _click(widget) -> None:
    if hasattr(widget, "click"):
        widget.click()
    else:
        QTest.mouseClick(widget, Qt.LeftButton)
    _pump()


def _click_list_row(list_widget, row: int) -> None:
    item = list_widget.item(row)
    if item is None:
        raise AssertionError(f"list row not found: {row}")
    list_widget.setCurrentItem(item)
    list_widget.itemClicked.emit(item)
    _pump()


def _labels(parent) -> list[str]:
    return [label.text() for label in parent.findChildren(QLabel)]


def _assert_labels_in_order(case: unittest.TestCase, parent, *texts: str) -> str:
    joined = "\n".join(_labels(parent))
    pos = -1
    for text in texts:
        idx = joined.find(text)
        case.assertGreaterEqual(idx, 0, joined)
        case.assertGreater(idx, pos, joined)
        pos = idx
    return joined


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


def _last_sent(ws: _FakeWS, msg_type: str) -> dict:
    for item in reversed(ws.sent):
        if item.get("type") == msg_type:
            return item
    raise AssertionError(f"sent message not found: {msg_type}")


def _sent_count(ws: _FakeWS, msg_type: str) -> int:
    return sum(1 for item in ws.sent if item.get("type") == msg_type)


def _bundle_response(upload: dict, user_id: int, identity_version: int = 0) -> dict:
    curve_otk = (upload.get("curve_one_time_prekeys") or [{}])[0]
    pq_otk = (upload.get("pq_one_time_prekeys") or [{}])[0]
    return {
        "type": "pqxdh_bundle",
        "user_id": int(user_id),
        "version": 2,
        "identity_version": int(identity_version),
        "identity_pk": upload["identity_pk"],
        "curve_spk_id": upload["curve_spk_id"],
        "curve_spk": upload["curve_spk"],
        "curve_spk_sig": upload["curve_spk_sig"],
        "pq_spk_id": upload["pq_spk_id"],
        "pq_kem_alg": upload["pq_kem_alg"],
        "pq_spk": upload["pq_spk"],
        "pq_spk_sig": upload["pq_spk_sig"],
        "curve_otk_id": int(curve_otk.get("key_id", -1) or -1),
        "curve_otk": curve_otk.get("public_key", "") or "",
        "curve_otk_sig": curve_otk.get("signature", "") or "",
        "pq_otk_id": int(pq_otk.get("key_id", -1) or -1),
        "pq_otk_alg": pq_otk.get("alg", upload["pq_kem_alg"]) or upload["pq_kem_alg"],
        "pq_otk": pq_otk.get("public_key", "") or "",
        "pq_otk_sig": pq_otk.get("signature", "") or "",
        "curve_pool_size": len(upload.get("curve_one_time_prekeys") or []),
        "pq_pool_size": len(upload.get("pq_one_time_prekeys") or []),
    }


class AppAccountSwitchingUiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.qt = _qt()

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_vnc2 = tempfile.TemporaryDirectory()
        self.active_home = self.tmp.name
        self.created_ws: list[_FakeWS] = []
        self.extra_windows: list[App] = []

        def fake_setup_ws(app_obj: App) -> None:
            ws = _FakeWS()
            self.created_ws.append(ws)
            app_obj._ws = ws
            ws.on_open.connect(app_obj._net_open)
            ws.on_close.connect(app_obj._net_close)
            ws.on_msg.connect(app_obj._net_msg)

        real_expanduser = os.path.expanduser

        def fake_expanduser(path: str) -> str:
            if path == "~":
                return self.active_home
            if path.startswith("~/") or path.startswith("~\\"):
                return os.path.join(self.active_home, path[2:])
            return real_expanduser(path)

        self.setup_patch = patch.object(App, "_setup_ws", fake_setup_ws)
        self.home_patch = patch("client.app.os.path.expanduser", side_effect=fake_expanduser)
        self.setup_patch.start()
        self.home_patch.start()
        self.window = App()
        _pump()

    def tearDown(self) -> None:
        for win in [getattr(self, "window", None), *getattr(self, "extra_windows", [])]:
            if win is None or sip.isdeleted(win):
                continue
            try:
                win._poll_timer.stop()
                win._inbox_refresh.stop()
                win._key_rot_timer.stop()
                win._teardown_ws()
            except Exception:
                pass
            sip.delete(win)
        self.setup_patch.stop()
        self.home_patch.stop()
        self.tmp.cleanup()
        self.tmp_vnc2.cleanup()

    def _new_window(self, *, home: str) -> App:
        old_home = self.active_home
        self.active_home = home
        try:
            win = App()
            self.extra_windows.append(win)
            _pump()
            return win
        finally:
            self.active_home = old_home

    def _login_as(self, *, email: str, username: str, uid: int,
                  password: str = "123456") -> _FakeWS:
        return self._login_window(
            self.window, email=email, username=username, uid=uid,
            password=password, home=self.tmp.name)

    def _login_window(self, window: App, *, email: str, username: str, uid: int,
                      password: str = "123456", home: str | None = None) -> _FakeWS:
        login = window._login
        old_home = self.active_home
        if home is not None:
            self.active_home = home
        try:
            window._stack.setCurrentIndex(0)
            login.e_host.setText("localhost")
            login.e_port.setText("8888")
            login.e_email.setText(email)
            login.e_pw.setText(password)
            _click(_button(login, "Log in"))
            ws = self.created_ws[-1]
            self.assertEqual(ws.connects[-1], ("localhost", 8888))
            ws.on_open.emit()
            _pump()
            self.assertEqual(ws.sent[0]["type"], "auth")
            self.assertEqual(ws.sent[0]["email"], email)

            ws.on_msg.emit({"type": "ok", "username": username, "user_id": uid})
            _pump()
            self.assertEqual(window._stack.currentIndex(), 1)
            self.assertEqual(window._chat.lbl_me.text(), username)
            self.assertEqual(window._my_uid, uid)
            self.assertTrue(window._secchat_dir.endswith(
                os.path.join(".secchat", username)))
            return ws
        finally:
            if home is not None:
                self.active_home = old_home

    def _logout_by_ui(self) -> None:
        self._logout_window(self.window)

    def _logout_window(self, window: App) -> None:
        _click(_button(window._chat, "Exit"))
        self.assertEqual(window._stack.currentIndex(), 0)
        self.assertEqual(window._chat.lbl_chat.text(), "Select a conversation")
        self.assertEqual(window._chat.active_conv_id, 0)

    def test_register_auto_logs_in_on_same_socket(self) -> None:
        register = self.window._register
        self.window._stack.setCurrentIndex(2)
        register.e_host.setText("localhost")
        register.e_port.setText("8888")
        register.e_user.setText("alice")
        register.e_email.setText("alice@example.test")
        register.e_pw.setText("123456")
        register.e_pw2.setText("123456")

        _click(_button(register, "Register"))
        ws = self.created_ws[-1]
        self.assertEqual(ws.connects[-1], ("localhost", 8888))
        ws.on_open.emit()
        _pump()
        self.assertEqual(ws.sent[0]["type"], "register")
        self.assertEqual(ws.sent[0]["email"], "alice@example.test")

        ws.on_msg.emit({"type": "ok", "msg": "Registration successful"})
        _pump()
        self.assertEqual(self.window._stack.currentIndex(), 2)
        self.assertEqual(ws.sent[1]["type"], "auth")
        self.assertEqual(ws.sent[1]["email"], "alice@example.test")
        self.assertEqual(ws.sent[1]["password"], ws.sent[0]["password"])
        self.assertEqual(
            register.lbl_status.text(),
            "Registration successful. Logging in...",
        )

        ws.on_msg.emit({"type": "ok", "username": "alice", "user_id": 11})
        _pump()
        self.assertEqual(self.window._stack.currentIndex(), 1)
        self.assertEqual(self.window._chat.lbl_me.text(), "alice")
        self.assertEqual(self.window._my_uid, 11)
        self.assertEqual(self.window._last_auth_email, "alice@example.test")
        self.assertEqual(self.window._last_auth_pw_hash, ws.sent[0]["password"])

    def _emit_dm_inbox(self, ws: _FakeWS, *, conv_id: int, peer_uid: int,
                       peer_name: str, wire: str = "S3DR:wire",
                       last_id: int = 1, unread_count: int = 0) -> None:
        ws.on_msg.emit({
            "type": "inbox",
            "conversations": [{
                "conversation_id": conv_id,
                "is_group": False,
                "username": peer_name,
                "with_user_id": peer_uid,
                "status": "online",
                "last_message": wire,
                "last_message_id": last_id,
                "last_sender_id": peer_uid,
                "unread_count": unread_count,
            }],
        })
        _pump()

    def _emit_group_inbox(self, ws: _FakeWS, *, conv_id: int, name: str,
                          wire: str = "S3MLS:wire", last_id: int = 1,
                          unread_count: int = 0) -> None:
        ws.on_msg.emit({
            "type": "inbox",
            "conversations": [{
                "conversation_id": conv_id,
                "is_group": True,
                "name": name,
                "creator_id": 123,
                "last_message": wire,
                "last_message_id": last_id,
                "last_sender_id": 123,
                "unread_count": unread_count,
            }],
        })
        _pump()

    def _emit_history(self, ws: _FakeWS, *, conv_id: int,
                      rows: list[dict]) -> None:
        ws.on_msg.emit({
            "type": "history",
            "conversation_id": conv_id,
            "messages": rows,
        })
        _pump()

    def _peer_upload(self, uid: int) -> tuple[CryptoSession, dict, tempfile.TemporaryDirectory]:
        tmp = tempfile.TemporaryDirectory()
        peer = CryptoSession(
            master_key=os.urandom(32),
            secchat_dir=tmp.name,
            my_uid=int(uid),
        )
        peer.load_or_create_identity_key()
        upload = peer.fresh_pqxdh_bundle_command()
        self.assertTrue(upload)
        return peer, upload, tmp

    def test_same_vnc_account_switch_keeps_cache_separate_and_merges_offline_history(self) -> None:
        conv_id = 77
        wire = "S3DR:cached-wire"

        ws123 = self._login_as(email="123@gmail.com", username="user123", uid=123)
        dir123 = self.window._secchat_dir
        self.window._cache_message(conv_id, 1, 234, "user123 old cached message", "10:00")
        self._emit_dm_inbox(
            ws123, conv_id=conv_id, peer_uid=234, peer_name="user234", wire=wire)
        self.assertIn(
            "user123 old cached message",
            _sidebar_text(self.window._chat.dm_list.item(0)),
        )
        _click_list_row(self.window._chat.dm_list, 0)
        self._emit_history(ws123, conv_id=conv_id, rows=[{
            "id": 1,
            "sender_id": 234,
            "body": wire,
            "time": "2026-05-30 10:00:00",
        }])
        self.assertIn("user123 old cached message", _labels(self.window._chat.view))

        self._logout_by_ui()
        ws123.on_msg.emit({
            "type": "message",
            "conversation_id": conv_id,
            "from_id": 234,
            "id": 99,
            "body": "stale event from user123 socket",
            "time": "2026-05-30 10:01:00",
        })
        _pump()

        ws345 = self._login_as(email="345@gmail.com", username="user345", uid=345)
        self.assertNotEqual(dir123, self.window._secchat_dir)
        self.assertEqual(self.window._chat.dm_list.count(), 0)
        self.assertNotIn("user123 old cached message", _labels(self.window._chat))
        self.assertNotIn("stale event from user123 socket", _labels(self.window._chat))

        self.window._cache_message(conv_id, 1, 234, "user345 private cached message", "10:00")
        self._emit_dm_inbox(
            ws345, conv_id=conv_id, peer_uid=234, peer_name="user234", wire=wire)
        _click_list_row(self.window._chat.dm_list, 0)
        self._emit_history(ws345, conv_id=conv_id, rows=[{
            "id": 1,
            "sender_id": 234,
            "body": wire,
            "time": "2026-05-30 10:00:00",
        }])
        labels345 = _labels(self.window._chat.view)
        self.assertIn("user345 private cached message", labels345)
        self.assertNotIn("user123 old cached message", labels345)

        self._logout_by_ui()
        ws123_again = self._login_as(email="123@gmail.com", username="user123", uid=123)
        self._emit_dm_inbox(
            ws123_again, conv_id=conv_id, peer_uid=234, peer_name="user234",
            wire=wire, last_id=2, unread_count=1)
        ws123_again.on_msg.emit({
            "type": "message",
            "conversation_id": conv_id,
            "from_id": 234,
            "id": 2,
            "body": "offline message while user123 was logged out",
            "time": "2026-05-30 10:02:00",
        })
        _pump()
        _click_list_row(self.window._chat.dm_list, 0)
        self.assertTrue(any(
            obj.get("type") == "history" and obj.get("conversation_id") == conv_id
            for obj in ws123_again.sent
        ))
        self._emit_history(ws123_again, conv_id=conv_id, rows=[
            {
                "id": 1,
                "sender_id": 234,
                "body": wire,
                "time": "2026-05-30 10:00:00",
            },
            {
                "id": 2,
                "sender_id": 234,
                "body": "offline message while user123 was logged out",
                "time": "2026-05-30 10:02:00",
            },
        ])
        labels123 = _labels(self.window._chat.view)
        self.assertIn("user123 old cached message", labels123)
        self.assertIn("offline message while user123 was logged out", labels123)
        self.assertNotIn("user345 private cached message", labels123)

    def test_two_vnc_random_account_switching_hides_unreadable_history_and_resets_badges(self) -> None:
        rng = random.Random(345)
        group_conv = 900
        dm_conv = 901
        group_wires = [f"S3MLS:opaque-group-{i}" for i in range(1, 5)]
        dm_wires = [f"S3DR:opaque-dm-{i}" for i in range(1, 4)]
        chosen_accounts = rng.sample([
            ("123@gmail.com", "user123", 123),
            ("345@gmail.com", "user345", 345),
            ("456@gmail.com", "user456", 456),
        ], 3)
        self.assertEqual({a[1] for a in chosen_accounts}, {"user123", "user345", "user456"})

        ws123 = self._login_window(
            self.window, email="123@gmail.com", username="user123", uid=123,
            home=self.tmp.name)
        self.window._cache_message(group_conv, 1, 234, "user123 cached group old", "10:00")
        self.window._cache_message(dm_conv, 10, 234, "user123 cached dm old", "10:01")
        self._emit_group_inbox(
            ws123, conv_id=group_conv, name="team", wire=group_wires[0],
            last_id=1)
        _click_list_row(self.window._chat.group_list, 0)
        self._emit_history(ws123, conv_id=group_conv, rows=[{
            "id": 1, "sender_id": 234, "body": group_wires[0],
            "time": "2026-05-30 10:00:00",
        }])
        self.assertIn("user123 cached group old", _labels(self.window._chat.view))

        ws123.on_msg.emit({
            "type": "friend_request_received",
            "from": "user456",
            "from_id": 456,
        })
        ws123.on_msg.emit({
            "type": "friend_requests",
            "requests": [{"user_id": 456, "username": "user456"}],
        })
        _pump()
        self.assertEqual(self.window._chat.btn_requests.text(), "Requests (1)")
        self._logout_window(self.window)

        ws345_same = self._login_window(
            self.window, email="345@gmail.com", username="user345", uid=345,
            home=self.tmp.name)
        self.assertEqual(self.window._chat.btn_requests.text(), "Requests")
        self._emit_group_inbox(
            ws345_same, conv_id=group_conv, name="team", wire=group_wires[0],
            last_id=1, unread_count=1)
        self.assertIn("[unread]", _sidebar_text(self.window._chat.group_list.item(0)))
        _click_list_row(self.window._chat.group_list, 0)
        self._emit_history(ws345_same, conv_id=group_conv, rows=[{
            "id": 1, "sender_id": 234, "body": group_wires[0],
            "time": "2026-05-30 10:00:00",
        }])
        joined = "\n".join(_labels(self.window._chat.view))
        self.assertNotIn("Forward-secret", joined)
        self.assertNotIn("MLS state unavailable", joined)
        self.assertFalse(self.window._chat._visible_message_ids(group_conv))

        self.window._cache_message(group_conv, 2, 123, "user345 same-vnc group new", "10:02")
        self._emit_history(ws345_same, conv_id=group_conv, rows=[
            {"id": 1, "sender_id": 234, "body": group_wires[0],
             "time": "2026-05-30 10:00:00"},
            {"id": 2, "sender_id": 123, "body": group_wires[1],
             "time": "2026-05-30 10:02:00"},
        ])
        self.assertIn("user345 same-vnc group new", _labels(self.window._chat.view))
        self._logout_window(self.window)

        ws123_again = self._login_window(
            self.window, email="123@gmail.com", username="user123", uid=123,
            home=self.tmp.name)
        self._emit_group_inbox(
            ws123_again, conv_id=group_conv, name="team", wire=group_wires[1],
            last_id=2, unread_count=0)
        self.assertNotIn("[unread]", _sidebar_text(self.window._chat.group_list.item(0)))
        _click_list_row(self.window._chat.group_list, 0)
        self._emit_history(ws123_again, conv_id=group_conv, rows=[
            {"id": 1, "sender_id": 234, "body": group_wires[0],
             "time": "2026-05-30 10:00:00"},
            {"id": 2, "sender_id": 123, "body": group_wires[1],
             "time": "2026-05-30 10:02:00"},
        ])
        labels123 = _labels(self.window._chat.view)
        self.assertIn("user123 cached group old", labels123)
        self.assertNotIn("user345 same-vnc group new", labels123)

        vnc2 = self._new_window(home=self.tmp_vnc2.name)
        ws345_other = self._login_window(
            vnc2, email="345@gmail.com", username="user345", uid=345,
            home=self.tmp_vnc2.name)
        self._emit_group_inbox(
            ws345_other, conv_id=group_conv, name="team", wire=group_wires[1],
            last_id=2)
        _click_list_row(vnc2._chat.group_list, 0)
        self._emit_history(ws345_other, conv_id=group_conv, rows=[{
            "id": 2, "sender_id": 123, "body": group_wires[1],
            "time": "2026-05-30 10:02:00",
        }])
        labels_other_vnc = "\n".join(_labels(vnc2._chat.view))
        self.assertNotIn("user345 same-vnc group new", labels_other_vnc)
        self.assertNotIn("MLS state unavailable", labels_other_vnc)
        self.assertFalse(vnc2._chat._visible_message_ids(group_conv))

        vnc2._cache_message(dm_conv, 11, 234, "user345 other-vnc dm new", "10:03")
        self._emit_dm_inbox(
            ws345_other, conv_id=dm_conv, peer_uid=234, peer_name="user234",
            wire=dm_wires[1], last_id=11)
        _click_list_row(vnc2._chat.dm_list, 0)
        self._emit_history(ws345_other, conv_id=dm_conv, rows=[
            {"id": 10, "sender_id": 234, "body": dm_wires[0],
             "time": "2026-05-30 10:01:00"},
            {"id": 11, "sender_id": 234, "body": dm_wires[1],
             "time": "2026-05-30 10:03:00"},
        ])
        labels_dm_other = _labels(vnc2._chat.view)
        self.assertIn("user345 other-vnc dm new", labels_dm_other)
        self.assertNotIn("user123 cached dm old", labels_dm_other)

    def test_group_conversation_does_not_get_dm_identity_verify_badge(self) -> None:
        ws123 = self._login_window(
            self.window, email="123@gmail.com", username="user123", uid=123,
            home=self.tmp.name)
        self._emit_group_inbox(
            ws123, conv_id=333, name="team", wire="S3MLS:opaque", last_id=1)
        _click_list_row(self.window._chat.group_list, 0)
        self._emit_history(ws123, conv_id=333, rows=[{
            "id": 1,
            "sender_id": 234,
            "body": "S3MLS:opaque",
            "time": "2026-05-31 10:00:00",
        }])
        item_text = _sidebar_text(self.window._chat.group_list.item(0))
        self.assertNotIn("[verify]", item_text)
        self.assertNotIn("[verified]", item_text)
        header = "\n".join(_labels(self.window._chat))
        self.assertNotIn("Verify safety", header)
        self.assertNotIn("Verified ", header)

    def test_cross_vnc_key_publish_and_new_account_do_not_corrupt_existing_caches(self) -> None:
        conv_id = 740
        wire_one = "S3DR:shared-wire-one"
        wire_two = "S3DR:shared-wire-two"

        ws345_vnc1 = self._login_window(
            self.window, email="345@gmail.com", username="user345", uid=345,
            home=self.tmp.name)
        ws345_vnc1.on_msg.emit({
            "type": "my_keys",
            "found": False,
            "identity_version": 0,
        })
        _pump()
        first_keys = _last_sent(ws345_vnc1, "upload_keys")
        _last_sent(ws345_vnc1, "upload_pqxdh_bundle")
        self.window._cache_message(
            conv_id, 1, 234, "user345 vnc1 cached first", "10:00")
        self.window._cache_message(
            conv_id, 2, 234, "user345 vnc1 cached second", "10:01")
        cache_path_345_vnc1 = self.window._crypto_session().msg_cache_path(conv_id)
        self.assertTrue(os.path.exists(cache_path_345_vnc1))
        self._emit_dm_inbox(
            ws345_vnc1, conv_id=conv_id, peer_uid=234, peer_name="user234",
            wire=wire_two, last_id=2)
        _click_list_row(self.window._chat.dm_list, 0)
        self._emit_history(ws345_vnc1, conv_id=conv_id, rows=[
            {"id": 1, "sender_id": 234, "body": wire_one,
             "time": "2026-05-31 10:00:00"},
            {"id": 2, "sender_id": 234, "body": wire_two,
             "time": "2026-05-31 10:01:00"},
        ])
        _assert_labels_in_order(
            self, self.window._chat.view,
            "user345 vnc1 cached first", "user345 vnc1 cached second")
        self._logout_window(self.window)

        ws123_vnc1 = self._login_window(
            self.window, email="123@gmail.com", username="user123", uid=123,
            home=self.tmp.name)
        self.window._cache_message(
            conv_id, 1, 234, "user123 vnc1 private cache", "10:02")
        cache_path_123_vnc1 = self.window._crypto_session().msg_cache_path(conv_id)
        self.assertTrue(os.path.exists(cache_path_123_vnc1))
        self.assertNotEqual(cache_path_123_vnc1, cache_path_345_vnc1)
        self._logout_window(self.window)

        vnc2 = self._new_window(home=self.tmp_vnc2.name)
        ws345_vnc2 = self._login_window(
            vnc2, email="345@gmail.com", username="user345", uid=345,
            home=self.tmp_vnc2.name)
        ws345_vnc2.on_msg.emit({
            "type": "my_keys",
            "found": True,
            "identity_pk": first_keys["identity_pk"],
            "identity_sig": first_keys["identity_sig"],
            "identity_sk_enc": first_keys["identity_sk_enc"],
            "identity_version": 0,
        })
        _pump()
        second_bundle = _last_sent(ws345_vnc2, "upload_pqxdh_bundle")
        self.assertTrue(same_identity_key(
            second_bundle["identity_pk"], first_keys["identity_pk"]))
        ws345_vnc2.on_msg.emit({"type": "ok", "msg": "PQXDH bundle uploaded"})
        _pump()
        vnc2._cache_message(
            conv_id, 1, 234, "user345 vnc2 active-device cache", "10:03")
        self.assertTrue(os.path.exists(cache_path_345_vnc1))
        self.assertTrue(os.path.exists(cache_path_123_vnc1))

        ws456_vnc1 = self._login_window(
            self.window, email="456@gmail.com", username="user456", uid=456,
            home=self.tmp.name)
        self.window._cache_message(
            conv_id, 1, 234, "user456 same-vnc cache", "10:04")
        self._emit_dm_inbox(
            ws456_vnc1, conv_id=conv_id, peer_uid=234, peer_name="user234",
            wire=wire_one, last_id=1)
        _click_list_row(self.window._chat.dm_list, 0)
        self._emit_history(ws456_vnc1, conv_id=conv_id, rows=[{
            "id": 1, "sender_id": 234, "body": wire_one,
            "time": "2026-05-31 10:04:00",
        }])
        self.assertIn("user456 same-vnc cache", _labels(self.window._chat.view))
        self._logout_window(self.window)

        ws123_again = self._login_window(
            self.window, email="123@gmail.com", username="user123", uid=123,
            home=self.tmp.name)
        self._emit_dm_inbox(
            ws123_again, conv_id=conv_id, peer_uid=234, peer_name="user234",
            wire=wire_one, last_id=1)
        _click_list_row(self.window._chat.dm_list, 0)
        self._emit_history(ws123_again, conv_id=conv_id, rows=[{
            "id": 1, "sender_id": 234, "body": wire_one,
            "time": "2026-05-31 10:02:00",
        }])
        labels123 = "\n".join(_labels(self.window._chat.view))
        self.assertIn("user123 vnc1 private cache", labels123)
        self.assertNotIn("user345 vnc1 cached first", labels123)
        self.assertNotIn("user345 vnc2 active-device cache", labels123)
        self.assertNotIn("user456 same-vnc cache", labels123)
        self.assertEqual(
            self.window._crypto_session().load_cached_messages(conv_id)[1]["body"],
            "user123 vnc1 private cache",
        )
        self._logout_window(self.window)

        ws345_again = self._login_window(
            self.window, email="345@gmail.com", username="user345", uid=345,
            home=self.tmp.name)
        self._emit_dm_inbox(
            ws345_again, conv_id=conv_id, peer_uid=234, peer_name="user234",
            wire=wire_two, last_id=2)
        _click_list_row(self.window._chat.dm_list, 0)
        self._emit_history(ws345_again, conv_id=conv_id, rows=[
            {"id": 1, "sender_id": 234, "body": wire_one,
             "time": "2026-05-31 10:00:00"},
            {"id": 2, "sender_id": 234, "body": wire_two,
             "time": "2026-05-31 10:01:00"},
        ])
        labels345 = _assert_labels_in_order(
            self, self.window._chat.view,
            "user345 vnc1 cached first", "user345 vnc1 cached second")
        self.assertNotIn("user345 vnc2 active-device cache", labels345)
        self.assertNotIn("user123 vnc1 private cache", labels345)
        self.assertNotIn("user456 same-vnc cache", labels345)

    def test_export_restore_cache_preserves_full_history_order_and_account_isolation(self) -> None:
        conv_id = 830
        backup_path = os.path.join(self.tmp.name, "user123-e2ee-backup.json")
        passphrase = "BackupPassphrase123!"
        rows = [
            {"id": 101, "sender_id": 234, "body": "S3DR:restore-wire-101",
             "time": "2026-05-31 11:00:00"},
            {"id": 102, "sender_id": 123, "body": "S3DR:restore-wire-102",
             "time": "2026-05-31 11:01:00"},
            {"id": 103, "sender_id": 234, "body": "S3DR:restore-wire-103",
             "time": "2026-05-31 11:02:00"},
        ]
        fresh_rows = lambda: [dict(row) for row in rows]

        ws345 = self._login_window(
            self.window, email="345@gmail.com", username="user345", uid=345,
            home=self.tmp.name)
        self.window._cache_message(
            conv_id, 101, 234, "wrong account cache must not restore", "10:55")
        self._emit_dm_inbox(
            ws345, conv_id=conv_id, peer_uid=234, peer_name="user234",
            wire=rows[0]["body"], last_id=101)
        _click_list_row(self.window._chat.dm_list, 0)
        self._emit_history(ws345, conv_id=conv_id, rows=[dict(rows[0])])
        self.assertIn(
            "wrong account cache must not restore",
            _labels(self.window._chat.view),
        )
        self._logout_window(self.window)

        ws123 = self._login_window(
            self.window, email="123@gmail.com", username="user123", uid=123,
            home=self.tmp.name)
        self.window._cache_message(
            conv_id, 102, 123, "restore second cached", "11:01")
        self.window._cache_message(
            conv_id, 101, 234, "restore first cached", "11:00")
        self.window._cache_message(
            conv_id, 103, 234, "restore third cached", "11:02")
        cache_before = self.window._crypto_session().load_cached_messages(conv_id)
        self.assertEqual(cache_before[101]["body"], "restore first cached")
        self.assertEqual(cache_before[102]["body"], "restore second cached")
        self.assertEqual(cache_before[103]["body"], "restore third cached")

        with (
            patch.object(QFileDialog, "getSaveFileName",
                         return_value=(backup_path, "")),
            patch.object(QMessageBox, "question",
                         return_value=QMessageBox.Yes),
            patch.object(QInputDialog, "getText",
                         return_value=(passphrase, True)),
            patch.object(QMessageBox, "information",
                         return_value=QMessageBox.Ok),
        ):
            self.window._export_e2ee_backup()
        self.assertTrue(os.path.exists(backup_path))
        info = self.window._crypto_session().inspect_e2ee_backup(backup_path)
        self.assertEqual(info["account_username"], "user123")
        self.assertTrue(info["include_cache"])
        self._logout_window(self.window)

        vnc2 = self._new_window(home=self.tmp_vnc2.name)
        ws123_vnc2 = self._login_window(
            vnc2, email="123@gmail.com", username="user123", uid=123,
            home=self.tmp_vnc2.name)
        self._emit_dm_inbox(
            ws123_vnc2, conv_id=conv_id, peer_uid=234, peer_name="user234",
            wire=rows[-1]["body"], last_id=103)
        _click_list_row(vnc2._chat.dm_list, 0)
        self._emit_history(ws123_vnc2, conv_id=conv_id, rows=fresh_rows())
        before_restore = "\n".join(_labels(vnc2._chat.view))
        self.assertNotIn("restore first cached", before_restore)
        self.assertNotIn("wrong account cache must not restore", before_restore)
        self.assertNotIn("[Forward-secret]", before_restore)
        self.assertFalse(vnc2._chat._visible_message_ids(conv_id))

        with (
            patch.object(QFileDialog, "getOpenFileName",
                         return_value=(backup_path, "")),
            patch.object(QMessageBox, "question",
                         return_value=QMessageBox.Yes),
            patch.object(QInputDialog, "getText",
                         return_value=(passphrase, True)),
            patch.object(QMessageBox, "information",
                         return_value=QMessageBox.Ok),
        ):
            vnc2._restore_e2ee_backup()
        self.assertTrue(vnc2._pending_pqxdh_bundle_upload)
        self.assertEqual(
            _last_sent(ws123_vnc2, "upload_pqxdh_bundle")["type"],
            "upload_pqxdh_bundle",
        )

        self._emit_dm_inbox(
            ws123_vnc2, conv_id=conv_id, peer_uid=234, peer_name="user234",
            wire=rows[-1]["body"], last_id=103)
        _click_list_row(vnc2._chat.dm_list, 0)
        self._emit_history(ws123_vnc2, conv_id=conv_id, rows=fresh_rows())
        restored_labels = _assert_labels_in_order(
            self, vnc2._chat.view,
            "restore first cached", "restore second cached", "restore third cached")
        self.assertNotIn("wrong account cache must not restore", restored_labels)
        self.assertNotIn("[Forward-secret]", restored_labels)
        self.assertNotIn("MLS state unavailable", restored_labels)
        cache_after = vnc2._crypto_session().load_cached_messages(conv_id)
        self.assertEqual(cache_after[101]["body"], "restore first cached")
        self.assertEqual(cache_after[102]["body"], "restore second cached")
        self.assertEqual(cache_after[103]["body"], "restore third cached")

    def test_restore_e2ee_on_new_vnc_recovers_old_chat_without_affecting_peer(self) -> None:
        conv_id = 930
        backup_path = os.path.join(self.tmp_vnc2.name, "user234-e2ee-backup.json")
        passphrase = "BackupPassphrase123!"
        rows = [
            {"id": 301, "sender_id": 123, "body": "S3DR:move-wire-301",
             "time": "2026-05-31 12:00:00"},
            {"id": 302, "sender_id": 234, "body": "S3DR:move-wire-302",
             "time": "2026-05-31 12:01:00"},
        ]
        fresh_rows = lambda: [dict(row) for row in rows]

        ws123 = self._login_window(
            self.window, email="123@gmail.com", username="user123", uid=123,
            home=self.tmp.name)
        self.window._cache_message(
            conv_id, 301, 123, "peer old first remains", "12:00")
        self.window._cache_message(
            conv_id, 302, 234, "peer old second remains", "12:01")
        peer_cache_path = self.window._crypto_session().msg_cache_path(conv_id)
        self.assertTrue(os.path.exists(peer_cache_path))
        self._emit_dm_inbox(
            ws123, conv_id=conv_id, peer_uid=234, peer_name="user234",
            wire=rows[-1]["body"], last_id=302)
        _click_list_row(self.window._chat.dm_list, 0)
        self._emit_history(ws123, conv_id=conv_id, rows=fresh_rows())
        _assert_labels_in_order(
            self, self.window._chat.view,
            "peer old first remains", "peer old second remains")
        self._logout_window(self.window)

        old_vnc = self._new_window(home=self.tmp_vnc2.name)
        ws234_old = self._login_window(
            old_vnc, email="234@gmail.com", username="user234", uid=234,
            home=self.tmp_vnc2.name)
        ws234_old.on_msg.emit({
            "type": "my_keys",
            "found": False,
            "identity_version": 0,
        })
        _pump()
        old_keys = _last_sent(ws234_old, "upload_keys")
        _last_sent(ws234_old, "upload_pqxdh_bundle")
        ws234_old.on_msg.emit({"type": "ok", "msg": "PQXDH bundle uploaded"})
        _pump()
        self.assertTrue(old_keys.get("identity_sk_enc"))
        old_vnc._cache_message(
            conv_id, 301, 123, "moved account old first", "12:00")
        old_vnc._cache_message(
            conv_id, 302, 234, "moved account old second", "12:01")
        with (
            patch.object(QFileDialog, "getSaveFileName",
                         return_value=(backup_path, "")),
            patch.object(QMessageBox, "question",
                         return_value=QMessageBox.Yes),
            patch.object(QInputDialog, "getText",
                         return_value=(passphrase, True)),
            patch.object(QMessageBox, "information",
                         return_value=QMessageBox.Ok),
        ):
            old_vnc._export_e2ee_backup()
        self.assertTrue(os.path.exists(backup_path))

        ws234_new = self._login_window(
            self.window, email="234@gmail.com", username="user234", uid=234,
            home=self.tmp.name)
        ws234_new.on_msg.emit({
            "type": "my_keys",
            "found": True,
            "identity_pk": old_keys["identity_pk"],
            "identity_sig": old_keys["identity_sig"],
            "identity_sk_enc": "",
            "identity_version": 0,
        })
        _pump()
        self.assertTrue(self.window._pqxdh_publish_blocked)
        self._emit_dm_inbox(
            ws234_new, conv_id=conv_id, peer_uid=123, peer_name="user123",
            wire=rows[-1]["body"], last_id=302)
        _click_list_row(self.window._chat.dm_list, 0)
        self._emit_history(ws234_new, conv_id=conv_id, rows=fresh_rows())
        before_restore = "\n".join(_labels(self.window._chat.view))
        self.assertNotIn("moved account old first", before_restore)
        self.assertNotIn("peer old first remains", before_restore)
        self.assertFalse(self.window._chat._visible_message_ids(conv_id))
        self.window._chat.inp.setPlainText("blocked before restore")
        with patch.object(QMessageBox, "warning", return_value=QMessageBox.Ok):
            _click(self.window._chat._btn_send)
        self.assertFalse(any(
            msg.get("type") == "rotate_identity" for msg in ws234_new.sent))

        with (
            patch.object(QFileDialog, "getOpenFileName",
                         return_value=(backup_path, "")),
            patch.object(QMessageBox, "question",
                         return_value=QMessageBox.Yes),
            patch.object(QInputDialog, "getText",
                         return_value=(passphrase, True)),
            patch.object(QMessageBox, "information",
                         return_value=QMessageBox.Ok),
        ):
            self.window._restore_e2ee_backup()
        restored_upload = _last_sent(ws234_new, "upload_keys")
        restored_bundle = _last_sent(ws234_new, "upload_pqxdh_bundle")
        self.assertEqual(restored_upload["identity_pk"], old_keys["identity_pk"])
        self.assertTrue(restored_upload.get("identity_sk_enc"))
        self.assertTrue(same_identity_key(
            restored_bundle["identity_pk"], old_keys["identity_pk"]))
        self.assertFalse(self.window._pqxdh_publish_blocked)
        self.assertTrue(self.window._pending_pqxdh_bundle_upload)
        self.assertFalse(any(
            msg.get("type") == "rotate_identity" for msg in ws234_new.sent))

        self._emit_history(ws234_new, conv_id=conv_id, rows=fresh_rows())
        restored_labels = _assert_labels_in_order(
            self, self.window._chat.view,
            "moved account old first", "moved account old second")
        self.assertNotIn("peer old first remains", restored_labels)
        ws234_new.on_msg.emit({"type": "ok", "msg": "PQXDH bundle uploaded"})
        _pump()
        ws234_new.on_msg.emit({
            "type": "dm_ready",
            "conversation_id": conv_id,
            "with_user_id": 123,
        })
        _pump()
        self.assertEqual(_last_sent(ws234_new, "get_pqxdh_bundle")["user_id"], 123)
        peer123, peer_upload, peer_tmp = self._peer_upload(123)
        self.addCleanup(peer_tmp.cleanup)
        ws234_new.on_msg.emit(_bundle_response(peer_upload, 123))
        _pump()
        self.assertTrue(_last_sent(ws234_new, "message")["body"].startswith("S3PQI:"))
        self.window._chat.inp.setPlainText("new segment after restore")
        _click(self.window._chat._btn_send)
        new_wire = _last_sent(ws234_new, "message")
        self.assertEqual(new_wire["conversation_id"], conv_id)
        self.assertTrue(new_wire["body"].startswith("S3DR:"))

        self._logout_window(self.window)
        ws123_again = self._login_window(
            self.window, email="123@gmail.com", username="user123", uid=123,
            home=self.tmp.name)
        self.assertTrue(os.path.exists(peer_cache_path))
        self._emit_dm_inbox(
            ws123_again, conv_id=conv_id, peer_uid=234, peer_name="user234",
            wire=rows[-1]["body"], last_id=302)
        _click_list_row(self.window._chat.dm_list, 0)
        self._emit_history(ws123_again, conv_id=conv_id, rows=fresh_rows())
        peer_labels = _assert_labels_in_order(
            self, self.window._chat.view,
            "peer old first remains", "peer old second remains")
        self.assertNotIn("moved account old first", peer_labels)
        peer_cache = self.window._crypto_session().load_cached_messages(conv_id)
        self.assertEqual(peer_cache[301]["body"], "peer old first remains")
        self.assertEqual(peer_cache[302]["body"], "peer old second remains")

    def test_restore_after_rotate_merges_old_cache_without_identity_rollback(self) -> None:
        conv_id = 940
        backup_path = os.path.join(self.tmp_vnc2.name, "user123-rotated-backup.json")
        passphrase = "BackupPassphrase123!"
        rows = [
            {"id": 1, "sender_id": 234, "body": "S3DR:old-rotated-wire-1",
             "time": "2026-05-31 12:00:00"},
            {"id": 2, "sender_id": 123, "body": "S3DR:old-rotated-wire-2",
             "time": "2026-05-31 12:01:00"},
            {"id": 3, "sender_id": 123, "body": "S3DR:new-rotated-wire-3",
             "time": "2026-05-31 12:02:00"},
        ]

        old_vnc = self._new_window(home=self.tmp_vnc2.name)
        ws_old = self._login_window(
            old_vnc, email="123@gmail.com", username="user123", uid=123,
            home=self.tmp_vnc2.name)
        ws_old.on_msg.emit({
            "type": "my_keys",
            "found": False,
            "identity_version": 0,
        })
        _pump()
        old_keys = _last_sent(ws_old, "upload_keys")
        ws_old.on_msg.emit({"type": "ok", "msg": "PQXDH bundle uploaded"})
        _pump()
        old_vnc._cache_message(
            conv_id, 1, 234, "old cache before rotate one", "12:00")
        old_vnc._cache_message(
            conv_id, 2, 123, "old cache before rotate two", "12:01")
        with (
            patch.object(QFileDialog, "getSaveFileName",
                         return_value=(backup_path, "")),
            patch.object(QMessageBox, "question",
                         return_value=QMessageBox.Yes),
            patch.object(QInputDialog, "getText",
                         return_value=(passphrase, True)),
            patch.object(QMessageBox, "information",
                         return_value=QMessageBox.Ok),
        ):
            old_vnc._export_e2ee_backup()
        self.assertTrue(os.path.exists(backup_path))

        ws_new = self._login_window(
            self.window, email="123@gmail.com", username="user123", uid=123,
            home=self.tmp.name)
        ws_new.on_msg.emit({
            "type": "my_keys",
            "found": True,
            "identity_pk": old_keys["identity_pk"],
            "identity_sig": old_keys["identity_sig"],
            "identity_sk_enc": "",
            "identity_version": 0,
        })
        _pump()
        self.assertTrue(self.window._pqxdh_publish_blocked)

        with (
            patch.object(QMessageBox, "question",
                         return_value=QMessageBox.Yes),
            patch.object(QMessageBox, "information",
                         return_value=QMessageBox.Ok),
        ):
            self.window._rotate_identity()
            rotate_cmd = _last_sent(ws_new, "rotate_identity")
            rotated_identity = rotate_cmd["identity_pk"]
            rotated_bundle = _last_sent(ws_new, "upload_pqxdh_bundle")
            self.assertTrue(same_identity_key(
                rotated_bundle["identity_pk"], rotated_identity))
            self.assertFalse(same_identity_key(
                rotated_identity, old_keys["identity_pk"]))
            ws_new.on_msg.emit({"type": "ok", "msg": "Identity rotated"})
            _pump()
        ws_new.on_msg.emit({"type": "ok", "msg": "PQXDH bundle uploaded"})
        _pump()
        self.assertFalse(self.window._pqxdh_publish_blocked)
        self.window._cache_message(
            conv_id, 3, 123, "new cache after rotate", "12:02")
        get_bundle_before_restore = _sent_count(ws_new, "get_pqxdh_bundle")
        self._emit_dm_inbox(
            ws_new, conv_id=conv_id, peer_uid=234, peer_name="user234",
            wire=rows[-1]["body"], last_id=3)
        _click_list_row(self.window._chat.dm_list, 0)
        self.assertGreater(
            _sent_count(ws_new, "get_pqxdh_bundle"),
            get_bundle_before_restore,
        )
        self.assertEqual(_last_sent(ws_new, "get_pqxdh_bundle")["user_id"], 234)

        upload_count_before = _sent_count(ws_new, "upload_keys")
        bundle_count_before = _sent_count(ws_new, "upload_pqxdh_bundle")
        history_count_before_restore = _sent_count(ws_new, "history")
        with (
            patch.object(QFileDialog, "getOpenFileName",
                         return_value=(backup_path, "")),
            patch.object(QMessageBox, "question",
                         return_value=QMessageBox.Yes),
            patch.object(QInputDialog, "getText",
                         return_value=(passphrase, True)),
            patch.object(QMessageBox, "information",
                         return_value=QMessageBox.Ok),
        ):
            self.window._restore_e2ee_backup()
        self.assertEqual(_sent_count(ws_new, "upload_keys"), upload_count_before)
        self.assertEqual(
            _sent_count(ws_new, "upload_pqxdh_bundle"), bundle_count_before)
        self.assertGreater(_sent_count(ws_new, "history"), history_count_before_restore)
        self.assertEqual(_last_sent(ws_new, "history")["conversation_id"], conv_id)
        self.assertNotIn(conv_id, self.window._chat._history_loaded_convs)
        self.assertTrue(same_identity_key(
            base64.b64encode(self.window._identity_pk).decode(),
            rotated_identity,
        ))
        self.assertFalse(self.window._pqxdh_publish_blocked)

        self._emit_dm_inbox(
            ws_new, conv_id=conv_id, peer_uid=234, peer_name="user234",
            wire=rows[-1]["body"], last_id=3)
        _click_list_row(self.window._chat.dm_list, 0)
        self._emit_history(ws_new, conv_id=conv_id, rows=[dict(r) for r in rows])
        _assert_labels_in_order(
            self, self.window._chat.view,
            "old cache before rotate one",
            "old cache before rotate two",
            "new cache after rotate",
        )
        cache = self.window._crypto_session().load_cached_messages(conv_id)
        self.assertEqual(cache[1]["body"], "old cache before rotate one")
        self.assertEqual(cache[2]["body"], "old cache before rotate two")
        self.assertEqual(cache[3]["body"], "new cache after rotate")

    def test_same_account_on_second_vnc_republishes_local_bundle_and_sends_new_dm(self) -> None:
        ws_vnc1 = self._login_window(
            self.window, email="345@gmail.com", username="user345", uid=345,
            home=self.tmp.name)
        ws_vnc1.on_msg.emit({
            "type": "my_keys",
            "found": False,
            "identity_version": 0,
        })
        _pump()

        first_keys = _last_sent(ws_vnc1, "upload_keys")
        first_bundle = _last_sent(ws_vnc1, "upload_pqxdh_bundle")
        self.assertTrue(first_keys.get("identity_sk_enc"))
        self.assertTrue(first_bundle.get("identity_pk"))
        self.assertTrue(self.window._pending_pqxdh_bundle_upload)
        ws_vnc1.on_msg.emit({"type": "ok", "msg": "PQXDH bundle uploaded"})
        _pump()
        self.assertTrue(self.window._kem_ready)

        vnc2 = self._new_window(home=self.tmp_vnc2.name)
        ws_vnc2 = self._login_window(
            vnc2, email="345@gmail.com", username="user345", uid=345,
            home=self.tmp_vnc2.name)
        ws_vnc2.on_msg.emit({
            "type": "my_keys",
            "found": True,
            "identity_pk": first_keys["identity_pk"],
            "identity_sig": first_keys["identity_sig"],
            "identity_sk_enc": first_keys["identity_sk_enc"],
            "identity_version": 0,
        })
        _pump()

        second_bundle = _last_sent(ws_vnc2, "upload_pqxdh_bundle")
        self.assertTrue(same_identity_key(
            second_bundle["identity_pk"], first_keys["identity_pk"]))
        self.assertTrue(vnc2._pending_pqxdh_bundle_upload)
        self.assertFalse(vnc2._kem_ready)
        self.assertFalse(vnc2._pqxdh_bundle_ready)

        get_bundle_before = _sent_count(ws_vnc2, "get_pqxdh_bundle")
        ws_vnc2.on_msg.emit({
            "type": "pqxdh_status",
            "has_bundle": True,
            "curve_prekeys": 12,
            "pq_prekeys": 12,
            "identity_version": 0,
        })
        _pump()
        self.assertFalse(vnc2._kem_ready)
        self.assertEqual(_sent_count(ws_vnc2, "get_pqxdh_bundle"), get_bundle_before)

        vnc2._chat.update_friends([{
            "id": 234,
            "username": "user234",
            "display_name": "user234",
            "status": "offline",
        }])
        item = vnc2._chat.friend_list.item(0)
        self.assertIsNotNone(item)
        with _choose_menu_action("Start Conversation"):
            vnc2._chat._friend_context_menu(
                vnc2._chat.friend_list.visualItemRect(item).center())
        _pump()
        self.assertEqual(_last_sent(ws_vnc2, "start_dm")["user_id"], 234)

        ws_vnc2.on_msg.emit({
            "type": "dm_ready",
            "conversation_id": 501,
            "with_user_id": 234,
        })
        _pump()
        self.assertIn((501, 234), vnc2._pending_kem_queue)
        self.assertEqual(_sent_count(ws_vnc2, "get_pqxdh_bundle"), get_bundle_before)

        self._emit_dm_inbox(
            ws_vnc2, conv_id=501, peer_uid=234, peer_name="user234",
            wire="", last_id=0)
        self.assertEqual(vnc2._chat.active_conv_id, 501)

        ws_vnc2.on_msg.emit({"type": "ok", "msg": "PQXDH bundle uploaded"})
        _pump()
        self.assertTrue(vnc2._kem_ready)
        self.assertEqual(_last_sent(ws_vnc2, "get_pqxdh_bundle")["user_id"], 234)

        peer234, peer_upload, peer_tmp = self._peer_upload(234)
        self.addCleanup(peer_tmp.cleanup)
        ws_vnc2.on_msg.emit(_bundle_response(peer_upload, 234))
        _pump()
        init_msg = _last_sent(ws_vnc2, "message")
        self.assertEqual(init_msg["conversation_id"], 501)
        self.assertTrue(init_msg["body"].startswith("S3PQI:"))

        vnc2._chat.inp.setPlainText("hello from vnc2")
        _click(vnc2._chat._btn_send)
        encrypted_msg = _last_sent(ws_vnc2, "message")
        self.assertEqual(encrypted_msg["conversation_id"], 501)
        self.assertTrue(encrypted_msg["body"].startswith("S3DR:"))
        labels = "\n".join(_labels(vnc2._chat.view))
        self.assertNotIn("Encryption is not ready", labels)
        self.assertNotIn("Could not establish SecChat encryption", labels)

        incoming_conv = 502
        vnc2_bundle_for_peer = _bundle_response(second_bundle, 345)
        incoming_wire, _peer_state, _fp = pqxdh_initiate(
            vnc2_bundle_for_peer,
            peer234.load_pqxdh_prekeys(),
            peer234.identity_pk,
            peer234.identity_sk,
            234,
            345,
            initial_body=peer234.pack_plaintext("incoming to vnc2"),
        )
        self._emit_dm_inbox(
            ws_vnc2, conv_id=incoming_conv, peer_uid=234, peer_name="user234",
            wire=incoming_wire, last_id=77)
        _click_list_row(vnc2._chat.dm_list, 0)
        self._emit_history(ws_vnc2, conv_id=incoming_conv, rows=[])
        ws_vnc2.on_msg.emit({
            "type": "message",
            "conversation_id": incoming_conv,
            "from_id": 234,
            "id": 77,
            "body": incoming_wire,
            "time": "2026-05-31 12:00:00",
        })
        _pump()
        self.assertIn("incoming to vnc2", _labels(vnc2._chat.view))

    def test_same_account_returns_to_first_vnc_without_restore_starts_fresh_dm(self) -> None:
        vnc2 = self._new_window(home=self.tmp_vnc2.name)
        ws_vnc2 = self._login_window(
            vnc2, email="234@gmail.com", username="user234", uid=234,
            home=self.tmp_vnc2.name)
        ws_vnc2.on_msg.emit({
            "type": "my_keys",
            "found": False,
            "identity_version": 0,
        })
        _pump()
        first_keys = _last_sent(ws_vnc2, "upload_keys")
        _last_sent(ws_vnc2, "upload_pqxdh_bundle")
        ws_vnc2.on_msg.emit({"type": "ok", "msg": "PQXDH bundle uploaded"})
        _pump()
        self.assertTrue(vnc2._kem_ready)

        ws_vnc1 = self._login_window(
            self.window, email="234@gmail.com", username="user234", uid=234,
            home=self.tmp.name)
        ws_vnc1.on_msg.emit({
            "type": "my_keys",
            "found": True,
            "identity_pk": first_keys["identity_pk"],
            "identity_sig": first_keys["identity_sig"],
            "identity_sk_enc": first_keys["identity_sk_enc"],
            "identity_version": 0,
        })
        _pump()
        _last_sent(ws_vnc1, "upload_pqxdh_bundle")
        self.assertTrue(self.window._pending_pqxdh_bundle_upload)
        self.assertFalse(self.window._kem_ready)

        self.window._chat.update_friends([{
            "id": 123,
            "username": "user123",
            "display_name": "user123",
            "status": "offline",
        }])
        item = self.window._chat.friend_list.item(0)
        self.assertIsNotNone(item)
        with _choose_menu_action("Start Conversation"):
            self.window._chat._friend_context_menu(
                self.window._chat.friend_list.visualItemRect(item).center())
        _pump()
        self.assertEqual(_last_sent(ws_vnc1, "start_dm")["user_id"], 123)

        ws_vnc1.on_msg.emit({
            "type": "dm_ready",
            "conversation_id": 612,
            "with_user_id": 123,
        })
        _pump()
        self.assertIn((612, 123), self.window._pending_kem_queue)
        queued_gets = _sent_count(ws_vnc1, "get_pqxdh_bundle")

        self._emit_dm_inbox(
            ws_vnc1, conv_id=612, peer_uid=123, peer_name="user123",
            wire="", last_id=0)
        self.assertEqual(self.window._chat.active_conv_id, 612)
        self.window._chat.inp.setPlainText("too early")
        with patch.object(QMessageBox, "warning", return_value=QMessageBox.Ok):
            _click(self.window._chat._btn_send)
        self.assertIn(
            "Encryption is not ready",
            "\n".join(_labels(self.window._chat.view)),
        )

        ws_vnc1.on_msg.emit({"type": "ok", "msg": "PQXDH bundle uploaded"})
        _pump()
        self.assertTrue(self.window._kem_ready)
        self.assertEqual(
            _sent_count(ws_vnc1, "get_pqxdh_bundle"),
            queued_gets + 1,
        )
        self.assertEqual(_last_sent(ws_vnc1, "get_pqxdh_bundle")["user_id"], 123)

        peer123, peer_upload, peer_tmp = self._peer_upload(123)
        self.addCleanup(peer_tmp.cleanup)
        ws_vnc1.on_msg.emit(_bundle_response(peer_upload, 123))
        _pump()
        self.assertTrue(_last_sent(ws_vnc1, "message")["body"].startswith("S3PQI:"))

        self.window._chat.inp.setPlainText("fresh segment from vnc1")
        _click(self.window._chat._btn_send)
        encrypted = _last_sent(ws_vnc1, "message")
        self.assertEqual(encrypted["conversation_id"], 612)
        self.assertTrue(encrypted["body"].startswith("S3DR:"))
        labels = "\n".join(_labels(self.window._chat.view))
        self.assertNotIn("Could not establish SecChat encryption", labels)

    def test_clear_on_logout_removes_only_current_account_plaintext_cache(self) -> None:
        conv_id = 88
        wire = "S3DR:logout-clear-wire"

        ws123 = self._login_as(email="123@gmail.com", username="user123", uid=123)
        self.window._crypto_session().set_cache_policy(
            enabled=True, ttl_days=30, clear_on_logout=True)
        self.window._chat.set_cache_policy(
            self.window._crypto_session().get_cache_policy())
        self.window._cache_message(conv_id, 1, 234, "clear me on logout", "10:00")
        cache_path = self.window._crypto_session().msg_cache_path(conv_id)
        self.assertTrue(os.path.exists(cache_path))

        self._logout_by_ui()
        self.assertFalse(os.path.exists(cache_path))

        ws123_again = self._login_as(email="123@gmail.com", username="user123", uid=123)
        self._emit_dm_inbox(
            ws123_again, conv_id=conv_id, peer_uid=234, peer_name="user234",
            wire=wire)
        _click_list_row(self.window._chat.dm_list, 0)
        self._emit_history(ws123_again, conv_id=conv_id, rows=[{
            "id": 1,
            "sender_id": 234,
            "body": wire,
            "time": "2026-05-30 10:00:00",
        }])
        labels = _labels(self.window._chat.view)
        self.assertNotIn("clear me on logout", labels)
        self.assertNotIn("[Forward-secret]", labels)
        self.assertFalse(self.window._chat._visible_message_ids(conv_id))

        ws345 = None
        self._logout_by_ui()
        ws345 = self._login_as(email="345@gmail.com", username="user345", uid=345)
        self.window._cache_message(conv_id, 1, 234, "user345 cache survives", "10:00")
        cache_path_345 = self.window._crypto_session().msg_cache_path(conv_id)
        self.assertTrue(os.path.exists(cache_path_345))
        self._emit_dm_inbox(
            ws345, conv_id=conv_id, peer_uid=234, peer_name="user234",
            wire=wire)
        _click_list_row(self.window._chat.dm_list, 0)
        self._emit_history(ws345, conv_id=conv_id, rows=[{
            "id": 1,
            "sender_id": 234,
            "body": wire,
            "time": "2026-05-30 10:00:00",
        }])
        self.assertIn("user345 cache survives", _labels(self.window._chat.view))


if __name__ == "__main__":
    unittest.main(verbosity=2)
