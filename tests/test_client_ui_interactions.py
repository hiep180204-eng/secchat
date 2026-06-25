#!/usr/bin/env python3
"""Widget-level client UI tests.

These tests interact with real PyQt widgets instead of calling only
controller handlers.  They stay offscreen so they can run in CI and Docker.
"""

from __future__ import annotations

import os
import sys
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from PyQt5.QtCore import Qt, QTimer  # noqa: E402
from PyQt5.QtTest import QTest  # noqa: E402
from PyQt5.QtWidgets import (  # noqa: E402
    QApplication,
    QCheckBox,
    QComboBox,
    QDialogButtonBox,
    QLabel,
    QMessageBox,
    QPushButton,
)

from client.app import App  # noqa: E402
from client.pages.chat_page import ChatPage  # noqa: E402
from client.dialogs import ProfileEditDialog  # noqa: E402


def _sidebar_text(item) -> str:
    return ChatPage.sidebar_item_text(item)


def _labels(parent) -> list[str]:
    return [lbl.text() for lbl in parent.findChildren(QLabel)]


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


class ClientUiInteractionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.qt = _app()

    def setUp(self) -> None:
        self.page = ChatPage()
        self.page.set_me("me@example.test", 101)
        self.page.friends = {202: {"username": "peer@example.test"}}
        self.page.active_conv_id = 50
        self.page.current_view = "chat"
        self.page.hist[50] = []
        self.sent: list[tuple] = []
        self.commands: list[dict] = []
        self.cache_policies: list[dict] = []
        self.conversation_cache_policies: list[tuple[int, bool]] = []
        self.page.sig_send.connect(lambda conv_id, body: self.sent.append((conv_id, body)))
        self.page.sig_command.connect(lambda obj: self.commands.append(dict(obj)))
        self.page.sig_update_cache_policy.connect(
            lambda policy: self.cache_policies.append(dict(policy)))
        self.page.sig_update_conversation_cache_policy.connect(
            lambda conv_id, enabled: self.conversation_cache_policies.append(
                (int(conv_id), bool(enabled))))

    def tearDown(self) -> None:
        self.page.deleteLater()
        self.qt.processEvents()

    def _button_with_text(self, text: str) -> QPushButton:
        for btn in self.page.findChildren(QPushButton):
            if btn.text() == text:
                return btn
        raise AssertionError(f"button not found: {text}")

    def test_message_search_filters_real_rows_and_keeps_action_button(self) -> None:
        self.page.add_msg(50, 202, "needle message", "12:00", msg_id=1)
        self.page.add_msg(50, 202, "different text", "12:01", msg_id=2)
        self.qt.processEvents()

        self.assertIsNotNone(self.page.view.row_for_msg(1))
        self.assertIsNotNone(self.page.view.row_for_msg(2))

        self.page.e_msg_search.setText("needle")
        self.qt.processEvents()

        row = self.page.view.row_for_msg(1)
        self.assertIsNotNone(row)
        self.assertIsNone(self.page.view.row_for_msg(2))
        action_buttons = [
            b for b in row.findChildren(QPushButton)
            if b.text() == "..." and "background:transparent" in b.styleSheet()
        ]
        self.assertEqual(len(action_buttons), 1)

    def test_retry_button_click_resends_failed_message(self) -> None:
        self.page.show_send_failed(50, "retry this", "connection lost")
        self.qt.processEvents()

        self._button_with_text("Retry").click()
        self.qt.processEvents()

        self.assertEqual(self.sent, [(50, "retry this")])
        self.assertEqual(self.page.hist[50], [])

    def test_sidebar_without_saved_messages_and_action_button_sizes(self) -> None:
        self.assertFalse(hasattr(self.page, "btn_saved"))
        self.assertEqual(
            self.page.dm_list.horizontalScrollBarPolicy(),
            Qt.ScrollBarAlwaysOff,
        )
        self.assertEqual(
            self.page.group_list.horizontalScrollBarPolicy(),
            Qt.ScrollBarAlwaysOff,
        )

        self.page.show_send_failed(50, "retry this", "connection lost")
        self.qt.processEvents()
        retry = self._button_with_text("Retry")
        dismiss = self._button_with_text("Dismiss")
        self.assertEqual(retry.size(), dismiss.size())

    def test_sidebar_custom_row_widget_click_opens_conversation(self) -> None:
        self.page.update_inbox(
            [{
                "conversation_id": 50,
                "username": "peer@example.test",
                "status": "online",
                "last_message": "hello",
            }],
            [{
                "conversation_id": 70,
                "name": "project room",
                "last_message": "group note",
                "creator_id": 101,
            }],
        )
        self.page.active_conv_id = 0
        self.qt.processEvents()

        dm_item = self.page.dm_list.item(0)
        dm_widget = self.page.dm_list.itemWidget(dm_item)
        self.assertIsNotNone(dm_widget)
        QTest.mouseClick(
            self.page.dm_list.viewport(), Qt.LeftButton,
            pos=self.page.dm_list.visualItemRect(dm_item).center(),
        )
        self.qt.processEvents()
        self.assertEqual(self.page.active_conv_id, 50)
        self.assertFalse(self.page._active_is_group)

        self.page.active_conv_id = 0
        group_item = self.page.group_list.item(0)
        group_widget = self.page.group_list.itemWidget(group_item)
        self.assertIsNotNone(group_widget)
        QTest.mouseClick(
            self.page.group_list.viewport(), Qt.LeftButton,
            pos=self.page.group_list.visualItemRect(group_item).center(),
        )
        self.qt.processEvents()
        self.assertEqual(self.page.active_conv_id, 70)
        self.assertTrue(self.page._active_is_group)

    def test_muted_conversation_does_not_raise_unread_badge(self) -> None:
        self.page.update_inbox([{
            "conversation_id": 50,
            "username": "peer@example.test",
            "status": "online",
            "last_message": "hello",
            "unread_count": 1,
            "muted": True,
        }], [])
        self.assertEqual(self.page.btn_chat.text(), "Chats")
        self.assertIn("[muted]", _sidebar_text(self.page.dm_list.item(0)))
        self.assertNotIn("[unread]", _sidebar_text(self.page.dm_list.item(0)))

    def test_profile_avatar_buttons_have_equal_size(self) -> None:
        dlg = ProfileEditDialog({"username": "me@example.test"}, self.page)
        try:
            buttons = {btn.text(): btn for btn in dlg.findChildren(QPushButton)}
            self.assertEqual(
                buttons["Upload Avatar"].size(),
                buttons["Remove Avatar"].size(),
            )
        finally:
            dlg.deleteLater()

    def test_pending_send_status_is_visible_and_removed_on_echo(self) -> None:
        pending_id = self.page.show_send_pending(50, "sending now")
        self.qt.processEvents()

        row = self.page.view.row_for_msg(pending_id)
        self.assertIsNotNone(row)
        labels = [lbl.text() for lbl in row.findChildren(QLabel)]
        self.assertIn("Sending", labels)
        self.assertTrue(any("accepted by the server" in text for text in labels))

        self.page.remove_pending_send(50, "sending now")
        self.qt.processEvents()
        self.assertEqual(self.page.hist[50], [])

    def test_pending_send_can_be_removed_by_exact_pending_id(self) -> None:
        first = self.page.show_send_pending(50, "same body")
        second = self.page.show_send_pending(50, "same body")
        self.qt.processEvents()

        self.page.remove_pending_send(50, "same body", pending_id=second)
        self.qt.processEvents()

        self.assertEqual([m["msg_id"] for m in self.page.hist[50]], [first])
        self.assertTrue(self.page.hist[50][0].get("sending"))

    def test_pending_sends_become_retryable_after_disconnect(self) -> None:
        self.page.show_send_pending(50, "will retry")
        self.page.mark_pending_sends_failed("Connection lost")
        self.qt.processEvents()

        row = self.page.hist[50][0]
        self.assertFalse(row.get("sending"))
        self.assertTrue(row.get("failed"))
        self.assertIn("Connection lost", row.get("failure_reason", ""))
        self._button_with_text("Retry").click()
        self.assertEqual(self.sent, [(50, "will retry")])

    def test_open_conversation_marks_read_without_read_receipt(self) -> None:
        self.page.dm_convs = [{
            "conversation_id": 50,
            "username": "peer@example.test",
            "status": "online",
            "last_message": "hello",
            "unread_count": 1,
        }]
        self.page.hist[50] = [{
            "sender_id": 202,
            "body": "hello",
            "ts": "12:00",
            "msg_id": 7,
            "deleted": False,
        }]
        self.page._history_loaded_convs.add(50)
        self.page._switch_to_conv(50, is_group=False)

        emitted = [cmd.get("type") for cmd in self.commands]
        self.assertIn("mark_read", emitted)
        self.assertNotIn("message_read", emitted)
        mark_read = next(cmd for cmd in self.commands if cmd.get("type") == "mark_read")
        self.assertEqual(mark_read.get("conversation_id"), 50)
        self.assertEqual(mark_read.get("last_message_id"), 7)
        self.assertNotIn("Chats (1)", self.page.btn_chat.text())

    def test_active_conversation_unread_count_is_cleared_on_inbox_refresh(self) -> None:
        self.page.dm_convs = [{
            "conversation_id": 50,
            "username": "peer@example.test",
            "status": "online",
            "last_message": "hello",
            "unread_count": 1,
        }]
        self.page._history_loaded_convs.add(50)
        self.page._switch_to_conv(50, is_group=False)
        self.page.update_inbox([{
            "conversation_id": 50,
            "username": "peer@example.test",
            "status": "online",
            "last_message": "hello",
            "unread_count": 1,
        }], [])

        self.assertEqual(self.page.btn_chat.text(), "Chats")
        self.assertNotIn("[unread]", _sidebar_text(self.page.dm_list.item(0)))

    def test_sidebar_items_keep_native_display_role_empty(self) -> None:
        self.page.update_friends([{
            "id": 202,
            "username": "peer@example.test",
            "status": "online",
        }])
        self.page.update_inbox(
            [{
                "conversation_id": 50,
                "username": "peer@example.test",
                "status": "online",
                "last_message": "hello",
            }],
            [{
                "conversation_id": 70,
                "name": "project room",
                "last_message": "group hello",
            }],
        )

        for widget, expected in (
            (self.page.friend_list, "peer@example.test"),
            (self.page.dm_list, "peer@example.test"),
            (self.page.group_list, "project room"),
        ):
            item = widget.item(0)
            self.assertEqual(item.text(), "")
            self.assertIn(expected, _sidebar_text(item))

    def test_read_group_does_not_reappear_unread_after_switching_to_dm(self) -> None:
        self.page.update_inbox(
            [{
                "conversation_id": 50,
                "username": "peer@example.test",
                "status": "online",
                "last_message": "dm from 234",
                "last_message_id": 10,
                "unread_count": 1,
            }],
            [{
                "conversation_id": 70,
                "name": "test group",
                "last_message": "group from 234",
                "last_message_id": 11,
                "unread_count": 1,
            }],
        )
        self.page.hist[50] = [{
            "sender_id": 202,
            "body": "dm from 234",
            "ts": "12:00",
            "msg_id": 10,
            "deleted": False,
        }]
        self.page.hist[70] = [{
            "sender_id": 202,
            "body": "group from 234",
            "ts": "12:01",
            "msg_id": 11,
            "deleted": False,
        }]
        self.page._history_loaded_convs.update({50, 70})

        self.page._switch_to_conv(50, is_group=False)
        self.page._switch_to_conv(70, is_group=True)
        self.page.update_inbox(
            [{
                "conversation_id": 50,
                "username": "peer@example.test",
                "status": "online",
                "last_message": "dm from 234",
                "last_message_id": 10,
                "unread_count": 0,
            }],
            [{
                "conversation_id": 70,
                "name": "test group",
                "last_message": "group from 234",
                "last_message_id": 11,
                "unread_count": 1,
            }],
        )
        self.page._switch_to_conv(50, is_group=False)

        self.assertEqual(self.page.btn_chat.text(), "Chats")
        self.assertNotIn("[unread]", _sidebar_text(self.page.group_list.item(0)))
        self.assertNotIn(70, self.page._unread_convs)

    def test_dm_header_shows_last_seen_when_peer_is_offline(self) -> None:
        dm = [{
            "conversation_id": 50,
            "username": "peer@example.test",
            "status": "offline",
            "last_seen": "2026-05-27 17:20:00",
            "last_message": "",
        }]
        self.page.update_inbox(dm, [])
        self.page._history_loaded_convs.add(50)
        self.page._switch_to_conv(50, is_group=False)

        self.assertEqual(self.page.lbl_chat.text(), "peer@example.test")
        self.assertEqual(
            self.page.lbl_chat_presence.text(),
            "Last seen 2026-05-27 17:20:00",
        )
        self.assertIn("Last seen", self.page.dm_list.item(0).toolTip())

    def test_typing_indicator_is_enabled_by_default_and_metadata_can_disable_it(self) -> None:
        self.page.active_conv_id = 50
        self.page.inp.setPlainText("typing")
        self.page._on_input_changed()
        emitted = [cmd.get("type") for cmd in self.commands]
        self.assertIn("typing_start", emitted)

        self.commands.clear()
        self.page.set_metadata_protection(True)
        self.page.inp.setPlainText("typing again")
        self.page._on_input_changed()
        self.assertEqual(self.commands, [])

    def test_typing_indicator_label_shows_and_clears_from_peer_event(self) -> None:
        self.page.active_conv_id = 50

        self.page.set_typing(50, 202, "peer@example.test", True)
        self.qt.processEvents()
        self.assertEqual(self.page.lbl_typing.text(), "peer@example.test is typing...")

        self.page.set_typing(50, 202, "peer@example.test", False)
        self.qt.processEvents()
        self.assertEqual(self.page.lbl_typing.text(), "")

    def test_reaction_chip_click_toggles_reaction_command(self) -> None:
        self.page.add_msg(
            50,
            202,
            "reactable",
            "12:00",
            msg_id=9,
            reactions={"ok": {"emoji": "ok", "count": 2, "me": False}},
        )
        self.qt.processEvents()

        self._button_with_text("ok 2").click()
        self.qt.processEvents()

        self.assertIn({
            "type": "add_reaction",
            "message_id": 9,
            "emoji": "ok",
        }, self.commands)

    def test_privacy_dialog_updates_cache_policy_from_real_controls(self) -> None:
        def drive_dialog() -> None:
            dlg = QApplication.activeModalWidget()
            self.assertIsNotNone(dlg)
            for cb in dlg.findChildren(QCheckBox):
                if cb.text().startswith("Store decrypted"):
                    cb.setChecked(False)
                if cb.text().startswith("Clear local message cache"):
                    cb.setChecked(True)
            ttl_combo = None
            for combo in dlg.findChildren(QComboBox):
                if combo.count() == 5 and combo.findData(7) >= 0:
                    ttl_combo = combo
                    break
            self.assertIsNotNone(ttl_combo)
            ttl_combo.setCurrentIndex(ttl_combo.findData(7))
            box = dlg.findChild(QDialogButtonBox)
            self.assertIsNotNone(box)
            box.button(QDialogButtonBox.Save).click()

        QTimer.singleShot(0, drive_dialog)
        self.page.show_privacy_settings({
            "privacy_online": "everyone",
            "privacy_last_seen": "friends",
        })
        self.qt.processEvents()

        self.assertEqual(self.cache_policies[-1], {
            "enabled": False,
            "ttl_days": 7,
            "clear_on_logout": True,
            "disabled_conversation_ids": [],
        })
        self.assertEqual(self.commands[-1]["type"], "update_privacy")

    def test_conversation_cache_state_is_visible_and_toggleable(self) -> None:
        self.page.dm_convs = [{
            "conversation_id": 50,
            "username": "peer@example.test",
            "status": "online",
            "last_message": "hello",
        }]
        self.page._switch_to_conv(50, is_group=False)

        self.page.set_cache_policy({
            "enabled": True,
            "ttl_days": 7,
            "clear_on_logout": False,
            "disabled_conversation_ids": [50],
        })
        self.qt.processEvents()

        self.assertEqual(self.page.lbl_cache_state.text(), "No local cache")
        self.assertIn("sensitive", self.page.lbl_cache_state.toolTip().lower())

        self.page.sig_update_conversation_cache_policy.emit(50, True)
        self.assertEqual(self.conversation_cache_policies[-1], (50, True))

        self.page.set_cache_policy({
            "enabled": True,
            "ttl_days": 7,
            "clear_on_logout": False,
            "disabled_conversation_ids": [],
        })
        self.assertEqual(self.page.lbl_cache_state.text(), "Cache 7 days")

    def test_profile_dialog_exposes_e2ee_backup_actions(self) -> None:
        dlg = ProfileEditDialog({
            "username": "me@example.test",
            "backup_status": {
                "latest_generation": 2,
                "latest_created_at": 1710000000,
                "latest_include_cache": False,
            },
        }, self.page)
        try:
            buttons = {b.text(): b for b in dlg.findChildren(QPushButton)}
            self.assertIn("Export E2EE Backup", buttons)
            self.assertIn("Restore E2EE Backup", buttons)
            self.assertIn("Backup Status", buttons)
            self.assertIn("Revoke Local Backups", buttons)
            labels = [lbl.text() for lbl in dlg.findChildren(QLabel)]
            self.assertTrue(any("generation 2" in text for text in labels))
            self.assertTrue(any("Backup and recovery" in text for text in labels))
            self.assertTrue(any("Contacts will see a key-change warning" in text for text in labels))

            buttons["Export E2EE Backup"].click()
            self.assertEqual(dlg.get_requested_action(), "export_backup")
        finally:
            dlg.deleteLater()

    def test_safety_header_uses_clear_verified_state(self) -> None:
        fp = "123456 234567 345678 456789 567890"
        self.page.set_fingerprint(fp, verified=False)
        self.assertIn("Verify safety", self.page.lbl_fingerprint.text())
        self.assertIn("Not verified", self.page.lbl_fingerprint.toolTip())
        self.assertIn("not verified", self.page.lbl_security_guide.text().lower())

        self.page.set_fingerprint(fp, verified=True)
        self.assertIn("Verified", self.page.lbl_fingerprint.text())
        self.assertIn("verified", self.page.lbl_fingerprint.toolTip().lower())

    def test_conversation_list_shows_identity_state_without_blocking_input(self) -> None:
        self.page.dm_convs = [{
            "conversation_id": 50,
            "username": "peer@example.test",
            "status": "online",
            "last_message": "hello",
        }]
        self.page._switch_to_conv(50, is_group=False)
        self.page.set_conversation_security(
            50,
            "key_changed",
            "key changed",
            "Safety number changed.",
            blocked=True,
        )
        self.qt.processEvents()

        self.assertIn("[key changed]", _sidebar_text(self.page.dm_list.item(0)))
        self.assertTrue(self.page.inp.isEnabled())
        self.assertFalse(self.page.btn_review_identity.isHidden())
        self.assertIn("You can send messages", self.page.lbl_security_guide.text())
        self.assertEqual(self.page.inp.placeholderText(), "Message...")

        self.page.set_conversation_security(
            50, "reviewed_unverified", "unverified", "", blocked=False)
        self.qt.processEvents()
        self.assertTrue(self.page.inp.isEnabled())

    def test_unverified_identity_does_not_create_history_warning(self) -> None:
        self.page.dm_convs = [{
            "conversation_id": 50,
            "username": "peer@example.test",
            "status": "online",
            "last_message": "hello",
        }]
        self.page._switch_to_conv(50, is_group=False)
        self.page.set_conversation_security(50, "unverified", "verify", "")
        self.page.set_fingerprint("123456 234567 345678 456789 567890", verified=False)
        self.qt.processEvents()

        self.assertTrue(self.page.lbl_consistency.isHidden())
        self.assertTrue(self.page.btn_warning_details.isHidden())
        self.assertFalse(self.page.btn_review_identity.isHidden())
        guide = self.page.lbl_security_guide.text().lower()
        self.assertIn("not verified", guide)
        self.assertNotIn("history or group consistency", guide)
        self.assertEqual(self.page._security_warnings.get(50), None)

    def test_group_never_shows_identity_review_header(self) -> None:
        self.page.group_convs = [{
            "conversation_id": 70,
            "name": "project room",
            "last_message": "",
        }]
        emitted: list[int] = []
        self.page.sig_verify_identity.connect(lambda cid: emitted.append(int(cid)))

        self.page._switch_to_conv(70, is_group=True)
        self.page.set_conversation_security(
            70,
            "key_changed",
            "key changed",
            "This stale identity state should not render on a group.",
        )
        self.page.set_fingerprint("123456 234567 345678 456789 567890", verified=False)
        self.qt.processEvents()

        self.assertTrue(self.page.btn_review_identity.isHidden())
        self.assertEqual(self.page.lbl_fingerprint.text(), "")
        self.assertNotIn("key changed", _sidebar_text(self.page.group_list.item(0)).lower())
        self.assertNotIn("verify", _sidebar_text(self.page.group_list.item(0)).lower())

        self.page.lbl_fingerprint.clicked.emit()
        self.page.btn_review_identity.click()
        self.assertEqual(emitted, [])

    def test_app_verify_dialog_blocks_group_ids(self) -> None:
        harness = type("Harness", (), {})()
        harness._chat = self.page
        harness._is_group_conv = lambda conv_id: int(conv_id) == 70
        captured = {}
        original = QMessageBox.information
        QMessageBox.information = staticmethod(
            lambda _parent, title, text, *args, **kwargs:
            captured.update({"title": title, "text": text}) or QMessageBox.Ok
        )
        try:
            App._show_verify_dialog(harness, 70)
        finally:
            QMessageBox.information = original

        self.assertEqual(captured.get("title"), "Not Available")
        self.assertIn("MLS membership state", captured.get("text", ""))

    def test_key_changed_identity_warning_does_not_use_history_details(self) -> None:
        self.page.dm_convs = [{
            "conversation_id": 50,
            "username": "peer@example.test",
            "status": "online",
            "last_message": "hello",
        }]
        self.page._switch_to_conv(50, is_group=False)
        self.page.set_conversation_security(
            50,
            "key_changed",
            "key changed",
            "Safety number changed.",
            blocked=False,
        )
        self.qt.processEvents()

        self.assertFalse(self.page.lbl_consistency.isHidden())
        self.assertEqual(self.page.lbl_consistency.text(), "Key changed")
        self.assertTrue(self.page.btn_warning_details.isHidden())
        self.assertFalse(self.page.btn_review_identity.isHidden())

    def test_dm_context_menu_uses_secchat_popover(self) -> None:
        self.page.dm_convs = [{
            "conversation_id": 50,
            "username": "peer@example.test",
            "status": "online",
            "last_message": "hello",
        }]
        self.page._refresh_dm_list()
        item = self.page.dm_list.item(0)
        pos = self.page.dm_list.visualItemRect(item).center()

        self.page._dm_context_menu(pos)
        self.qt.processEvents()

        pop = self.page._active_context_popover
        self.assertIsNotNone(pop)
        self.assertEqual(pop.objectName(), "secchatContextPopover")
        actions = [
            btn.text() for btn in pop.findChildren(QPushButton)
            if btn.objectName() == "secchatContextAction"
        ]
        self.assertIn("Open", actions)
        self.assertIn("Verify Identity", actions)

    def test_security_guidance_explains_loading_and_disabled_cache(self) -> None:
        self.page.dm_convs = [{
            "conversation_id": 50,
            "username": "peer@example.test",
            "status": "online",
            "last_message": "hello",
        }]
        self.page._switch_to_conv(50, is_group=False)
        self.qt.processEvents()
        self.assertIn("Loading history", self.page.lbl_security_guide.text())

        self.page.set_cache_policy({
            "enabled": True,
            "ttl_days": 7,
            "clear_on_logout": False,
            "disabled_conversation_ids": [50],
        })
        self.qt.processEvents()
        self.assertIn("Local cache is disabled", self.page.lbl_security_guide.text())

    def test_safety_short_code_and_visual_are_deterministic(self) -> None:
        fp = "123456 234567 345678 456789 567890"
        self.assertEqual(App._safety_short_code(fp), "123 456 234 567")
        first = App._safety_visual_code(fp)
        second = App._safety_visual_code(fp)
        self.assertEqual(first.size(), second.size())
        self.assertFalse(first.isNull())

    def test_group_consistency_warning_has_clickable_details(self) -> None:
        self.page.group_convs = [{
            "conversation_id": 50,
            "name": "project room",
            "last_message": "",
            "creator_id": 101,
        }]
        self.page._switch_to_conv(50, is_group=True)
        self.page.show_security_warning(50, [
            "Group commit chain mismatch.",
            "Server history may be missing a membership event.",
        ])
        self.qt.processEvents()

        self.assertFalse(self.page.lbl_consistency.isHidden())
        self.assertEqual(self.page.lbl_consistency.text(), "History warning")
        self.assertFalse(self.page.btn_warning_details.isHidden())
        self.assertTrue(self.page.btn_review_identity.isHidden())

        captured = {}
        original = QMessageBox.warning
        QMessageBox.warning = staticmethod(
            lambda _parent, title, text, *args, **kwargs:
            captured.update({"title": title, "text": text}) or QMessageBox.Ok
        )
        try:
            self.page.btn_warning_details.click()
            self.qt.processEvents()
        finally:
            QMessageBox.warning = original

        self.assertEqual(captured["title"], "Warning Details")
        self.assertIn("Group commit chain mismatch.", captured["text"])
        self.assertIn("missing a membership event", captured["text"])

    def test_group_system_event_survives_history_reload(self) -> None:
        self.page.group_convs = [{
            "conversation_id": 70,
            "name": "project room",
            "last_message": "",
        }]
        self.page._switch_to_conv(70, is_group=True)
        self.page.add_system_event(
            70,
            "bob@example.test joined the group.",
            event_key=("member_added", 202, "", "op-1"),
        )
        self.assertTrue(any("bob@example.test joined the group." in t for t in _labels(self.page)))

        self.page.load_history(70, [{
            "id": 1,
            "sender_id": 101,
            "body": "hello before event",
            "time": "2026-06-08 10:00:00",
        }])
        labels = _labels(self.page)
        self.assertTrue(any("hello before event" in t for t in labels))
        self.assertTrue(any("bob@example.test joined the group." in t for t in labels))

    def test_persisted_group_system_event_keeps_timeline_anchor(self) -> None:
        self.page.group_convs = [{
            "conversation_id": 70,
            "name": "project room",
            "last_message": "",
        }]
        self.page._switch_to_conv(70, is_group=True)
        self.page.load_history(
            70,
            [
                {"id": 10, "sender_id": 101, "body": "before role",
                 "time": "2026-06-08 10:00:00"},
                {"id": 11, "sender_id": 101, "body": "after role",
                 "time": "2026-06-08 10:00:01"},
            ],
            [{
                "system_event_id": 5,
                "text": "alice@example.test made bob@example.test admin.",
                "after_message_id": 10,
                "event_key": ("member_role_changed", 202, "admin", "op-role"),
                "time": "2026-06-08 10:00:00",
            }],
        )

        bodies = [m["body"].replace("__SYSTEM__:", "") for m in self.page.hist[70]]
        self.assertEqual(
            bodies,
            [
                "before role",
                "alice@example.test made bob@example.test admin.",
                "after role",
            ],
        )

    def test_live_group_system_event_keeps_position_after_history_reload(self) -> None:
        self.page.group_convs = [{
            "conversation_id": 70,
            "name": "project room",
            "last_message": "",
        }]
        self.page._switch_to_conv(70, is_group=True)
        self.page.load_history(70, [{
            "id": 10,
            "sender_id": 101,
            "body": "before role",
            "time": "2026-06-08 10:00:00",
        }])
        self.page.add_system_event(
            70,
            "alice@example.test made bob@example.test admin.",
            event_key=("member_role_changed", 202, "admin", "op-role"),
        )
        self.page.load_history(70, [
            {"id": 10, "sender_id": 101, "body": "before role",
             "time": "2026-06-08 10:00:00"},
            {"id": 11, "sender_id": 101, "body": "after role",
             "time": "2026-06-08 10:00:01"},
        ])

        bodies = [m["body"].replace("__SYSTEM__:", "") for m in self.page.hist[70]]
        self.assertEqual(
            bodies,
            [
                "before role",
                "alice@example.test made bob@example.test admin.",
                "after role",
            ],
        )

    def test_live_and_persisted_group_system_event_do_not_duplicate(self) -> None:
        self.page.group_convs = [{
            "conversation_id": 70,
            "name": "project room",
            "last_message": "",
        }]
        self.page._switch_to_conv(70, is_group=True)
        event_key = ("member_added", 202, "", "op-add")
        self.page.add_system_event(
            70,
            "bob@example.test joined the group.",
            event_key=event_key,
            system_event_id=42,
            after_message_id=10,
        )
        self.page.load_history(
            70,
            [
                {"id": 10, "sender_id": 101, "body": "before add",
                 "time": "2026-06-08 10:00:00"},
                {"id": 11, "sender_id": 101, "body": "after add",
                 "time": "2026-06-08 10:00:01"},
            ],
            [{
                "system_event_id": 42,
                "text": "bob@example.test joined the group.",
                "after_message_id": 10,
                "event_key": event_key,
                "time": "2026-06-08 10:00:00",
            }],
        )

        bodies = [m["body"].replace("__SYSTEM__:", "") for m in self.page.hist[70]]
        self.assertEqual(bodies.count("bob@example.test joined the group."), 1)
        self.assertEqual(bodies[1], "bob@example.test joined the group.")

    def test_pending_failed_rows_survive_history_reload(self) -> None:
        self.page.show_send_pending(70, "pending group message")
        self.page.show_send_failed(70, "failed group message", "network")
        self.page.load_history(70, [{
            "id": 10,
            "sender_id": 202,
            "body": "server message",
            "time": "2026-06-08 10:00:00",
        }])

        bodies = [m["body"] for m in self.page.hist[70]]
        self.assertIn("server message", bodies)
        self.assertIn("pending group message", bodies)
        self.assertIn("failed group message", bodies)

    def test_group_system_event_dedupes_by_operation_id(self) -> None:
        self.page.group_convs = [{
            "conversation_id": 70,
            "name": "project room",
            "last_message": "",
        }]
        self.page._switch_to_conv(70, is_group=True)
        key = ("member_role_changed", 202, "admin", "op-role")
        self.page.add_system_event(70, "alice made bob admin.", event_key=key)
        self.page.add_system_event(70, "alice made bob admin.", event_key=key)
        labels = [t for t in _labels(self.page) if "alice made bob admin." in t]
        self.assertEqual(len(labels), 1)

    def test_app_membership_role_event_uses_names_and_dedupes(self) -> None:
        window = App()
        try:
            window._my_uid = 101
            window._chat.set_me("alice@example.test", 101)
            window._chat.group_convs = [{
                "conversation_id": 70,
                "name": "project room",
                "last_message": "",
            }]
            window._chat.friends = {202: {"username": "bob@example.test"}}
            window._chat._switch_to_conv(70, is_group=True)
            window._group_members_cache[70] = [
                {"user_id": 101, "role": "admin", "username": "alice@example.test"},
                {"user_id": 202, "role": "member", "username": "bob@example.test"},
            ]
            sent = []
            window._safe_send = lambda obj: sent.append(dict(obj)) or True
            event = {
                "type": "member_role_changed",
                "group_id": 70,
                "user_id": 202,
                "username": "bob@example.test",
                "role": "admin",
                "by_user_id": 101,
                "by_username": "alice@example.test",
                "operation_id": "op-role-1",
                "members": [
                    {"user_id": 101, "role": "admin"},
                    {"user_id": 202, "role": "admin"},
                ],
            }

            window._handle_ui_refresh(dict(event))
            window._handle_ui_refresh(dict(event))
            labels = [t for t in _labels(window._chat)
                      if "alice@example.test made bob@example.test admin." in t]
            self.assertEqual(len(labels), 1)
            self.assertIn({"type": "get_group_info", "group_id": 70}, sent)
        finally:
            window.deleteLater()

    def test_app_member_removed_self_keeps_system_event_after_history(self) -> None:
        window = App()
        try:
            window._my_uid = 101
            window._chat.set_me("alice@example.test", 101)
            window._chat.group_convs = [{
                "conversation_id": 70,
                "name": "project room",
                "last_message": "",
            }]
            window._chat._switch_to_conv(70, is_group=True)
            window._group_conv_ids.add(70)
            window._group_members_cache[70] = [
                {"user_id": 101, "role": "member", "username": "alice@example.test"},
                {"user_id": 202, "role": "admin", "username": "bob@example.test"},
            ]
            sent = []
            window._safe_send = lambda obj: sent.append(dict(obj)) or True

            window._handle_member_removed({
                "type": "member_removed",
                "group_id": 70,
                "user_id": 101,
                "username": "alice@example.test",
                "by_user_id": 202,
                "by_username": "bob@example.test",
                "operation": "remove_member",
                "operation_id": "op-remove-self",
                "members": [{"user_id": 202, "role": "admin"}],
            })
            window._chat.load_history(70, [])

            self.assertNotIn(70, window._group_conv_ids)
            self.assertNotIn(70, window._group_members_cache)
            self.assertIn({"type": "get_inbox"}, sent)
            labels = _labels(window._chat)
            self.assertTrue(any("You were removed from the group." in t for t in labels))
        finally:
            window.deleteLater()

    def test_connection_warning_uses_specific_label(self) -> None:
        self.page.active_conv_id = 1
        self.page.show_security_warning(
            1,
            "Connection was interrupted. SecChat will reconnect automatically.",
        )
        self.qt.processEvents()

        self.assertFalse(self.page.lbl_consistency.isHidden())
        self.assertEqual(self.page.lbl_consistency.text(), "Connection warning")
        self.assertFalse(self.page.lbl_security_guide.isHidden())
        guide = self.page.lbl_security_guide.text().lower()
        self.assertIn("connection warning", guide)
        self.assertIn("reconnecting", guide)
        self.assertNotIn("history or group consistency", guide)


if __name__ == "__main__":
    unittest.main(verbosity=2)
