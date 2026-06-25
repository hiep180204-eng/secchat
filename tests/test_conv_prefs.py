"""
test_conv_prefs.py — per-user conversation preferences.

Handlers covered (server/services/conv_pref_service.c):
  mute_conversation, archive_conversation, pin_conversation, mark_unread, mark_read.

Server returns "ok" / "error"; state is not exposed via a separate
get_prefs API, so these tests assert API contract (response shape +
auth/membership rejection paths) rather than DB state.

  CP-1   mute_conversation with secs > 0 returns ok
  CP-2   mute_conversation with secs == 0 (unmute) returns ok
  CP-3   archive_conversation toggles — two calls both return ok
  CP-4   pin_conversation toggles — two calls both return ok
  CP-5   mark_unread returns ok on a real conversation
  CP-5b  mark_read clears unread without broadcasting read receipt
  CP-6   mute_conversation rejects invalid conversation_id (<=0)
  CP-7   archive_conversation rejects invalid conversation_id
  CP-8   pin_conversation rejects invalid conversation_id
  CP-9   mark_unread rejects invalid conversation_id
  CP-10  Non-member is rejected for mute
  CP-11  Non-member is rejected for archive
  CP-12  Non-member is rejected for pin
  CP-13  delete_conversation is no longer supported
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secchat_testlib import (
    wait_ready, db_reset, unique,
    ChatClient, make_friends, ws_send, ws_send_msg, recv_until, _mysql,
)


def _open_dm(c: ChatClient, peer_uid: int) -> int:
    ws_send(c.sock, {"type": "start_dm", "user_id": peer_uid})
    msg = recv_until(c.sock,
                      lambda m: m.get("type") == "error" or m.get("conversation_id") is not None,
                      timeout=8.0)
    assert msg is not None, "start_dm got no response"
    assert msg.get("type") != "error", f"start_dm failed: {msg}"
    return msg["conversation_id"]


def _expect_ok(c: ChatClient, timeout: float = 3.0) -> dict:
    msg = recv_until(c.sock,
                      lambda m: m.get("type") in ("ok", "error"),
                      timeout=timeout)
    assert msg is not None, "no ok/error response"
    return msg


class TestConvPrefs(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        wait_ready()
        db_reset()

    def setUp(self):
        # Each test gets a fresh DM between alice and bob.
        self.alice = ChatClient(); self.alice.register_and_login(unique("alice"))
        self.bob = ChatClient(); self.bob.register_and_login(unique("bob"))
        make_friends(self.alice.sock, self.alice.user_id,
                      self.bob.sock, self.bob.user_id)
        self.conv = _open_dm(self.alice, self.bob.user_id)

    def tearDown(self):
        self.alice.close(); self.bob.close()

    # --- happy-path mutates ---

    def test_CP1_mute_with_secs(self):
        ws_send(self.alice.sock, {"type": "mute_conversation",
                                    "conversation_id": self.conv,
                                    "mute_secs": 600})
        r = _expect_ok(self.alice)
        self.assertEqual(r.get("type"), "ok")
        self.assertIn("mute", r.get("msg", "").lower())

    def test_CP2_mute_with_zero_unmutes(self):
        ws_send(self.alice.sock, {"type": "mute_conversation",
                                    "conversation_id": self.conv,
                                    "mute_secs": 0})
        r = _expect_ok(self.alice)
        self.assertEqual(r.get("type"), "ok")

    def test_CP3_archive_toggles(self):
        for _ in range(2):
            ws_send(self.alice.sock, {"type": "archive_conversation",
                                        "conversation_id": self.conv})
            r = _expect_ok(self.alice)
            self.assertEqual(r.get("type"), "ok")
            self.assertIn("archive", r.get("msg", "").lower())

    def test_CP4_pin_toggles(self):
        for _ in range(2):
            ws_send(self.alice.sock, {"type": "pin_conversation",
                                        "conversation_id": self.conv})
            r = _expect_ok(self.alice)
            self.assertEqual(r.get("type"), "ok")
            self.assertIn("pin", r.get("msg", "").lower())

    def test_CP5_mark_unread(self):
        ws_send(self.alice.sock, {"type": "mark_unread",
                                    "conversation_id": self.conv})
        r = _expect_ok(self.alice)
        self.assertEqual(r.get("type"), "ok")
        self.assertIn("unread", r.get("msg", "").lower())

    def test_CP5b_mark_read(self):
        ws_send(self.alice.sock, {"type": "mark_unread",
                                    "conversation_id": self.conv})
        self.assertEqual(_expect_ok(self.alice).get("type"), "ok")
        ws_send(self.alice.sock, {"type": "mark_read",
                                    "conversation_id": self.conv})
        r = _expect_ok(self.alice)
        self.assertEqual(r.get("type"), "ok")
        self.assertIn("read", r.get("msg", "").lower())
        receipt = recv_until(
            self.bob.sock,
            lambda m: m.get("type") == "message_read",
            timeout=0.5,
        )
        self.assertIsNone(receipt)

    def test_CP5d_mark_read_cursor_prevents_timestamp_unread_regression(self):
        sent = ws_send_msg(self.bob.sock, self.conv, "same-second read cursor")
        delivered = recv_until(
            self.alice.sock,
            lambda m: m.get("type") == "message" and m.get("body") == sent,
            timeout=4.0,
        )
        self.assertIsNotNone(delivered)
        msg_id = int(delivered["id"])

        ws_send(self.alice.sock, {
            "type": "mark_read",
            "conversation_id": self.conv,
            "last_message_id": msg_id,
        })
        self.assertEqual(_expect_ok(self.alice).get("type"), "ok")
        cursor = _mysql(
            "SELECT last_read_message_id, force_unread"
            " FROM conversation_members"
            f" WHERE conversation_id={self.conv}"
            f"   AND user_id={self.alice.user_id}"
        ).strip()
        self.assertEqual(cursor, f"{msg_id}\t0")

        _mysql(
            "UPDATE messages"
            " SET sent_at='2030-01-01 00:00:00.900000'"
            f" WHERE id={msg_id}"
        )
        _mysql(
            "UPDATE conversation_members"
            " SET last_read_at='2030-01-01 00:00:00', force_unread=0"
            f" WHERE conversation_id={self.conv}"
            f"   AND user_id={self.alice.user_id}"
        )
        ws_send(self.alice.sock, {"type": "get_inbox"})
        inbox = recv_until(
            self.alice.sock,
            lambda m: m.get("type") == "inbox",
            timeout=4.0,
        )
        self.assertIsNotNone(inbox)
        conv = next(
            c for c in inbox.get("conversations", [])
            if int(c.get("conversation_id", 0) or 0) == self.conv
        )
        self.assertEqual(int(conv.get("unread_count", 0) or 0), 0)

    def test_CP5c_message_read_removed(self):
        ws_send(self.alice.sock, {"type": "message_read",
                                  "conversation_id": self.conv,
                                  "message_id": 1})
        r = _expect_ok(self.alice)
        self.assertEqual(r.get("type"), "error")
        self.assertIn("unsupported", r.get("msg", "").lower())

    # --- invalid conversation_id ---

    def test_CP6_mute_invalid_id(self):
        ws_send(self.alice.sock, {"type": "mute_conversation",
                                    "conversation_id": 0,
                                    "mute_secs": 60})
        r = _expect_ok(self.alice)
        self.assertEqual(r.get("type"), "error")

    def test_CP7_archive_invalid_id(self):
        ws_send(self.alice.sock, {"type": "archive_conversation",
                                    "conversation_id": -1})
        r = _expect_ok(self.alice)
        self.assertEqual(r.get("type"), "error")

    def test_CP8_pin_invalid_id(self):
        ws_send(self.alice.sock, {"type": "pin_conversation",
                                    "conversation_id": 0})
        r = _expect_ok(self.alice)
        self.assertEqual(r.get("type"), "error")

    def test_CP9_mark_unread_invalid_id(self):
        ws_send(self.alice.sock, {"type": "mark_unread",
                                    "conversation_id": -42})
        r = _expect_ok(self.alice)
        self.assertEqual(r.get("type"), "error")

    # --- non-member rejection ---

    def test_CP10_non_member_mute_rejected(self):
        carol = ChatClient(); carol.register_and_login(unique("carol"))
        try:
            ws_send(carol.sock, {"type": "mute_conversation",
                                  "conversation_id": self.conv,
                                  "mute_secs": 60})
            r = _expect_ok(carol)
            self.assertEqual(r.get("type"), "error")
            self.assertIn("member", r.get("msg", "").lower())
        finally:
            carol.close()

    def test_CP11_non_member_archive_rejected(self):
        carol = ChatClient(); carol.register_and_login(unique("carol"))
        try:
            ws_send(carol.sock, {"type": "archive_conversation",
                                  "conversation_id": self.conv})
            r = _expect_ok(carol)
            self.assertEqual(r.get("type"), "error")
        finally:
            carol.close()

    def test_CP12_non_member_pin_rejected(self):
        carol = ChatClient(); carol.register_and_login(unique("carol"))
        try:
            ws_send(carol.sock, {"type": "pin_conversation",
                                  "conversation_id": self.conv})
            r = _expect_ok(carol)
            self.assertEqual(r.get("type"), "error")
        finally:
            carol.close()

    def test_CP12b_non_member_mark_read_rejected(self):
        carol = ChatClient(); carol.register_and_login(unique("carol"))
        try:
            ws_send(carol.sock, {
                "type": "mark_read",
                "conversation_id": self.conv,
                "last_message_id": 1,
            })
            r = _expect_ok(carol)
            self.assertEqual(r.get("type"), "error")
            self.assertIn("member", r.get("msg", "").lower())
        finally:
            carol.close()

    def test_CP13_delete_conversation_removed(self):
        ws_send(self.alice.sock, {"type": "delete_conversation",
                                  "conversation_id": self.conv})
        r = _expect_ok(self.alice)
        self.assertEqual(r.get("type"), "error")
        self.assertIn("unsupported", r.get("msg", "").lower())

    def test_CP14_disappearing_timer_keeps_preexisting_history(self):
        sent = ws_send_msg(self.alice.sock, self.conv, "preexisting history")
        echoed = recv_until(
            self.alice.sock,
            lambda m: m.get("type") == "message" and m.get("body") == sent,
            timeout=4.0,
        )
        self.assertIsNotNone(echoed)
        msg_id = int(echoed["id"])

        _mysql(
            "UPDATE messages"
            " SET sent_at=DATE_SUB(NOW(), INTERVAL 2 HOUR)"
            f" WHERE id={msg_id}"
        )
        ws_send(self.alice.sock, {"type": "set_disappearing",
                                  "conversation_id": self.conv,
                                  "disappear_after_secs": 60})
        updated = recv_until(
            self.alice.sock,
            lambda m: m.get("type") == "disappearing_updated",
            timeout=4.0,
        )
        self.assertIsNotNone(updated)

        _mysql(
            "UPDATE messages m"
            " JOIN conversations c ON m.conversation_id = c.id"
            " SET m.deleted_at = NOW()"
            " WHERE c.disappear_after_secs IS NOT NULL"
            "   AND c.disappear_enabled_at IS NOT NULL"
            "   AND m.deleted_at IS NULL"
            "   AND m.sent_at >= c.disappear_enabled_at"
            "   AND TIMESTAMPDIFF(SECOND, m.sent_at, NOW())"
            "       > c.disappear_after_secs"
        )
        still_visible = _mysql(
            f"SELECT COUNT(*) FROM messages WHERE id={msg_id} AND deleted_at IS NULL"
        ).strip()
        self.assertEqual(still_visible, "1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
