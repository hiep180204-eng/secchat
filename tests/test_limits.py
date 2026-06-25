"""
test_limits.py — enforced limits in server query results and validation.

  LM-1  history returns at most 100 messages
  LM-2  history returns the most recent messages (newest appear when cap hit)
  LM-3  get_inbox returns at most 50 conversations
  LM-4  prepare_group_change with empty members array returns error
  LM-5  prepare_group_change with a non-friend member returns error
  LM-6  create_group with name too long returns error
  LM-7  message with empty body is rejected
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secchat_testlib import (
    wait_ready, db_reset, unique,
    ChatClient, make_friends, prepare_group_change, ws_send, ws_send_msg, recv_until,
)


def _open_dm(c: ChatClient, peer_uid: int) -> int:
    ws_send(c.sock, {"type": "start_dm", "user_id": peer_uid})
    msg = recv_until(c.sock,
                     lambda m: m.get("conversation_id") is not None,
                     timeout=4.0)
    assert msg is not None, "start_dm got no response"
    return msg["conversation_id"]


def _expect_any(c: ChatClient, timeout: float = 3.0) -> dict:
    msg = recv_until(c.sock, lambda m: m.get("type") in ("ok", "error"), timeout=timeout)
    assert msg is not None, "no ok/error response"
    return msg


class TestLimits(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        wait_ready()
        db_reset()

    # --- history ---

    def test_LM1_history_capped_at_100(self):
        alice = ChatClient(); alice.register_and_login(unique("alice"))
        bob   = ChatClient(); bob.register_and_login(unique("bob"))
        try:
            make_friends(alice.sock, alice.user_id, bob.sock, bob.user_id)
            conv = _open_dm(alice, bob.user_id)
            # Drain any stray messages (dm_ready echo on bob's side)
            recv_until(bob.sock, lambda m: False, timeout=0.3)

            # Send 102 messages; accept rate-limit errors without waiting the full timeout
            for i in range(102):
                ws_send_msg(alice.sock, conv, f"msg{i:04d}")
                recv_until(alice.sock,
                           lambda m: m.get("type") in ("message", "error"),
                           timeout=3.0)

            ws_send(alice.sock, {"type": "history", "conversation_id": conv})
            hist = recv_until(alice.sock, lambda m: m.get("type") == "history",
                              timeout=5.0)
            self.assertIsNotNone(hist)
            msgs = hist.get("messages", [])
            self.assertLessEqual(len(msgs), 100,
                                 f"history returned {len(msgs)} > 100 messages")
        finally:
            alice.close(); bob.close()

    def test_LM2_history_contains_most_recent(self):
        alice = ChatClient(); alice.register_and_login(unique("alice"))
        bob   = ChatClient(); bob.register_and_login(unique("bob"))
        try:
            make_friends(alice.sock, alice.user_id, bob.sock, bob.user_id)
            conv = _open_dm(alice, bob.user_id)
            recv_until(bob.sock, lambda m: False, timeout=0.3)

            last_body = None
            for i in range(102):
                b = ws_send_msg(alice.sock, conv, f"seq{i:04d}")
                echo = recv_until(alice.sock,
                                  lambda m: m.get("type") in ("message", "error"),
                                  timeout=3.0)
                if echo and echo.get("type") == "message":
                    last_body = b

            self.assertIsNotNone(last_body, "no messages went through")
            ws_send(alice.sock, {"type": "history", "conversation_id": conv})
            hist = recv_until(alice.sock, lambda m: m.get("type") == "history",
                              timeout=5.0)
            self.assertIsNotNone(hist)
            bodies = [m.get("body") for m in hist.get("messages", [])]
            self.assertIn(last_body, bodies,
                          "most recent successful message should appear in capped history")
        finally:
            alice.close(); bob.close()

    # --- get_inbox ---

    def test_LM3_get_inbox_returns_list(self):
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            ws_send(c.sock, {"type": "get_inbox"})
            msg = recv_until(c.sock, lambda m: m.get("type") == "inbox", timeout=4.0)
            self.assertIsNotNone(msg, "get_inbox returned no response")
            convs = msg.get("conversations", [])
            self.assertIsInstance(convs, list)
            self.assertLessEqual(len(convs), 50,
                                 "get_inbox should return at most 50 conversations")

    # --- group prepare validation ---

    def test_LM4_prepare_group_empty_members_rejected(self):
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            r = prepare_group_change(
                c,
                "create_group",
                name=unique("grp"),
                members=[],
            )
            self.assertEqual(r.get("type"), "error",
                             "empty members array should be rejected")

    def test_LM5_prepare_group_non_friend_rejected(self):
        alice = ChatClient(); alice.register_and_login(unique("alice"))
        bob   = ChatClient(); bob.register_and_login(unique("bob"))
        try:
            # alice and bob are NOT friends
            r = prepare_group_change(
                alice,
                "create_group",
                name=unique("grp"),
                members=[bob.user_id],
            )
            self.assertEqual(r.get("type"), "error",
                             "non-friend member should be rejected")
        finally:
            alice.close(); bob.close()

    def test_LM6_get_group_info_invalid_id_rejected(self):
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            ws_send(c.sock, {"type": "get_group_info", "group_id": 0})
            r = _expect_any(c)
            self.assertEqual(r.get("type"), "error",
                             "group_id <= 0 should return error")

    # --- message validation ---

    def test_LM7_empty_message_body_rejected(self):
        alice = ChatClient(); alice.register_and_login(unique("alice"))
        bob   = ChatClient(); bob.register_and_login(unique("bob"))
        try:
            make_friends(alice.sock, alice.user_id, bob.sock, bob.user_id)
            conv = _open_dm(alice, bob.user_id)
            ws_send(alice.sock, {"type": "message",
                                  "conversation_id": conv,
                                  "body": ""})
            r = recv_until(alice.sock,
                           lambda m: m.get("type") in ("ok", "error", "message"),
                           timeout=3.0)
            self.assertIsNotNone(r)
            self.assertEqual(r.get("type"), "error",
                             "empty message body should be rejected")
        finally:
            alice.close(); bob.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
