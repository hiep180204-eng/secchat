#!/usr/bin/env python3
"""Saved Messages removal regression tests.

The product no longer exposes self-DM/Saved Messages. Old clients may still
send the removed commands, so the server must reject them clearly and avoid
creating confusing self-DM rows in the inbox.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secchat_testlib import (
    ChatClient,
    db_reset,
    recv_until,
    unique,
    wait_ready,
    ws_send,
)


class TestSavedMessagesRemoved(unittest.TestCase):
    def setUp(self):
        wait_ready()
        db_reset()

    def test_saved_messages_command_is_rejected(self):
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            ws_send(c.sock, {"type": "saved_messages"})
            r = recv_until(c.sock, lambda m: m.get("type") == "error", timeout=4.0)
            self.assertIsNotNone(r)
            self.assertIn(
                r.get("msg", ""),
                ("Unsupported command", "Saved Messages is no longer supported"),
            )

    def test_start_dm_self_is_rejected_and_not_listed_in_inbox(self):
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            ws_send(c.sock, {"type": "start_dm", "user_id": c.user_id})
            r = recv_until(c.sock, lambda m: m.get("type") == "error", timeout=4.0)
            self.assertIsNotNone(r)
            self.assertIn("no longer supported", r.get("msg", ""))

            ws_send(c.sock, {"type": "get_inbox"})
            inbox = recv_until(c.sock, lambda m: m.get("type") == "inbox", timeout=4.0)
            self.assertIsNotNone(inbox)
            self.assertFalse(inbox.get("conversations"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
