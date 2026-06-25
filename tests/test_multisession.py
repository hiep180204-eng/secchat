"""
test_multisession.py - same-account session replacement.

SecChat keeps one active E2EE session per account. A second login for the same
uid replaces older sockets so Double Ratchet and MLS state cannot fork across
two live windows.

  MS-1  Second login sends session_replaced to the first session
  MS-2  Replaced session can no longer use authenticated commands
  MS-3  New session receives messages after replacement
"""

from __future__ import annotations

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secchat_testlib import (
    wait_ready, db_reset, unique,
    ChatClient, make_friends, ws_send, ws_send_msg, recv_until,
)


def _open_dm(c: ChatClient, peer_uid: int) -> int:
    ws_send(c.sock, {"type": "start_dm", "user_id": peer_uid})
    msg = recv_until(
        c.sock,
        lambda m: m.get("conversation_id") is not None,
        timeout=4.0,
    )
    assert msg is not None, "start_dm got no response"
    return int(msg["conversation_id"])


class TestSessionReplacement(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        wait_ready()
        db_reset()
        time.sleep(11.0)

    def test_MS1_second_login_replaces_first_session(self):
        alice_name = unique("alice")
        a1 = ChatClient()
        a1.register_and_login(alice_name)
        a2 = ChatClient()
        try:
            a2.login(alice_name, a1.password)
            replaced = recv_until(
                a1.sock,
                lambda m: m.get("type") == "session_replaced",
                timeout=4.0,
            )
            self.assertIsNotNone(replaced)
            self.assertEqual(a1.user_id, a2.user_id)
        finally:
            a1.close()
            a2.close()

    def test_MS2_replaced_session_is_not_authenticated(self):
        alice_name = unique("alice")
        a1 = ChatClient()
        a1.register_and_login(alice_name)
        a2 = ChatClient()
        try:
            a2.login(alice_name, a1.password)
            recv_until(a1.sock, lambda m: m.get("type") == "session_replaced", timeout=4.0)
            ws_send(a1.sock, {"type": "get_inbox"})
            got = recv_until(
                a1.sock,
                lambda m: m.get("type") == "error" and "authenticated" in m.get("msg", ""),
                timeout=4.0,
            )
            self.assertIsNotNone(got)
        finally:
            a1.close()
            a2.close()

    def test_MS3_new_session_receives_messages_after_replacement(self):
        alice_name = unique("alice")
        a1 = ChatClient()
        a1.register_and_login(alice_name)
        bob = ChatClient()
        bob.register_and_login(unique("bob"))
        try:
            make_friends(a1.sock, a1.user_id, bob.sock, bob.user_id)
            conv = _open_dm(bob, a1.user_id)
            a2 = ChatClient()
            try:
                a2.login(alice_name, a1.password)
                recv_until(a1.sock, lambda m: m.get("type") == "session_replaced", timeout=4.0)

                body = unique("post-replacement")
                sent_body = ws_send_msg(bob.sock, conv, body)
                got_old = recv_until(
                    a1.sock,
                    lambda m: m.get("type") == "message" and m.get("body") == sent_body,
                    timeout=1.0,
                )
                got_new = recv_until(
                    a2.sock,
                    lambda m: m.get("type") == "message" and m.get("body") == sent_body,
                    timeout=4.0,
                )
                self.assertIsNone(got_old)
                self.assertIsNotNone(got_new)
            finally:
                a2.close()
        finally:
            a1.close()
            bob.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
