"""
test_notifications.py — notification delivery.

What is implemented:
  * mention_notification: when a message includes "mentions": [uid, …], the
    server sends {"type":"mention_notification","conversation_id":…,"from_id":…,
    "from":…,"message_id":…} to each mentioned user who is currently online.
  * notifications_flush: on login, any rows in notification_queue are sent.
    (notif_enqueue is not yet wired into message delivery; offline queuing
    is infrastructure-only. Tests verify flush runs without error.)

  NT-1   mention_notification delivered to online member
  NT-2   mention_notification includes correct conversation_id and from_id
  NT-3   Self-mention does not generate a notification to sender
  NT-4   Mention of non-member is silently ignored (no error, no notification)
  NT-5   Login produces no spurious messages if no notifications are queued
  NT-6   Mention from a group message is delivered to mentioned member
  NT-7   Offline friend request is flushed on target login
  NT-8   Offline friend accept is flushed on requester login
  NT-9   Offline chat message is flushed on recipient login
"""

from __future__ import annotations

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secchat_testlib import (
    wait_ready, db_reset, unique,
    ChatClient, create_group_mls, make_friends, ws_send, ws_send_msg, recv_until,
)


def _open_dm(c: ChatClient, peer_uid: int) -> int:
    ws_send(c.sock, {"type": "start_dm", "user_id": peer_uid})
    msg = recv_until(c.sock,
                     lambda m: m.get("conversation_id") is not None,
                     timeout=4.0)
    assert msg is not None, "start_dm got no response"
    return msg["conversation_id"]


def _create_group(creator: ChatClient, *members: ChatClient) -> int:
    return create_group_mls(creator, unique("grp"), list(members))


class TestNotifications(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        wait_ready()
        db_reset()
        # Full-suite runs can reuse user ids after DB TRUNCATE while the
        # server-side message token buckets still live in memory.
        time.sleep(11.0)

    # --- mention notifications ---

    def test_NT1_mention_delivered_to_online_member(self):
        alice = ChatClient(); alice.register_and_login(unique("alice"))
        bob   = ChatClient(); bob.register_and_login(unique("bob"))
        try:
            make_friends(alice.sock, alice.user_id, bob.sock, bob.user_id)
            conv = _open_dm(alice, bob.user_id)
            # Drain bob's side
            recv_until(bob.sock, lambda m: False, timeout=0.3)

            ws_send_msg(alice.sock, conv, "hey bob", mentions=[bob.user_id])
            notif = recv_until(
                bob.sock,
                lambda m: m.get("type") == "mention_notification",
                timeout=4.0,
            )
            self.assertIsNotNone(notif,
                                  "mention_notification should reach online bob")
        finally:
            alice.close(); bob.close()

    def test_NT2_mention_notification_fields(self):
        alice = ChatClient(); alice.register_and_login(unique("alice"))
        bob   = ChatClient(); bob.register_and_login(unique("bob"))
        try:
            make_friends(alice.sock, alice.user_id, bob.sock, bob.user_id)
            conv = _open_dm(alice, bob.user_id)
            recv_until(bob.sock, lambda m: False, timeout=0.3)

            ws_send_msg(alice.sock, conv, "hi", mentions=[bob.user_id])
            notif = recv_until(
                bob.sock,
                lambda m: m.get("type") == "mention_notification",
                timeout=4.0,
            )
            self.assertIsNotNone(notif)
            self.assertEqual(notif.get("conversation_id"), conv)
            self.assertEqual(notif.get("from_id"), alice.user_id)
            self.assertIsNotNone(notif.get("message_id"),
                                  "message_id should be present in mention_notification")
        finally:
            alice.close(); bob.close()

    def test_NT3_self_mention_no_notification(self):
        alice = ChatClient(); alice.register_and_login(unique("alice"))
        bob   = ChatClient(); bob.register_and_login(unique("bob"))
        try:
            make_friends(alice.sock, alice.user_id, bob.sock, bob.user_id)
            conv = _open_dm(alice, bob.user_id)
            # Drain alice's own echo from dm_ready
            recv_until(alice.sock, lambda m: m.get("type") == "dm_ready", timeout=1.0)

            ws_send_msg(alice.sock, conv, "note to self", mentions=[alice.user_id])
            # Consume the echo of the message itself
            recv_until(alice.sock,
                       lambda m: m.get("type") == "message",
                       timeout=3.0)
            # Should NOT get a mention_notification
            got = recv_until(
                alice.sock,
                lambda m: m.get("type") == "mention_notification",
                timeout=1.5,
            )
            self.assertIsNone(got,
                              "sender should not receive a mention_notification for self-mention")
        finally:
            alice.close(); bob.close()

    def test_NT4_non_member_mention_ignored(self):
        alice = ChatClient(); alice.register_and_login(unique("alice"))
        bob   = ChatClient(); bob.register_and_login(unique("bob"))
        eve   = ChatClient(); eve.register_and_login(unique("eve"))
        try:
            make_friends(alice.sock, alice.user_id, bob.sock, bob.user_id)
            conv = _open_dm(alice, bob.user_id)
            recv_until(eve.sock, lambda m: False, timeout=0.3)

            ws_send_msg(alice.sock, conv, "hey", mentions=[eve.user_id])
            # Eve should NOT receive a mention_notification
            got = recv_until(
                eve.sock,
                lambda m: m.get("type") == "mention_notification",
                timeout=2.0,
            )
            self.assertIsNone(got,
                              "non-member should not receive a mention_notification")
            # Also verify no error was returned to sender
            err = recv_until(alice.sock,
                             lambda m: m.get("type") == "error",
                             timeout=1.0)
            self.assertIsNone(err,
                              "non-member mention should not cause an error to sender")
        finally:
            alice.close(); bob.close(); eve.close()

    def test_NT5_login_no_spurious_notifications(self):
        alice_name = unique("alice")
        with ChatClient() as a1:
            a1.register_and_login(alice_name)

        # Re-login: flush should run and deliver 0 queued notifications
        with ChatClient() as a2:
            a2.login(alice_name, "Pw!12345")
            # Any notification arriving immediately after login would be suspicious
            notif = recv_until(a2.sock,
                               lambda m: m.get("type") == "notification",
                               timeout=1.5)
            self.assertIsNone(notif,
                              "no spurious notifications should arrive right after login")

    def test_NT6_group_mention_delivered(self):
        alice = ChatClient(); alice.register_and_login(unique("alice"))
        bob   = ChatClient(); bob.register_and_login(unique("bob"))
        carol = ChatClient(); carol.register_and_login(unique("carol"))
        try:
            make_friends(alice.sock, alice.user_id, bob.sock, bob.user_id)
            make_friends(alice.sock, alice.user_id, carol.sock, carol.user_id)
            conv = _create_group(alice, bob, carol)
            # Drain added_to_group on bob and carol
            recv_until(bob.sock, lambda m: False, timeout=0.5)
            recv_until(carol.sock, lambda m: False, timeout=0.5)

            ws_send_msg(alice.sock, conv, "group mention test", mentions=[bob.user_id])
            notif = recv_until(
                bob.sock,
                lambda m: m.get("type") == "mention_notification",
                timeout=4.0,
            )
            self.assertIsNotNone(notif,
                                  "group member should receive mention_notification")
            self.assertEqual(notif.get("conversation_id"), conv)
        finally:
            alice.close(); bob.close(); carol.close()

    def test_NT7_offline_friend_request_flushed_on_login(self):
        bob_name = unique("bob")
        bob = ChatClient(); bob.register_and_login(bob_name)
        bob_uid = bob.user_id
        bob.close()

        alice = ChatClient(); alice.register_and_login(unique("alice"))
        bob2 = ChatClient()
        try:
            ws_send(alice.sock, {"type": "friend_request", "target_id": bob_uid})
            ok = recv_until(alice.sock, lambda m: m.get("type") == "ok", timeout=4.0)
            self.assertIsNotNone(ok)

            login_resp = bob2.login(bob_name)
            self.assertIsNotNone(login_resp.get("user_id"))
            notif = recv_until(
                bob2.sock,
                lambda m: m.get("type") == "friend_request_received",
                timeout=4.0,
            )
            self.assertIsNotNone(notif)
            self.assertEqual(notif.get("from_id"), alice.user_id)

            ws_send(bob2.sock, {"type": "get_requests"})
            reqs = recv_until(
                bob2.sock,
                lambda m: m.get("type") == "friend_requests",
                timeout=4.0,
            )
            self.assertTrue(any(
                int(r.get("user_id", 0) or 0) == alice.user_id
                for r in reqs.get("requests", [])))
        finally:
            alice.close(); bob2.close()

    def test_NT7b_online_friend_request_ack_and_badge_event(self):
        alice = ChatClient(); bob = ChatClient()
        try:
            alice.register_and_login(unique("alice"))
            bob.register_and_login(unique("bob"))

            ws_send(alice.sock, {"type": "friend_request", "target_id": bob.user_id})
            ok = recv_until(alice.sock, lambda m: m.get("type") == "ok", timeout=4.0)
            self.assertIsNotNone(ok)
            self.assertEqual(ok.get("msg"), "Friend request sent")

            notif = recv_until(
                bob.sock,
                lambda m: m.get("type") == "friend_request_received",
                timeout=4.0,
            )
            self.assertIsNotNone(notif)
            self.assertEqual(notif.get("from_id"), alice.user_id)

            ws_send(alice.sock, {"type": "friend_request", "target_id": bob.user_id})
            ok2 = recv_until(
                alice.sock,
                lambda m: m.get("type") in ("ok", "error"),
                timeout=4.0,
            )
            self.assertIsNotNone(ok2)
            self.assertEqual(ok2.get("type"), "ok")
        finally:
            alice.close(); bob.close()

    def test_NT8_offline_friend_accept_flushed_on_login(self):
        alice_name = unique("alice")
        alice = ChatClient(); alice.register_and_login(alice_name)
        bob = ChatClient(); bob.register_and_login(unique("bob"))
        try:
            ws_send(alice.sock, {"type": "friend_request", "target_id": bob.user_id})
            recv_until(bob.sock, lambda m: m.get("type") == "friend_request_received",
                       timeout=4.0)
            alice_uid = alice.user_id
            alice.close()

            ws_send(bob.sock, {"type": "friend_accept", "requester_id": alice_uid})
            ok = recv_until(bob.sock, lambda m: m.get("type") == "ok", timeout=4.0)
            self.assertIsNotNone(ok)

            alice2 = ChatClient()
            try:
                login_resp = alice2.login(alice_name)
                self.assertIsNotNone(login_resp.get("user_id"))
                notif = recv_until(
                    alice2.sock,
                    lambda m: m.get("type") == "friend_accepted",
                    timeout=4.0,
                )
                self.assertIsNotNone(notif)
                self.assertEqual(notif.get("by_id"), bob.user_id)
            finally:
                alice2.close()
        finally:
            bob.close()

    def test_NT9_offline_chat_message_flushed_on_login(self):
        bob_name = unique("bob")
        alice = ChatClient(); alice.register_and_login(unique("alice"))
        bob = ChatClient(); bob.register_and_login(bob_name)
        try:
            make_friends(alice.sock, alice.user_id, bob.sock, bob.user_id)
            conv = _open_dm(alice, bob.user_id)
            recv_until(bob.sock, lambda m: False, timeout=0.3)
            bob.close()

            sent = ws_send_msg(alice.sock, conv, "offline queued message")
            recv_until(
                alice.sock,
                lambda m: m.get("type") == "message" and m.get("body") == sent,
                timeout=4.0,
            )

            bob2 = ChatClient()
            try:
                login_resp = bob2.login(bob_name)
                self.assertIsNotNone(login_resp.get("user_id"))
                queued = recv_until(
                    bob2.sock,
                    lambda m: m.get("type") == "message"
                    and m.get("conversation_id") == conv
                    and m.get("body") == sent,
                    timeout=4.0,
                )
                self.assertIsNotNone(queued)
            finally:
                bob2.close()
        finally:
            alice.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
