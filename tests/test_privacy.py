"""
test_privacy.py — privacy settings (presence.c).

Handlers:
  update_privacy  — set privacy_online / privacy_last_seen
  get_privacy     — fetch the two supported fields

Valid values per field: "everyone", "friends", "nobody". An empty/missing
field in update_privacy is allowed (means "leave unchanged"). Bad values
return an error.

  PV-1   get_privacy returns defaults on a fresh user (everyone everywhere)
  PV-2   update_privacy with privacy_online="friends" persists across get_privacy
  PV-3   update_privacy can change both fields atomically
  PV-4   update_privacy with empty body returns error
  PV-5   update_privacy with invalid privacy_online value returns error
  PV-6   update_privacy with invalid privacy_last_seen value returns error
  PV-7   read receipt privacy is no longer supported
  PV-8   update_privacy can change only one field (others retain prior value)
  PV-9   privacy_online="nobody" suppresses presence broadcast to friends
  PV-10  Setting privacy back to "everyone" restores broadcasts
  PV-11  last_seen is returned to friends unless privacy_last_seen="nobody"
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secchat_testlib import (
    wait_ready, db_reset, unique,
    ChatClient, make_friends, ws_send, recv_until,
)


def _expect(c: ChatClient, type_: str, timeout: float = 3.0) -> dict:
    msg = recv_until(c.sock, lambda m: m.get("type") == type_, timeout=timeout)
    assert msg is not None, f"no {type_} response"
    return msg


def _expect_any(c: ChatClient, types: tuple, timeout: float = 3.0) -> dict:
    msg = recv_until(c.sock, lambda m: m.get("type") in types, timeout=timeout)
    assert msg is not None, f"no response in {types}"
    return msg


def _get_privacy(c: ChatClient) -> dict:
    ws_send(c.sock, {"type": "get_privacy"})
    return _expect(c, "privacy_settings")


class TestPrivacy(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        wait_ready()
        db_reset()

    # --- defaults & roundtrip ---

    def test_PV1_defaults_everyone(self):
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            r = _get_privacy(c)
            self.assertEqual(r["privacy_online"], "everyone")
            self.assertEqual(r["privacy_last_seen"], "everyone")
            self.assertNotIn("privacy_read_receipt", r)

    def test_PV2_update_online_friends_persists(self):
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            ws_send(c.sock, {"type": "update_privacy",
                              "privacy_online": "friends"})
            ok = _expect_any(c, ("ok", "error"))
            self.assertEqual(ok.get("type"), "ok")
            r = _get_privacy(c)
            self.assertEqual(r["privacy_online"], "friends")

    def test_PV3_update_both_fields(self):
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            ws_send(c.sock, {"type": "update_privacy",
                              "privacy_online": "nobody",
                              "privacy_last_seen": "friends"})
            ok = _expect_any(c, ("ok", "error"))
            self.assertEqual(ok.get("type"), "ok")
            r = _get_privacy(c)
            self.assertEqual(r["privacy_online"], "nobody")
            self.assertEqual(r["privacy_last_seen"], "friends")

    # --- validation rejections ---

    def test_PV4_empty_body_is_error(self):
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            ws_send(c.sock, {"type": "update_privacy"})
            r = _expect_any(c, ("ok", "error"))
            self.assertEqual(r.get("type"), "error")

    def test_PV5_bad_online_is_error(self):
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            ws_send(c.sock, {"type": "update_privacy",
                              "privacy_online": "bogus"})
            r = _expect_any(c, ("ok", "error"))
            self.assertEqual(r.get("type"), "error")

    def test_PV6_bad_last_seen_is_error(self):
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            ws_send(c.sock, {"type": "update_privacy",
                              "privacy_last_seen": "always"})
            r = _expect_any(c, ("ok", "error"))
            self.assertEqual(r.get("type"), "error")

    def test_PV7_read_receipt_privacy_is_removed(self):
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            ws_send(c.sock, {"type": "update_privacy",
                              "privacy_read_receipt": "private"})
            r = _expect_any(c, ("ok", "error"))
            self.assertEqual(r.get("type"), "error")
            self.assertIn("not supported", r.get("msg", "").lower())

    # --- partial updates ---

    def test_PV8_partial_update_preserves_other_fields(self):
        with ChatClient() as c:
            c.register_and_login(unique("alice"))
            # First set both supported fields to "friends"
            ws_send(c.sock, {"type": "update_privacy",
                              "privacy_online": "friends",
                              "privacy_last_seen": "friends"})
            _expect_any(c, ("ok", "error"))
            # Then update only privacy_online
            ws_send(c.sock, {"type": "update_privacy",
                              "privacy_online": "nobody"})
            ok = _expect_any(c, ("ok", "error"))
            self.assertEqual(ok.get("type"), "ok")
            r = _get_privacy(c)
            self.assertEqual(r["privacy_online"], "nobody")
            self.assertEqual(r["privacy_last_seen"], "friends")

    # --- broadcast suppression ---

    def test_PV9_online_nobody_suppresses_presence(self):
        # Alice sets privacy_online=nobody, then logs out + back in.
        # Bob (her friend) should NOT receive a presence broadcast.
        alice_name = unique("alice")
        a = ChatClient(); a.register_and_login(alice_name)
        b = ChatClient(); b.register_and_login(unique("bob"))
        try:
            make_friends(a.sock, a.user_id, b.sock, b.user_id)
            ws_send(a.sock, {"type": "update_privacy",
                              "privacy_online": "nobody"})
            _expect_any(a, ("ok", "error"))

            # Drain bob's queue of any pending traffic.
            recv_until(b.sock, lambda m: False, timeout=0.5)

            # Re-login alice — kick a, login a2.
            ws_send(a.sock, {"type": "logout"})
            recv_until(a.sock, lambda m: m.get("type") == "ok", timeout=2.0)
            ws_send(a.sock, {"type": "logout"})
            recv_until(a.sock, lambda m: m.get("type") == "ok", timeout=2.0)
            a.close()
            a2 = ChatClient(); a2.login(alice_name, "Pw!12345")
            try:
                # Bob should NOT see a presence broadcast within 2s.
                got = recv_until(
                    b.sock,
                    lambda m: m.get("type") == "presence"
                              and m.get("user_id") == a2.user_id,
                    timeout=2.0,
                )
                self.assertIsNone(got,
                                  "presence broadcast leaked despite privacy_online=nobody")
            finally:
                a2.close()
        finally:
            b.close()

    def test_PV10_everyone_restores_broadcast(self):
        alice_name = unique("alice")
        a = ChatClient(); a.register_and_login(alice_name)
        b = ChatClient(); b.register_and_login(unique("bob"))
        try:
            make_friends(a.sock, a.user_id, b.sock, b.user_id)
            # Set to nobody, then back to everyone.
            for value in ("nobody", "everyone"):
                ws_send(a.sock, {"type": "update_privacy",
                                  "privacy_online": value})
                _expect_any(a, ("ok", "error"))

            recv_until(b.sock, lambda m: False, timeout=0.5)

            a.close()
            a2 = ChatClient(); a2.login(alice_name, "Pw!12345")
            try:
                got = recv_until(
                    b.sock,
                    lambda m: m.get("type") == "presence"
                              and m.get("user_id") == a2.user_id
                              and m.get("status") == "online",
                    timeout=3.0,
                )
                self.assertIsNotNone(got,
                                      "presence broadcast did not arrive after privacy_online=everyone")
            finally:
                a2.close()
        finally:
            b.close()

    def test_PV11_last_seen_privacy_applies_to_friend_list(self):
        alice_name = unique("alice")
        a = ChatClient(); a.register_and_login(alice_name)
        b = ChatClient(); b.register_and_login(unique("bob"))
        try:
            make_friends(a.sock, a.user_id, b.sock, b.user_id)
            ws_send(a.sock, {"type": "logout"})
            recv_until(a.sock, lambda m: m.get("type") == "ok", timeout=2.0)
            a.close()
            ws_send(b.sock, {"type": "get_friends"})
            friends = recv_until(
                b.sock,
                lambda m: m.get("type") == "friends_list",
                timeout=4.0,
            )
            self.assertIsNotNone(friends)
            alice = next(f for f in friends["friends"] if f["id"] == a.user_id)
            self.assertEqual(alice["status"], "offline")
            self.assertTrue(alice.get("last_seen"))
        finally:
            b.close()

        a2 = ChatClient(); a2.login(alice_name, "Pw!12345")
        b2 = ChatClient(); b2.login(b.username, "Pw!12345")
        try:
            ws_send(a2.sock, {"type": "update_privacy",
                              "privacy_last_seen": "nobody"})
            _expect_any(a2, ("ok", "error"))
            ws_send(a2.sock, {"type": "logout"})
            recv_until(a2.sock, lambda m: m.get("type") == "ok", timeout=2.0)
            a2.close()
            ws_send(b2.sock, {"type": "get_friends"})
            friends = recv_until(
                b2.sock,
                lambda m: m.get("type") == "friends_list",
                timeout=4.0,
            )
            self.assertIsNotNone(friends)
            alice = next(f for f in friends["friends"] if f["id"] == a.user_id)
            self.assertEqual(alice.get("last_seen", ""), "")
        finally:
            b2.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
