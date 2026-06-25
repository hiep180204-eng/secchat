"""
test_rate_limit.py — per-user token-bucket rate limiter.

Server parameters (infra/ratelimit.c):
  CAPACITY = 10   — max burst
  REFILL   = 1/s  — one token per second

  RL-1   10 messages in a row all succeed
  RL-2   11th message is rejected with an error
  RL-3   After waiting 1 second a token is replenished (can send again)
  RL-4   A second user has an independent bucket (not throttled by first user)

Note: time.sleep(1) is intentional here — replenishment is tested and
requires waiting for the server's real-time refill cycle.
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
    msg = recv_until(c.sock,
                     lambda m: m.get("conversation_id") is not None
                     or m.get("type") == "error",
                     timeout=8.0)
    assert msg is not None, "start_dm got no response"
    assert msg.get("type") != "error", f"start_dm failed: {msg}"
    return msg["conversation_id"]


def _send_and_collect(c: ChatClient, conv: int, body: str, timeout: float = 3.0) -> dict:
    """Send a message and return the first ok/error/message response."""
    ws_send_msg(c.sock, conv, body)
    resp = recv_until(c.sock,
                      lambda m: m.get("type") in ("message", "ok", "error"),
                      timeout=timeout)
    return resp


class TestRateLimit(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        wait_ready()
        db_reset()
        # The preceding integration files may leave the in-memory token bucket
        # partially depleted; DB reset does not reset that server-side state.
        # Wait for a full bucket refill so user-id reuse after TRUNCATE cannot
        # leak state from earlier files in a full-suite run.
        time.sleep(11.0)

    def _make_pair(self):
        """Return (alice, bob, conv_id) as a fully set-up DM."""
        alice = ChatClient(); alice.register_and_login(unique("alice"))
        bob   = ChatClient(); bob.register_and_login(unique("bob"))
        make_friends(alice.sock, alice.user_id, bob.sock, bob.user_id)
        conv = _open_dm(alice, bob.user_id)
        # Drain bob's side
        recv_until(bob.sock, lambda m: False, timeout=0.3)
        return alice, bob, conv

    def test_RL1_burst_of_10_allowed(self):
        alice, bob, conv = self._make_pair()
        try:
            for i in range(10):
                r = _send_and_collect(alice, conv, f"burst{i}")
                self.assertNotEqual(r.get("type"), "error",
                                    f"message {i} should not be rate-limited")
        finally:
            alice.close(); bob.close()

    def test_RL2_eleventh_message_rejected(self):
        alice, bob, conv = self._make_pair()
        try:
            # Fire 25 messages without pausing for echoes so the rate limiter
            # is certain to be exhausted even if a few tokens refill server-side.
            for i in range(25):
                ws_send_msg(alice.sock, conv, f"tok{i}")
            # Drain all 25 responses; at least one must be a rate-limit error.
            errors = []
            for _ in range(25):
                r = recv_until(alice.sock,
                               lambda m: m.get("type") in ("message", "error"),
                               timeout=3.0)
                if r and r.get("type") == "error":
                    errors.append(r)
            self.assertGreaterEqual(len(errors), 1,
                                    "at least one of 11 rapid messages should be rate-limited")
            self.assertTrue(any("rate" in e.get("msg", "").lower() for e in errors),
                            "rate-limit error should mention 'rate'")
        finally:
            alice.close(); bob.close()

    def test_RL3_replenishment_after_1s(self):
        alice, bob, conv = self._make_pair()
        try:
            # Exhaust all 10 tokens
            for i in range(10):
                _send_and_collect(alice, conv, f"exhaust{i}")

            # Wait for 1 token to refill
            time.sleep(1.1)

            # Should now be able to send 1 more
            r = _send_and_collect(alice, conv, "after-refill")
            self.assertNotEqual(r.get("type"), "error",
                                "message after 1s wait should succeed (token refilled)")
        finally:
            alice.close(); bob.close()

    def test_RL4_per_user_isolation(self):
        alice, bob, conv_ab = self._make_pair()
        carol = ChatClient(); carol.register_and_login(unique("carol"))
        try:
            make_friends(alice.sock, alice.user_id, carol.sock, carol.user_id)
            conv_ac = _open_dm(alice, carol.user_id)
            recv_until(carol.sock, lambda m: False, timeout=0.3)

            # Exhaust alice's bucket
            for i in range(10):
                _send_and_collect(alice, conv_ab, f"a{i}")

            # Bob → carol DM: bob has his own full bucket
            make_friends(bob.sock, bob.user_id, carol.sock, carol.user_id)
            conv_bc = _open_dm(bob, carol.user_id)
            recv_until(carol.sock, lambda m: False, timeout=0.3)

            r = _send_and_collect(bob, conv_bc, "bob-first-msg")
            self.assertNotEqual(r.get("type"), "error",
                                "bob's bucket is independent of alice's — should not be throttled")
        finally:
            alice.close(); bob.close(); carol.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
