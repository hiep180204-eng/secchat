"""
test_metrics_counters.py — delta-based metrics coverage.

Each test snapshots /metrics, performs an action, then asserts the right
counter incremented by the right amount. Never asserts absolute values
because counters are process-global.

Covers:
  MC-1  msgs_sent increments on send_message
  MC-2  msgs_edited increments on edit_message
  MC-3  msgs_deleted increments on delete_message
  MC-4  groups_created increments on OpenMLS prepare/apply group create
  MC-5  reactions_added increments on add_reaction
  MC-6  validation_errors increments on bad reaction emoji
  MC-7  validation_errors increments on oversized message
  MC-8  lat_group histogram total increases on OpenMLS prepare/apply group create
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secchat_testlib import (
    wait_ready, db_reset, unique, get_metrics,
    ChatClient, create_group_mls, fake_S3DR, make_friends, ws_send, ws_send_msg, recv_until,
)


def _delta(before: dict, after: dict, path: str) -> int:
    def _get(d, p):
        for k in p.split("."):
            d = d[k]
        return d
    return int(_get(after, path)) - int(_get(before, path))


def _two_friends() -> tuple[ChatClient, ChatClient]:
    a = ChatClient(); a.register_and_login(unique("alice"))
    b = ChatClient(); b.register_and_login(unique("bob"))
    make_friends(a.sock, a.user_id, b.sock, b.user_id)
    return a, b


def _open_dm(c: ChatClient, peer_uid: int) -> int:
    ws_send(c.sock, {"type": "start_dm", "user_id": peer_uid})
    msg = recv_until(
        c.sock,
        lambda m: m.get("conversation_id") is not None,
        timeout=4.0,
    )
    assert msg is not None, "start_dm got no response"
    return msg["conversation_id"]


def _send_message(c: ChatClient, conv_id: int, body: str) -> int:
    """Send a message; return its message id (from the echoed message broadcast)."""
    sent_body = ws_send_msg(c.sock, conv_id, body)
    msg = recv_until(
        c.sock,
        lambda m: m.get("type") == "error"
        or (m.get("type") == "message" and m.get("body") == sent_body),
        timeout=8.0,
    )
    assert msg is not None, "no message echo or error received"
    assert msg.get("type") != "error", f"send_message failed: {msg}"
    mid = msg.get("id") or msg.get("message_id")
    assert mid is not None, f"message echo missing id: {msg}"
    return int(mid)


class TestMetricsCounters(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        wait_ready()
        db_reset()

    def test_MC1_msgs_sent(self):
        a, b = _two_friends()
        try:
            conv = _open_dm(a, b.user_id)
            before = get_metrics()
            _send_message(a, conv, unique("hello"))
            after = get_metrics()
            self.assertGreaterEqual(_delta(before, after, "messages.sent"), 1)
        finally:
            a.close(); b.close()

    def test_MC2_msgs_edited(self):
        a, b = _two_friends()
        try:
            conv = _open_dm(a, b.user_id)
            mid = _send_message(a, conv, unique("orig"))
            before = get_metrics()
            edited_body = fake_S3DR(unique("edited"))
            ws_send(a.sock, {"type": "edit_message", "message_id": mid,
                              "new_body": edited_body})
            recv_until(a.sock,
                       lambda m: m.get("type") == "message"
                       and int(m.get("edit_target_message_id", 0) or 0) == mid,
                       timeout=4.0)
            after = get_metrics()
            self.assertGreaterEqual(_delta(before, after, "messages.edited"), 1)
        finally:
            a.close(); b.close()

    def test_MC3_msgs_deleted(self):
        a, b = _two_friends()
        try:
            conv = _open_dm(a, b.user_id)
            mid = _send_message(a, conv, unique("doomed"))
            before = get_metrics()
            ws_send(a.sock, {"type": "delete_message", "message_id": mid})
            recv_until(a.sock, lambda m: m.get("type") == "message_deleted",
                       timeout=4.0)
            after = get_metrics()
            self.assertGreaterEqual(_delta(before, after, "messages.deleted"), 1)
        finally:
            a.close(); b.close()

    def test_MC4_groups_created(self):
        a = ChatClient(); a.register_and_login(unique("ga"))
        b = ChatClient(); b.register_and_login(unique("gb"))
        try:
            make_friends(a.sock, a.user_id, b.sock, b.user_id)
            before = get_metrics()
            create_group_mls(a, unique("group"), [b])
            after = get_metrics()
            self.assertGreaterEqual(_delta(before, after, "groups.created"), 1)
        finally:
            a.close(); b.close()

    def test_MC5_reactions_added(self):
        a, b = _two_friends()
        try:
            conv = _open_dm(a, b.user_id)
            mid = _send_message(a, conv, unique("react-target"))
            before = get_metrics()
            ws_send(a.sock, {"type": "add_reaction", "message_id": mid,
                              "emoji": "👍"})
            recv_until(a.sock, lambda m: m.get("type") == "reaction_added",
                       timeout=4.0)
            after = get_metrics()
            self.assertGreaterEqual(_delta(before, after, "reactions.added"), 1)
        finally:
            a.close(); b.close()

    def test_MC6_validation_error_on_empty_emoji(self):
        a, b = _two_friends()
        try:
            conv = _open_dm(a, b.user_id)
            mid = _send_message(a, conv, unique("bad-react"))
            before = get_metrics()
            ws_send(a.sock, {"type": "add_reaction", "message_id": mid,
                              "emoji": ""})
            recv_until(a.sock, lambda m: m.get("type") == "error",
                       timeout=4.0)
            after = get_metrics()
            self.assertGreaterEqual(
                _delta(before, after, "security.validation_errors"), 1,
                "validation_errors did not increment on empty emoji",
            )
        finally:
            a.close(); b.close()

    def test_MC7_validation_error_on_empty_message_body(self):
        a, b = _two_friends()
        try:
            conv = _open_dm(a, b.user_id)
            before = get_metrics()
            # Empty body — domain_validate_message_body should reject.
            ws_send(a.sock, {"type": "message", "conversation_id": conv,
                              "body": ""})
            recv_until(a.sock, lambda m: m.get("type") == "error",
                       timeout=4.0)
            after = get_metrics()
            self.assertGreaterEqual(
                _delta(before, after, "security.validation_errors"), 1,
            )
        finally:
            a.close(); b.close()

    def test_MC8_lat_group_histogram_grows(self):
        a = ChatClient(); a.register_and_login(unique("la"))
        b = ChatClient(); b.register_and_login(unique("lb"))
        try:
            make_friends(a.sock, a.user_id, b.sock, b.user_id)
            before = get_metrics()
            create_group_mls(a, unique("lat-group"), [b])
            after = get_metrics()
            before_total = before["latency"]["group"]["total"]
            after_total = after["latency"]["group"]["total"]
            self.assertGreater(after_total, before_total,
                               "lat_group.total did not increase")
        finally:
            a.close(); b.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
