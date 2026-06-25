"""
test_http_control.py — HTTP control plane (/healthz, /readyz, /metrics).

Covers:
  HC-1  /healthz returns 200 "ok"
  HC-2  /readyz returns 200 "ok" while DB is up
  HC-3  /metrics returns 200 with valid JSON
  HC-4  /metrics has all required top-level sections
  HC-5  /metrics histograms have all 12 buckets
  HC-6  Counters are monotonic across two snapshots
  HC-7  uptime_s increases between two snapshots
  HC-8  Unknown HTTP path returns non-200
"""

from __future__ import annotations

import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secchat_testlib import (
    wait_ready, db_reset, http_get, get_metrics,
)


REQUIRED_SECTIONS = [
    "uptime_s", "connections", "auth", "messages", "groups", "reactions",
    "io", "database", "security", "system", "latency",
]

REQUIRED_LATENCY_HISTOGRAMS = ["auth", "msg", "db", "ws_recv", "group"]

EXPECTED_BUCKETS = [
    "100us", "250us", "500us", "1ms", "2.5ms", "5ms",
    "10ms", "25ms", "50ms", "100ms", "1s", "inf",
]


class TestHttpControl(unittest.TestCase):

    def test_HC1_healthz_200(self):
        status, body = http_get("/healthz")
        self.assertEqual(status, 200)
        self.assertIn("ok", body.lower())

    def test_HC2_readyz_200(self):
        status, body = http_get("/readyz")
        self.assertEqual(status, 200)
        self.assertIn("ok", body.lower())

    def test_HC3_metrics_returns_valid_json(self):
        status, body = http_get("/metrics")
        self.assertEqual(status, 200)
        try:
            doc = json.loads(body)
        except json.JSONDecodeError as e:
            self.fail(f"/metrics body is not valid JSON: {e}\n{body[:200]}")
        self.assertIsInstance(doc, dict)

    def test_HC4_metrics_has_required_sections(self):
        m = get_metrics()
        for section in REQUIRED_SECTIONS:
            self.assertIn(section, m, f"missing top-level section: {section}")

    def test_HC5_latency_histograms_have_12_buckets(self):
        m = get_metrics()
        latency = m.get("latency", {})
        for hist_name in REQUIRED_LATENCY_HISTOGRAMS:
            self.assertIn(hist_name, latency, f"missing histogram: {hist_name}")
            buckets = latency[hist_name].get("buckets", [])
            self.assertEqual(len(buckets), 12,
                             f"{hist_name} has {len(buckets)} buckets, expected 12")
            labels = [b["le"] for b in buckets]
            self.assertEqual(labels, EXPECTED_BUCKETS,
                             f"{hist_name} bucket labels mismatch: {labels}")

    def test_HC6_counters_monotonic(self):
        before = get_metrics()
        # Hit /metrics twice (with delay) to give some time for activity
        time.sleep(0.5)
        after = get_metrics()

        def _get(d: dict, path: str) -> int:
            for k in path.split("."):
                d = d[k]
            return d

        # All these counters can only ever increase.
        for path in [
            "connections.accepted", "auth.ok", "auth.fail", "auth.registers",
            "messages.sent", "messages.edited", "messages.deleted",
            "groups.created", "reactions.added",
            "io.ws_frames_recv", "io.ws_frames_sent",
            "database.queries",
        ]:
            self.assertGreaterEqual(
                _get(after, path), _get(before, path),
                f"{path} decreased: before={_get(before, path)} "
                f"after={_get(after, path)}",
            )

    def test_HC7_uptime_increases(self):
        before = get_metrics()
        time.sleep(1.1)
        after = get_metrics()
        self.assertGreater(after["uptime_s"], before["uptime_s"],
                           "uptime_s did not increase across 1s sleep")

    def test_HC8_unknown_path_not_200(self):
        status, _ = http_get("/this-path-does-not-exist")
        # The control plane is deliberately narrow; accept anything that
        # isn't a 200 (404 / 400 / 501 are all reasonable).
        self.assertNotEqual(status, 200)


if __name__ == "__main__":
    wait_ready()
    db_reset()
    unittest.main(verbosity=2)
