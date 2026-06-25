#!/usr/bin/env python3
"""Smoke tests for SecChat formal verification assets."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest


HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


class FormalVerificationAssetsTest(unittest.TestCase):
    def test_model_and_runner_are_present(self) -> None:
        self.assertTrue(os.path.exists(
            os.path.join(REPO, "formal", "proverif", "secchat_dm.pv")))
        self.assertTrue(os.path.exists(
            os.path.join(REPO, "tools", "run_formal_verification.py")))

    def test_runner_executes_or_skips_cleanly(self) -> None:
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO, "tools", "run_formal_verification.py")],
            cwd=REPO,
            text=True,
            capture_output=True,
            timeout=120,
        )
        self.assertEqual(
            proc.returncode, 0,
            msg=f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
