#!/usr/bin/env python3
"""Server GUI regression tests."""

from __future__ import annotations

import os
import sys
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from PyQt5.QtWidgets import QApplication  # noqa: E402

from server_gui import ServerGUI  # noqa: E402


class ServerGuiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_api_coverage_tab_is_removed(self) -> None:
        win = ServerGUI()
        try:
            labels = [
                win._tabs.tabText(i)
                for i in range(win._tabs.count())
            ]
            self.assertEqual(labels, ["Logs", "Metrics"])
            self.assertNotIn("API Coverage", labels)
        finally:
            win.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
