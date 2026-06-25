#!/usr/bin/env python3
"""Điểm vào của client SecChat (ứng dụng PyQt).

Chạy bằng:  python3 main.py
Khởi tạo QApplication, nạp font, rồi mở cửa sổ chính ``App``.
"""

import sys
import platform
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui     import QFont, QFontDatabase
from client.app import App


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("SecChat")

    # Pick a font family that exists on the current OS and has CJK+Vietnamese glyphs
    if platform.system() == "Windows":
        families = ["Segoe UI", "Microsoft YaHei", "Arial"]
    else:
        # Linux / Docker — Noto Sans CJK installed via Dockerfile
        for path in [
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        ]:
            QFontDatabase.addApplicationFont(path)
        families = ["Noto Sans CJK SC", "Noto Sans", "Liberation Sans", "DejaVu Sans"]

    # Use the first available family
    font = QFont()
    font.setFamilies(families) if hasattr(font, 'setFamilies') else font.setFamily(families[0])
    font.setPointSize(10)
    font.setHintingPreference(QFont.PreferFullHinting)
    app.setFont(font)

    window = App()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
