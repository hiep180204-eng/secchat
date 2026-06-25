#!/usr/bin/env python3

import json
import os
import subprocess
import sys
import threading
from datetime import datetime, timedelta

from PyQt5.QtCore import QObject, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QTextCursor
from PyQt5.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

try:
    from client.components.scrolling import set_plain_text_preserve_scroll
except ModuleNotFoundError:
    def set_plain_text_preserve_scroll(view: QTextEdit, text: str):
        bar = view.verticalScrollBar()
        old_max = max(1, bar.maximum())
        old_value = bar.value()
        at_bottom = old_value >= bar.maximum() - 4
        ratio = old_value / old_max

        view.setPlainText(text)

        new_bar = view.verticalScrollBar()
        if at_bottom:
            new_bar.setValue(new_bar.maximum())
        else:
            new_bar.setValue(min(new_bar.maximum(), int(new_bar.maximum() * ratio)))


class Bridge(QObject):
    sig_line = pyqtSignal(str)
    sig_done = pyqtSignal(int)


class ServerProcess:
    def __init__(self, bridge: Bridge):
        self._bridge = bridge
        self._proc = None
        self.running = False

    def start(self):
        here = os.path.dirname(os.path.abspath(__file__))
        binary = os.path.join(here, "server.exe" if sys.platform == "win32" else "server")
        if not os.path.exists(binary):
            self._bridge.sig_line.emit(f"[ERROR] Binary not found: {binary}")
            return False
        try:
            kw = {}
            if sys.platform == "win32":
                kw["creationflags"] = subprocess.CREATE_NEW_CONSOLE
            self._proc = subprocess.Popen(
                [binary],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                **kw,
            )
            self.running = True
            threading.Thread(target=self._reader, daemon=True).start()
            return True
        except Exception as exc:
            self._bridge.sig_line.emit(f"[ERROR] Cannot launch server: {exc}")
            return False

    def stop(self):
        self.running = False
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                self._proc.kill()
            self._proc = None

    def _reader(self):
        for line in self._proc.stdout:
            line = line.rstrip()
            print(line, flush=True)
            self._bridge.sig_line.emit(line)
        rc = self._proc.wait()
        self.running = False
        self._bridge.sig_done.emit(rc)


CSS = """
QMainWindow,QWidget { background:#2f3136; color:#dcddde; }
QPushButton          { background:#5865f2; color:#fff; border:none;
                       border-radius:4px; padding:10px 22px;
                       font-size:14px; font-weight:700; }
QPushButton:hover    { background:#4752c4; }
QPushButton#stop     { background:#ed4245; }
QPushButton#stop:hover { background:#c03537; }
QTextEdit            { background:#1e2124; color:#b5bac1; border:none;
                       font-family:Consolas,monospace; font-size:13px; }
QFrame#info          { background:#23272a; border-radius:6px; padding:2px; }
QTabWidget::pane     { border:none; background:#2f3136; }
QTabBar::tab         { background:#23272a; color:#b5bac1; padding:6px 18px;
                       border-radius:4px 4px 0 0; margin-right:2px; }
QTabBar::tab:selected { background:#5865f2; color:#fff; }
QTabBar::tab:hover    { background:#4752c4; color:#fff; }
"""

METRICS_FILE = "/tmp/chat_metrics.json"


class ServerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecChat Server")
        self.resize(920, 640)
        self.setStyleSheet(CSS)

        self._bridge = Bridge()
        self._server = ServerProcess(self._bridge)

        self._bridge.sig_line.connect(self._on_line)
        self._bridge.sig_done.connect(self._on_done)

        self._build()

        # Cho phép mở GUI trực tiếp ở tab Metrics (đặt SECCHAT_GUI_TAB=metrics).
        # Dùng khi chụp ảnh màn hình quan sát vận hành cho báo cáo.
        if (os.environ.get("SECCHAT_GUI_TAB") or "").strip().lower() == "metrics":
            self._tabs.setCurrentWidget(self.metrics_view)

        # Auto-start the C server when running inside a Docker container.
        if os.path.isdir("/certs") or os.environ.get("DB_HOST"):
            self._start()

    def _build(self):
        root = QWidget()
        self.setCentralWidget(root)
        lay = QVBoxLayout(root)
        lay.setContentsMargins(18, 18, 18, 18)
        lay.setSpacing(10)

        hl = QHBoxLayout()
        title = QLabel("SecChat Server")
        title.setStyleSheet("color:#fff; font-size:20px; font-weight:700;")
        hl.addWidget(title)
        hl.addStretch()
        self.lbl_status = QLabel("STOPPED")
        self._status(False)
        hl.addWidget(self.lbl_status)
        lay.addLayout(hl)

        info = QFrame()
        info.setObjectName("info")
        il = QHBoxLayout(info)
        il.setContentsMargins(12, 6, 12, 6)
        for k, v in [
            ("WebSocket", "wss://localhost:8888"),
            ("VNC", "localhost:5900  pw:docker"),
            ("DB", "MySQL / chatdb"),
            ("Max clients", "200"),
        ]:
            il.addWidget(QLabel(f"<b style='color:#5865f2'>{k}:</b> {v}"))
        il.addStretch()
        lay.addWidget(info)

        self._tabs = QTabWidget()

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self._tabs.addTab(self.log, "Logs")

        self.metrics_view = QTextEdit()
        self.metrics_view.setReadOnly(True)
        self.metrics_view.setFont(QFont("Consolas", 11))
        self.metrics_view.setPlainText("Metrics will appear here once the server starts...")
        self._tabs.addTab(self.metrics_view, "Metrics")

        lay.addWidget(self._tabs)

        self._metrics_timer = QTimer(self)
        self._metrics_timer.setInterval(2000)
        self._metrics_timer.timeout.connect(self._refresh_metrics)
        self._metrics_timer.start()

        br = QHBoxLayout()
        self.btn_start = QPushButton("Start Server")
        self.btn_start.clicked.connect(self._start)
        br.addWidget(self.btn_start)
        self.btn_stop = QPushButton("Stop Server")
        self.btn_stop.setObjectName("stop")
        self.btn_stop.clicked.connect(self._stop)
        self.btn_stop.setEnabled(False)
        br.addWidget(self.btn_stop)
        br.addStretch()
        lay.addLayout(br)

    @staticmethod
    def _set_plain_preserve_scroll(view: QTextEdit, text: str):
        set_plain_text_preserve_scroll(view, text)

    def _refresh_metrics(self):
        if not os.path.exists(METRICS_FILE):
            return
        try:
            with open(METRICS_FILE, "r", encoding="utf-8") as f:
                metrics = json.load(f)
            self._set_plain_preserve_scroll(
                self.metrics_view, self._format_metrics(metrics))
        except Exception as exc:
            self._set_plain_preserve_scroll(
                self.metrics_view, f"Could not read metrics: {exc}")

    @staticmethod
    def _format_metrics(m: dict) -> str:
        up = m.get("uptime_s", 0)
        ups = str(timedelta(seconds=up))

        sys_ = m.get("system", {})
        conn = m.get("connections", {})
        auth = m.get("auth", {})
        msgs = m.get("messages", {})
        io = m.get("io", {})
        db = m.get("database", {})
        sec = m.get("security", {})
        lat = m.get("latency", {})

        rss_mb = sys_.get("rss_kb", 0) / 1024
        vsz_mb = sys_.get("vsz_kb", 0) / 1024
        cpu = sys_.get("cpu_pct", 0.0)

        def us_str(us):
            if us == 0:
                return "  -  "
            if us < 1000:
                return f"{us}us"
            if us < 1e6:
                return f"{us / 1000:.1f}ms"
            return f"{us / 1e6:.2f}s"

        def hist_row(label, h):
            if not h or h.get("total", 0) == 0:
                return f"  {label:<8}  (no data yet)"
            return (
                f"  {label:<8}  n={h['total']:>7,}"
                f"  avg={us_str(h['avg_us']):<8}"
                f"  p50={us_str(h['p50_us']):<8}"
                f"  p95={us_str(h['p95_us']):<8}"
                f"  p99={us_str(h['p99_us']):<8}"
            )

        width = 72
        sep = "-" * width
        top = "=" * width

        lines = [
            top,
            "  SecChat Performance Dashboard",
            f"  Uptime: {ups:<20}  CPU: {cpu:.1f}%",
            f"  RSS: {rss_mb:.1f} MB            VSZ: {vsz_mb:.1f} MB",
            top,
            "",
            "  CONNECTIONS",
            sep,
            f"  Accepted : {conn.get('accepted', 0):>10,}    Rejected : {conn.get('rejected', 0):>10,}",
            f"  Active   : {conn.get('active', 0):>10,}    Peak     : {conn.get('peak', 0):>10,}",
            "",
            "  AUTHENTICATION",
            sep,
            f"  Success  : {auth.get('ok', 0):>10,}    Failed   : {auth.get('fail', 0):>10,}",
            f"  RateLimit: {auth.get('ratelimited', 0):>10,}    Registers: {auth.get('registers', 0):>10,}",
            "",
            "  MESSAGES",
            sep,
            f"  Sent     : {msgs.get('sent', 0):>10,}    Oversized: {msgs.get('oversized', 0):>10,}",
            f"  Searches : {msgs.get('searches', 0):>10,}    SrchLimit: {msgs.get('search_ratelimited', 0):>10,}",
            "",
            "  NETWORK I/O",
            sep,
            f"  Frames in : {io.get('ws_frames_recv', 0):>9,}    Bytes in : {io.get('ws_bytes_recv', 0) / 1024:>9.1f} KB",
            f"  Frames out: {io.get('ws_frames_sent', 0):>9,}    Bytes out: {io.get('ws_bytes_sent', 0) / 1024:>9.1f} KB",
            "",
            "  DATABASE",
            sep,
            f"  Queries  : {db.get('queries', 0):>10,}    Errors   : {db.get('errors', 0):>10,}",
            "",
            "  SECURITY",
            sep,
            f"  Pre-auth timeouts: {sec.get('preauth_timeouts', 0):,}",
            "",
            "  LATENCY HISTOGRAMS",
            sep,
            hist_row("Auth", lat.get("auth")),
            hist_row("Message", lat.get("msg")),
            hist_row("DB", lat.get("db")),
            hist_row("WS Recv", lat.get("ws_recv")),
            "",
            top,
            f"  Refreshed: {datetime.now().strftime('%H:%M:%S')}",
        ]
        return "\n".join(lines)

    def _start(self):
        self._log("--- Starting server ---")
        if self._server.start():
            self._status(True)
            self.btn_start.setEnabled(False)
            self.btn_stop.setEnabled(True)

    def _stop(self):
        self._server.stop()
        self._log("--- Server stopped ---")
        self._status(False)
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)

    def _on_line(self, line: str):
        self._log(line)

    def _on_done(self, rc: int):
        self._log(f"--- Server exited (code {rc}) ---")
        self._status(False)
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)

    def _log(self, text: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.append(f'<span style="color:#5865f2">[{ts}]</span> {text}')
        self.log.moveCursor(QTextCursor.End)

    def _status(self, running: bool):
        if running:
            self.lbl_status.setStyleSheet("color:#57f287; font-weight:700;")
            self.lbl_status.setText("RUNNING")
        else:
            self.lbl_status.setStyleSheet("color:#ed4245; font-weight:700;")
            self.lbl_status.setText("STOPPED")

    def closeEvent(self, ev):
        self._server.stop()
        ev.accept()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("SecChat")
    app.setFont(QFont("Liberation Sans", 10))
    window = ServerGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
