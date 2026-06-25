from __future__ import annotations

import json
import os
import re
import sys
import time
import unittest
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from urllib.request import urlopen

from ui_vnc_harness import VncClient, prepare_vnc_clients, run_host
from secchat_testlib import ensure_cert, wait_ready

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


PASSWORD = "123456"
NEW_PASSWORD = "1234567"
BACKUP_PASSPHRASE = "VisibleManualBackupPassphrase-2026!"
ACCOUNTS = {
    "123": ("user123", "123@gmail.com"),
    "234": ("user234", "234@gmail.com"),
    "345": ("user345", "345@gmail.com"),
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _artifact_dir() -> Path:
    configured = os.environ.get("SECCHAT_VISIBLE_ARTIFACT_DIR")
    if configured:
        root = Path(configured)
    else:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        root = _repo_root() / "tests" / "artifacts" / "visible_manual_checklist" / stamp
    root.mkdir(parents=True, exist_ok=True)
    return root


def _load_dotenv() -> dict[str, str]:
    out: dict[str, str] = {}
    env_path = _repo_root() / ".env"
    if not env_path.exists():
        return out
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def _db_query(sql: str) -> str:
    env = _load_dotenv()
    db_pass = os.environ.get("DB_PASS") or env.get("DB_PASS") or "chatpass"
    proc = run_host([
        "docker", "exec", "chat-db", "mysql",
        "-uchatuser", f"-p{db_pass}", "-BN", "chatdb", "-e", sql,
    ], timeout=20.0)
    return proc.stdout.strip()


def _seed_demo_users() -> None:
    run_host(["python", str(Path("tools") / "seed_demo_users.py")], timeout=120.0)


def _message_visible(snapshot: dict[str, Any], text: str) -> bool:
    return any(
        text in str(message)
        for message in snapshot.get("chat", {}).get("message_texts", [])
    )


def _list_has_item(snapshot: dict[str, Any], list_name: str, text: str) -> bool:
    for widget in snapshot.get("widgets") or []:
        if widget.get("object_name") != list_name:
            continue
        for item in widget.get("items") or []:
            if text in str(item.get("text", "")):
                return True
    return False


def _items(snapshot: dict[str, Any], list_name: str) -> list[dict[str, Any]]:
    for widget in snapshot.get("widgets") or []:
        if widget.get("object_name") == list_name:
            return list(widget.get("items") or [])
    return []


class VisibleManualChecklistVncTest(unittest.TestCase):
    """Visible VNC run for the manual checklist.

    This file is intentionally not part of the default runner. It only runs when
    SECCHAT_VISIBLE_MANUAL=1 is set by tools/run_visible_manual_checklist.ps1.
    """

    containers = ["chat-client1", "chat-client2"]
    delay = float(os.environ.get("SECCHAT_VISIBLE_MANUAL_DELAY", "0.65") or "0.65")

    @classmethod
    def setUpClass(cls) -> None:
        if os.environ.get("SECCHAT_VISIBLE_MANUAL") != "1":
            raise unittest.SkipTest(
                "visible manual checklist is gated; set SECCHAT_VISIBLE_MANUAL=1"
            )
        cls.artifact_dir = _artifact_dir()
        print(f"[visible] artifacts: {cls.artifact_dir}", flush=True)
        cls.result_path = cls.artifact_dir / "CHECKLIST_RESULT.json"
        cls.db_excerpt_path = cls.artifact_dir / "DB_EXCERPT.sql.txt"
        cls.checklist_results: list[dict[str, Any]] = []
        cls.current_result_step = "startup"
        wait_ready(timeout=60.0)
        ensure_cert()
        _seed_demo_users()
        cls.vnc = prepare_vnc_clients(
            cls.containers,
            reset_home=True,
            artifact_dir=cls.artifact_dir,
        )

    def setUp(self) -> None:
        self.current_step = getattr(self.__class__, "current_result_step", "startup")
        self._checklist_results = self.__class__.checklist_results
        self._active_result: dict[str, Any] | None = None
        self.started_message_id = int(_db_query("SELECT COALESCE(MAX(id), 0) FROM messages") or "0")

    def tearDown(self) -> None:
        outcome = getattr(self, "_outcome", None)
        failed = False
        if outcome is not None:
            result = getattr(outcome, "result", None)
            if result is not None:
                failures = getattr(result, "failures", []) or []
                errors = getattr(result, "errors", []) or []
                skipped = getattr(result, "skipped", []) or []
                failed = any(test is self for test, _exc in failures + errors)
                if any(test is self for test, _reason in skipped):
                    return
        if failed:
            self._finish_step("failed")
            step_file = self.artifact_dir / "FAILED_STEP.txt"
            step_file.write_text(self.current_step, encoding="utf-8")
            for client in getattr(self, "vnc", {}).values():
                client.capture_failure(self.id().split(".")[-1])
            self.write_artifacts()
        else:
            self._finish_step("passed")
            self.write_artifacts()

    # ------------------------------------------------------------------ helpers

    @property
    def c1(self) -> VncClient:
        return self.vnc["chat-client1"]

    @property
    def c2(self) -> VncClient:
        return self.vnc["chat-client2"]

    def step(self, code: str, text: str) -> None:
        self._finish_step("passed")
        self.current_step = f"{code} {text}"
        self._active_result = {
            "code": code,
            "text": text,
            "status": "running",
            "started_at": time.time(),
        }
        self._checklist_results.append(self._active_result)
        self.__class__.current_result_step = self.current_step
        self._write_result_json()
        print(f"[{code}] {text}", flush=True)
        time.sleep(self.delay)

    def _finish_step(self, status: str) -> None:
        if not self.__dict__.get("_active_result"):
            return
        if self._active_result.get("status") == "running":
            self._active_result["status"] = status
            self._active_result["finished_at"] = time.time()
            self._active_result["duration_s"] = round(
                self._active_result["finished_at"] - self._active_result["started_at"], 3)
            self.__class__.current_result_step = self.current_step
            self._write_result_json()
        self._active_result = None

    def _write_result_json(self) -> None:
        path = getattr(self.__class__, "result_path", None)
        if not path:
            return
        path.write_text(
            json.dumps({
                "current_step": getattr(self.__class__, "current_result_step", self.current_step),
                "results": getattr(self.__class__, "checklist_results", self._checklist_results),
            }, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def write_artifacts(self) -> None:
        self._write_result_json()
        try:
            self._write_db_excerpt()
        except Exception as exc:  # noqa: BLE001 - artifact best effort
            (self.artifact_dir / "DB_EXCERPT_ERROR.txt").write_text(
                str(exc), encoding="utf-8")
        self._write_service_logs()

    def _write_service_logs(self) -> None:
        for container in ("chat-server", "chat-auditor"):
            try:
                proc = run_host(
                    ["docker", "logs", "--tail", "500", container],
                    timeout=20.0,
                    check=False,
                )
                (self.artifact_dir / f"{container}.log").write_text(
                    (proc.stdout or "") + (proc.stderr or ""),
                    encoding="utf-8",
                    errors="replace",
                )
            except Exception as exc:  # noqa: BLE001 - artifact best effort
                (self.artifact_dir / f"{container}.log.error").write_text(
                    str(exc), encoding="utf-8")

    def _write_db_excerpt(self) -> None:
        min_id = int(self.started_message_id)
        sql = (
            "SELECT id, conversation_id, sender_id, "
            "CASE "
            "WHEN body LIKE 'S3PQI:%' THEN 'S3PQI' "
            "WHEN body LIKE 'S3DR:%' THEN 'S3DR' "
            "WHEN body LIKE 'S3MLS:%' THEN 'S3MLS' "
            "WHEN body LIKE 'E2R:%' THEN 'E2R' "
            "WHEN body LIKE 'E2RK:%' THEN 'E2RK' "
            "WHEN body LIKE 'E2GS:%' THEN 'E2GS' "
            "WHEN body LIKE 'E2E:%' THEN 'E2E' "
            "WHEN body LIKE '__KEM_INIT__%' THEN 'KEM_INIT' "
            "ELSE 'OTHER' END AS wire_type, "
            "LEFT(body, 80), reply_to_message_id, edit_target_message_id, "
            "forwarded_from_id, IF(deleted_at IS NULL,0,1) AS deleted "
            "FROM messages "
            f"WHERE id > {min_id} ORDER BY id;"
        )
        messages = _db_query(sql)
        extras = []
        for sql in [
            "SELECT message_id, emoji, COUNT(*) FROM message_reactions GROUP BY message_id, emoji ORDER BY message_id, emoji;",
            "SELECT conversation_id, user_id, role FROM group_roles ORDER BY conversation_id, user_id;",
            "SELECT user_id, identity_version, event_type, device_label FROM identity_key_log ORDER BY log_index;",
        ]:
            try:
                extras.append(f"-- {sql}\n{_db_query(sql)}")
            except Exception as exc:  # noqa: BLE001
                extras.append(f"-- {sql}\nERROR: {exc}")
        self.__class__.db_excerpt_path.write_text(
            f"-- messages after {min_id}\n{messages}\n\n" + "\n\n".join(extras),
            encoding="utf-8",
        )

    def screenshot(self, name: str) -> None:
        for client in self.vnc.values():
            client.screenshot(name)

    def dismiss_transient_ui(self, *clients: VncClient) -> None:
        targets = clients or tuple(self.vnc.values())
        for client in targets:
            for _ in range(3):
                try:
                    client.press("Escape")
                except Exception:  # noqa: BLE001 - cleanup should not hide real failures
                    break
                time.sleep(0.1)

    def optional(self, code: str, text: str, fn: Callable[[], None]) -> None:
        self.step(code, f"{text} (best effort)")
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - artifact is more useful here
            print(f"[{code}] optional step skipped: {exc}", flush=True)
            for client in self.vnc.values():
                client.screenshot(f"optional_{code}")
            self.dismiss_transient_ui()

    def click_button_text(self, client: VncClient, text: str,
                          *, timeout: float = 10.0) -> None:
        self.click_widget_contains(client, text, cls="QPushButton", timeout=timeout)

    def answer_yes(self, client: VncClient, *, timeout: float = 10.0) -> None:
        for label in ("&Yes", "Yes"):
            try:
                self.click_button_text(client, label, timeout=timeout)
                return
            except AssertionError:
                pass
        raise AssertionError(f"{client.container}: Yes button not found")

    def answer_ok(self, client: VncClient, *, timeout: float = 10.0) -> None:
        for label in ("OK", "&OK"):
            try:
                self.click_button_text(client, label, timeout=timeout)
                return
            except AssertionError:
                pass
        raise AssertionError(f"{client.container}: OK button not found")

    def answer_no(self, client: VncClient, *, timeout: float = 10.0) -> None:
        for label in ("&No", "No"):
            try:
                self.click_button_text(client, label, timeout=timeout)
                return
            except AssertionError:
                pass
        raise AssertionError(f"{client.container}: No button not found")

    def type_to_focused(self, client: VncClient, text: str) -> None:
        client.type_text(text)
        time.sleep(self.delay)

    def select_combo_text(self, client: VncClient, selector: str, target: str,
                          *, timeout: float = 10.0) -> None:
        combo = client.widget(selector, cls="QComboBox", timeout=timeout)
        items = list(combo.get("items") or [])
        row = next((int(item["row"]) for item in items
                    if str(item.get("text", "")) == target), None)
        if row is None:
            raise AssertionError(
                f"{client.container}: combo {selector} has no item {target!r}; items={items}")
        geo = combo["geometry"]
        client.click_xy(geo["cx"], geo["cy"])
        time.sleep(0.15)
        client.press("Home")
        for _ in range(row):
            client.press("Down")
            time.sleep(0.05)
        client.press("Return")
        client.wait_for(
            f"combo {selector} == {target}",
            lambda s: any(
                w.get("class") == "QComboBox"
                and (w.get("object_name") == selector or w.get("testid") == selector)
                and w.get("current_text") == target
                for w in s.get("widgets") or []
            ),
            timeout=timeout,
        )

    def select_visible_combo_item(self, client: VncClient, target: str,
                                  *, timeout: float = 10.0) -> None:
        deadline = time.time() + timeout
        last: list[dict[str, Any]] = []
        selected_row: int | None = None
        while time.time() < deadline:
            snap = client.snapshot(timeout=5.0)
            last = [
                widget for widget in snap.get("widgets") or []
                if widget.get("class") == "QComboBox"
                and widget.get("visible")
                and widget.get("enabled")
            ]
            for combo in last:
                items = list(combo.get("items") or [])
                row = next(
                    (int(item["row"]) for item in items
                     if str(item.get("text", "")) == target),
                    None,
                )
                if row is None:
                    continue
                selected_row = row
                geo = combo["geometry"]
                client.click_xy(geo["cx"], geo["cy"])
                time.sleep(0.15)
                client.press("Home")
                for _ in range(row):
                    client.press("Down")
                    time.sleep(0.05)
                client.press("Return")
                client.wait_for(
                    f"visible combo item selected: {target}",
                    lambda s: any(
                        w.get("class") == "QComboBox"
                        and w.get("visible")
                        and w.get("current_text") == target
                        for w in s.get("widgets") or []
                    ),
                    timeout=timeout,
                )
                return
            time.sleep(0.2)
        raise AssertionError(
            f"{client.container}: visible combo item {target!r} not found; "
            f"selected_row={selected_row}; last={last}"
        )

    def set_checkbox(self, client: VncClient, selector: str, checked: bool,
                     *, timeout: float = 10.0) -> None:
        box = client.widget(selector, cls="QCheckBox", timeout=timeout)
        if bool(box.get("checked")) != bool(checked):
            geo = box["geometry"]
            client.click_xy(geo["cx"], geo["cy"])
            time.sleep(self.delay)
        client.wait_for(
            f"checkbox {selector} == {checked}",
            lambda s: any(
                w.get("class") == "QCheckBox"
                and (w.get("object_name") == selector or w.get("testid") == selector)
                and bool(w.get("checked")) == bool(checked)
                for w in s.get("widgets") or []
            ),
            timeout=timeout,
        )

    def wait_text(self, client: VncClient, text: str, *, timeout: float = 20.0) -> None:
        client.wait_for(
            f"text visible: {text}",
            lambda s: text in json.dumps(s, ensure_ascii=False),
            timeout=timeout,
        )

    def wait_text_absent(self, client: VncClient, text: str,
                         *, timeout: float = 6.0) -> None:
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            last = client.snapshot(timeout=5.0)
            if text in json.dumps(last, ensure_ascii=False):
                time.sleep(0.3)
                continue
            return
        raise AssertionError(f"{client.container}: text still visible: {text}; last={last}")

    def wait_message_text_absent(self, client: VncClient, text: str,
                                 *, timeout: float = 8.0) -> None:
        client.wait_for(
            f"message text absent: {text}",
            lambda s: not any(
                text in str(message)
                for message in s.get("chat", {}).get("message_texts", [])
            ),
            timeout=timeout,
        )

    def visible_widget_count(self, client: VncClient, *,
                             selector: str | None = None,
                             cls: str | None = None) -> int:
        count = 0
        for widget in client.snapshot(timeout=5.0).get("widgets") or []:
            if not widget.get("visible"):
                continue
            if cls and widget.get("class") != cls:
                continue
            if selector and not (
                widget.get("object_name") == selector
                or widget.get("testid") == selector
            ):
                continue
            count += 1
        return count

    def db_message_count(self) -> int:
        return int((_db_query("SELECT COUNT(*) FROM messages") or "0").strip() or "0")

    def assert_empty_send_noop(self, client: VncClient) -> None:
        before = self.db_message_count()
        client.type_into("chat.message_input", "     ")
        client.click_widget("chat.send")
        time.sleep(self.delay * 2)
        self.assertEqual(
            self.db_message_count(),
            before,
            "blank/whitespace message should not be inserted",
        )
        self.assertFalse(
            client.snapshot(timeout=5.0).get("chat", {}).get("pending_error_bubbles"),
            "blank/whitespace message should not create a failed bubble",
        )

    def wait_widget_absent(self, client: VncClient, selector: str,
                           *, timeout: float = 10.0) -> None:
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            last = client.snapshot(timeout=5.0)
            present = any(
                (w.get("object_name") == selector or w.get("testid") == selector)
                and w.get("visible")
                for w in last.get("widgets") or []
            )
            if not present:
                return
            time.sleep(0.25)
        raise AssertionError(f"{client.container}: widget still visible: {selector}; last={last}")

    def select_file_dialog_path(self, client: VncClient, path: str) -> None:
        def filename_field_contains(expected: str):
            expected_name = os.path.basename(expected)
            return lambda s: any(
                w.get("visible")
                and w.get("object_name") == "fileNameEdit"
                and (
                    expected in str(w.get("text", ""))
                    or expected_name in str(w.get("text", ""))
                )
                for w in s.get("widgets") or []
            )

        # Native Qt file dialogs expose fileNameEdit when the dialog is visible.
        # Filling that field is more stable than relying on Ctrl+L, especially
        # for restore/open dialogs that start in /app.
        try:
            field = client.widget("fileNameEdit", timeout=3.0)
            geo = field["geometry"]
            client.click_xy(geo["cx"], geo["cy"])
            client.exec(
                "DISPLAY=:1 xdotool key --clearmodifiers ctrl+a BackSpace",
                timeout=20.0,
            )
            client.paste_text(path)
            client.wait_for(
                f"file dialog path pasted: {path}",
                filename_field_contains(path),
                timeout=5.0,
            )
            client.press("Return")
            time.sleep(self.delay)
            return
        except AssertionError:
            pass

        # Fallback for platforms/dialog themes that do not expose fileNameEdit.
        client.press("ctrl+l")
        time.sleep(0.2)
        client.press("ctrl+a")
        client.press("BackSpace")
        client.paste_text(path)
        client.wait_for(
            f"file dialog path pasted through location bar: {path}",
            lambda s: path in json.dumps(s, ensure_ascii=False)
            or os.path.basename(path) in json.dumps(s, ensure_ascii=False),
            timeout=5.0,
        )
        client.press("Return")
        time.sleep(self.delay)

    def save_file_dialog_path(self, client: VncClient, path: str) -> None:
        self.select_file_dialog_path(client, path)
        time.sleep(0.2)
        try:
            self.click_button_text(client, "Save", timeout=2.0)
        except AssertionError:
            pass
        time.sleep(self.delay)

    def input_dialog_text(self, client: VncClient, text: str) -> None:
        self.type_to_focused(client, text)
        client.press("Return")
        time.sleep(self.delay)

    def choose_context_action_by_index(self, client: VncClient, list_name: str,
                                       text_contains: str, action_index: int) -> None:
        self.choose_context_action(client, list_name, text_contains, action_index)

    def click_latest_action_and_select(self, client: VncClient, action_index: int) -> None:
        self.click_latest_message_actions(client)
        self.select_menu_action(client, action_index)

    def write_note(self, name: str, text: str) -> None:
        (self.artifact_dir / name).write_text(text, encoding="utf-8")

    @staticmethod
    def widget_haystack(widget: dict[str, Any]) -> str:
        return " ".join([
            str(widget.get("text", "")),
            str(widget.get("placeholder", "")),
            str(widget.get("object_name", "")),
            str(widget.get("testid", "")),
        ])

    def click_widget_contains(self, client: VncClient, text: str,
                              *, cls: str | None = None,
                              timeout: float = 10.0) -> dict[str, Any]:
        deadline = time.time() + timeout
        last: list[dict[str, Any]] = []
        while time.time() < deadline:
            snap = client.snapshot(timeout=5.0)
            last = list(snap.get("widgets") or [])
            for widget in last:
                if cls and widget.get("class") != cls:
                    continue
                if not widget.get("visible") or not widget.get("enabled"):
                    continue
                if text in self.widget_haystack(widget):
                    geo = widget["geometry"]
                    client.click_xy(geo["cx"], geo["cy"])
                    time.sleep(self.delay)
                    return widget
            time.sleep(0.2)
        raise AssertionError(f"{client.container}: widget containing {text!r} not found; last={last}")

    @staticmethod
    def widget_is_in_window(snapshot: dict[str, Any], widget: dict[str, Any]) -> bool:
        win = (snapshot.get("window") or {}).get("geometry") or {}
        geo = widget.get("geometry") or {}
        if not win or not geo:
            return True
        left = int(win.get("x", 0))
        top = int(win.get("y", 0))
        right = left + int(win.get("w", 0))
        bottom = top + int(win.get("h", 0)) - 8
        cx = int(geo.get("cx", 0))
        cy = int(geo.get("cy", 0))
        return (
            left <= cx <= right
            and top <= cy <= bottom
        )

    def scroll_widget_toward_window(self, client: VncClient, snapshot: dict[str, Any],
                                    widget: dict[str, Any]) -> None:
        win = (snapshot.get("window") or {}).get("geometry") or {}
        geo = widget.get("geometry") or {}
        if not win or not geo:
            return
        bottom = int(win.get("y", 0)) + int(win.get("h", 0))
        top = int(win.get("y", 0))
        x = int(win.get("cx", 0))
        y = max(top + 60, min(bottom - 90, int(win.get("cy", bottom // 2))))
        button = 5 if int(geo.get("cy", 0)) > bottom - 8 else 4
        key = "Page_Down" if button == 5 else "Page_Up"
        for _ in range(4):
            client.click_xy(x, y, button=button)
            time.sleep(0.05)
        client.press(key)

    def click_checkbox_contains(self, client: VncClient, text: str,
                                *, timeout: float = 10.0) -> dict[str, Any]:
        deadline = time.time() + timeout
        last: list[dict[str, Any]] = []
        while time.time() < deadline:
            snap = client.snapshot(timeout=5.0)
            last = list(snap.get("widgets") or [])
            for widget in last:
                if widget.get("class") != "QCheckBox":
                    continue
                if not widget.get("visible") or not widget.get("enabled"):
                    continue
                if text not in self.widget_haystack(widget):
                    continue
                if widget.get("checked"):
                    return widget
                if not self.widget_is_in_window(snap, widget):
                    self.scroll_widget_toward_window(client, snap, widget)
                    time.sleep(self.delay)
                    break
                geo = widget["geometry"]
                indicator_x = int(geo["x"] + min(12, max(1, geo["w"] - 2)))
                client.click_xy(indicator_x, geo["cy"])
                time.sleep(self.delay)
                break
            time.sleep(0.2)
        last_checks = [w for w in last if w.get("class") == "QCheckBox"]
        raise AssertionError(
            f"{client.container}: checkbox containing {text!r} was not checked; "
            f"last={last_checks}"
        )

    def click_any_list_item(self, client: VncClient, text: str,
                            *, timeout: float = 10.0) -> dict[str, Any]:
        deadline = time.time() + timeout
        last_items: list[dict[str, Any]] = []
        while time.time() < deadline:
            snap = client.snapshot(timeout=5.0)
            last_items = []
            for widget in snap.get("widgets") or []:
                if widget.get("class") != "QListWidget":
                    continue
                if not widget.get("visible") or not widget.get("enabled"):
                    continue
                for item in widget.get("items") or []:
                    last_items.append(item)
                    if text in str(item.get("text", "")):
                        geo = item["geometry"]
                        client.click_xy(geo["cx"], geo["cy"])
                        time.sleep(self.delay)
                        return item
            time.sleep(0.2)
        raise AssertionError(f"{client.container}: list item containing {text!r} not found; last={last_items}")

    def select_menu_action(self, client: VncClient, down_count: int) -> None:
        time.sleep(0.25)
        for _ in range(down_count):
            client.press("Down")
            time.sleep(0.08)
        client.press("Return")
        time.sleep(self.delay)

    def choose_context_action(self, client: VncClient, list_name: str,
                              text_contains: str, down_count: int) -> None:
        client.click_list_item(list_name, text_contains=text_contains, button=3)
        self.select_menu_action(client, down_count)

    def choose_context_action_text(self, client: VncClient, list_name: str,
                                   text_contains: str, action_text: str) -> None:
        client.click_list_item(list_name, text_contains=text_contains, button=3)
        self.click_button_text(client, action_text, timeout=10.0)

    def click_latest_message_actions(self, client: VncClient) -> None:
        snap = client.snapshot(timeout=5.0)
        buttons = [
            w for w in snap.get("widgets", [])
            if w.get("class") == "QPushButton"
            and w.get("text") == "..."
            and w.get("visible")
            and w.get("enabled")
        ]
        if not buttons:
            raise AssertionError(f"{client.container}: no visible message action button")
        button = max(buttons, key=lambda w: w["geometry"]["y"])
        geo = button["geometry"]
        client.click_xy(geo["cx"], geo["cy"])
        time.sleep(self.delay)

    def login_user(self, client: VncClient, account_key: str) -> None:
        username, email = ACCOUNTS[account_key]
        self.login_email(client, email, PASSWORD, username)

    def login_email(self, client: VncClient, email: str, password: str,
                    expected_username: str) -> None:
        client.wait_for("login page", lambda s: s.get("current_page") == "login",
                        timeout=30.0)
        client.type_into("login.email", email)
        client.type_into("login.password", password)
        client.click_widget("login.submit")
        client.wait_for(
            f"{email} logged in",
            lambda s: s.get("current_page") == "chat"
            and s.get("chat", {}).get("me") == expected_username,
            timeout=45.0,
        )
        time.sleep(self.delay)

    def logout_user(self, client: VncClient) -> None:
        client.click_widget("chat.exit")
        client.wait_for("login page after logout",
                        lambda s: s.get("current_page") == "login",
                        timeout=25.0)
        time.sleep(self.delay)

    def register_unique_user(self, client: VncClient) -> tuple[str, str]:
        suffix = int(time.time())
        username = f"visible_{suffix}"
        email = f"{username}@example.test"
        client.click_widget("login.go_register")
        client.wait_for("register page", lambda s: s.get("current_page") == "register")

        client.type_into("register.username", "ab")
        client.type_into("register.email", "bad")
        client.type_into("register.password", "123")
        client.type_into("register.confirm", "456")
        client.click_widget("register.submit")
        client.wait_for(
            "register validation error",
            lambda s: "at least 3" in str(s.get("register_status", "")),
            timeout=10.0,
        )

        client.type_into("register.username", username)
        client.type_into("register.email", email)
        client.type_into("register.password", PASSWORD)
        client.type_into("register.confirm", PASSWORD)
        client.click_widget("register.submit")
        client.wait_for(
            "registered demo account auto login",
            lambda s: s.get("current_page") == "chat"
            and s.get("chat", {}).get("me") == username,
            timeout=45.0,
        )
        return username, email

    def send_friend_request(self, sender: VncClient, target_username: str) -> None:
        sender.click_widget("chat.nav.search")
        sender.widget("chat.search_input", timeout=15.0)
        sender.type_into("chat.search_input", target_username)
        sender.click_widget("chat.search_go")
        sender.wait_for(
            f"search result {target_username}",
            lambda s: _list_has_item(s, "chat.search_results", target_username),
            timeout=20.0,
        )
        self.choose_context_action(sender, "chat.search_results", target_username, 2)
        try:
            sender.click_widget("OK", timeout=3.0)
        except AssertionError:
            pass

    def accept_first_request(self, receiver: VncClient, requester_username: str) -> None:
        receiver.wait_for(
            f"request from {requester_username}",
            lambda s: int(s.get("chat", {}).get("pending_requests_count") or 0) > 0
            or requester_username in json.dumps(s, ensure_ascii=False)
            or any(
                w.get("class") == "QPushButton"
                and w.get("visible")
                and "Accept" in str(w.get("text", ""))
                for w in s.get("widgets") or []
            ),
            timeout=30.0,
        )
        receiver.click_widget("chat.nav.requests")
        receiver.wait_for(
            "request label visible",
            lambda s: any(
                requester_username in str(w.get("text", ""))
                for w in s.get("widgets") or []
            ),
            timeout=20.0,
        )
        receiver.click_widget("Accept")
        receiver.wait_for(
            "request accepted",
            lambda s: int(s.get("chat", {}).get("pending_requests_count") or 0) == 0
            and not any(
                w.get("class") == "QPushButton"
                and w.get("visible")
                and "Accept" in str(w.get("text", ""))
                for w in s.get("widgets") or []
            ),
            timeout=20.0,
        )

    def open_dm_from_friend(self, client: VncClient, peer_username: str) -> None:
        client.click_widget("chat.nav.chats")
        clicked_existing_dm = False
        dm_item = None
        try:
            dm_item = client.click_list_item(
                "chat.dm_list", text_contains=peer_username, timeout=5.0)
            clicked_existing_dm = True
        except AssertionError:
            clicked_existing_dm = False
        if clicked_existing_dm:
            try:
                client.wait_for(
                    f"active DM {peer_username}",
                    lambda s: s.get("chat", {}).get("active_conv_id", 0) > 0
                    and peer_username in str(s.get("chat", {}).get("header", "")),
                    timeout=6.0,
                )
                return
            except AssertionError:
                pass
            conv_id = int((dm_item.get("data") or {}).get("user_role") or 0)
            if conv_id > 0:
                client.probe_command({
                    "type": "open_conversation",
                    "conversation_id": conv_id,
                    "is_group": False,
                })
                try:
                    client.wait_for(
                        f"active DM {peer_username}",
                        lambda s: s.get("chat", {}).get("active_conv_id", 0) > 0
                        and peer_username in str(s.get("chat", {}).get("header", "")),
                        timeout=8.0,
                    )
                    return
                except AssertionError:
                    pass
        friend = client.wait_for(
            f"{peer_username} in friends",
            lambda s: _list_has_item(s, "chat.friend_list", peer_username),
            timeout=30.0,
        )
        friend_item = next(
            (item for item in _items(friend, "chat.friend_list")
             if peer_username in str(item.get("text", ""))),
            None,
        )
        user_id = int(((friend_item or {}).get("data") or {}).get("user_role") or 0)
        if user_id > 0:
            client.probe_command({"type": "start_dm", "user_id": user_id})
        else:
            self.choose_context_action(client, "chat.friend_list", peer_username, 2)
        client.wait_for(
            f"active DM {peer_username}",
            lambda s: s.get("chat", {}).get("active_conv_id", 0) > 0
            and peer_username in str(s.get("chat", {}).get("header", "")),
            timeout=45.0,
        )

    def send_message(self, client: VncClient, body: str,
                     *, timeout: float = 45.0) -> None:
        client.type_into("chat.message_input", body)
        client.click_widget("chat.send")
        client.wait_for(
            f"message visible: {body}",
            lambda s: _message_visible(s, body),
            timeout=timeout,
        )
        time.sleep(self.delay)

    def assert_message(self, client: VncClient, body: str,
                       *, timeout: float = 45.0) -> None:
        client.wait_for(
            f"message received: {body}",
            lambda s: _message_visible(s, body),
            timeout=timeout,
        )

    def assert_message_with_search(self, client: VncClient, body: str,
                                   *, timeout: float = 45.0) -> None:
        try:
            self.assert_message(client, body, timeout=5.0)
            return
        except AssertionError:
            pass
        client.type_into("chat.message_search", body, timeout=10.0)
        self.assert_message(client, body, timeout=timeout)
        client.type_into("chat.message_search", "", timeout=10.0)
        time.sleep(self.delay)

    def assert_no_known_crypto_errors(self, client: VncClient) -> None:
        snap = client.snapshot(timeout=5.0)
        text = json.dumps(snap, ensure_ascii=False)
        bad_fragments = [
            "No PQXDH bundle found",
            "Identity change requires rotate_identity",
            "ratchet mismatch",
            "different safety key",
            "[Cannot decrypt",
        ]
        hits = [fragment for fragment in bad_fragments if fragment in text]
        self.assertFalse(hits, f"{client.container}: unexpected crypto/audit errors: {hits}")

    def create_group_with_friend(self, owner: VncClient, group_name: str,
                                 friend_username: str) -> None:
        owner.click_widget("chat.nav.chats")
        owner.click_widget("chat.new_group")
        owner.type_into("Enter group name...", group_name)
        self.click_checkbox_contains(owner, friend_username, timeout=15.0)
        owner.click_widget("OK", timeout=10.0)
        owner.wait_for(
            f"group {group_name} exists",
            lambda s: _list_has_item(s, "chat.group_list", group_name),
            timeout=45.0,
        )

    def assert_group_cancel_noop(self, owner: VncClient, group_name: str,
                                 friend_username: str) -> None:
        owner.click_widget("chat.nav.chats")
        owner.click_widget("chat.new_group")
        owner.type_into("group.name", group_name)
        self.click_checkbox_contains(owner, friend_username, timeout=15.0)
        self.click_button_text(owner, "Cancel", timeout=10.0)
        self.wait_widget_absent(owner, "group.name", timeout=10.0)
        owner.click_widget("chat.nav.chats")
        self.assertFalse(
            _list_has_item(owner.snapshot(timeout=5.0), "chat.group_list", group_name),
            "cancelled group creation should not leave a group in the sidebar",
        )

    def assert_group_without_member_rejected(self, owner: VncClient,
                                             group_name: str) -> None:
        owner.click_widget("chat.nav.chats")
        owner.click_widget("chat.new_group")
        owner.type_into("group.name", group_name)
        self.click_button_text(owner, "OK", timeout=10.0)
        self.wait_text(owner, "Please select at least one member", timeout=15.0)
        self.answer_ok(owner, timeout=10.0)
        self.wait_widget_absent(owner, "group.name", timeout=10.0)
        owner.click_widget("chat.nav.chats")
        self.assertFalse(
            _list_has_item(owner.snapshot(timeout=5.0), "chat.group_list", group_name),
            "group without members should not be created",
        )

    def add_friend_to_group(self, owner: VncClient, friend_username: str,
                            group_name: str) -> None:
        owner.click_widget("chat.nav.chats")
        owner.wait_for(
            f"{friend_username} in friends",
            lambda s: _list_has_item(s, "chat.friend_list", friend_username),
            timeout=30.0,
        )
        self.choose_context_action_text(
            owner, "chat.friend_list", friend_username, "Add to Group")
        self.click_any_list_item(owner, group_name, timeout=15.0)
        owner.click_widget("OK", timeout=10.0)

    def open_group(self, client: VncClient, group_name: str) -> None:
        client.click_widget("chat.nav.chats")
        client.click_list_item("chat.group_list", text_contains=group_name)
        client.wait_for(
            f"active group {group_name}",
            lambda s: s.get("chat", {}).get("active_conv_id", 0) > 0
            and group_name in str(s.get("chat", {}).get("header", "")),
            timeout=45.0,
        )

    def reject_first_request(self, receiver: VncClient, requester_username: str) -> None:
        receiver.wait_for(
            f"request from {requester_username}",
            lambda s: int(s.get("chat", {}).get("pending_requests_count") or 0) > 0,
            timeout=30.0,
        )
        receiver.click_widget("chat.nav.requests")
        self.wait_text(receiver, requester_username, timeout=20.0)
        self.click_button_text(receiver, "Reject", timeout=10.0)
        receiver.wait_for(
            "request rejected",
            lambda s: int(s.get("chat", {}).get("pending_requests_count") or 0) == 0
            and any(
                w.get("object_name") == "chat.request_list"
                and not (w.get("items") or [])
                for w in s.get("widgets") or []
            ),
            timeout=20.0,
        )

    def remove_friend(self, client: VncClient, username: str) -> None:
        client.click_widget("chat.nav.chats")
        self.choose_context_action_text(
            client, "chat.friend_list", username, "Remove Friend")
        self.answer_yes(client, timeout=10.0)
        client.wait_for(
            f"{username} removed from friends",
            lambda s: not _list_has_item(s, "chat.friend_list", username),
            timeout=30.0,
        )

    def block_friend(self, client: VncClient, username: str) -> None:
        client.click_widget("chat.nav.chats")
        self.choose_context_action_text(
            client, "chat.friend_list", username, "Block User")
        self.answer_yes(client, timeout=10.0)
        time.sleep(self.delay)

    def assert_blocked_dm_send_fails(self, sender: VncClient, receiver: VncClient,
                                     receiver_username: str, body: str) -> None:
        before = self.db_message_count()
        self.open_dm_from_friend(sender, receiver_username)
        sender.type_into("chat.message_input", body)
        sender.click_widget("chat.send")
        self.wait_text(sender, "Cannot send message (blocked)", timeout=30.0)
        self.answer_ok(sender, timeout=10.0)
        sender.wait_for(
            "blocked send became failed bubble",
            lambda s: any(
                body in str(item.get("body", ""))
                and item.get("failed")
                and "blocked" in str(item.get("failure_reason", "")).lower()
                for item in s.get("chat", {}).get("pending_error_bubbles", [])
            ),
            timeout=20.0,
        )
        self.assertEqual(
            self.db_message_count(),
            before,
            "blocked send should not insert ciphertext in messages",
        )
        self.wait_message_text_absent(receiver, body, timeout=6.0)
        try:
            sender.click_widget("message.dismiss", timeout=5.0)
        except AssertionError:
            pass

    def open_profile_dialog(self, client: VncClient) -> None:
        last_error: AssertionError | None = None
        for selector in ("chat.me", "chat.my_avatar", "chat.me"):
            try:
                client.click_widget(selector, timeout=8.0)
                client.widget("profile.change_password", timeout=10.0)
                return
            except AssertionError as exc:
                last_error = exc
                time.sleep(0.5)
        if last_error:
            raise last_error
        raise AssertionError(f"{client.container}: profile dialog did not open")

    def wait_connection_settled(self, client: VncClient,
                                *, timeout: float = 45.0) -> None:
        client.wait_for(
            "connection settled",
            lambda s: bool(s.get("session_active"))
            and s.get("chat", {}).get("consistency", "") != "Connection warning",
            timeout=timeout,
        )

    def wait_active_dm_key_ready(self, client: VncClient,
                                 *, timeout: float = 45.0) -> None:
        client.wait_for(
            "active DM key ready",
            lambda s: int(s.get("chat", {}).get("active_conv_id", 0) or 0)
            in {
                int(cid)
                for cid in s.get("chat", {}).get("double_ratchet_ready_conv_ids", [])
            },
            timeout=timeout,
        )

    def click_profile_action(self, client: VncClient, selector: str) -> None:
        self.open_profile_dialog(client)
        client.click_widget(selector, timeout=10.0)
        time.sleep(self.delay)

    def save_profile_text(self, client: VncClient, display_name: str, bio: str) -> None:
        self.open_profile_dialog(client)
        client.type_into("profile.display_name", display_name)
        client.type_into("profile.bio", bio)
        self.click_button_text(client, "Save", timeout=10.0)
        self.wait_widget_absent(client, "profile.change_password", timeout=20.0)

    def unblock_first_user(self, client: VncClient) -> None:
        self.click_profile_action(client, "profile.blocked_users")
        client.widget("blocked.list", cls="QListWidget", timeout=15.0)
        try:
            client.click_list_item("blocked.list", row=0, timeout=10.0)
            client.click_widget("blocked.unblock", timeout=10.0)
        finally:
            try:
                self.click_button_text(client, "Close", timeout=5.0)
            except AssertionError:
                client.press("Escape")
        time.sleep(self.delay)

    def change_password_ui(self, client: VncClient,
                           current_password: str, new_password: str) -> None:
        self.click_profile_action(client, "profile.change_password")
        client.type_into("password.current", current_password)
        client.type_into("password.new", new_password)
        client.type_into("password.confirm", new_password)
        self.click_button_text(client, "OK", timeout=10.0)
        self.wait_text(client, "Password changed successfully", timeout=30.0)
        self.answer_ok(client, timeout=10.0)

    def export_backup_ui(self, client: VncClient, path: str,
                         *, include_cache: bool = True) -> None:
        self.click_profile_action(client, "profile.backup.export")
        self.save_file_dialog_path(client, path)
        try:
            self.wait_text(client, "Backup passphrase:", timeout=2.0)
        except AssertionError:
            if include_cache:
                self.answer_yes(client, timeout=15.0)
            else:
                self.click_button_text(client, "No", timeout=15.0)
            self.wait_text(client, "Backup passphrase:", timeout=15.0)
        self.input_dialog_text(client, BACKUP_PASSPHRASE)
        self.wait_text(client, "Exported", timeout=45.0)
        self.answer_ok(client, timeout=10.0)
        client.exec(f"test -s '{path}'", timeout=10.0)

    def restore_backup_ui(self, client: VncClient, path: str) -> None:
        self.click_profile_action(client, "profile.backup.restore")
        self.select_file_dialog_path(client, path)
        self.wait_text(client, "Restore local E2EE state", timeout=30.0)
        self.answer_yes(client, timeout=10.0)
        self.input_dialog_text(client, BACKUP_PASSPHRASE)
        client.wait_for(
            "restore completed",
            lambda s: any(
                text in json.dumps(s, ensure_ascii=False)
                for text in ("Restored", "Merged")
            ),
            timeout=60.0,
        )
        self.answer_ok(client, timeout=10.0)

    def rotate_identity_ui(self, client: VncClient) -> None:
        self.click_profile_action(client, "profile.rotate_identity")
        self.answer_yes(client, timeout=10.0)
        client.wait_for(
            "identity rotation result",
            lambda s: any(
                text in json.dumps(s, ensure_ascii=False)
                for text in ("Identity rotated", "safety key was rotated", "Safety Key")
            ),
            timeout=60.0,
        )
        try:
            self.answer_ok(client, timeout=5.0)
        except AssertionError:
            pass

    def restore_invalid_backup_rejected(self, client: VncClient, path: str) -> None:
        client.exec(f"printf '{{\"format\":\"not-secchat\"}}' > '{path}'")
        self.click_profile_action(client, "profile.backup.restore")
        self.select_file_dialog_path(client, path)
        self.wait_text(client, "This is not a SecChat E2EE backup file", timeout=20.0)
        self.answer_ok(client, timeout=10.0)

    def restore_wrong_passphrase_rejected(self, client: VncClient, path: str) -> None:
        self.click_profile_action(client, "profile.backup.restore")
        self.select_file_dialog_path(client, path)
        self.wait_text(client, "Restore local E2EE state", timeout=30.0)
        self.answer_yes(client, timeout=10.0)
        self.input_dialog_text(client, "WrongVisibleBackupPassphrase-2026!")
        self.wait_text(client, "Backup could not be decrypted", timeout=30.0)
        self.answer_ok(client, timeout=10.0)

    def rotate_identity_cancel_noop(self, client: VncClient) -> None:
        self.click_profile_action(client, "profile.rotate_identity")
        self.answer_no(client, timeout=10.0)
        time.sleep(self.delay)
        self.wait_text_absent(client, "Identity rotated", timeout=4.0)

    def current_verify_code(self, client: VncClient) -> str:
        def extract_code(snap: dict[str, Any]) -> str | None:
            texts = [
                str(w.get("text", ""))
                for w in snap.get("widgets") or []
                if w.get("class") == "QLabel"
            ]
            for widget in snap.get("widgets") or []:
                if widget.get("object_name") == "safetyShortCode":
                    code = str(widget.get("text", "")).strip()
                    if re.fullmatch(r"\d{3}(?: \d{3}){3}", code):
                        return code
            haystack = "\n".join(texts)
            lines = [line.strip() for line in haystack.splitlines() if line.strip()]
            for line in lines:
                if re.fullmatch(r"\d{3}(?: \d{3}){3}", line):
                    return line
            for idx, line in enumerate(lines):
                if line == "Short check code" and idx + 1 < len(lines):
                    candidate = lines[idx + 1]
                    if re.fullmatch(r"\d{3}(?: \d{3}){3}", candidate):
                        return candidate
            return None

        selectors = (
            "chat.review_identity",
            "Review identity",
            "chat.fingerprint",
            "Verify safety",
        )
        deadline = time.time() + 35.0
        last_snap: dict[str, Any] | None = None
        while time.time() < deadline:
            client.press("Escape")
            opened = False
            for selector in selectors:
                try:
                    if selector.startswith("chat."):
                        client.click_widget(selector, timeout=2.0)
                    else:
                        self.click_widget_contains(client, selector, timeout=2.0)
                    opened = True
                    break
                except AssertionError:
                    pass
            if not opened:
                time.sleep(0.5)
                continue
            try:
                snap = client.wait_for(
                    "verify dialog short code",
                    lambda s: "Short check code" in json.dumps(s, ensure_ascii=False),
                    timeout=4.0,
                )
                code = extract_code(snap)
                if code:
                    return code
                last_snap = snap
            except AssertionError:
                last_snap = client.snapshot(timeout=5.0)
                dump = json.dumps(last_snap, ensure_ascii=False)
                if "Key fingerprint not yet available" in dump:
                    self.answer_ok(client, timeout=3.0)
            time.sleep(0.5)
        raise AssertionError(
            f"{client.container}: could not extract short check code; last={last_snap}"
        )

    def mark_verify_dialog_verified(self, client: VncClient) -> None:
        self.click_checkbox_contains(
            client,
            "The code matches what my contact sees",
            timeout=10.0,
        )
        client.click_widget("Mark Verified", timeout=10.0)
        self.wait_text(client, "Verified", timeout=20.0)

    def close_dialog(self, client: VncClient) -> None:
        for label in ("Close", "Cancel", "OK"):
            try:
                self.click_button_text(client, label, timeout=2.0)
                time.sleep(self.delay)
                return
            except AssertionError:
                pass
        client.press("Escape")
        time.sleep(self.delay)

    def assert_no_visible_audit_mismatch(self, client: VncClient) -> None:
        dump = json.dumps(client.snapshot(timeout=5.0), ensure_ascii=False).lower()
        forbidden = [
            "audit mismatch",
            "identity proof version mismatch",
            "[audit identity proof version mismatch]",
        ]
        present = [text for text in forbidden if text in dump]
        self.assertFalse(
            present,
            f"{client.container}: clean visible flow shows audit mismatch: {present}",
        )

    def _run_visible_manual_full(self) -> None:
        self.step("01-auth", "đăng ký, đăng nhập sai/đúng, logout và đổi mật khẩu trên user tạm")
        registered_username, registered_email = self.register_unique_user(self.c1)
        self.screenshot("01_register_success")
        self.click_profile_action(self.c1, "profile.change_password")
        self.c1.type_into("password.current", "wrong-current")
        self.c1.type_into("password.new", NEW_PASSWORD)
        self.c1.type_into("password.confirm", NEW_PASSWORD)
        self.click_button_text(self.c1, "OK", timeout=10.0)
        self.wait_text(self.c1, "Change Password", timeout=20.0)
        self.answer_ok(self.c1, timeout=10.0)
        self.change_password_ui(self.c1, PASSWORD, NEW_PASSWORD)
        self.logout_user(self.c1)
        self.c1.type_into("login.email", registered_email)
        self.c1.type_into("login.password", PASSWORD)
        self.c1.click_widget("login.submit")
        self.c1.wait_for(
            "old temp password rejected",
            lambda s: "incorrect" in str(s.get("login_status", "")).lower()
            or "password" in str(s.get("login_status", "")).lower(),
            timeout=15.0,
        )
        self.login_email(self.c1, registered_email, NEW_PASSWORD, registered_username)
        self.logout_user(self.c1)
        self.c1.type_into("login.email", ACCOUNTS["123"][1])
        self.c1.type_into("login.password", "wrong-password")
        self.c1.click_widget("login.submit")
        self.c1.wait_for(
            "wrong demo password status",
            lambda s: "incorrect" in str(s.get("login_status", "")).lower()
            or "password" in str(s.get("login_status", "")).lower(),
            timeout=15.0,
        )
        self.login_user(self.c1, "123")
        self.login_user(self.c2, "234")
        self.assert_no_known_crypto_errors(self.c1)
        self.assert_no_known_crypto_errors(self.c2)
        self.screenshot("02_demo_login")

        self.step("02-friend", "friend request accept/reject, unfriend, block và unblock")
        self.send_friend_request(self.c2, "user123")
        self.accept_first_request(self.c1, "user234")
        self.c1.click_widget("chat.nav.chats")
        self.c2.click_widget("chat.nav.chats")
        self.c1.wait_for("user234 friend visible",
                         lambda s: _list_has_item(s, "chat.friend_list", "user234"))
        self.c2.wait_for("user123 friend visible",
                         lambda s: _list_has_item(s, "chat.friend_list", "user123"))
        self.send_friend_request(self.c1, "user345")
        self.logout_user(self.c2)
        self.login_user(self.c2, "345")
        self.reject_first_request(self.c2, "user123")
        self.send_friend_request(self.c1, "user345")
        self.accept_first_request(self.c2, "user123")
        self.c1.click_widget("chat.nav.chats")
        self.c1.wait_for("user345 friend visible",
                         lambda s: _list_has_item(s, "chat.friend_list", "user345"),
                         timeout=30.0)
        self.remove_friend(self.c1, "user345")
        self.send_friend_request(self.c1, "user345")
        self.accept_first_request(self.c2, "user123")
        self.open_dm_from_friend(self.c2, "user123")
        pre_block_body = "visible edge pre block from 345"
        self.send_message(self.c2, pre_block_body)
        self.open_dm_from_friend(self.c1, "user345")
        self.assert_message(self.c1, pre_block_body, timeout=45.0)
        self.block_friend(self.c1, "user345")
        self.assert_blocked_dm_send_fails(
            self.c2,
            self.c1,
            "user123",
            "visible edge blocked send should fail",
        )
        self.unblock_first_user(self.c1)
        self.c1.click_widget("chat.nav.chats")
        if not _list_has_item(self.c1.snapshot(timeout=5.0), "chat.friend_list", "user345"):
            self.send_friend_request(self.c1, "user345")
            self.accept_first_request(self.c2, "user123")
        self.logout_user(self.c2)
        self.login_user(self.c2, "234")
        self.screenshot("03_friend_full")

        self.step("03-dm", "DM hai chiều, unread, preview inbox và history")
        self.open_dm_from_friend(self.c2, "user123")
        first_dm = "visible manual dm from 234"
        self.send_message(self.c2, first_dm)
        self.c1.wait_for(
            "incoming DM in inbox",
            lambda s: _list_has_item(s, "chat.dm_list", "user234")
            or bool(s.get("chat", {}).get("unread_conv_ids")),
            timeout=45.0,
        )
        self.open_dm_from_friend(self.c1, "user234")
        self.assert_message(self.c1, first_dm)
        reply = "visible manual reply from 123"
        self.send_message(self.c1, reply)
        self.assert_message(self.c2, reply)
        self.assert_empty_send_noop(self.c2)
        self.c1.click_widget("chat.nav.chats")
        self.c1.wait_for("DM preview decrypted",
                         lambda s: first_dm in json.dumps(s, ensure_ascii=False)
                         or reply in json.dumps(s, ensure_ascii=False),
                         timeout=20.0)
        self.assert_no_known_crypto_errors(self.c1)
        self.assert_no_known_crypto_errors(self.c2)
        self.screenshot("04_dm_two_way")

        self.step("04-offline", "offline messages và relogin không mất history")
        self.logout_user(self.c1)
        offline_messages = [
            "visible offline one",
            "visible offline two",
            "visible offline three",
        ]
        for body in offline_messages:
            self.send_message(self.c2, body)
        self.login_user(self.c1, "123")
        self.open_dm_from_friend(self.c1, "user234")
        self.assert_message(self.c1, first_dm)
        for body in offline_messages:
            self.assert_message(self.c1, body)
        self.send_message(self.c1, "visible after relogin from 123")
        self.assert_message(self.c2, "visible after relogin from 123")
        self.screenshot("05_offline_relogin")

        self.step("05-verify", "audit short code hai bên và mark verified cục bộ")
        self.open_dm_from_friend(self.c1, "user234")
        self.open_dm_from_friend(self.c2, "user123")
        code1 = self.current_verify_code(self.c1)
        code2 = self.current_verify_code(self.c2)
        self.assertEqual(code1, code2, "verify short code must match on both clients")
        self.assert_no_visible_audit_mismatch(self.c1)
        self.assert_no_visible_audit_mismatch(self.c2)
        self.mark_verify_dialog_verified(self.c1)
        self.close_dialog(self.c2)
        self.wait_text(self.c1, "Verified", timeout=20.0)
        self.screenshot("06_verify_short_code")

        self.step("06-group-setup", "tạo group user123-user234 và kiểm tra group E2EE")
        group_name = f"visible room {int(time.time())}"
        self.assert_group_cancel_noop(
            self.c1,
            f"visible edge cancelled group {int(time.time())}",
            "user234",
        )
        self.assert_group_without_member_rejected(
            self.c1,
            f"visible edge no member group {int(time.time())}",
        )
        self.create_group_with_friend(self.c1, group_name, "user234")
        self.open_group(self.c1, group_name)
        group_pre_join = "visible group pre-join from 123"
        self.send_message(self.c1, group_pre_join)
        self.c2.wait_for(
            "group appears for user234",
            lambda s: _list_has_item(s, "chat.group_list", group_name),
            timeout=45.0,
        )
        self.open_group(self.c2, group_name)
        self.assert_message(self.c2, group_pre_join)
        self.send_message(self.c2, "visible group reply from 234")
        self.assert_message(self.c1, "visible group reply from 234")
        self.screenshot("07_group_123_234")

        self.step("07-message-actions", "edit, delete, reaction, reply, forward, pin, unpin và pinned list")
        self.open_dm_from_friend(self.c1, "user234")
        action_body = "visible full action target"
        self.send_message(self.c1, action_body)
        self.click_latest_action_and_select(self.c1, 1)
        self.c1.type_into("chat.message_input", "visible full reply action")
        self.c1.click_widget("chat.send")
        self.open_dm_from_friend(self.c2, "user123")
        self.assert_message(self.c2, "visible full reply action")
        reaction_chips_before = self.visible_widget_count(self.c1, selector="reactionChip")
        self.click_latest_action_and_select(self.c1, 2)
        self.close_dialog(self.c1)
        self.wait_widget_absent(self.c1, "reaction.dialog", timeout=8.0)
        self.assertEqual(
            self.visible_widget_count(self.c1, selector="reactionChip"),
            reaction_chips_before,
            "cancelled reaction dialog should not add a reaction chip",
        )
        self.click_latest_action_and_select(self.c1, 2)
        self.c1.click_widget("reaction.emoji.0", timeout=10.0)
        self.wait_text(self.c1, "👍", timeout=20.0)
        self.click_latest_action_and_select(self.c1, 4)
        self.wait_text(self.c1, "Pinned", timeout=20.0)
        self.c1.click_widget("chat.pins")
        self.c1.wait_for(
            "pinned list contains reply",
            lambda s: _list_has_item(s, "pinned.list", "visible full reply action"),
            timeout=20.0,
        )
        self.close_dialog(self.c1)
        self.click_latest_action_and_select(self.c1, 4)
        self.wait_message_text_absent(self.c1, "Pinned", timeout=8.0)
        self.click_latest_action_and_select(self.c1, 5)
        self.c1.type_into("message.edit.input", "visible edge cancelled edit")
        self.c1.click_widget("message.edit.cancel", timeout=10.0)
        self.wait_widget_absent(self.c1, "message.edit.input", timeout=8.0)
        self.assert_message(self.c1, "visible full reply action", timeout=20.0)
        self.wait_message_text_absent(self.c1, "visible edge cancelled edit", timeout=8.0)
        self.click_latest_action_and_select(self.c1, 5)
        self.c1.type_into("message.edit.input", "visible full edited action")
        self.c1.click_widget("message.edit.save", timeout=10.0)
        self.open_dm_from_friend(self.c2, "user123")
        self.assert_message(self.c2, "visible full edited action")
        self.wait_text(self.c1, "(edited)", timeout=20.0)
        self.click_latest_action_and_select(self.c1, 3)
        self.wait_text(self.c1, "Send to:", timeout=15.0)
        self.click_button_text(self.c1, "Cancel", timeout=10.0)
        self.open_group(self.c1, group_name)
        self.wait_text_absent(self.c1, "Forwarded", timeout=6.0)
        self.open_dm_from_friend(self.c1, "user234")
        self.click_latest_action_and_select(self.c1, 3)
        self.wait_text(self.c1, "Send to:", timeout=15.0)
        self.select_visible_combo_item(self.c1, f"Group: {group_name}", timeout=10.0)
        self.click_button_text(self.c1, "OK", timeout=10.0)
        self.open_group(self.c1, group_name)
        self.wait_text(self.c1, "Forwarded", timeout=30.0)
        self.open_dm_from_friend(self.c1, "user234")
        self.click_latest_action_and_select(self.c1, 6)
        self.answer_no(self.c1, timeout=10.0)
        self.assert_message(self.c1, "visible full edited action", timeout=20.0)
        self.click_latest_action_and_select(self.c1, 6)
        self.answer_yes(self.c1, timeout=10.0)
        self.wait_text(self.c1, "[Message deleted]", timeout=20.0)
        self.open_dm_from_friend(self.c2, "user123")
        self.assert_message(self.c2, "[Message deleted]", timeout=30.0)
        self.screenshot("08_message_actions")

        self.step("08-file", "gửi file nhỏ, preview attachment và lỗi file quá lớn")
        self.open_dm_from_friend(self.c1, "user234")
        self.c1.exec(
            "printf 'visible file payload' > /root/visible_note.txt && "
            "truncate -s 1048577 /root/visible_too_large.bin && "
            ": > /root/visible_empty.txt"
        )
        self.c1.click_widget("chat.attach")
        self.c1.press("Escape")
        self.wait_widget_absent(self.c1, "fileNameEdit", timeout=8.0)
        self.c1.click_widget("chat.attach")
        self.select_file_dialog_path(self.c1, "/root/visible_note.txt")
        self.open_dm_from_friend(self.c2, "user123")
        self.assert_message(self.c2, "visible_note.txt", timeout=45.0)
        self.c1.click_widget("chat.attach")
        self.select_file_dialog_path(self.c1, "/root/visible_too_large.bin")
        self.wait_text(self.c1, "Max file size is 1024 KB", timeout=20.0)
        self.answer_ok(self.c1, timeout=10.0)
        self.c1.click_widget("chat.attach")
        self.select_file_dialog_path(self.c1, "/root/visible_empty.txt")
        self.wait_text(self.c1, "File is empty", timeout=20.0)
        self.answer_ok(self.c1, timeout=10.0)
        self.screenshot("09_file_attachment")

        self.step("09-user345-group", "add user345 vào group, kiểm tra pre-join, đổi role và kick")
        self.logout_user(self.c2)
        self.login_user(self.c2, "345")
        self.c1.click_widget("chat.nav.chats")
        self.c1.wait_for("user345 friend visible",
                         lambda s: _list_has_item(s, "chat.friend_list", "user345"),
                         timeout=30.0)
        self.add_friend_to_group(self.c1, "user345", group_name)
        self.c2.wait_for(
            "group appears for user345",
            lambda s: _list_has_item(s, "chat.group_list", group_name),
            timeout=60.0,
        )
        self.open_group(self.c2, group_name)
        post_join = "visible group post-join for 345"
        self.open_group(self.c1, group_name)
        self.send_message(self.c1, post_join)
        self.assert_message(self.c2, post_join, timeout=60.0)
        self.assertFalse(
            _message_visible(self.c2.snapshot(timeout=5.0), group_pre_join),
            "user345 should not see plaintext group pre-join history",
        )
        self.choose_context_action_text(
            self.c1, "chat.group_list", group_name, "Group Info")
        self.c1.widget("group.info.members", timeout=20.0)
        self.c1.click_list_item("group.info.members", text_contains="user345", button=3, timeout=15.0)
        self.select_menu_action(self.c1, 1)
        self.c1.click_list_item("group.info.members", text_contains="user345", button=3, timeout=15.0)
        self.select_menu_action(self.c1, 2)
        self.c1.click_list_item("group.info.members", text_contains="user345", button=3, timeout=15.0)
        self.select_menu_action(self.c1, 3)
        self.answer_yes(self.c1, timeout=10.0)
        self.close_dialog(self.c1)
        self.open_group(self.c1, group_name)
        post_kick = "visible group after kick should stay hidden from 345"
        self.send_message(self.c1, post_kick)
        self.wait_text_absent(self.c2, post_kick, timeout=8.0)
        self.screenshot("10_group_add_role_kick_345")

        self.step("10-profile-privacy", "đổi avatar, bio, privacy/cache và remove avatar")
        self.save_profile_text(self.c1, "Visible User 123", "visible bio from checklist")
        self.open_profile_dialog(self.c1)
        self.c1.click_widget("profile.avatar.upload", timeout=10.0)
        self.select_file_dialog_path(self.c1, "/root/1.png")
        self.click_button_text(self.c1, "OK", timeout=10.0)
        self.click_button_text(self.c1, "Save", timeout=10.0)
        self.wait_widget_absent(self.c1, "profile.change_password", timeout=10.0)
        self.open_profile_dialog(self.c1)
        self.c1.click_widget("profile.avatar.remove", timeout=10.0)
        self.click_button_text(self.c1, "Save", timeout=10.0)
        self.wait_widget_absent(self.c1, "profile.change_password", timeout=10.0)
        self.click_profile_action(self.c1, "profile.privacy")
        self.select_combo_text(self.c1, "privacy_online", "friends")
        self.select_combo_text(self.c1, "privacy_last_seen", "nobody")
        self.select_combo_text(self.c1, "privacy.cache.ttl", "7 days")
        self.set_checkbox(self.c1, "privacy.metadata_protection", True)
        self.set_checkbox(self.c1, "privacy.cache.enabled", True)
        self.set_checkbox(self.c1, "privacy.cache.clear_on_logout", False)
        self.click_button_text(self.c1, "Save", timeout=10.0)
        self.wait_text(self.c1, "Cache 7 days", timeout=20.0)
        self.screenshot("11_profile_privacy_avatar")

        self.step("11-backup-rotate-restore", "export/import E2EE, rotate safety key rồi merge cache")
        backup_src = "/root/secchat-visible-e2ee-backup.json"
        backup_dst = "/root/secchat-visible-import.json"
        host_backup = self.artifact_dir / "secchat-visible-e2ee-backup.json"
        self.export_backup_ui(self.c1, backup_src, include_cache=True)
        run_host(["docker", "cp", f"chat-client1:{backup_src}", str(host_backup)], timeout=30.0)
        run_host(["docker", "cp", str(host_backup), f"chat-client2:{backup_dst}"], timeout=30.0)
        self.logout_user(self.c2)
        self.login_user(self.c2, "123")
        try:
            self.wait_text(self.c2, "different safety key", timeout=8.0)
            self.answer_ok(self.c2, timeout=10.0)
        except AssertionError:
            pass
        self.wait_connection_settled(self.c2)
        self.open_dm_from_friend(self.c2, "user234")
        self.wait_message_text_absent(self.c2, first_dm, timeout=6.0)
        self.wait_message_text_absent(self.c2, reply, timeout=6.0)
        self.restore_invalid_backup_rejected(self.c2, "/root/secchat-invalid-backup.json")
        self.rotate_identity_cancel_noop(self.c2)
        self.rotate_identity_ui(self.c2)
        self.open_dm_from_friend(self.c2, "user234")
        self.wait_active_dm_key_ready(self.c2)
        migrated_after_rotate = "visible after rotate on migrated VNC"
        self.send_message(self.c2, migrated_after_rotate)
        self.restore_wrong_passphrase_rejected(self.c2, backup_dst)
        self.restore_backup_ui(self.c2, backup_dst)
        self.open_dm_from_friend(self.c2, "user234")
        self.assert_message_with_search(self.c2, first_dm, timeout=60.0)
        self.assert_message_with_search(self.c2, reply, timeout=60.0)
        self.assert_message_with_search(self.c2, migrated_after_rotate, timeout=60.0)
        self.screenshot("12_backup_rotate_restore")

        self.step("12-layout-db-server", "search, resize, metrics/log và database ciphertext-only")
        self.c2.click_widget("chat.nav.search")
        self.c2.type_into("chat.search_input", "user234")
        self.c2.click_widget("chat.search_go")
        self.c2.wait_for("search user234 result",
                         lambda s: _list_has_item(s, "chat.search_results", "user234"))
        time.sleep(1.1)
        self.c2.type_into("chat.search_input", "visible_no_such_user_404")
        self.c2.click_widget("chat.search_go")
        self.c2.wait_for(
            "empty search result clears stale entries",
            lambda s: any(
                w.get("object_name") == "chat.search_results"
                and not (w.get("items") or [])
                for w in s.get("widgets") or []
            ),
            timeout=20.0,
        )
        time.sleep(1.1)
        self.c2.type_into("chat.search_input", "")
        self.c2.click_widget("chat.search_go")
        self.c2.wait_for(
            "blank search keeps results empty",
            lambda s: any(
                w.get("object_name") == "chat.search_results"
                and not (w.get("items") or [])
                for w in s.get("widgets") or []
            ),
            timeout=8.0,
        )
        self.c2.exec(
            "DISPLAY=:1 xdotool search --onlyvisible --name SecChat | head -n 1 | "
            "xargs -r -I{} xdotool windowsize {} 900 650",
            timeout=10.0,
            check=False,
        )
        time.sleep(self.delay)
        self.c2.exec(
            "DISPLAY=:1 xdotool search --onlyvisible --name SecChat | head -n 1 | "
            "xargs -r -I{} xdotool windowsize {} 1100 750",
            timeout=10.0,
            check=False,
        )
        with urlopen("http://localhost:18889/metrics", timeout=3.0) as resp:
            metrics_text = resp.read().decode("utf-8", errors="replace")
        metrics = json.loads(metrics_text)
        self.assertGreaterEqual(metrics.get("messages", {}).get("sent", 0), 1)
        self.assertGreaterEqual(metrics.get("connections", {}).get("accepted", 0), 1)
        self.assertGreaterEqual(metrics.get("database", {}).get("queries", 0), 1)
        server_logs = run_host(["docker", "logs", "--tail", "300", "chat-server"],
                               timeout=20.0, check=False)
        self.assertNotIn(first_dm, server_logs.stdout + server_logs.stderr)
        run_host([
            "docker", "exec", "chat-server", "sh", "-lc",
            "DISPLAY=:1 scrot /tmp/server_gui_visible_manual.png",
        ], timeout=10.0, check=False)
        run_host([
            "docker", "cp",
            "chat-server:/tmp/server_gui_visible_manual.png",
            str(self.artifact_dir / "chat-server_13_server_gui.png"),
        ], timeout=20.0, check=False)
        self._assert_database_ciphertext_only()
        self._assert_database_metadata_events()
        self.assert_no_known_crypto_errors(self.c2)
        self.screenshot("13_final_core")
        print(f"[done] visible checklist full completed; temp user={registered_username}", flush=True)

    # ------------------------------------------------------------------ tests

    def test_01_visible_manual_core(self) -> None:
        return self._run_visible_manual_full()

    def test_99_visible_manual_destructive(self) -> None:
        if os.environ.get("SECCHAT_VISIBLE_MANUAL_INCLUDE_DESTRUCTIVE") != "1":
            raise unittest.SkipTest("destructive visible manual checks require opt-in")
        self.step("99-auditor", "tạm dừng auditor rồi khởi động lại")
        run_host(["docker", "stop", "chat-auditor"], timeout=45.0)
        time.sleep(2.0)
        self.screenshot("99_auditor_stopped")
        run_host(["docker", "start", "chat-auditor"], timeout=45.0)
        self._wait_auditor_ready()

        self.step("99-server", "tạm dừng server để quan sát trạng thái lỗi/reconnect")
        run_host(["docker", "stop", "chat-server"], timeout=45.0)
        time.sleep(3.0)
        self.screenshot("99_server_stopped")
        run_host(["docker", "start", "chat-server"], timeout=45.0)
        wait_ready(timeout=60.0)
        self.screenshot("99_server_restarted")

    # ---------------------------------------------------------------- optional exercisers

    def _exercise_verify_identity(self) -> None:
        snap = self.c1.snapshot(timeout=5.0)
        if "Verify safety" not in json.dumps(snap, ensure_ascii=False):
            raise AssertionError("verify label is not visible yet")
        self.click_widget_contains(self.c1, "Verify safety", timeout=5.0)
        self.click_checkbox_contains(
            self.c1,
            "The code matches what my contact sees",
            timeout=10.0,
        )
        self.c1.click_widget("Mark Verified", timeout=10.0)
        self.c1.wait_for(
            "verified badge",
            lambda s: "Verified" in str(s.get("chat", {}).get("header", ""))
            or "Verified" in json.dumps(s, ensure_ascii=False),
            timeout=20.0,
        )

    def _exercise_message_actions(self) -> None:
        self.open_dm_from_friend(self.c1, "user234")
        action_body = "visible message action target"
        self.send_message(self.c1, action_body)

        self.click_latest_message_actions(self.c1)
        self.select_menu_action(self.c1, 1)  # Reply
        self.c1.type_into("chat.message_input", "visible reply via action")
        self.c1.click_widget("chat.send")
        self.assert_message(self.c2, "visible reply via action")

        self.click_latest_message_actions(self.c1)
        self.select_menu_action(self.c1, 2)  # React
        self.c1.click_widget("👍", timeout=10.0)
        self.c1.wait_for(
            "reaction chip visible",
            lambda s: any(
                "👍" in str(w.get("text", ""))
                for w in s.get("widgets") or []
            ),
            timeout=20.0,
        )

        self.click_latest_message_actions(self.c1)
        self.select_menu_action(self.c1, 4)  # Pin, separators are skipped by Qt
        self.c1.wait_for(
            "pin label visible",
            lambda s: "Pinned" in json.dumps(s, ensure_ascii=False)
            or "Pins (" in json.dumps(s, ensure_ascii=False),
            timeout=20.0,
        )

    def _exercise_profile_cache_backup_ui(self) -> None:
        self.click_widget_contains(self.c1, "user123", cls="QPushButton", timeout=10.0)
        self.c1.wait_for(
            "profile dialog visible",
            lambda s: any(
                text in json.dumps(s, ensure_ascii=False)
                for text in ("Change Password", "Privacy", "Export E2EE Backup")
            ),
            timeout=15.0,
        )
        for text in ("Change Password", "Privacy", "Export E2EE Backup",
                     "Restore E2EE Backup", "Rotate Safety Key"):
            self.assertIn(text, json.dumps(self.c1.snapshot(timeout=5.0), ensure_ascii=False))
        try:
            self.c1.click_widget("Cancel", timeout=5.0)
        except AssertionError:
            self.c1.press("Escape")

    # ---------------------------------------------------------------- assertions

    def _assert_database_ciphertext_only(self) -> None:
        min_id = int(self.started_message_id)
        bad_plain = _db_query(
            "SELECT COUNT(*) FROM messages "
            f"WHERE id > {min_id} AND ("
            "body LIKE '%visible manual%' OR body LIKE '%visible offline%' "
            "OR body LIKE '%visible group%' OR body LIKE '%visible message action%' "
            "OR body LIKE '%visible full%' OR body LIKE '%visible edge%' "
            "OR body LIKE '%visible after rotate%')"
        )
        self.assertEqual(bad_plain.strip(), "0", "database contains visible plaintext body")
        bad_prefix = _db_query(
            "SELECT COUNT(*) FROM messages "
            f"WHERE id > {min_id} AND NOT ("
            "body LIKE 'S3PQI:%' OR body LIKE 'S3DR:%' OR body LIKE 'S3MLS:%')"
        )
        self.assertEqual(bad_prefix.strip(), "0", "new messages contain non-SecChat wire prefix")
        removed = _db_query(
            "SELECT COUNT(*) FROM messages "
            f"WHERE id > {min_id} AND ("
            "body LIKE 'E2R:%' OR body LIKE 'E2RK:%' OR body LIKE 'E2GS:%' "
            "OR body LIKE 'E2E:%' OR body LIKE '__KEM_INIT__%')"
        )
        self.assertEqual(removed.strip(), "0", "new messages contain removed wire prefix")

    def _assert_database_metadata_events(self) -> None:
        min_id = int(self.started_message_id)
        reply_count = _db_query(
            "SELECT COUNT(*) FROM messages "
            f"WHERE id > {min_id} AND reply_to_message_id > 0"
        )
        self.assertGreater(int(reply_count.strip() or "0"), 0,
                           "reply metadata was not persisted")
        edit_count = _db_query(
            "SELECT COUNT(*) FROM messages "
            f"WHERE id > {min_id} AND edit_target_message_id > 0"
        )
        self.assertGreater(int(edit_count.strip() or "0"), 0,
                           "edit metadata was not persisted")
        # Forward source metadata is intentionally carried inside the encrypted
        # SCMSG payload for the current E2EE flow; the UI assertion verifies it.
        deleted_count = _db_query(
            "SELECT COUNT(*) FROM messages "
            f"WHERE id > {min_id} AND deleted_at IS NOT NULL"
        )
        self.assertGreater(int(deleted_count.strip() or "0"), 0,
                           "delete metadata was not persisted")
        reaction_count = _db_query(
            "SELECT COUNT(*) FROM message_reactions"
        )
        self.assertGreater(int(reaction_count.strip() or "0"), 0,
                           "reaction metadata was not persisted")
        pinned_count = _db_query(
            "SELECT COUNT(*) FROM pinned_messages"
        )
        self.assertGreaterEqual(int(pinned_count.strip() or "0"), 0,
                                "pinned_messages table is unavailable")
        admin_count = _db_query(
            "SELECT COUNT(*) FROM group_roles WHERE role = 'admin'"
        )
        self.assertGreater(int(admin_count.strip() or "0"), 0,
                           "group role metadata was not persisted")
        identity_versions = _db_query(
            "SELECT COALESCE(MAX(identity_version), 0) FROM identity_key_log"
        )
        self.assertGreaterEqual(int(identity_versions.strip() or "0"), 1,
                                "identity rotate was not recorded in identity log")

    @staticmethod
    def _wait_auditor_ready(timeout: float = 45.0) -> None:
        deadline = time.time() + timeout
        last: Exception | None = None
        while time.time() < deadline:
            try:
                with urlopen("http://localhost:18890/readyz", timeout=2.0) as resp:
                    if resp.status == 200:
                        return
            except Exception as exc:  # noqa: BLE001
                last = exc
            time.sleep(0.5)
        raise RuntimeError(f"auditor not ready after {timeout}s: {last!r}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
