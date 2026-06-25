from __future__ import annotations

import json
import os
import subprocess
import time
import unittest
from pathlib import Path
from typing import Any, Callable

from secchat_testlib import db_reset, ensure_cert, wait_ready


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DEFAULT_PROBE_PATH = "/tmp/secchat-ui-state.json"


class DockerCommandError(AssertionError):
    pass


def artifact_root() -> Path:
    base = os.environ.get("SECCHAT_TEST_ARTIFACT_DIR")
    if base:
        root = Path(base)
    else:
        root = REPO / "tests" / "artifacts" / "ui_vnc"
    root.mkdir(parents=True, exist_ok=True)
    return root


def run_host(args: list[str], *, timeout: float = 30.0,
             check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        args,
        cwd=REPO,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=timeout,
    )
    if check and proc.returncode != 0:
        raise DockerCommandError(
            f"command failed ({proc.returncode}): {' '.join(args)}\n"
            f"stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}"
        )
    return proc


def docker_available() -> bool:
    try:
        proc = run_host(["docker", "version", "--format", "{{.Server.Version}}"],
                        timeout=10.0, check=False)
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


class VncClient:
    def __init__(self, container: str, artifact_dir: Path | None = None):
        self.container = container
        self.artifact_dir = artifact_dir or artifact_root()
        self.probe_path = os.environ.get("SECCHAT_TEST_PROBE_PATH", DEFAULT_PROBE_PATH)

    def exec(self, script: str, *, timeout: float = 30.0,
             check: bool = True) -> subprocess.CompletedProcess[str]:
        return run_host(
            ["docker", "exec", self.container, "sh", "-lc", script],
            timeout=timeout,
            check=check,
        )

    def logs(self, *, tail: int = 300) -> str:
        proc = run_host(
            ["docker", "logs", "--tail", str(tail), self.container],
            timeout=20.0,
            check=False,
        )
        return (proc.stdout or "") + (proc.stderr or "")

    def probe_enabled(self) -> bool:
        proc = self.exec("printf '%s' \"${SECCHAT_TEST_PROBE:-}\"",
                         timeout=10.0, check=False)
        return proc.returncode == 0 and proc.stdout.strip() == "1"

    def clear_state(self) -> None:
        self.exec(f"rm -rf /root/.secchat {self.probe_path}", timeout=15.0)

    def restart(self) -> None:
        run_host(["docker", "restart", self.container], timeout=45.0)

    def wait_window(self, *, timeout: float = 30.0) -> str:
        deadline = time.time() + timeout
        last = ""
        while time.time() < deadline:
            proc = self.exec(
                "DISPLAY=:1 xdotool search --onlyvisible --name SecChat | head -n 1",
                timeout=5.0,
                check=False,
            )
            last = (proc.stdout or proc.stderr or "").strip()
            if proc.returncode == 0 and last:
                self.exec(
                    f"DISPLAY=:1 xdotool windowactivate {last} "
                    f"windowsize {last} 1100 750 windowmove {last} 0 0",
                    timeout=5.0,
                    check=False,
                )
                return last
            time.sleep(0.25)
        raise AssertionError(f"{self.container}: SecChat window not found: {last}")

    def snapshot(self, *, timeout: float = 20.0) -> dict[str, Any]:
        deadline = time.time() + timeout
        last = ""
        while time.time() < deadline:
            proc = self.exec(
                f"test -s {self.probe_path} && cat {self.probe_path}",
                timeout=5.0,
                check=False,
            )
            last = proc.stdout or proc.stderr or ""
            if proc.returncode == 0 and proc.stdout.strip():
                try:
                    return json.loads(proc.stdout)
                except json.JSONDecodeError:
                    pass
            time.sleep(0.2)
        raise AssertionError(f"{self.container}: UI probe snapshot unavailable: {last}")

    def wait_for(self, label: str, predicate: Callable[[dict[str, Any]], bool],
                 *, timeout: float = 20.0) -> dict[str, Any]:
        deadline = time.time() + timeout
        last: dict[str, Any] | None = None
        while time.time() < deadline:
            last = self.snapshot(timeout=5.0)
            if predicate(last):
                return last
            time.sleep(0.25)
        raise AssertionError(f"{self.container}: timed out waiting for {label}; last={last}")

    def _widgets(self, snap: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        snap = snap or self.snapshot()
        return list(snap.get("widgets") or [])

    @staticmethod
    def _matches_widget(widget: dict[str, Any], selector: str,
                        *, exact_text: bool = True) -> bool:
        values = [
            widget.get("object_name", ""),
            widget.get("testid", ""),
            widget.get("placeholder", ""),
        ]
        if exact_text:
            values.append(widget.get("text", ""))
            return selector in values
        return (
            selector in values
            or selector in str(widget.get("text", ""))
            or selector in str(widget.get("placeholder", ""))
        )

    def widget(self, selector: str, *, cls: str | None = None,
               visible: bool = True, enabled: bool | None = True,
               timeout: float = 10.0) -> dict[str, Any]:
        def find(snap: dict[str, Any]) -> dict[str, Any] | None:
            for widget in self._widgets(snap):
                if cls and widget.get("class") != cls:
                    continue
                if visible and not widget.get("visible"):
                    continue
                if enabled is not None and bool(widget.get("enabled")) != enabled:
                    continue
                if self._matches_widget(widget, selector):
                    return widget
            return None

        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            snap = self.snapshot(timeout=5.0)
            last = find(snap)
            if last:
                return last
            time.sleep(0.2)
        raise AssertionError(f"{self.container}: widget not found: {selector}")

    def click_xy(self, x: int, y: int, *, button: int = 1) -> None:
        self.exec(
            "win=$(DISPLAY=:1 xdotool search --onlyvisible --name SecChat | head -n 1); "
            "[ -n \"$win\" ] && DISPLAY=:1 xdotool windowactivate \"$win\" || true; "
            "sleep 0.20; "
            f"DISPLAY=:1 xdotool mousemove {int(x)} {int(y)} "
            f"mousedown {int(button)}; sleep 0.05; "
            f"DISPLAY=:1 xdotool mouseup {int(button)}",
            timeout=10.0,
        )

    def click_widget(self, selector: str, *, timeout: float = 10.0) -> None:
        widget = self.widget(selector, timeout=timeout)
        geo = widget["geometry"]
        self.click_xy(geo["cx"], geo["cy"])

    def type_text(self, text: str, *, delay_ms: int = 1) -> None:
        escaped = text.replace("'", "'\"'\"'")
        self.exec(
            f"DISPLAY=:1 xdotool type --clearmodifiers --delay {int(delay_ms)} '{escaped}'",
            timeout=30.0,
        )

    def paste_text(self, text: str) -> None:
        escaped = text.replace("'", "'\"'\"'")
        proc = self.exec(
            "(command -v xclip >/dev/null 2>&1 && "
            f"(printf '%s' '{escaped}' | "
            "DISPLAY=:1 xclip -selection clipboard -i -loops 10 "
            ">/tmp/secchat-xclip.log 2>&1 &) && sleep 0.35)",
            timeout=10.0,
            check=False,
        )
        if proc.returncode == 0:
            self.press("ctrl+v")
        else:
            self.type_text(text, delay_ms=35)

    def type_into(self, selector: str, text: str, *, timeout: float = 10.0) -> None:
        widget = self.widget(selector, timeout=timeout)
        geo = widget["geometry"]
        self.click_xy(geo["cx"], geo["cy"])
        self.exec(
            "DISPLAY=:1 xdotool key --clearmodifiers ctrl+a BackSpace",
            timeout=20.0,
        )
        self.type_text(text)

    def press(self, key: str) -> None:
        self.exec(f"DISPLAY=:1 xdotool key --clearmodifiers {key}", timeout=10.0)

    def list_items(self, selector: str) -> list[dict[str, Any]]:
        widget = self.widget(selector, cls="QListWidget", enabled=None)
        return list(widget.get("items") or [])

    def probe_command(self, command: dict[str, Any]) -> None:
        payload = json.dumps(command, ensure_ascii=False, sort_keys=True)
        escaped = payload.replace("'", "'\"'\"'")
        self.exec(
            f"printf '%s' '{escaped}' > /tmp/secchat-ui-command.json",
            timeout=10.0,
        )

    def click_list_item(self, selector: str, *, text_contains: str | None = None,
                        row: int | None = None, button: int = 1,
                        timeout: float = 10.0) -> dict[str, Any]:
        deadline = time.time() + timeout
        last_items: list[dict[str, Any]] = []
        while time.time() < deadline:
            last_items = self.list_items(selector)
            for item in last_items:
                if row is not None and int(item.get("row", -1)) != row:
                    continue
                if text_contains and text_contains not in str(item.get("text", "")):
                    continue
                geo = item["geometry"]
                self.click_xy(geo["cx"], geo["cy"], button=button)
                return item
            time.sleep(0.25)
        raise AssertionError(
            f"{self.container}: list item not found in {selector}; "
            f"text_contains={text_contains!r}; items={last_items}"
        )

    def screenshot(self, name: str) -> Path:
        safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name)
        remote = f"/tmp/{safe}.png"
        local = self.artifact_dir / f"{self.container}_{safe}.png"
        self.exec(f"DISPLAY=:1 scrot {remote}", timeout=10.0, check=False)
        run_host(["docker", "cp", f"{self.container}:{remote}", str(local)],
                 timeout=20.0, check=False)
        return local

    def capture_failure(self, name: str) -> None:
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.screenshot(name)
        try:
            snap = self.snapshot(timeout=3.0)
        except Exception as exc:
            snap = {"error": str(exc)}
        (self.artifact_dir / f"{self.container}_{name}_snapshot.json").write_text(
            json.dumps(snap, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logs = self.logs()
        debug = self.exec(
            "test -f /tmp/secchat-mls-debug.log && "
            "cat /tmp/secchat-mls-debug.log || true",
            timeout=5.0,
            check=False,
        )
        if debug.stdout.strip():
            logs += "\n\n--- /tmp/secchat-mls-debug.log ---\n" + debug.stdout
        (self.artifact_dir / f"{self.container}_{name}_logs.txt").write_text(
            logs,
            encoding="utf-8",
        )


def prepare_vnc_clients(containers: list[str], *, reset_home: bool = True,
                        artifact_dir: Path | None = None) -> dict[str, VncClient]:
    if not docker_available():
        raise unittest.SkipTest("Docker is not available for ui_vnc tests")

    clients = {name: VncClient(name, artifact_dir=artifact_dir) for name in containers}
    for client in clients.values():
        inspect = run_host(
            ["docker", "inspect", "-f", "{{.State.Running}}", client.container],
            timeout=10.0,
            check=False,
        )
        if inspect.returncode != 0:
            raise unittest.SkipTest(f"{client.container} container is not available")
        if inspect.stdout.strip() != "true":
            run_host(["docker", "start", client.container], timeout=45.0, check=False)
        if not client.probe_enabled():
            raise unittest.SkipTest(
                f"{client.container} is not running with SECCHAT_TEST_PROBE=1"
            )
        if reset_home:
            client.clear_state()
        client.restart()
    for client in clients.values():
        client.wait_window(timeout=40.0)
        client.wait_for("login page", lambda s: s.get("current_page") == "login",
                        timeout=40.0)
    return clients


class VncE2ETestCase(unittest.TestCase):
    artifact_dir = artifact_root()
    containers = ["chat-client1", "chat-client2"]

    def setUp(self) -> None:
        wait_ready(timeout=30.0)
        ensure_cert()
        db_reset()
        self.vnc = prepare_vnc_clients(
            self.containers,
            reset_home=True,
            artifact_dir=self.artifact_dir,
        )

    def tearDown(self) -> None:
        outcome = getattr(self, "_outcome", None)
        failed = False
        if outcome is not None:
            result = getattr(outcome, "result", None)
            if result is not None:
                failures = getattr(result, "failures", []) or []
                errors = getattr(result, "errors", []) or []
                failed = any(test is self for test, _exc in failures + errors)
        if failed:
            name = self.id().split(".")[-1]
            for client in getattr(self, "vnc", {}).values():
                client.capture_failure(name)
