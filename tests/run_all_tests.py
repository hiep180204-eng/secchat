"""
run_all_tests.py — single entry point for the SecChat test suite.

Usage:
  python tests/run_all_tests.py                     # run everything, default --reset
  python tests/run_all_tests.py --no-reset          # skip the initial DB reset
  python tests/run_all_tests.py --reset-each        # reset between every file
  python tests/run_all_tests.py --filter privacy    # only files matching 'privacy'
  python tests/run_all_tests.py --category ui_vnc   # real VNC UI E2E only
  python tests/run_all_tests.py --skip-vnc-ui       # run default suite without VNC UI
  python tests/run_all_tests.py --artifact-dir out  # failure screenshots/logs/snapshots
  python tests/run_all_tests.py --timeout 240       # per-file timeout (seconds)
  python tests/run_all_tests.py --list              # list files and exit

Each file runs as a subprocess so a hung socket in one cannot poison the next.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from typing import Optional

# Make secchat_testlib importable regardless of cwd.
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)

from secchat_testlib import wait_ready, db_reset, ensure_cert  # noqa: E402


# Broader integration suites live under tests/integration; focused suites live
# directly under tests/.
INTEGRATION_TESTS = [
    "tests/integration/test_domain_layer.py",
    "tests/integration/test_auth_friendship_validation.py",
    "tests/integration/test_presence_metrics_search.py",
    "tests/integration/test_blocking_disappearing_messages.py",
]

NEW_TESTS = [
    "tests/test_http_control.py",
    "tests/test_conv_prefs.py",
    "tests/test_privacy.py",
    "tests/test_multisession.py",
    "tests/test_metrics_counters.py",
    "tests/test_limits.py",
    "tests/test_notifications.py",
    "tests/test_avatar.py",
    "tests/test_saved_messages.py",
    "tests/test_rate_limit.py",
    "tests/test_secure_protocol_crypto.py",
    "tests/test_identity_audit.py",
    "tests/test_crypto_session.py",
    "tests/test_client_ui_interactions.py",
    "tests/test_client_ui_user_flows.py",
    "tests/test_client_ui_two_user_flow.py",
    "tests/test_client_ui_account_switching.py",
    "tests/test_client_ui_manual_checklist.py",
    "tests/test_server_gui.py",
    "tests/test_formal_verification.py",
    "tests/test_secure_protocol_server.py",
    "tests/test_operational_fault_injection.py",
]

UI_VNC_TESTS = [
    "tests/test_ui_vnc_e2e.py",
]

SERVER_CONTRACT_TESTS = [
    "tests/test_http_control.py",
    "tests/test_conv_prefs.py",
    "tests/test_privacy.py",
    "tests/test_multisession.py",
    "tests/test_metrics_counters.py",
    "tests/test_limits.py",
    "tests/test_notifications.py",
    "tests/test_avatar.py",
    "tests/test_saved_messages.py",
    "tests/test_rate_limit.py",
    "tests/test_identity_audit.py",
    "tests/test_secure_protocol_server.py",
    "tests/test_operational_fault_injection.py",
]

CRYPTO_CONTRACT_TESTS = [
    "tests/test_secure_protocol_crypto.py",
    "tests/test_crypto_session.py",
]

UI_WIDGET_TESTS = [
    "tests/test_client_ui_interactions.py",
    "tests/test_client_ui_user_flows.py",
    "tests/test_client_ui_two_user_flow.py",
    "tests/test_client_ui_account_switching.py",
    "tests/test_client_ui_manual_checklist.py",
    "tests/test_server_gui.py",
]

FORMAL_TESTS = [
    "tests/test_formal_verification.py",
]

TEST_CATEGORIES = {
    "integration": INTEGRATION_TESTS,
    "server_contract": SERVER_CONTRACT_TESTS,
    "crypto_contract": CRYPTO_CONTRACT_TESTS,
    "ui_widget": UI_WIDGET_TESTS,
    "ui_vnc": UI_VNC_TESTS,
    "formal": FORMAL_TESTS,
}

DEFAULT_CATEGORY_ORDER = [
    "integration",
    "server_contract",
    "crypto_contract",
    "ui_widget",
    "ui_vnc",
    "formal",
]


def _abs(path: str) -> str:
    return os.path.join(_REPO, path)


def _exists(path: str) -> bool:
    return os.path.exists(_abs(path))


def _dedupe(paths: list[str]) -> list[str]:
    seen = set()
    out = []
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        out.append(path)
    return out


def _parse_categories(raw: list[str] | None) -> list[str]:
    if not raw:
        return []
    out = []
    for item in raw:
        out.extend(part.strip() for part in item.split(",") if part.strip())
    return out


def _run_one(path: str, timeout: float, env: dict[str, str]) -> tuple[int, float]:
    """Run a test file as a subprocess. Returns (returncode, wall_seconds)."""
    start = time.time()
    abs_path = _abs(path)
    try:
        proc = subprocess.run(
            [sys.executable, abs_path],
            cwd=_REPO,
            env=env,
            timeout=timeout,
        )
        return proc.returncode, time.time() - start
    except subprocess.TimeoutExpired:
        return 124, time.time() - start


def _print_summary(results: list[tuple[str, int, float]]) -> None:
    print()
    print("=" * 72)
    print(f"{'FILE':50s} {'STATUS':8s} {'TIME':>8s}")
    print("-" * 72)
    for path, rc, wall in results:
        status = "PASS" if rc == 0 else (f"TIMEOUT" if rc == 124 else f"FAIL({rc})")
        print(f"{path:50s} {status:8s} {wall:>7.1f}s")
    print("-" * 72)
    passed = sum(1 for _, rc, _ in results if rc == 0)
    total = len(results)
    failed = total - passed
    print(f"{passed}/{total} passed, {failed} failed")
    print("=" * 72)


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    p.add_argument("--no-reset", action="store_true",
                   help="Skip the one-time DB reset at startup")
    p.add_argument("--reset-each", action="store_true",
                   help="Reset DB between every test file (slow but bulletproof)")
    p.add_argument("--filter", type=str, default=None,
                   help="Only run files whose path contains this substring")
    p.add_argument("--timeout", type=float, default=240.0,
                   help="Per-file timeout in seconds (default 240)")
    p.add_argument("--vnc-timeout", type=float, default=900.0,
                   help="Per-file timeout for ui_vnc tests in seconds (default 900)")
    p.add_argument("--list", action="store_true",
                   help="List files that would run and exit")
    p.add_argument("--list-categories", action="store_true",
                   help="List available test categories and exit")
    p.add_argument("--category", action="append", default=None,
                   help="Run one or more categories (comma separated allowed)")
    p.add_argument("--skip-vnc-ui", action="store_true",
                   help="Skip real VNC UI E2E tests")
    p.add_argument("--artifact-dir", type=str, default=None,
                   help="Directory for screenshots/logs/UI snapshots")
    p.add_argument("--only-existing", action="store_true",
                   help="Only run broad integration tests")
    p.add_argument("--only-new", action="store_true",
                   help="Only run the new tests/ files")
    args = p.parse_args(argv)

    if args.list_categories:
        for name in DEFAULT_CATEGORY_ORDER:
            print(f"{name}:")
            for path in TEST_CATEGORIES[name]:
                print(f"  {path}")
        return 0

    categories = _parse_categories(args.category)
    unknown = [name for name in categories if name not in TEST_CATEGORIES]
    if unknown:
        p.error(f"unknown category: {', '.join(unknown)}")

    if categories:
        files = []
        for category in categories:
            files += TEST_CATEGORIES[category]
    elif args.only_existing:
        files = list(INTEGRATION_TESTS)
    elif args.only_new:
        files = list(NEW_TESTS) + list(UI_VNC_TESTS)
    else:
        files = []
        for category in DEFAULT_CATEGORY_ORDER:
            files += TEST_CATEGORIES[category]

    files = _dedupe(files)
    if args.skip_vnc_ui:
        files = [f for f in files if f not in UI_VNC_TESTS]
    if args.filter:
        files = [f for f in files if args.filter in f]
    files = [f for f in files if _exists(f)]

    if args.list:
        for f in files:
            print(f)
        return 0

    if not files:
        print("no test files matched", file=sys.stderr)
        return 2

    host = os.environ.get("CHAT_HOST", "localhost")
    http_port = os.environ.get("CHAT_HTTP_PORT", "18889")
    print(f"[runner] waiting for server on http://{host}:{http_port}/readyz ...")
    wait_ready(timeout=30.0)
    ensure_cert()
    if not args.no_reset:
        print(f"[runner] db_reset() — TRUNCATE all tables")
        db_reset()

    artifact_dir = args.artifact_dir or os.path.join(_REPO, "tests", "artifacts")
    os.makedirs(artifact_dir, exist_ok=True)
    env = os.environ.copy()
    env["SECCHAT_TEST_ARTIFACT_DIR"] = os.path.abspath(artifact_dir)
    env.setdefault("SECCHAT_DB_RESET_SETTLE_SECONDS", "11")

    results: list[tuple[str, int, float]] = []
    for f in files:
        if args.reset_each:
            print(f"[runner] db_reset() before {f}")
            db_reset()
            wait_ready(timeout=10.0)
        print(f"\n{'#' * 72}\n# {f}\n{'#' * 72}")
        timeout = args.vnc_timeout if f in UI_VNC_TESTS else args.timeout
        rc, wall = _run_one(f, timeout, env)
        results.append((f, rc, wall))

    _print_summary(results)
    return 0 if all(rc == 0 for _, rc, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main())
