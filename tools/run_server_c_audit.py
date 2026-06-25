#!/usr/bin/env python3
"""Run repeatable C security checks for the SecChat server.

The script runs the project heuristic scanner locally, then executes the
tooling that needs Linux headers inside the Docker server image:
cppcheck, ASan/UBSan builds, and libFuzzer runs over WebSocket/JSON
validation helpers. Local runs default to a quick smoke fuzz pass; CI can pass
--fuzz-seconds for a longer timed run and collect crash artifacts.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(cmd: list[str], *, cwd: Path = ROOT) -> None:
    print("+ " + " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=cwd, check=True)


def run_optional(cmd: list[str], *, cwd: Path = ROOT) -> int:
    print("+ " + " ".join(cmd), flush=True)
    return subprocess.run(cmd, cwd=cwd, check=False).returncode


def run_shell(script: str) -> None:
    cmd = ["docker", "compose", "exec", "-T", "server", "bash", "-lc", script]
    run(cmd)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run SecChat C server static analysis, sanitizer, and fuzz checks."
    )
    parser.add_argument(
        "--fuzz-runs",
        type=int,
        default=10000,
        help="number of libFuzzer smoke iterations",
    )
    parser.add_argument(
        "--fuzz-seconds",
        type=int,
        default=0,
        help="run libFuzzer by wall-clock seconds instead of --fuzz-runs",
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=None,
        help="optional local directory for copied fuzz corpus/artifacts",
    )
    parser.add_argument(
        "--skip-install",
        action="store_true",
        help="assume clang/cppcheck are already installed in the server container",
    )
    args = parser.parse_args()

    run([sys.executable, "tools/security_audit.py", "--limit", "60"])

    install = ""
    if not args.skip_install:
        install = (
            "apt-get update >/dev/null && "
            "apt-get install -y clang cppcheck >/dev/null && "
        )

    if args.fuzz_seconds > 0:
        fuzz_cmd = f"make fuzz_long FUZZ_SECONDS={args.fuzz_seconds}"
    else:
        fuzz_cmd = f"make fuzz_smoke FUZZ_RUNS={args.fuzz_runs}"

    script = (
        "set -euo pipefail; "
        f"{install}"
        "cd /build; "
        "make clean; "
        "make test_domain; "
        "make asan_test_domain; "
        "make asan_build; "
        f"{fuzz_cmd}; "
        "make cppcheck"
    )
    run_shell(script)

    if args.artifact_dir:
        artifact_dir = args.artifact_dir
        if not artifact_dir.is_absolute():
            artifact_dir = ROOT / artifact_dir
        artifact_dir.mkdir(parents=True, exist_ok=True)
        run_optional([
            "docker", "compose", "cp",
            "server:/tmp/secchat_fuzz/artifacts",
            str(artifact_dir / "fuzz_artifacts"),
        ])
        run_optional([
            "docker", "compose", "cp",
            "server:/tmp/secchat_fuzz/corpus",
            str(artifact_dir / "fuzz_corpus"),
        ])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
