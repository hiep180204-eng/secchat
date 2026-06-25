#!/usr/bin/env python3
"""Lightweight static security review helper for the C server.

This is not a replacement for cppcheck, clang-tidy, sanitizers, or fuzzing.
It gives repeatable reminders for risky areas that matter in this project:
WebSocket parsing, JSON output, buffer handling, SQL, input limits, rate
limiting, and network/database failure paths.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "server"


@dataclass
class Finding:
    category: str
    path: Path
    line: int
    detail: str
    text: str


CHECKS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "buffer",
        re.compile(r"\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\("),
        "Avoid unbounded string/buffer functions.",
    ),
    (
        "buffer",
        re.compile(r"\bmemcpy\s*\("),
        "Check that memcpy length is validated against the destination size.",
    ),
    (
        "json",
        re.compile(r"\bsnprintf\s*\([^;]*%s", re.DOTALL),
        "JSON/string formatting with %s needs escaping and truncation checks.",
    ),
    (
        "sql",
        re.compile(r"\bmysql_query\s*\("),
        "Prefer prepared statements for any query using user-controlled data.",
    ),
    (
        "allocation",
        re.compile(r"\b(malloc|calloc|realloc|strdup)\s*\("),
        "Verify allocation failure handling and cleanup on every path.",
    ),
]


AREA_HINTS = {
    "websocket": [
        SERVER / "transport",
        SERVER / "main.c",
    ],
    "json": [
        SERVER / "infra" / "log.c",
        SERVER / "services",
    ],
    "input_limits": [
        SERVER / "domain" / "validation.c",
        SERVER / "services",
    ],
    "rate_limit": [
        SERVER / "services",
        SERVER / "infra",
    ],
    "database_errors": [
        SERVER / "repository",
        SERVER / "services",
    ],
}


def iter_c_files() -> list[Path]:
    return sorted(
        path for path in SERVER.rglob("*")
        if path.suffix in {".c", ".h"}
        and path.is_file()
        and not path.name.startswith("test_")
    )


def scan_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return findings
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if (not stripped or stripped.startswith("//")
                or stripped.startswith("/*")
                or stripped.startswith("*")):
            continue
        for category, pattern, detail in CHECKS:
            if pattern.search(line):
                findings.append(
                    Finding(category, path, lineno, detail, stripped)
                )
    return findings


def summarize_area_presence(files: list[Path]) -> dict[str, int]:
    out: dict[str, int] = {}
    for area, roots in AREA_HINTS.items():
        count = 0
        for path in files:
            for root in roots:
                try:
                    if path == root or path.is_relative_to(root):
                        count += 1
                        break
                except ValueError:
                    continue
        out[area] = count
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a lightweight static security scan over server C files."
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="return non-zero when heuristic findings are present",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=80,
        help="maximum number of findings to print",
    )
    args = parser.parse_args()

    files = iter_c_files()
    findings: list[Finding] = []
    for path in files:
        findings.extend(scan_file(path))

    print("SecChat C server security audit helper")
    print(f"Scanned {len(files)} C/header files under {SERVER}")
    print()
    print("Review coverage areas:")
    for area, count in summarize_area_presence(files).items():
        print(f"- {area}: {count} file(s) to review")

    print()
    if not findings:
        print("No heuristic findings.")
        return 0

    print(f"Heuristic findings: {len(findings)}")
    for finding in findings[: max(0, args.limit)]:
        rel = finding.path.relative_to(ROOT)
        print(
            f"- [{finding.category}] {rel}:{finding.line}: "
            f"{finding.detail} :: {finding.text}"
        )
    if len(findings) > args.limit:
        print(f"... {len(findings) - args.limit} more finding(s) hidden by --limit")

    print()
    print(
        "Next recommended tools: cppcheck, clang-tidy, ASan/UBSan test runs, "
        "and fuzzing for the WebSocket frame parser and JSON command parser."
    )
    return 1 if args.strict and findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
