#!/usr/bin/env python3
"""Run SecChat formal verification models with ProVerif.

The runner prefers PROVERIF_BIN or a proverif executable on PATH. On Windows,
``--download`` fetches the official ProVerif 2.05 binary archive into the
repo-local .tools cache.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
FORMAL_DIR = REPO / "formal" / "proverif"
TOOLS_DIR = REPO / ".tools"
VERSION = "2.05"
ARCHIVE = TOOLS_DIR / f"proverifbin{VERSION}.tar.gz"
PROVERIF_DIR = TOOLS_DIR / f"proverif{VERSION}"
PROVERIF_URL = (
    f"https://bblanche.gitlabpages.inria.fr/proverif/"
    f"proverifbin{VERSION}.tar.gz"
)


def _local_proverif() -> Path:
    exe = "proverif.exe" if platform.system() == "Windows" else "proverif"
    return PROVERIF_DIR / exe


def _download_windows_binary() -> Path:
    if platform.system() != "Windows":
        raise RuntimeError(
            "Automatic download is only implemented for the official Windows "
            "binary. Install proverif on PATH or set PROVERIF_BIN."
        )
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    if not ARCHIVE.exists():
        print(f"[formal] downloading ProVerif {VERSION} from official site...")
        urllib.request.urlretrieve(PROVERIF_URL, ARCHIVE)
    if not _local_proverif().exists():
        print("[formal] extracting ProVerif...")
        with tarfile.open(ARCHIVE, "r:gz") as tf:
            tf.extractall(TOOLS_DIR)
    return _local_proverif()


def resolve_proverif(download: bool) -> Path | None:
    env = os.environ.get("PROVERIF_BIN")
    if env:
        path = Path(env)
        if path.exists():
            return path
    found = shutil.which("proverif")
    if found:
        return Path(found)
    if _local_proverif().exists():
        return _local_proverif()
    if download:
        return _download_windows_binary()
    return None


def run_model(proverif: Path, model: Path, parse_only: bool = False) -> int:
    cmd = [str(proverif)]
    if parse_only:
        cmd.append("-parse-only")
    cmd.append(str(model))
    print(f"[formal] running {' '.join(cmd)}")
    proc = subprocess.run(cmd, cwd=REPO, text=True, capture_output=True)
    if proc.stdout:
        print(proc.stdout)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr)
    if proc.returncode != 0:
        return proc.returncode
    if " is false." in proc.stdout or " is false.\r" in proc.stdout:
        print(f"[formal] model failed at least one query: {model}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download", action="store_true",
                        help="Download the official Windows ProVerif binary if needed")
    parser.add_argument("--require", action="store_true",
                        help="Fail when ProVerif is unavailable instead of skipping")
    parser.add_argument("--parse-only", action="store_true",
                        help="Only parse models")
    parser.add_argument("--model", action="append",
                        help="Specific .pv model to run; defaults to all models")
    parser.add_argument("--list", action="store_true",
                        help="List models and exit")
    args = parser.parse_args(argv)

    models = [Path(p) for p in args.model] if args.model else sorted(FORMAL_DIR.glob("*.pv"))
    models = [p if p.is_absolute() else (REPO / p) for p in models]
    if args.list:
        for model in models:
            print(model.relative_to(REPO))
        return 0
    missing = [str(p) for p in models if not p.exists()]
    if missing:
        print("[formal] missing model(s): " + ", ".join(missing), file=sys.stderr)
        return 2

    try:
        proverif = resolve_proverif(args.download)
    except Exception as exc:
        print(f"[formal] ProVerif setup failed: {exc}", file=sys.stderr)
        return 2 if args.require else 0

    if proverif is None:
        print(
            "[formal] ProVerif is not installed; skipping formal models. "
            "Use --download on Windows, install proverif on PATH, or set PROVERIF_BIN."
        )
        return 2 if args.require else 0

    rc = 0
    for model in models:
        rc = max(rc, run_model(proverif, model, parse_only=args.parse_only))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
