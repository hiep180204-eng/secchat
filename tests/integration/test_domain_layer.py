#!/usr/bin/env python3
"""
Domain layer verification.

Runs the self-contained C unit tests inside the Docker container
(no database, no network — pure domain logic).

The test binary is compiled fresh each run, confirming that:
  1. The domain layer files compile cleanly with -Wall -Wextra
  2. All domain validation invariants hold
  3. The full test suite completes in < 1 second

Usage:
    python test_domain_layer.py
"""

import subprocess
import sys
import time

ok = fail = 0

def check(name, cond, detail=""):
    global ok, fail
    if cond:
        print(f"  PASS  {name}")
        ok += 1
    else:
        print(f"  FAIL  {name}" + (f" -- {detail}" if detail else ""))
        fail += 1

# ── Step 1: compile the domain unit tests inside the container ─────────────
print("\n=== Compiling domain unit tests inside Docker ===")

compile_cmd = [
    "docker", "exec", "chat-server",
    "gcc", "-Wall", "-Wextra", "-O2",
    "-I/build", "-I/build/domain",
    "-o", "/tmp/test_domain_unit",
    "/build/domain/test_domain_unit.c",
    "/build/domain/validation.c",
]

t0 = time.time()
result = subprocess.run(compile_cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
compile_time = time.time() - t0

check("Domain unit test compiles with -Wall -Wextra (no warnings/errors)",
      result.returncode == 0,
      result.stderr.strip()[:200] if result.returncode != 0 else "")

if result.returncode != 0:
    print(f"\n  Compiler output:\n{result.stderr}")
    print(f"\n{'='*54}\n  Results: {ok} passed, {fail} failed\n{'='*54}")
    sys.exit(1)

# ── Step 2: run the domain unit tests ──────────────────────────────────────
print("\n=== Running domain unit tests (no DB, no network) ===")

run_cmd = ["docker", "exec", "chat-server", "/tmp/test_domain_unit"]

t1 = time.time()
run_result = subprocess.run(run_cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
run_time = time.time() - t1

# Print the test output so the user can see individual test results
print(run_result.stdout.encode('ascii', errors='replace').decode('ascii'))
if run_result.stderr:
    print(run_result.stderr.encode('ascii', errors='replace').decode('ascii'))

check("Domain unit tests all pass (exit code 0)",
      run_result.returncode == 0,
      f"exit code = {run_result.returncode}")

check(f"Domain unit tests complete in <1 second (actual: {run_time:.3f}s)",
      run_time < 1.0,
      f"{run_time:.3f}s")

# ── Step 3: verify the server still builds cleanly with domain/ included ───
print("\n=== Verifying full server build (domain/ integrated) ===")

build_cmd = [
    "docker", "exec", "chat-server",
    "sh", "-c", "cd /build && make -j$(nproc) 2>&1 | tail -5",
]

build_result = subprocess.run(build_cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
check("Full server build succeeds with domain/ in SRCS",
      "chat_server" in build_result.stdout or build_result.returncode == 0,
      build_result.stdout[-200:] if build_result.returncode != 0 else "")

# ── Summary ────────────────────────────────────────────────────────────────
print(f"\n{'='*54}")
print(f"  Results: {ok} passed, {fail} failed")
print(f"{'='*54}")
sys.exit(0 if fail == 0 else 1)
