#!/usr/bin/env python3
"""Measure gate decision time and Lean small allocations on one owner thread.

Build with ``lake build lean-net-gate-perf``. The Lean executable warms each
case, uses ``IO.getNumHeartbeats`` for small-allocation counts, and measures
monotonic nanoseconds. This is a local microbenchmark, not server throughput.
"""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SUFFIX = ".exe" if sys.platform == "win32" else ""
SOURCES = (
    "LeanNet/Gate/Policy.lean", "LeanNet/Gate/Gate.lean",
    "LeanNet/HTTP/Admission.lean", "test/GatePerf.lean",
    "test/bench_gate.py", "lakefile.lean",
)
CASES = {"disabled-reference", "host-only-gate", "route-gate"}


def command_output(*args):
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path,
                        default=ROOT / ".lake/build/bin" / f"lean-net-gate-perf{SUFFIX}")
    parser.add_argument("--iterations", type=int, default=100000)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.binary.is_file() or args.iterations < 1000 or args.rounds < 1:
        parser.error("a built binary, at least 1000 iterations, and positive rounds are required")

    runs = []
    for round_index in range(1, args.rounds + 1):
        result = subprocess.run([str(args.binary), str(args.iterations)], cwd=ROOT,
                                capture_output=True, text=True, timeout=180)
        if result.returncode:
            raise RuntimeError(f"gate benchmark exited {result.returncode}: {result.stderr}")
        samples = [json.loads(line) for line in result.stdout.splitlines()]
        if {sample["case"] for sample in samples} != CASES or len(samples) != len(CASES):
            raise RuntimeError(f"unexpected gate cases: {result.stdout}")
        if any(sample["requests"] != args.iterations or
               sample["small_allocations"] < 0 or sample["elapsed_ns"] <= 0
               for sample in samples):
            raise RuntimeError(f"invalid gate sample: {result.stdout}")
        runs.append({"round": round_index, "samples": samples})

    report = {
        "method": "single-thread compiled Lean gate decision; prebuilt head and policy; warmed cases",
        "allocation_metric": "IO.getNumHeartbeats: small allocations on current Lean thread only",
        "limitations": ["large allocations are not counted", "no socket, parser, TLS, or GC pause included",
                        "elapsed time is a local microbenchmark, not RPS per core"],
        "environment": {"platform": platform.platform(),
                        "lean": command_output("lean", "--version"),
                        "git_head": command_output("git", "rev-parse", "HEAD"),
                        "git_status": command_output("git", "status", "--short")},
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "source_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                          for name in SOURCES},
        "iterations": args.iterations,
        "runs": runs,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(args.output)
    for case in sorted(CASES):
        values = [next(sample for sample in run["samples"] if sample["case"] == case)
                  for run in runs]
        print(f"{case}: small allocations/request="
              f"{[round(value['small_allocations_per_request'], 2) for value in values]}, "
              f"ns/request={[round(value['ns_per_request']) for value in values]}")


if __name__ == "__main__":
    main()
