#!/usr/bin/env python3
"""Bounded deterministic pure-protocol fuzzing; this does not build Lake targets.

Short profile is intended for CI. Long profile is explicit, reproducible and
still bounded. Every case announces its independent replay seed before work;
timeout/panic/OOM failures retain the log and final seed as well as input hex
when Lean catches an invariant failure. Use --case-seed to replay one case.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "test/ProtocolFuzz.lean"


def stop(process):
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, timeout=15)
    else:
        os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=15)


def linux_startup_sample(pid, elapsed):
    """Bounded diagnostics distinguish reserved VA from physical memory."""
    try:
        with Path(f'/proc/{pid}/status').open() as stream:
            status = stream.read(16384)
        result = {'elapsed_seconds': elapsed}
        for key in ('VmPeak', 'VmSize', 'VmRSS', 'Threads'):
            match = re.search(r'^' + key + r':\s*(\d+)(?:\s+(kB))?', status, re.M)
            if match:
                result[key + ('_bytes' if match[2] else '')] = int(match[1]) * (1024 if match[2] else 1)
        with Path(f'/proc/{pid}/maps').open() as stream:
            maps = stream.read(512 * 1024 + 1)
        result['maps_truncated'] = len(maps) > 512 * 1024
        mappings = []
        for line in maps[:512 * 1024].splitlines():
            fields = line.split(maxsplit=5)
            if len(fields) < 5 or not re.fullmatch(r'[0-9a-f]+-[0-9a-f]+', fields[0]):
                continue
            low, high = (int(value, 16) for value in fields[0].split('-'))
            mappings.append({'address_range': fields[0], 'permissions': fields[1], 'bytes': high - low,
                             'name': fields[5][:256] if len(fields) == 6 else ''})
        result['largest_mappings'] = sorted(mappings, key=lambda row: row['bytes'], reverse=True)[:12]
        return result
    except (OSError, ValueError):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path(os.environ.get("LEAN_NET_FUZZ_BIN", ROOT / (".lake/build/bin/lean-net-protocol-fuzz.exe" if os.name == "nt" else ".lake/build/bin/lean-net-protocol-fuzz"))), help="Prebuilt fuzz executable; this wrapper never builds")
    parser.add_argument("--interpret", action="store_true", help="Explicit slow Lean interpreter fallback instead of the compiled binary")
    parser.add_argument("--profile", choices=["short", "long"], default="short")
    parser.add_argument("--seed", type=int, default=20261114)
    parser.add_argument("--case-seed", type=int, help="Replay one independent seed printed by FUZZ_CASE/FUZZ_REPRO")
    parser.add_argument("--cases", type=int)
    parser.add_argument("--max-bytes", type=int)
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--max-log-mib", type=int, default=16)
    parser.add_argument("--max-address-mib", type=int, default=2048, help="Inherited Linux address-space bound; input/state bounds apply on every OS")
    parser.add_argument("--output", type=Path, required=True, help="New artifact directory; never overwrites evidence")
    args = parser.parse_args()
    cases = args.cases if args.cases is not None else (500 if args.profile == "short" else 100000)
    maximum = args.max_bytes if args.max_bytes is not None else (2048 if args.profile == "short" else 16384)
    timeout = args.timeout if args.timeout is not None else (120 if args.profile == "short" else 7200)
    seed = args.case_seed if args.case_seed is not None else args.seed
    if args.case_seed is not None:
        cases = 1
    if not 0 <= seed < 2**64 or not 1 <= cases <= 1000000 or not 256 <= maximum <= 16384 or timeout <= 0 or args.max_log_mib <= 0 or args.max_address_mib < 512:
        parser.error("seed, case, input, timeout or resource bounds are invalid")
    if args.output.exists():
        parser.error("output already exists; choose a fresh artifact directory")
    if not args.interpret and not args.binary.is_file():
        parser.error("compiled fuzz binary is missing; ask the build coordinator to build lean-net-protocol-fuzz, or explicitly choose --interpret")
    stack_bytes = 64 * 1024**2
    stack_hard = None
    if sys.platform == 'linux':
        import resource
        stack_hard = resource.getrlimit(resource.RLIMIT_STACK)[1]
        if stack_hard != resource.RLIM_INFINITY and stack_hard < stack_bytes:
            parser.error('Linux hard stack limit cannot support the required 64 MiB main-thread bound')
    args.output.mkdir(parents=True)
    child_env = os.environ.copy()
    child_env['LEAN_NUM_THREADS'] = '1'
    child_env['LEAN_STACK_SIZE_KB'] = '65536'
    child_env['LEAN_MAIN_USE_THREAD'] = '0'
    command = (["lake", "env", "lean", "--run", str(SOURCE)] if args.interpret else [str(args.binary.resolve())]) + [str(seed), str(cases), str(maximum)]
    report = {"started_utc": datetime.now(timezone.utc).isoformat(), "platform": platform.platform(),
              "python": sys.version, "command": command, "seed": seed, "cases": cases,
              "max_input_bytes": maximum, "timeout_seconds": timeout, "profile": args.profile,
              "max_log_bytes": args.max_log_mib * 1024**2,
              "linux_address_space_bytes": args.max_address_mib * 1024**2 if sys.platform == "linux" else None,
              "lean_runtime_environment": {name: child_env[name] for name in ('LEAN_NUM_THREADS', 'LEAN_STACK_SIZE_KB', 'LEAN_MAIN_USE_THREAD')},
              "linux_main_stack_soft_bytes": stack_bytes if sys.platform == 'linux' else None,
              "linux_main_stack_hard_limit": stack_hard,
              "linux_startup_resource_samples": [], "linux_startup_sample_limit": 32,
              "lean_runtime_resource_note": "The pure fuzzer runs serially on its existing process thread. Linux sets a lazy 64 MiB main-stack soft limit under the existing hard limit, preserving the unchanged 2 GiB address-space cap. Any lazily created Lean task worker is limited to one and a 64 MiB stack.",
              "lean_runtime_investigation_note": "The earlier pool-stack diagnosis was not established: v4.35 task-manager construction is lazy and does not preallocate worker stacks. Startup samples record actual VA/RSS/thread counts and largest mappings; no mandatory allocator VA baseline or physical-memory budget increase is assumed.",
              "lean_runtime_sources": ['https://raw.githubusercontent.com/leanprover/lean4/v4.35.0/src/runtime/object.cpp',
                                       'https://raw.githubusercontent.com/leanprover/lean4/v4.35.0/src/runtime/thread.cpp'],
              "driver_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
              "compiled_binary_sha256": None if args.interpret else hashlib.sha256(args.binary.read_bytes()).hexdigest(),
              "execution_mode": "explicit_interpreter" if args.interpret else "compiled", "passed": False}
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
    report["source_commit"] = head.stdout.strip()
    report["source_status"] = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    log_path = args.output / "fuzz.log"
    started = time.monotonic()
    failure = None
    def limits():
        if sys.platform == "linux":
            import resource
            bound = args.max_address_mib * 1024**2
            resource.setrlimit(resource.RLIMIT_AS, (bound, bound))
            resource.setrlimit(resource.RLIMIT_STACK, (stack_bytes, stack_hard))
    try:
        with log_path.open("w") as log:
            process = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                       env=child_env,
                                       start_new_session=os.name != "nt", preexec_fn=limits if sys.platform == "linux" else None,
                                       creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0)
            try:
                while process.poll() is None:
                    if sys.platform == 'linux' and len(report['linux_startup_resource_samples']) < report['linux_startup_sample_limit']:
                        sample = linux_startup_sample(process.pid, time.monotonic() - started)
                        if sample is not None:
                            report['linux_startup_resource_samples'].append(sample)
                    if time.monotonic() - started > timeout:
                        raise TimeoutError("fuzz wall-clock budget exceeded")
                    if log_path.stat().st_size > report["max_log_bytes"]:
                        raise RuntimeError("fuzz log-size budget exceeded")
                    time.sleep(.1)
            finally:
                stop(process)
            report["exit_code"] = process.returncode
        text = log_path.read_text(errors="replace")
        matches = re.findall(r"FUZZ_CASE index=(\d+) seed=(\d+)", text)
        report["last_case"] = {"index": int(matches[-1][0]), "seed": int(matches[-1][1])} if matches else None
        success = f"FUZZ_OK seed={seed} cases={cases} max_input_bytes={maximum} "
        if process.returncode or success not in text or re.search(r"panic|out of memory|stack overflow|FUZZ_FAILURE", text, re.I):
            raise RuntimeError("fuzz failed; inspect fuzz.log and last_case for exact reproduction")
        report["passed"] = True
    except BaseException as error:
        failure = error
        report["failure"] = str(error)
        text = log_path.read_text(errors="replace") if log_path.exists() else ""
        matches = re.findall(r"FUZZ_CASE index=(\d+) seed=(\d+)", text)
        report["last_case"] = {"index": int(matches[-1][0]), "seed": int(matches[-1][1])} if matches else None
    finally:
        report["elapsed_seconds"] = time.monotonic() - started
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        if report.get("last_case"):
            report["replay"] = f"python3 test/fuzz_protocols.py --case-seed {report['last_case']['seed']} --max-bytes {maximum} {'--interpret' if args.interpret else '--binary ' + str(args.binary.resolve())} --output NEW_DIRECTORY"
        (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "cases": cases, "seed": seed,
                      "elapsed_seconds": report["elapsed_seconds"], "report": str(args.output / "report.json")}))
    if failure:
        print(str(failure), file=sys.stderr)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
