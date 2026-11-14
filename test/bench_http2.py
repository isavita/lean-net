#!/usr/bin/env python3
"""Real fixed-count h2load gate with binary-body preflight and RSS samples.

The default workload is exactly -n100000 -c10 -m100. h2load validates request,
status and aggregate byte counts; this harness independently verifies binary
body bytes before and after load. The first round warms caches for the separate
RSS comparison: post-final-round RSS may grow at most1% over post-round1 RSS,
with at least3 rounds required. All rounds still count for correctness/RPS.
This short observation does not establish the final24-hour soak.
"""
import argparse
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

from http2_test_support import H2Client

ROOT = Path(__file__).resolve().parents[1]


def output(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=15)
    return result.stdout.strip() if result.returncode == 0 else None


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def parse_result(text, requests, body_bytes):
    counts = re.search(r"requests:\s*(\d+) total,\s*(\d+) started,\s*(\d+) done,\s*(\d+) succeeded,\s*(\d+) failed,\s*(\d+) errored,\s*(\d+) timeout", text)
    rate = re.search(r"finished in ([^,]+),\s*([\d.]+) req/s", text)
    statuses = re.search(r"status codes:\s*(\d+) 2xx,\s*(\d+) 3xx,\s*(\d+) 4xx,\s*(\d+) 5xx", text)
    data = re.search(r"\((\d+)\) data", text)
    protocol = re.search(r"Application protocol:\s*(\S+)", text)
    if not all((counts, rate, statuses, data, protocol)):
        raise RuntimeError("unrecognized h2load output:\n" + text)
    total, started, done, succeeded, failed, errored, timeout = map(int, counts.groups())
    valid = ([total, started, done, succeeded] == [requests] * 4 and failed == errored == timeout == 0
             and list(map(int, statuses.groups())) == [requests, 0, 0, 0]
             and int(data[1]) == requests * body_bytes and protocol[1] in ("h2", "h2c"))
    return {"requests": requests, "requests_per_second": float(rate[2]), "duration_text": rate[1],
            "started": started, "done": done, "succeeded": succeeded,
            "successful_requests_per_second": float(rate[2]) * succeeded / done if done else 0,
            "failed": failed, "errored": errored, "timeouts": timeout,
            "response_data_bytes": int(data[1]), "application_protocol": protocol[1],
            "aggregate_bytes_match_successful_responses": int(data[1]) == succeeded * body_bytes,
            "valid": valid, "raw_stdout": text}


def process_sample(pid, started):
    # ps RSS is KiB on macOS/Linux. The benchmark's claimed host and platform
    # are recorded explicitly; Windows conformance is exercised separately.
    result = subprocess.run(["ps", "-p", str(pid), "-o", "rss=,pcpu=,time="],
                            capture_output=True, text=True, timeout=5)
    values = result.stdout.split()
    if result.returncode or len(values) != 3:
        return None
    return {"seconds": round(time.monotonic() - started, 6), "rss_kib": int(values[0]),
            "cpu_percent": float(values[1]), "cpu_time": values[2]}


def verify_body(port, path, expected):
    peer = H2Client(port)
    try:
        advertised = dict(peer.server_settings)
        peer.request(1, path.encode())
        actual = peer.response(1)
        if actual != expected:
            raise RuntimeError(f"binary body mismatch: {actual[:64].hex()} != {expected.hex()}")
        return advertised
    finally:
        peer.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / ".lake/build/bin/lean-net-http2-reactor-fixture")
    parser.add_argument("--server-arg", action="append", default=[])
    parser.add_argument("--workers", type=int, nargs="+", default=[1, 8])
    parser.add_argument("--requests", type=int, default=100000)
    parser.add_argument("--connections", type=int, default=10)
    parser.add_argument("--streams", type=int, default=100)
    parser.add_argument("--threads", type=int, default=1, help="Default preserves the exact requested h2load workload; extra client-thread diagnostics must be separate")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--require-rps", type=float, default=0)
    parser.add_argument("--throughput-gate-workers", type=int, nargs="+",
                        help="Apply --require-rps only to these selected worker counts; other counts remain explicit characterization")
    parser.add_argument("--path", default="/binary")
    parser.add_argument("--body-hex", default="00ff0d0a41")
    parser.add_argument("--h2load", default=shutil.which("h2load") or "h2load")
    parser.add_argument("--base-commit", help="Known commit of a pre-change immutable baseline binary")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.binary.is_file() or any(n <= 0 for n in [args.requests, args.connections, args.streams, args.threads, args.rounds, *args.workers]):
        parser.error("existing binary and positive workload bounds are required")
    gate_workers = args.throughput_gate_workers if args.throughput_gate_workers is not None else args.workers
    if not set(gate_workers) <= set(args.workers):
        parser.error("throughput gate workers must be included in --workers")
    if args.output.exists():
        parser.error("choose a new output file; benchmark evidence is never overwritten")
    expected = bytes.fromhex(args.body_hex)
    if not expected:
        parser.error("expected body cannot be empty")
    original_hash = sha256(args.binary)
    report = {"started_utc": datetime.now(timezone.utc).isoformat(),
              "git_head": output(["git", "rev-parse", "HEAD"]), "git_status": output(["git", "status", "--short"]),
              "binary": str(args.binary.resolve()), "binary_sha256": original_hash, "base_commit": args.base_commit,
              "environment": {"platform": platform.platform(), "python": sys.version, "logical_cpus": os.cpu_count(),
                              "hpack": version("hpack"),
                              "cpu": output(["sysctl", "-n", "machdep.cpu.brand_string"]), "h2load": output([args.h2load, "--version"]),
                              "lean": output(["lean", "--version"])},
              "configuration": {"server_arguments_after_port": args.server_arg or ["bench"], "workers": args.workers,
                                "max_clients": 128, "requested_output_buffers": 512, "http_output_flights_per_client": 4},
              "workload": {"requests": args.requests, "connections": args.connections, "max_streams_per_connection": args.streams,
                           "client_threads": args.threads, "rounds": args.rounds, "path": args.path, "expected_body_hex": expected.hex()},
              "throughput_gate": {"workers": gate_workers, "require_rps_strictly_greater_than": args.require_rps},
              "rss_gate": {"max_growth_percent": 1.0, "minimum_rounds": 3,
                           "method": "Round1 warms caches. Compare the same persistent server's RSS immediately after the final round against immediately after round1; all rounds remain correctness/throughput samples. This is a short phase4 observation, not the final24-hour soak."},
              "verification_scope": "Exact binary-body samples before/after fixed-count h2load; every h2load request/status and aggregate data count checked. h2load does not validate each body's contents. Short RSS samples are not the final soak.",
              "source_sha256": {str(p.relative_to(ROOT)): sha256(p) for directory in [ROOT / "LeanNet/HTTP2", ROOT / "LeanNet/HTTP"] for p in directory.rglob("*.lean")},
              "runs": [], "rss_assessments": [], "passed": False}
    for name in ["test/bench_http2.py", "test/http2_test_support.py", "test/HTTP2ReactorFixture.lean",
                 "test/HTTP1ReactorFixture.lean", "test/requirements-http2.txt", "LeanNet/HTTP1/Handlers.lean",
                 "c/reactor_posix.c", "c/reactor_windows.c", "c/reactor_group.c", "lakefile.lean"]:
        if (ROOT / name).is_file(): report["source_sha256"][name] = sha256(ROOT / name)
    if args.base_commit:
        report["base_commit_source_sha256"] = {}
        for name in report["source_sha256"]:
            old = subprocess.run(["git", "show", f"{args.base_commit}:{name}"], capture_output=True)
            if old.returncode == 0:
                report["base_commit_source_sha256"][name] = hashlib.sha256(old.stdout).hexdigest()
        report["source_scope"] = "source_sha256 records the current working tree/tooling; base_commit_source_sha256 records the immutable historical source for the pre-change binary."
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="lean-net-h2-bench-") as temporary:
        snapshot = Path(temporary) / "server"; shutil.copy2(args.binary, snapshot)
        assert sha256(snapshot) == original_hash
        for workers in args.workers:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0)); port = probe.getsockname()[1]
            flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
            with tempfile.TemporaryFile(mode="w+") as log:
                server = subprocess.Popen([str(snapshot), str(port), *(args.server_arg or ["bench"]), str(workers)],
                                          stdout=log, stderr=log, creationflags=flags)
                try:
                    deadline = time.monotonic() + 10
                    while True:
                        if server.poll() is not None:
                            log.seek(0); raise RuntimeError("server startup: " + log.read())
                        try:
                            advertised = verify_body(port, args.path, expected)
                            break
                        except (OSError, EOFError):
                            if time.monotonic() >= deadline: raise
                            time.sleep(.02)
                    for index in range(args.rounds):
                        command = [args.h2load, "-n", str(args.requests), "-c", str(args.connections),
                                   "-m", str(args.streams), "-t", str(args.threads), "-N", "10s", "-T", "120s",
                                   f"http://127.0.0.1:{port}{args.path}"]
                        started = time.monotonic(); samples = []; client_samples = []
                        before = process_sample(server.pid, started)
                        if before: samples.append(before)
                        client = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        try:
                            while client.poll() is None:
                                if time.monotonic() - started > 130:
                                    raise TimeoutError("h2load exceeded bounded deadline")
                                sample = process_sample(server.pid, started)
                                if sample: samples.append(sample)
                                client_sample = process_sample(client.pid, started)
                                if client_sample: client_samples.append(client_sample)
                                time.sleep(.05)
                            stdout, stderr = client.communicate(timeout=5)
                        finally:
                            if client.poll() is None:
                                client.kill(); client.wait(timeout=5)
                        if client.returncode:
                            raise RuntimeError(f"h2load exit{client.returncode}: {stderr}")
                        run = parse_result(stdout, args.requests, len(expected))
                        verify_body(port, args.path, expected)
                        after = process_sample(server.pid, started)
                        if after: samples.append(after)
                        run.update({"workers": workers, "round": index + 1, "command": command,
                                    "observed_wall_seconds": time.monotonic() - started, "raw_stderr": stderr,
                                    "server_settings": advertised, "resource_samples": samples,
                                    "client_resource_samples": client_samples,
                                    "rss_before_kib": before["rss_kib"] if before else None,
                                    "rss_after_kib": after["rss_kib"] if after else None,
                                    "rss_peak_kib": max((s["rss_kib"] for s in samples), default=None),
                                    "rss_growth_kib": after["rss_kib"] - before["rss_kib"] if before and after else None})
                        run["throughput_gate_applied"] = workers in gate_workers
                        run["throughput_gate_passed"] = not run["throughput_gate_applied"] or run["requests_per_second"] > args.require_rps
                        report["runs"].append(run); args.output.write_text(json.dumps(report, indent=2) + "\n")
                        print(json.dumps({k:run[k] for k in ["workers", "round", "requests_per_second", "valid", "throughput_gate_passed", "rss_growth_kib"]}), flush=True)
                    worker_runs = [run for run in report["runs"] if run["workers"] == workers]
                    first_rss, last_rss = worker_runs[0]["rss_after_kib"], worker_runs[-1]["rss_after_kib"]
                    enough = len(worker_runs) >= 3 and first_rss is not None and first_rss > 0 and last_rss is not None
                    growth = 100 * (last_rss - first_rss) / first_rss if enough else None
                    assessment = {"workers": workers, "assessed": enough,
                                  "post_round1_rss_kib": first_rss, "post_final_round_rss_kib": last_rss,
                                  "growth_kib": last_rss - first_rss if enough else None,
                                  "growth_percent": growth, "passed": enough and growth <= 1.0}
                    report["rss_assessments"].append(assessment)
                    args.output.write_text(json.dumps(report, indent=2) + "\n")
                    print(json.dumps({"rss_assessment": assessment}), flush=True)
                finally:
                    if server.poll() is None:
                        server.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
                    try: code = server.wait(timeout=6)
                    except subprocess.TimeoutExpired:
                        server.kill(); server.wait(timeout=5)
                        raise RuntimeError("server failed bounded shutdown")
                    if code:
                        log.seek(0); raise RuntimeError(f"server exit{code}: {log.read()}")
    report["passed"] = (all(run["valid"] and run["throughput_gate_passed"] for run in report["runs"])
                        and all(item["passed"] for item in report["rss_assessments"]))
    report["original_binary_unchanged"] = sha256(args.binary) == original_hash
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
