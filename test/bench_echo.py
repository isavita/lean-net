#!/usr/bin/env python3
"""Reproducible loopback echo benchmark with a compiled nonblocking load client.

This measures completed payload round trips, never byte counts or pipelined
messages. One request is outstanding on each connection. The client verifies
all echoed bytes. Connection establishment is outside the measured interval.
The report includes binary hash, machine details, latency and early fairness.

Run `lake build lean-net-echo`, then `python3 test/bench_echo.py`.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def info(command):
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / ".lake/build/bin/lean-net-echo")
    parser.add_argument("--server-arg", action="append", default=[], help="argument passed after the server port (repeatable)")
    parser.add_argument("--requests", type=int, default=200000)
    parser.add_argument("--connections", type=int, nargs="+", default=[1, 16, 100])
    parser.add_argument("--payload-bytes", type=int, default=16)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-rps", type=float, help="fail if any measured round is below this completed-RPS threshold")
    args = parser.parse_args()
    if not args.binary.is_file():
        parser.error(f"server executable does not exist: {args.binary}")
    if args.requests <= 0 or args.rounds <= 0 or args.payload_bytes <= 0 or any(c <= 0 or c > args.requests for c in args.connections):
        parser.error("requests, rounds, payload and connections must be positive; requests >= connections")
    report = {"environment": {"platform": platform.platform(), "cpu_count": os.cpu_count(),
              "cpu": info(["sysctl", "-n", "machdep.cpu.brand_string"]) if platform.system() == "Darwin" else info(["uname", "-m"]),
              "memory_bytes": info(["sysctl", "-n", "hw.memsize"]) if platform.system() == "Darwin" else None,
              "compiler": info([os.environ.get("CC", "cc"), "--version"]),
              "lean": info(["lean", "--version"])},
              "git_head": info(["git", "rev-parse", "HEAD"]),
              "client_source_sha256": hashlib.sha256((ROOT / "test/bench_echo.c").read_bytes()).hexdigest(),
              "driver_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "binary": str(args.binary.resolve()), "server_args": args.server_arg, "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
              "method": "fixed-count closed-loop, one outstanding verified echo per connection; connects excluded", "runs": []}
    with tempfile.TemporaryDirectory(prefix="lean-net-echo-bench-") as temporary:
        client = Path(temporary) / "echo-bench"
        server_binary = Path(temporary) / "server"
        shutil.copy2(args.binary, server_binary)
        subprocess.run([os.environ.get("CC", "cc"), "-O3", "-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror", str(ROOT / "test/bench_echo.c"), "-o", str(client)], check=True)
        for connections in args.connections:
            for round_index in range(args.rounds):
                with socket.socket() as probe:
                    probe.bind(("127.0.0.1", 0)); port = probe.getsockname()[1]
                with tempfile.TemporaryFile(mode="w+") as log:
                    server = subprocess.Popen([str(server_binary), str(port), *args.server_arg], stdout=log, stderr=log)
                    try:
                        deadline = time.monotonic() + 5
                        while True:
                            if server.poll() is not None:
                                log.seek(0); raise RuntimeError(f"server exited: {log.read()}")
                            try:
                                with socket.create_connection(("127.0.0.1", port), timeout=.1): break
                            except OSError:
                                if time.monotonic() >= deadline: raise RuntimeError("server startup timeout")
                                time.sleep(.01)
                        result = subprocess.run([str(client), str(port), str(connections), str(args.requests), str(args.payload_bytes)], capture_output=True, text=True, timeout=130)
                        if result.returncode:
                            raise RuntimeError(f"load generator failed ({result.returncode}): {result.stderr}")
                        run = json.loads(result.stdout); run["round"] = round_index + 1
                        report["runs"].append(run)
                        print(json.dumps(run), flush=True)
                    finally:
                        if server.poll() is None: server.send_signal(signal.SIGINT)
                        try: code = server.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            server.kill(); server.wait(); raise RuntimeError("server failed to exit after SIGINT")
                        if code != 0 and sys.exc_info()[0] is None:
                            log.seek(0); raise RuntimeError(f"server exit {code}: {log.read()}")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    if args.require_rps and any(run["requests_per_second"] < args.require_rps for run in report["runs"]):
        raise SystemExit("completed echo throughput below requested threshold")


if __name__ == "__main__":
    main()
