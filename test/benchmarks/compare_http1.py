#!/usr/bin/env python3
"""Compare lean-net with Go net/http using the same verified HTTP/1.1 client."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
REFERENCE = Path(__file__).with_name("go_http1_reference.go")
CLIENT = ROOT / "test" / "bench_http1.c"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def version(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return None
    return (result.stdout or result.stderr).strip().splitlines()[0] if result.returncode == 0 else None


def cpu_seconds(pid):
    result = subprocess.run(["ps", "-p", str(pid), "-o", "time="],
                            capture_output=True, text=True, check=False)
    if result.returncode:
        return None
    parts = result.stdout.strip().split(":")
    try:
        seconds = 0.0
        for part in parts:
            seconds = seconds * 60 + float(part)
        return seconds
    except (ValueError, IndexError):
        return None


def source_snapshot():
    paths = [ROOT / "lakefile.lean", ROOT / "LeanNet.lean",
             ROOT / "test" / "HTTP1ReactorFixture.lean"]
    paths += list((ROOT / "LeanNet").rglob("*.lean"))
    paths += list((ROOT / "c").glob("*.c")) + list((ROOT / "c").glob("*.h"))
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return {"sha256": digest.hexdigest(), "files": len(paths)}


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wire_signature(port):
    with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
        connection.settimeout(2)
        connection.sendall(b"GET /binary HTTP/1.1\r\nHost: localhost\r\n\r\n")
        wire = bytearray()
        while b"\r\n\r\n" not in wire or len(wire.split(b"\r\n\r\n", 1)[1]) < 5:
            chunk = connection.recv(4096)
            if not chunk or len(wire) + len(chunk) > 8192:
                raise RuntimeError("incomplete or oversized probe response")
            wire.extend(chunk)
    head, body = bytes(wire).split(b"\r\n\r\n", 1)
    if body != bytes.fromhex("00ff0d0a41"):
        raise RuntimeError("probe response body differs")
    lines = head.decode("ascii").split("\r\n")
    if lines[0] != "HTTP/1.1 200 OK":
        raise RuntimeError(f"probe response status differs: {lines[0]}")
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        name = name.lower()
        if separator != ":" or name in headers:
            raise RuntimeError("invalid or duplicate probe response header")
        headers[name] = value.strip()
    if not headers.get("date"):
        raise RuntimeError("probe response has no Date")
    headers["date"] = "<date>"
    return {"bytes": len(wire), "header_bytes": len(head) + 4,
            "headers": dict(sorted(headers.items()))}


def measure(server_binary, server_args, environment, client, connections, requests, warmup):
    port = free_port()
    with tempfile.TemporaryFile(mode="w+") as log:
        server = subprocess.Popen([str(server_binary), str(port), *server_args],
                                  stdout=log, stderr=log, env=environment)
        failed = False
        try:
            deadline = time.monotonic() + 10
            while True:
                if server.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(f"server startup exit {server.returncode}: {log.read()}")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("server startup timed out")
                    time.sleep(.01)
            def run(count):
                command = [str(client), str(port), str(connections), str(count),
                           "/binary", "00ff0d0a41"]
                result = subprocess.run(command, capture_output=True, text=True, timeout=130)
                if result.returncode:
                    log.seek(0)
                    raise RuntimeError(f"client failed: {result.stderr}; server: {log.read()}")
                data = json.loads(result.stdout)
                if data["requests"] != count or data["verified_responses"] != count or data["clients_progressed_in_first_second"] != connections:
                    raise RuntimeError(f"invalid response counts: {data}")
                return data
            wire = wire_signature(port)
            run(warmup)
            cpu_before = cpu_seconds(server.pid)
            data = run(requests)
            cpu_after = cpu_seconds(server.pid)
            if cpu_before is not None and cpu_after is not None:
                data["server_cpu_seconds"] = round(cpu_after - cpu_before, 3)
                data["approx_server_cpu_cores"] = round((cpu_after - cpu_before) / data["seconds"], 3)
            data["wire"] = wire
            return data
        except BaseException:
            failed = True
            raise
        finally:
            if server.poll() is None:
                server.send_signal(signal.SIGINT)
            try:
                code = server.wait(timeout=8)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=8)
                raise RuntimeError("server did not stop after SIGINT")
            if code and not failed:
                log.seek(0)
                raise RuntimeError(f"server shutdown exit {code}: {log.read()}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lean-binary", type=Path,
                        default=ROOT / ".lake/build/bin/lean-net-http1-reactor-fixture")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--connections", type=int, default=100)
    parser.add_argument("--requests", type=int, default=200000)
    parser.add_argument("--warmup", type=int, default=10000)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.lean_binary.is_file() or min(args.workers, args.connections, args.requests,
                                            args.warmup, args.rounds) < 1 or args.workers > 256 or args.connections > 128 or args.requests < args.connections or args.warmup < args.connections:
        parser.error("build the Lean fixture and specify positive workload values (connections <= 128)")
    report = {
        "scope": "HTTP/1.1 GET /binary: five response bytes, no TLS, no proxy, loopback",
        "method": "same verified C client, fixed request count, persistent connections, one outstanding request per connection, no pipelining; connection setup excluded; every status, Content-Length and body byte checked",
        "environment": {"platform": platform.platform(), "cpu": version(["sysctl", "-n", "machdep.cpu.brand_string"]),
                        "logical_cpus": os.cpu_count(), "lean": version(["lean", "--version"]),
                        "go": version(["go", "version"]), "cc": version(["cc", "--version"])},
        "source": {"git_head": version(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
                   "git_status": subprocess.run(["git", "status", "--short"], cwd=ROOT,
                                                capture_output=True, text=True, check=True).stdout.strip(),
                   "lean_source_snapshot": source_snapshot(),
                   "lean_binary_sha256": sha256(args.lean_binary),
                   "go_source_sha256": sha256(REFERENCE), "client_source_sha256": sha256(CLIENT),
                   "driver_source_sha256": sha256(Path(__file__))},
        "configuration": {"lean_workers": args.workers, "go_gomaxprocs": args.workers,
                          "connections": args.connections, "requests_per_round": args.requests,
                          "warmup_requests_per_server": args.warmup,
                          "rounds_per_server": args.rounds,
                          "lean_fixture_mode": "bench", "lean_max_clients": 128,
                          "lean_output_buffers": 512},
        "runs": []
    }
    with tempfile.TemporaryDirectory(prefix="lean-net-http1-comparison-") as temp:
        temp = Path(temp)
        lean_binary = temp / "lean-server"
        go_binary = temp / "go-server"
        client = temp / "verified-client"
        shutil.copy2(args.lean_binary, lean_binary)
        build = ["go", "build", "-trimpath"]
        if platform.system() == "Darwin":
            # The installed Go toolchain needs an external link and fresh ad-hoc
            # signature to launch binaries on this macOS host.
            build.append("-ldflags=-linkmode=external")
        subprocess.run([*build, "-o", str(go_binary), str(REFERENCE)], check=True)
        if platform.system() == "Darwin":
            subprocess.run(["codesign", "--force", "--sign", "-", str(go_binary)],
                           check=True, capture_output=True)
        subprocess.run(["cc", "-O3", "-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
                        str(CLIENT), "-o", str(client)], check=True)
        report["source"]["go_binary_sha256"] = sha256(go_binary)
        report["source"]["client_binary_sha256"] = sha256(client)
        for round_index in range(args.rounds):
            order = ("lean-net", "Go net/http") if round_index % 2 == 0 else ("Go net/http", "lean-net")
            for name in order:
                if name == "lean-net":
                    binary, server_args, environment = lean_binary, ["bench", str(args.workers)], os.environ.copy()
                else:
                    binary, server_args, environment = go_binary, [], {**os.environ, "GOMAXPROCS": str(args.workers)}
                data = measure(binary, server_args, environment, client, args.connections,
                               args.requests, args.warmup)
                wire = data.pop("wire")
                if "wire" not in report:
                    report["wire"] = wire
                elif report["wire"] != wire:
                    raise RuntimeError(f"response headers/size differ for {name}: {wire}")
                report["runs"].append({"server": name, "round": round_index + 1, **data})
                print(f"{name} round {round_index + 1}: {data['requests_per_second']:.0f} req/s; p99 {data['latency_us_p99']:.0f} us", flush=True)
        if sha256(args.lean_binary) != report["source"]["lean_binary_sha256"]:
            raise RuntimeError("Lean fixture changed during comparison")
        if source_snapshot() != report["source"]["lean_source_snapshot"]:
            raise RuntimeError("Lean or native source changed during comparison")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
