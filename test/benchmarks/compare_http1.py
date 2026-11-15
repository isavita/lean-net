#!/usr/bin/env python3
"""Compare lean-net with production HTTP servers using one verified HTTP/1.1 client."""

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
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
REFERENCE = Path(__file__).with_name("go_http1_reference.go")
PYTHON_REFERENCE = Path(__file__).with_name("python_http1_reference.py")
RUBY_REFERENCE = Path(__file__).with_name("ruby_http1_reference.ru")
RUBY_CONFIG = Path(__file__).with_name("ruby_http1_puma.rb")
CLIENT = ROOT / "test" / "bench_http1.c"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def version(command, environment=None):
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                check=False, env=environment)
    except FileNotFoundError:
        return None
    return (result.stdout or result.stderr).strip().splitlines()[0] if result.returncode == 0 else None


def cpu_model():
    name = version(["sysctl", "-n", "machdep.cpu.brand_string"])
    if name:
        return name
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.partition(":")[2].strip()
    except FileNotFoundError:
        pass
    return platform.processor()


def process_family_cpu(pid):
    """Return summed CPU time and child PIDs for a process-manager tree."""
    result = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,time="],
                            capture_output=True, text=True, check=False)
    if result.returncode:
        return None, set()
    processes = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 3:
            continue
        try:
            seconds = 0.0
            for part in fields[2].split(":"):
                seconds = seconds * 60 + float(part)
            processes[int(fields[0])] = (int(fields[1]), seconds)
        except ValueError:
            continue
    if pid not in processes:
        return None, set()
    family = {pid}
    while True:
        children = {child for child, (parent, _) in processes.items() if parent in family}
        if children <= family:
            break
        family |= children
    return sum(processes[member][1] for member in family), family - {pid}


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


def measure(command_for_port, environment, client, connections, requests, warmup,
            expected_workers=0):
    port = free_port()
    with tempfile.TemporaryFile(mode="w+") as log:
        server = subprocess.Popen(command_for_port(port), cwd=ROOT,
                                  stdout=log, stderr=log, env=environment,
                                  start_new_session=True)
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
            cpu_before, children_before = process_family_cpu(server.pid)
            if len(children_before) < expected_workers:
                raise RuntimeError(f"expected {expected_workers} server workers; observed {sorted(children_before)}")
            data = run(requests)
            cpu_after, children_after = process_family_cpu(server.pid)
            if children_after != children_before:
                raise RuntimeError(f"server worker PIDs changed during the run: {children_before} -> {children_after}")
            if cpu_before is not None and cpu_after is not None:
                data["server_family_cpu_seconds"] = round(cpu_after - cpu_before, 3)
                data["approx_server_family_cpu_cores"] = round((cpu_after - cpu_before) / data["seconds"], 3)
            data["server_child_processes"] = len(children_before)
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
                os.killpg(server.pid, signal.SIGKILL)
                server.wait(timeout=8)
                raise RuntimeError("server did not stop after SIGINT")
            for _ in range(20):
                try:
                    os.killpg(server.pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(.05)
            else:
                os.killpg(server.pid, signal.SIGKILL)
                if not failed:
                    raise RuntimeError("server worker process group survived shutdown")
            if code and not failed:
                log.seek(0)
                raise RuntimeError(f"server shutdown exit {code}: {log.read()}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lean-binary", type=Path,
                        default=ROOT / ".lake/build/bin/lean-net-http1-reactor-fixture")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--references", nargs="+", choices=["go", "uvicorn", "puma"],
                        default=["go"], help="reference servers to include")
    parser.add_argument("--uvicorn-python", type=Path, default=Path(sys.executable),
                        help="Python interpreter with pinned Uvicorn, uvloop and httptools")
    parser.add_argument("--puma-exe", type=Path,
                        help="pinned Puma executable")
    parser.add_argument("--ruby-gem-home", type=Path,
                        help="directory containing the pinned Puma, Rack and nio4r gems")
    parser.add_argument("--connections", type=int, default=100)
    parser.add_argument("--requests", type=int, default=200000)
    parser.add_argument("--warmup", type=int, default=10000)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.lean_binary.is_file() or min(args.workers, args.connections, args.requests,
                                            args.warmup, args.rounds) < 1 or args.workers > 256 or args.connections > 128 or args.requests < args.connections or args.warmup < args.connections:
        parser.error("build the Lean fixture and specify positive workload values (connections <= 128)")
    if len(set(args.references)) != len(args.references):
        parser.error("reference server names must be unique")
    if "uvicorn" in args.references and not args.uvicorn_python.is_file():
        parser.error("--uvicorn-python must name a Python interpreter")
    if "puma" in args.references and (args.puma_exe is None or
                                       not args.puma_exe.is_file() or
                                       args.ruby_gem_home is None or
                                       not args.ruby_gem_home.is_dir()):
        parser.error("Puma requires --puma-exe and --ruby-gem-home")
    ruby_environment = {**os.environ, "GEM_HOME": str(args.ruby_gem_home),
                        "GEM_PATH": str(args.ruby_gem_home)} if args.ruby_gem_home else None
    report = {
        "scope": "HTTP/1.1 GET /binary: five response bytes, no TLS, no proxy, loopback",
        "method": "same verified C client, fixed request count, persistent connections, one outstanding request per connection, no pipelining; connection setup excluded; every status, Content-Length and body byte checked",
        "environment": {"platform": platform.platform(), "cpu": cpu_model(),
                        "logical_cpus": os.cpu_count(),
                        "available_cpus": len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count(),
                        "lean": version(["lean", "--version"]),
                        "go": version(["go", "version"]), "cc": version(["cc", "--version"])},
        "source": {"git_head": version(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
                   "git_status": subprocess.run(["git", "status", "--short"], cwd=ROOT,
                                                capture_output=True, text=True, check=True).stdout.strip(),
                   "lean_source_snapshot": source_snapshot(),
                   "lean_binary_sha256": sha256(args.lean_binary),
                   "go_source_sha256": sha256(REFERENCE), "client_source_sha256": sha256(CLIENT),
                   "driver_source_sha256": sha256(Path(__file__))},
        "configuration": {"lean_workers": args.workers, "go_gomaxprocs": args.workers,
                          "references": args.references, "uvicorn_workers": args.workers if "uvicorn" in args.references else None,
                          "puma_workers": args.workers if "puma" in args.references else None,
                          "puma_threads_per_worker": "8:32" if "puma" in args.references else None,
                          "puma_max_keep_alive": 100000 if "puma" in args.references else None,
                          "connections": args.connections, "requests_per_round": args.requests,
                          "warmup_requests_per_server": args.warmup,
                          "rounds_per_server": args.rounds,
                          "lean_fixture_mode": "bench", "lean_max_clients": 128,
                          "lean_output_buffers": 512},
        "runs": []
    }
    if "uvicorn" in args.references:
        report["environment"]["python"] = version([str(args.uvicorn_python), "--version"])
        report["environment"]["uvicorn"] = version([str(args.uvicorn_python), "-m", "uvicorn", "--version"])
        report["environment"]["python_packages"] = version([str(args.uvicorn_python), "-c",
            "from importlib.metadata import version; print(', '.join(f'{name}=={version(name)}' for name in ('click', 'h11', 'httptools', 'uvicorn', 'uvloop')))"])
        report["source"]["python_reference_sha256"] = sha256(PYTHON_REFERENCE)
        report["source"]["python_requirements_sha256"] = sha256(Path(__file__).with_name("python-http1-requirements.txt"))
    if "puma" in args.references:
        report["environment"]["ruby"] = version(["ruby", "--version"], ruby_environment)
        report["environment"]["puma"] = version([str(args.puma_exe), "--version"], ruby_environment)
        report["environment"]["rack"] = version(["ruby", "-e", "require 'rack'; puts Rack.release"], ruby_environment)
        report["environment"]["nio4r"] = version(["gem", "list", "--local", "--exact", "nio4r"], ruby_environment)
        report["source"]["ruby_reference_sha256"] = sha256(RUBY_REFERENCE)
        report["source"]["ruby_config_sha256"] = sha256(RUBY_CONFIG)
        report["source"]["ruby_installer_sha256"] = sha256(Path(__file__).with_name("install_ruby_http1.sh"))
    with tempfile.TemporaryDirectory(prefix="lean-net-http1-comparison-") as temp:
        temp = Path(temp)
        lean_binary = temp / "lean-server"
        go_binary = temp / "go-server"
        client = temp / "verified-client"
        shutil.copy2(args.lean_binary, lean_binary)
        if "go" in args.references:
            build = ["go", "build", "-trimpath"]
            if platform.system() == "Darwin":
                # The installed Go toolchain needs an external link and fresh ad-hoc
                # signature to launch binaries on this macOS host.
                build.append("-ldflags=-linkmode=external")
            subprocess.run([*build, "-o", str(go_binary), str(REFERENCE)], check=True)
            if platform.system() == "Darwin":
                subprocess.run(["codesign", "--force", "--sign", "-", str(go_binary)],
                               check=True, capture_output=True)
            report["source"]["go_binary_sha256"] = sha256(go_binary)
        subprocess.run(["cc", "-O3", "-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
                        str(CLIENT), "-o", str(client)], check=True)
        report["source"]["client_binary_sha256"] = sha256(client)
        names = ["lean-net"] + [{"go": "Go net/http", "uvicorn": "Python Uvicorn",
                                 "puma": "Ruby Puma"}[ref] for ref in args.references]
        for round_index in range(args.rounds):
            rotation = round_index % len(names)
            order = names[rotation:] + names[:rotation]
            for name in order:
                if name == "lean-net":
                    command = lambda port: [str(lean_binary), str(port), "bench", str(args.workers)]
                    environment, expected_workers = os.environ.copy(), 0
                elif name == "Go net/http":
                    command = lambda port: [str(go_binary), str(port)]
                    environment, expected_workers = {**os.environ, "GOMAXPROCS": str(args.workers)}, 0
                elif name == "Python Uvicorn":
                    command = lambda port: [str(args.uvicorn_python), "-m", "uvicorn",
                                            "python_http1_reference:app", "--app-dir", str(PYTHON_REFERENCE.parent),
                                            "--host", "127.0.0.1", "--port", str(port),
                                            "--workers", str(args.workers), "--http", "httptools",
                                            "--loop", "uvloop", "--lifespan", "off", "--no-server-header",
                                            "--no-access-log", "--log-level", "error"]
                    environment, expected_workers = os.environ.copy(), args.workers
                else:
                    command = lambda port: [str(args.puma_exe), "-C", str(RUBY_CONFIG), "-b",
                                            f"tcp://127.0.0.1:{port}", "-w", str(args.workers),
                                            "-t", "8:32", "-e", "production", "-s", str(RUBY_REFERENCE)]
                    environment, expected_workers = ruby_environment, args.workers
                data = measure(command, environment, client, args.connections,
                               args.requests, args.warmup, expected_workers)
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
