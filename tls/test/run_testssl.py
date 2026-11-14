#!/usr/bin/env python3
"""Run the pinned, full testssl.sh scan against both native fixture SNI hosts.

This intentionally performs the entire default scan, including vulnerabilities
and rating. It installs no tools, changes no trust stores and accepts no grade
substitution. A completed tool grade A/A+ is necessary; incomplete scans and
scanner errors fail. Public deployment trust is a separate acceptance question.

Example (after building the fixture and cloning the pinned tool outside repo):
  python3 tls/test/run_testssl.py --testssl /tmp/lean-net-testssl-v3.2.5 \
      --output /tmp/lean-net-testssl-report
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time

from tls_test_support import (HOST, NAMES, ROOT, context, create_certificates,
                              openssl_binary, request, tls_socket)

PIN = "4f17be931a9d60f3f987975aea8221f1a8eaf7aa"
SUFFIX = ".exe" if sys.platform == "win32" else ""


def findings(value):
    if isinstance(value, dict):
        if {"id", "severity", "finding"} <= value.keys():
            yield value
        for child in value.values():
            yield from findings(child)
    elif isinstance(value, list):
        for child in value:
            yield from findings(child)


def assess_report(document, *, generated_private_ca=False, client_openssl=None):
    items = list(findings(document))
    grades = [item["finding"] for item in items if item["id"] == "overall_grade"]
    scanner_limitations, certificate_limitations, problems = [], [], []
    for item in items:
        # These are deliberately exact, scoped classifications. Never turn a
        # general HIGH/WARN filter off or reinterpret a vulnerability finding.
        if (client_openssl and item["id"] == "engine_problem" and item["severity"] == "WARN" and
                item["finding"] == f"No engine or GOST support via engine with your {client_openssl}"):
            scanner_limitations.append(item)
        elif (generated_private_ca and item["id"] == "cert_revocation" and item["severity"] == "HIGH" and
              item["finding"] == "Neither CRL nor OCSP URI provided"):
            certificate_limitations.append(item)
        elif item["id"] == "scanProblem" or item["severity"] in ("FATAL", "WARN", "HIGH", "CRITICAL"):
            problems.append(item)
    completed = isinstance(document, dict) and isinstance(document.get("scanTime"), (int, float))
    # Missing grades or multiple hosts/IPs cannot silently collapse into one A.
    passed = completed and len(grades) == 1 and grades[0] in ("A", "A+") and not problems
    return {"passed": passed, "grades": grades, "completed": completed,
            "scan_seconds": document.get("scanTime") if isinstance(document, dict) else None,
            "problems": problems,
            "scanner_limitations": scanner_limitations,
            "fixture_certificate_limitations": certificate_limitations,
            "grade_caps": [item for item in items if item["id"].startswith("grade_cap_")],
            "scores": [item for item in items if item["id"] in ("final_score", "rating_spec")]}


def checked_output(command, **kwargs):
    return subprocess.run(command, capture_output=True, text=True, check=True, timeout=15, **kwargs).stdout.strip()


def run_scan(command, tool, output, timeout):
    """Bound the whole scanner process tree, including helper s_client calls."""
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
    process = subprocess.Popen(command, cwd=tool, stdout=output, stderr=subprocess.STDOUT,
                               start_new_session=sys.platform != "win32", creationflags=flags)
    try:
        return process.wait(timeout=timeout)
    except BaseException:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(process.pid)],
                           capture_output=True, timeout=10)
        else:
            try: os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError: pass
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired: pass
            # The group leader can exit while an OpenSSL helper remains.
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--testssl", required=True, type=Path, help="Official v3.2.5 checkout (outside tracked repository)")
    parser.add_argument("--output", required=True, type=Path, help="New report directory; never overwritten")
    parser.add_argument("--fixture", type=Path, default=ROOT / f"tls/.lake/build/bin/lean-net-tls-reactor-fixture{SUFFIX}")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=1800, help="Maximum seconds per full SNI scan")
    args = parser.parse_args()
    tool = args.testssl.resolve()
    fixture = args.fixture.resolve()
    if not 1 <= args.workers <= 256 or args.timeout <= 0:
        parser.error("workers must be 1..256 and timeout must be positive")
    if not fixture.is_file():
        parser.error(f"missing native TLS fixture: {fixture}")
    if ROOT == tool or ROOT in tool.parents:
        parser.error("testssl checkout must be outside the tracked repository")
    commit = checked_output(["git", "-C", str(tool), "rev-parse", "HEAD"])
    if commit != PIN:
        parser.error(f"testssl must be v3.2.5 commit {PIN}, found {commit}")
    dirty = checked_output(["git", "-C", str(tool), "status", "--porcelain", "--untracked-files=no"])
    if dirty:
        parser.error("testssl checkout has tracked modifications")
    if args.output.exists():
        parser.error("output directory already exists; choose a new directory to preserve evidence")
    output = args.output.resolve()
    output.mkdir(parents=True)
    openssl = openssl_binary()
    metadata = {
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_head": checked_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
        "source_status": checked_output(["git", "-C", str(ROOT), "status", "--short"]),
        "fixture": str(fixture), "fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
        "testssl_commit": commit, "testssl_sha256": hashlib.sha256((tool / "testssl.sh").read_bytes()).hexdigest(),
        "openssl": checked_output([openssl, "version", "-a"]),
        "trust_scope": "isolated ephemeral root supplied via --add-ca; no system trust changes",
        "workers": args.workers, "results": [],
    }
    # --version is standalone, and this release finds its Git revision from
    # cwd. Explicit --openssl is used on each real scan rather than trusting
    # the version command's helper selection or the global pkg-config result.
    metadata["testssl_banner"] = checked_output(["bash", str(tool / "testssl.sh"), "--version"], cwd=tool)
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="lean-net-testssl-pki-") as temporary, (output / "server.log").open("w+") as server_log:
            certs = create_certificates(Path(temporary))
            (output / "test-ca.pem").write_bytes(certs.ca.read_bytes())
            for name, chain in zip(NAMES, certs.chains):
                (output / f"{name}.chain.pem").write_bytes(chain.read_bytes())
            metadata["certificate_sha256"] = dict(zip(NAMES, certs.fingerprints))
            with socket.socket() as probe:
                probe.bind((HOST, 0)); port = probe.getsockname()[1]
            flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
            command = [str(fixture), *certs.fixture_arguments(), str(port), "normal", str(args.workers)]
            process = subprocess.Popen(command, stdout=server_log, stderr=server_log, creationflags=flags)
            ctx = context(certs)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"fixture exited before scan with {process.returncode}")
                try:
                    with tls_socket(port, ctx) as sock:
                        sock.sendall(request(close=True))
                        if not sock.recv(4096).startswith(b"HTTP/1.1 200"):
                            raise RuntimeError("fixture failed verified HTTP readiness")
                        break
                except (ConnectionError, ssl.SSLError, socket.timeout):
                    time.sleep(.025)
            else:
                raise TimeoutError("native TLS fixture did not start")
            for name in NAMES:
                report = output / f"{name}.json"
                command = ["bash", str(tool / "testssl.sh"), "--openssl", openssl,
                           "--warnings", "batch", "--color", "0", "--ip", HOST,
                           "--nodns", "none", "--add-ca", str(certs.ca),
                           "--jsonfile-pretty", str(report), "--logfile", str(output / f"{name}.log"),
                           f"https://{name}:{port}/"]
                result = {"name": name, "command": command, "passed": False}
                metadata["results"].append(result)
                print(f"Running full testssl v3.2.5 scan for {name}; timeout {args.timeout}s", flush=True)
                with (output / f"{name}.stdout.log").open("w") as scan_log:
                    try:
                        result["exit_code"] = run_scan(command, tool, scan_log, args.timeout)
                    except subprocess.TimeoutExpired:
                        result["error"] = "full scanner exceeded deadline"
                if report.is_file():
                    try:
                        result.update(assess_report(json.loads(report.read_text()), generated_private_ca=True,
                                                    client_openssl=openssl))
                    except (OSError, ValueError) as error:
                        result["error"] = f"invalid/incomplete JSON: {error}"
                result["passed"] = result["passed"] and result.get("exit_code") == 0
                print(f"{name}: grades={result.get('grades', [])} passed={result['passed']}", flush=True)
    except BaseException as error:
        metadata["error"] = f"{type(error).__name__}: {error}"
    finally:
        if process is not None:
            if process.poll() is None:
                process.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)
                    metadata["shutdown_error"] = "TLS fixture failed to join after scan"
            metadata["fixture_exit_code"] = process.returncode
        metadata["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        metadata["passed"] = (not metadata.get("error") and not metadata.get("shutdown_error") and
                              metadata.get("fixture_exit_code") == 0 and len(metadata["results"]) == 2 and
                              all(result["passed"] for result in metadata["results"]))
        (output / "summary.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"Full-scan evidence: {output / 'summary.json'}; passed={metadata['passed']}")
    return 0 if metadata["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
