#!/usr/bin/env python3
"""`--gate POLICY` on the public server: enforcement, metrics, access-log
fields, SIGHUP reload and startup validation."""
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUFFIX = ".exe" if sys.platform == "win32" else ""
BINARY = ROOT / f".lake/build/bin/lean-net-http1{SUFFIX}"
CURL = os.environ.get("LEAN_NET_TEST_CURL", "curl")

POLICY = """
ratelimit tight 2/m burst 2 by client-ip
host gated.test {
  tls sni off
  route GET /        -> app
  route * /admin/*   -> deny 403
  route GET /limited -> app { limit tight }
}
on unknown-host 421
"""

RELOADED = POLICY.replace("route * /admin/*   -> deny 403", "route GET /admin/* -> app")


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@unittest.skipIf(sys.platform == "win32", "SIGHUP reload is POSIX-only")
class GateCLI(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.policy = Path(self.temp.name) / "gate.policy"
        self.policy.write_text(POLICY)
        self.log = Path(self.temp.name) / "access.jsonl"
        self.port = free_port()
        self.server = subprocess.Popen([str(BINARY), "--workers", "2", "--metrics", "--access-log", str(self.log),
                                        "--gate", str(self.policy), str(self.port)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.addCleanup(self.stop)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.server.poll() is not None:
                self.fail("server exited: " + self.server.stderr.read().decode())
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.05)

    def stop(self):
        if self.server.poll() is None:
            self.server.send_signal(signal.SIGTERM)
            try:
                self.server.wait(10)
            except subprocess.TimeoutExpired:
                self.server.kill(); self.server.wait()
        self.server.stderr.close()

    def get(self, path, host="gated.test", mode="--http1.1"):
        result = subprocess.run([CURL, "-sS", "--noproxy", "*", mode, "-H", f"Host: {host}", "-o", "-",
                                 "-w", "\n%{http_code}", f"http://127.0.0.1:{self.port}{path}"],
                                capture_output=True, timeout=20)
        body, _, status = result.stdout.decode(errors="replace").rpartition("\n")
        return int(status), body

    def metric(self, name):
        _, body = self.get("/metrics")
        return {line.split(" ")[0]: float(line.split(" ")[1]) for line in body.splitlines()
                if line.startswith(name)}

    def test_enforcement_metrics_and_access_log(self):
        self.assertEqual(self.get("/")[0], 200)
        self.assertEqual(self.get("/", "evil.test")[0], 421)
        self.assertEqual(self.get("/admin/x", mode="--http2-prior-knowledge")[0], 403)
        # The first two reach the demo handler (404 for this path); the third is limited.
        self.assertEqual([self.get("/limited")[0] for _ in range(3)], [404, 404, 429])
        rejections = self.metric("lean_net_gate_rejections_total")
        self.assertGreaterEqual(rejections['lean_net_gate_rejections_total{reason="unknown_host"}'], 1)
        self.assertGreaterEqual(rejections['lean_net_gate_rejections_total{reason="denied"}'], 1)
        self.assertGreaterEqual(rejections['lean_net_gate_rejections_total{reason="rate_limited"}'], 1)
        limits = self.metric("lean_net_rate_limit_decisions_total")
        self.assertGreaterEqual(limits['lean_net_rate_limit_decisions_total{result="limited"}'], 1)
        self.server.send_signal(signal.SIGTERM)
        self.assertEqual(self.server.wait(10), 0)
        records = [json.loads(line) for line in self.log.read_text().splitlines()]
        by_status = {}
        for record in records:
            by_status.setdefault(record["status"], record)
        self.assertEqual(by_status[200]["route"], "/")
        self.assertIsNone(by_status[200]["reject_reason"])
        self.assertEqual(by_status[421]["reject_reason"], "unknown_host")
        self.assertEqual(by_status[403]["reject_reason"], "denied")
        self.assertEqual(by_status[429]["reject_reason"], "rate_limited")

    def test_sighup_reload_and_invalid_reload(self):
        self.assertEqual(self.get("/admin/x")[0], 403)
        self.policy.write_text(RELOADED)
        self.server.send_signal(signal.SIGHUP)
        deadline = time.monotonic() + 5
        # After the reload /admin/* reaches the demo handler (404) instead of 403.
        while self.get("/admin/x")[0] != 404:
            self.assertLess(time.monotonic(), deadline, "reload not applied")
            time.sleep(0.05)
        self.assertEqual(self.metric("lean_net_gate_policy_generation")["lean_net_gate_policy_generation"], 1)
        # An invalid policy is refused and the last good one stays active.
        self.policy.write_text("host gated.test { route GET / -> nonsense }")
        self.server.send_signal(signal.SIGHUP)
        deadline = time.monotonic() + 5
        while self.metric("lean_net_gate_reloads_total").get('lean_net_gate_reloads_total{result="failed"}', 0) < 1:
            self.assertLess(time.monotonic(), deadline, "failed reload not counted")
            time.sleep(0.05)
        self.assertEqual(self.get("/admin/x")[0], 404)
        # Changing rate rules requires a restart.
        self.policy.write_text(RELOADED.replace("2/m burst 2", "5/m burst 5"))
        self.server.send_signal(signal.SIGHUP)
        deadline = time.monotonic() + 5
        while self.metric("lean_net_gate_reloads_total").get('lean_net_gate_reloads_total{result="failed"}', 0) < 2:
            self.assertLess(time.monotonic(), deadline, "rate-rule change accepted")
            time.sleep(0.05)
        self.assertIsNone(self.server.poll())


class GateCLIStartup(unittest.TestCase):
    def test_invalid_policy_stops_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "bad.policy"
            policy.write_text("host a.test { route GET /x -> proxy missing }")
            result = subprocess.run([str(BINARY), "--gate", str(policy), str(free_port())],
                                    capture_output=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"unknown backend", result.stderr)


if __name__ == "__main__":
    unittest.main()
