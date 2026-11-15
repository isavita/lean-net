#!/usr/bin/env python3
"""Gate policy end to end (HTTP/1.1, h2c prior knowledge, h2c Upgrade) and
compile-time `gate%` literal checking."""
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUFFIX = ".exe" if sys.platform == "win32" else ""
BINARY = ROOT / f".lake/build/bin/lean-net-gate-fixture{SUFFIX}"
CURL = os.environ.get("LEAN_NET_TEST_CURL", "curl")
MODES = ("--http1.1", "--http2-prior-knowledge", "--http2")


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class GateWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = free_port()
        cls.server = subprocess.Popen([str(BINARY), str(cls.port)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.kill(); cls.server.wait(); cls.server.stderr.close()

    def get(self, path, host="api.test", mode="--http1.1", *extra):
        command = [CURL, "-sS", "--noproxy", "*", mode, "-H", f"Host: {host}", "-D", "-", "-o", "-",
                   "-w", "\n%{http_code}", *extra, f"http://127.0.0.1:{self.port}{path}"]
        result = subprocess.run(command, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = result.stdout.decode(errors="replace")
        output, _, status = text.rpartition("\n")
        return int(status), output

    def test_routes_and_captures(self):
        for mode in MODES:
            with self.subTest(mode=mode):
                status, body = self.get("/items/42", mode=mode)
                self.assertEqual(status, 200)
                self.assertIn("item id=42 host=api.test debug=false", body)

    def test_unknown_host_admin_and_missing(self):
        for mode in MODES[:2]:
            with self.subTest(mode=mode):
                self.assertEqual(self.get("/items/1", "evil.test", mode)[0], 421)
                self.assertEqual(self.get("/admin/users", mode=mode)[0], 403)
                self.assertEqual(self.get("/%61dmin/users", mode=mode)[0], 403)
                self.assertEqual(self.get("/nothing", mode=mode)[0], 404)
                self.assertEqual(self.get("/a/../admin/x", "api.test", mode, "--path-as-is")[0], 400)

    def test_method_not_allowed_lists_allow(self):
        status, output = self.get("/items/1", "api.test", "--http1.1", "-X", "DELETE")
        self.assertEqual(status, 405)
        self.assertIn("allow: get", output.lower())

    def test_headers_rules_and_strip(self):
        self.assertEqual(self.get("/items/1", "api.test", "--http1.1", "-H", "X-Internal-Trace: 1")[0], 400)
        for mode in MODES[:2]:
            with self.subTest(mode=mode):
                status, body = self.get("/items/1", "api.test", mode, "-H", "X-Debug: 1")
                self.assertIn("debug=false", body, "strip rule did not reach the app handler")
                status, body = self.get("/legacy", "api.test", mode, "-H", "X-Debug: 1")
                self.assertEqual(status, 200)
                self.assertIn("server debug=false", body, "strip rule did not reach the server handler")

    def test_body_limit_and_check(self):
        for mode in MODES[:2]:
            with self.subTest(mode=mode):
                status, body = self.get("/upload", "api.test", mode, "--data-binary", "x" * 8)
                self.assertEqual(status, 200)
                self.assertIn("upload bytes=8", body)
                self.assertEqual(self.get("/upload", "api.test", mode, "--data-binary", "x" * 64)[0], 413)
                self.assertEqual(self.get("/keyed", "api.test", mode)[0], 401)
                status, body = self.get("/keyed", "api.test", mode, "-H", "X-Api-Key: secret")
                self.assertEqual(status, 200)

    def test_wildcard_host_and_port_pattern(self):
        status, body = self.get("/x/y", "acme.tenant.test")
        self.assertEqual(status, 200)
        self.assertIn("tenant=acme.tenant.test path=/x/y", body)
        self.assertEqual(self.get("/x", "a.b.tenant.test")[0], 421)
        self.assertEqual(self.get("/items/1", "api.test:8443")[0], 200)
        # A port-less pattern (api.test) covers every port.
        self.assertEqual(self.get("/items/1", "api.test:9999")[0], 200)


class GateLiteral(unittest.TestCase):
    def run_lean(self, source):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Literal.lean"
            path.write_text("import LeanNet.Gate.Literal\nopen LeanNet.Gate\n" + source)
            return subprocess.run(["lake", "env", "lean", str(path)], cwd=ROOT, capture_output=True, text=True, timeout=300)

    def test_valid_literal_compiles(self):
        result = self.run_lean('def policy : Spec := gate% "host a.example.com { route GET /x/:id -> app }"\n')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_invalid_literals_fail_the_build(self):
        cases = {
            'gate% "host a.example.com { route GET /x -> proxy missing }"': "unknown backend",
            'gate% "host a.example.com { route GET /x -> app\\n route GET /x -> app }"': "overlaps",
            'gate% "host a.example.com { route GET /x -> nonsense }"': "unknown action",
        }
        for literal, fragment in cases.items():
            with self.subTest(fragment=fragment):
                result = self.run_lean(f"def policy : Spec := {literal}\n")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(fragment, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
