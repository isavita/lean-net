#!/usr/bin/env python3
"""Server-level admission hook over HTTP/1.1, h2c prior knowledge and h2c Upgrade."""
import os
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUFFIX = ".exe" if sys.platform == "win32" else ""
BINARY = ROOT / f".lake/build/bin/lean-net-admission-fixture{SUFFIX}"
CURL = os.environ.get("LEAN_NET_TEST_CURL", "curl")


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Admission(unittest.TestCase):
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
        cls.server.kill()
        cls.server.wait()
        cls.server.stderr.close()

    def curl(self, *arguments, mode="--http1.1", host=None):
        command = [CURL, "-sS", "--noproxy", "*", mode, "-o", "-", "-D", "-", "-w", "\n%{http_code} %{http_version}"]
        if host:
            command += ["-H", f"Host: {host}"]
        result = subprocess.run(command + list(arguments), capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = result.stdout.decode(errors="replace")
        body, _, summary = text.rpartition("\n")
        status, version = summary.split()
        return int(status), version, body

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def test_reject_unknown_host_and_rate_limit(self):
        for mode in ("--http1.1", "--http2-prior-knowledge"):
            with self.subTest(mode=mode):
                status, _, body = self.curl(self.url("/"), mode=mode, host="blocked.test")
                self.assertEqual(status, 403)
                status, _, body = self.curl(self.url("/limited"), mode=mode)
                self.assertEqual(status, 429)
                self.assertIn("retry-after: 1", body.lower())

    def test_accept_passes_to_application(self):
        for mode in ("--http1.1", "--http2-prior-knowledge", "--http2"):
            with self.subTest(mode=mode):
                status, version, body = self.curl(self.url("/anything"), mode=mode)
                self.assertEqual(status, 200)
                self.assertTrue(body.endswith("app body=0\n"), body)
                if mode == "--http2":
                    self.assertEqual(version, "2", "h2c Upgrade did not switch after admission")

    def test_dispatch_replaces_handler_and_sees_transport_facts(self):
        for mode in ("--http1.1", "--http2-prior-knowledge", "--http2"):
            with self.subTest(mode=mode):
                status, _, body = self.curl(self.url("/dispatch"), mode=mode)
                self.assertEqual(status, 200)
                self.assertIn("dispatched secure=false peer=4 ", body)
        status, _, body = self.curl(self.url("/dispatch"), "--data-binary", "abc", mode="--http2-prior-knowledge")
        self.assertIn("kind=request body=3", body)

    def test_route_body_limit(self):
        for mode in ("--http1.1", "--http2-prior-knowledge"):
            with self.subTest(mode=mode):
                status, _, body = self.curl(self.url("/small"), "--data-binary", "x" * 4, mode=mode)
                self.assertEqual((status, body.endswith("app body=4\n")), (200, True), body)
                status, _, _ = self.curl(self.url("/small"), "--data-binary", "x" * 64, mode=mode)
                self.assertEqual(status, 413)
        # Chunked HTTP/1 upload above the bound.
        status, _, _ = self.curl(self.url("/small"), "-H", "Transfer-Encoding: chunked", "--data-binary", "x" * 64)
        self.assertEqual(status, 413)

    def test_rejection_isolated_to_one_http2_stream(self):
        # Two requests over one HTTP/2 connection: the blocked one must not
        # disturb the other.
        result = subprocess.run([CURL, "-sS", "--noproxy", "*", "--http2-prior-knowledge", "-w", "%{http_code}\n",
                                 "-o", os.devnull, self.url("/limited"), "-o", os.devnull, self.url("/ok")],
                                capture_output=True, timeout=20)
        self.assertEqual(result.stdout.decode().split(), ["429", "200"])

    def test_every_request_is_decided_once(self):
        before = int(self.curl(self.url("/decisions"))[2].strip().splitlines()[-1])
        for mode in ("--http1.1", "--http2-prior-knowledge", "--http2"):
            self.curl(self.url("/x"), mode=mode)
        after = int(self.curl(self.url("/decisions"))[2].strip().splitlines()[-1])
        self.assertEqual(after - before, 4)


if __name__ == "__main__":
    unittest.main()
