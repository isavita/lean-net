#!/usr/bin/env python3
"""Exercise the public Lean server examples as actual HTTP applications."""

from contextlib import contextmanager
import gzip
import http.client
import json
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test"))
sys.path.insert(0, str(ROOT / "tls/test"))
from http2_test_support import H2Client, frame
from tls_test_support import create_certificates

SUFFIX = ".exe" if sys.platform == "win32" else ""
BIN = ROOT / "examples/.lake/build/bin"
HELLO = b"Hello from lean-net!\n"


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextmanager
def server(name, arguments):
    binary = BIN / (name + SUFFIX)
    if not binary.is_file():
        raise AssertionError(f"build examples first: missing {binary}")
    port = unused_port()
    with tempfile.TemporaryFile(mode="w+") as log:
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        process = subprocess.Popen([str(binary), *map(str, arguments(port))],
                                   cwd=ROOT, stdout=log, stderr=log, creationflags=flags)
        try:
            deadline = time.monotonic() + 15
            while True:
                if process.poll() is not None:
                    log.seek(0)
                    raise AssertionError(f"{name} startup failed: {log.read()}")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        log.seek(0)
                        raise AssertionError(f"{name} startup timed out: {log.read()}")
                    time.sleep(.025)
            yield port
        finally:
            if process.poll() is None:
                process.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
            try:
                result = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                raise AssertionError(f"{name} failed to shut down")
            if result != 0:
                log.seek(0)
                raise AssertionError(f"{name} exited with {result}: {log.read()}")


def request(port, path="/", *, method="GET", body=None, headers=None, certificates=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    if certificates:
        context = ssl.create_default_context(cafile=str(certificates.ca))
        context.set_alpn_protocols(["http/1.1"])
        connection.sock = context.wrap_socket(
            socket.create_connection(("127.0.0.1", port), timeout=5), server_hostname="alpha.test")
        if connection.sock.selected_alpn_protocol() != "http/1.1":
            raise AssertionError("HTTP/1.1 ALPN selection failed")
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, {name.lower(): value for name, value in response.getheaders()}, response.read()
    finally:
        connection.close()


def h2_peer(port, certificates=None):
    if not certificates:
        return H2Client(port)
    context = ssl.create_default_context(cafile=str(certificates.ca))
    context.set_alpn_protocols(["h2", "http/1.1"])
    sock = context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5),
                               server_hostname="alpha.test")
    if sock.selected_alpn_protocol() != "h2":
        sock.close()
        raise AssertionError("HTTP/2 ALPN selection failed")
    return H2Client(sock=sock, scheme=b"https", authority=b"alpha.test")


class RunnableExamples(unittest.TestCase):
    def test_01_hello_serves_both_protocols_on_one_port(self):
        with server("hello-server", lambda port: [port]) as port:
            peer = h2_peer(port)
            try:
                peer.request(1, b"/")
                self.assertEqual(request(port)[0::2], (200, HELLO))
                self.assertEqual(peer.response(1), HELLO)
            finally:
                peer.close()

    def test_02_api_routes_methods_and_independent_limits(self):
        with server("api-server", lambda port: [port]) as port:
            self.assertEqual(json.loads(request(port, "/items/42?expand=true")[2]), {"id": 42})
            self.assertEqual(request(port, "/missing")[0], 404)
            status, headers, _ = request(port, "/echo")
            self.assertEqual((status, headers.get("allow")), (405, "POST"))
            self.assertEqual(request(port, "/", method="HEAD")[2], b"")
            payload = bytes(range(256)) * 80
            self.assertEqual(request(port, "/echo", method="POST", body=payload)[0], 413)
            peer = h2_peer(port)
            try:
                self.assertEqual(peer.server_settings[3], 64)
                peer.request(1, b"/echo", method=b"POST", end_stream=False)
                for offset in range(0, len(payload), 16384):
                    part = payload[offset:offset + 16384]
                    peer.send(frame(0, int(offset + len(part) == len(payload)), 1, part))
                self.assertEqual(peer.response(1), payload)
            finally:
                peer.close()
            self.assertEqual(request(port, "/healthz")[0], 200)
            self.assertIn(b"lean_net_", request(port, "/metrics")[2])

    def test_03_tls_static_verification_ranges_and_compression(self):
        with tempfile.TemporaryDirectory(prefix="lean-net-examples-pki-") as directory:
            certificates = create_certificates(directory)
            root = ROOT / "examples/public"
            expected = (root / "index.html").read_bytes()
            with server("tls-static-server", lambda port: [root, certificates.chains[0],
                        certificates.keys[0], port]) as port:
                self.assertEqual(request(port, certificates=certificates)[0::2], (200, expected))
                status, _, body = request(port, "/index.html", certificates=certificates,
                                          headers={"Range": "bytes=0-14"})
                self.assertEqual((status, body), (206, expected[:15]))
                status, headers, body = request(port, "/index.html", certificates=certificates,
                                               headers={"Accept-Encoding": "gzip"})
                self.assertEqual(status, 200)
                if headers.get("content-encoding") == "gzip":
                    body = gzip.decompress(body)
                self.assertEqual(body, expected)
                self.assertEqual(request(port, "/index.html", method="HEAD", certificates=certificates)[2], b"")
                peer = h2_peer(port, certificates)
                try:
                    peer.request(1, b"/index.html")
                    self.assertEqual(peer.response(1), expected)
                finally:
                    peer.close()

    def test_04_gateway_proxy_host_policy_and_rate_limit(self):
        with server("hello-server", lambda port: [port]) as backend:
            with server("gateway-server", lambda port: [port, backend]) as port:
                headers = {"Host": "localhost"}
                self.assertEqual(request(port, headers=headers)[0::2], (200, HELLO))
                self.assertEqual(request(port, headers={"Host": "untrusted.test"})[0], 421)
                self.assertEqual(request(port, headers={**headers, "X-Internal-Role": "admin"})[0], 400)
                self.assertIn(str(backend).encode(), request(port, "/about", headers=headers)[2])
                peer = H2Client(port, authority=b"localhost")
                try:
                    peer.request(1, b"/")
                    self.assertEqual(peer.response(1), HELLO)
                finally:
                    peer.close()
                self.assertEqual(request(port, "/healthz", headers=headers)[0], 200)
                self.assertIn(b"lean_net_gate_", request(port, "/metrics", headers=headers)[2])
                limited = False
                for _ in range(50):
                    status, response_headers, _ = request(port, "/about", headers=headers)
                    self.assertIn(status, (200, 429))
                    if status == 429:
                        self.assertIn("retry-after", response_headers)
                        limited = True
                        break
                self.assertTrue(limited, "the configured client budget did not reject a burst")


if __name__ == "__main__":
    unittest.main()
