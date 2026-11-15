#!/usr/bin/env python3
"""Exercise downstream TLS, the request gate, and verified upstream TLS together.

Build ``lean-net-tls`` before running this test. Certificates and policy are
created in a temporary directory; no external DNS or trust store is used.
"""
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest

from test_tls_gateway import TLSServer, create_ipv6_certificate
from tls_test_support import ROOT, create_certificates


SUFFIX = ".exe" if sys.platform == "win32" else ""
BINARY = Path(os.environ.get(
    "LEAN_NET_TLS_BIN", ROOT / f"tls/.lake/build/bin/lean-net-tls{SUFFIX}"))


class AbruptCloseServer(TLSServer):
    """Send an unframed response and end TCP without TLS close_notify."""

    def run(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.connections += 1
            try:
                secure = self.context.wrap_socket(conn, server_side=True)
                secure.settimeout(5)
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    data = secure.recv(4096)
                    if not data:
                        break
                    request.extend(data)
                secure.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\npartial")
                os.close(secure.detach())
            except (OSError, ssl.SSLError):
                conn.close()


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def request_once(process, context, listen_port):
    deadline = time.monotonic() + 8
    while True:
        if process.poll() is not None:
            raise AssertionError(f"gateway exited early: {process.stdout.read()}")
        try:
            raw = socket.create_connection(("127.0.0.1", listen_port), 0.3)
            break
        except (ConnectionRefusedError, TimeoutError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)
    with raw:
        with context.wrap_socket(raw, server_hostname="alpha.test") as secure:
            secure.settimeout(4)
            secure.sendall(b"GET / HTTP/1.1\r\nHost: alpha.test\r\nConnection: close\r\n\r\n")
            response = bytearray()
            while len(response) < 33 * 1024 * 1024:
                chunk = secure.recv(65536)
                if not chunk:
                    break
                response.extend(chunk)
                if b"\r\n\r\n" in response:
                    head, body = bytes(response).split(b"\r\n\r\n", 1)
                    for line in head.split(b"\r\n"):
                        if line.lower().startswith(b"content-length:"):
                            if len(body) >= int(line.split(b":", 1)[1].strip()):
                                return bytes(response)
            return bytes(response)


def call_gateway(certs, upstream_port, verify_name, upstream_ca, policy_file,
                 target_host="127.0.0.1", requests=1):
    policy_file.write_text(
        f"backend origin {{ https {target_host}:{upstream_port} ; "
        f"verify {verify_name} ; serves alpha.test }}\n"
        "host alpha.test { tls sni strict ; route GET / -> proxy origin }\n"
    )
    listen_port = free_port()
    arguments = [
        str(BINARY), str(certs.chains[0]), str(certs.keys[0]),
        "--host", "127.0.0.1", "--workers", "1", "--max-clients", "8",
        "--gate", str(policy_file), "--upstream-ca", str(upstream_ca),
        str(listen_port),
    ]
    process = subprocess.Popen(arguments, cwd=ROOT, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True)
    try:
        context = ssl.create_default_context(cafile=str(certs.ca))
        context.set_alpn_protocols(["http/1.1"])
        responses = [request_once(process, context, listen_port) for _ in range(requests)]
        return responses[0] if requests == 1 else responses
    finally:
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)


class GatewayEndToEndTest(unittest.TestCase):
    def test_abrupt_upstream_tls_eof_never_completes_response(self):
        self.assertTrue(BINARY.is_file(), f"build {BINARY} first")
        with tempfile.TemporaryDirectory(prefix="lean-net-gateway-e2e-truncated-") as directory:
            certs = create_certificates(directory)
            policy_file = Path(directory) / "gateway.policy"
            with AbruptCloseServer(certs.chains[0], certs.keys[0]) as upstream:
                response = call_gateway(certs, upstream.port, "alpha.test", certs.ca, policy_file)
                # A streamed 200 can already have sent its head, but the
                # downstream must never receive the terminating chunk.
                self.assertFalse(response.startswith(b"HTTP/1.1 200") and
                                 response.endswith(b"0\r\n\r\n"), response[-128:])

    def test_large_https_response(self):
        self.assertTrue(BINARY.is_file(), f"build {BINARY} first")
        body = bytes(range(256)) * 1024
        with tempfile.TemporaryDirectory(prefix="lean-net-gateway-e2e-large-") as directory:
            certs = create_certificates(directory)
            policy_file = Path(directory) / "gateway.policy"
            with TLSServer(certs.chains[0], certs.keys[0], body=body) as upstream:
                response = call_gateway(certs, upstream.port, "alpha.test", certs.ca, policy_file)
                self.assertIn(b"HTTP/1.1 200 OK", response)
                head, received = response.split(b"\r\n\r\n", 1)
                self.assertIn(b"content-length: 262144", head.lower())
                self.assertEqual(received, body, head.decode("latin1"))

    def test_verified_upstream_and_fail_closed(self):
        self.assertTrue(BINARY.is_file(), f"build {BINARY} first")
        with tempfile.TemporaryDirectory(prefix="lean-net-gateway-e2e-") as directory:
            certs = create_certificates(directory)
            policy_file = Path(directory) / "gateway.policy"
            with TLSServer(certs.chains[0], certs.keys[0]) as upstream:
                good = call_gateway(certs, upstream.port, "alpha.test", certs.ca,
                                    policy_file, requests=2)
                for response in good:
                    self.assertIn(b"HTTP/1.1 200 OK", response)
                    self.assertIn(b"tls gateway ok", response)
                self.assertEqual(upstream.connections, 1, "clean upstream TLS socket was not reused")
                wrong_name = call_gateway(certs, upstream.port, "beta.test", certs.ca, policy_file)
                self.assertIn(b"HTTP/1.1 502 Bad Gateway", wrong_name)
                self.assertNotIn(b"tls gateway ok", wrong_name)
                wrong_roots = call_gateway(certs, upstream.port, "alpha.test", certs.unrelated_ca, policy_file)
                self.assertIn(b"HTTP/1.1 502 Bad Gateway", wrong_roots)
                self.assertNotIn(b"tls gateway ok", wrong_roots)

    def test_bracketed_ipv6_target_and_ip_san(self):
        self.assertTrue(BINARY.is_file(), f"build {BINARY} first")
        if not socket.has_ipv6:
            self.skipTest("IPv6 is unavailable")
        with tempfile.TemporaryDirectory(prefix="lean-net-gateway-e2e-ipv6-") as directory:
            certs = create_certificates(directory)
            chain, key = create_ipv6_certificate(directory)
            policy_file = Path(directory) / "gateway.policy"
            try:
                upstream = TLSServer(chain, key, host="::1")
            except OSError:
                self.skipTest("IPv6 loopback is unavailable")
            with upstream:
                good = call_gateway(certs, upstream.port, "::1", certs.ca,
                                    policy_file, target_host="[::1]")
                self.assertIn(b"HTTP/1.1 200 OK", good)
                self.assertIn(b"tls gateway ok", good)


if __name__ == "__main__":
    unittest.main()
