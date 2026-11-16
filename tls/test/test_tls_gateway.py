#!/usr/bin/env python3
"""Loopback verification tests for the optional upstream TLS client.

Build `lean-net-tls-gateway-test` first. Certificates are generated in an
isolated temporary directory; no system trust store is modified.
"""
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

from tls_test_support import ROOT, create_certificates, openssl


SUFFIX = ".exe" if sys.platform == "win32" else ""
BINARY = Path(os.environ.get(
    "LEAN_NET_TLS_GATEWAY_TEST_BIN",
    ROOT / f"tls/.lake/build/bin/lean-net-tls-gateway-test{SUFFIX}"))


class TLSServer:
    def __init__(self, chain, key, host="127.0.0.1", body=b"tls gateway ok"):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(chain, key)
        self.context.set_alpn_protocols(["http/1.1"])
        self.listener = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET)
        self.listener.bind((host, 0))
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.body = body
        self.connections = 0
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.connections += 1
            conn.settimeout(5)
            try:
                with self.context.wrap_socket(conn, server_side=True) as secure:
                    try:
                        while True:
                            request = b""
                            while b"\r\n\r\n" not in request and len(request) < 4096:
                                part = secure.recv(4096)
                                if not part:
                                    break
                                request += part
                            if not request:
                                break
                            if request.startswith(b"GET / HTTP/1.1\r\n"):
                                secure.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " +
                                               str(len(self.body)).encode("ascii") +
                                               b"\r\n\r\n" + self.body)
                    except (TimeoutError, OSError):
                        pass
            except (ssl.SSLError, OSError):
                conn.close()

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=5)


def create_ipv6_certificate(directory):
    directory = Path(directory)
    key, csr, leaf = (directory / name for name in
                      ("ipv6.key", "ipv6.csr", "ipv6.pem"))
    chain, extensions = directory / "ipv6.chain.pem", directory / "ipv6.ext"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=IP:::1\n"
    )
    openssl("req", "-new", "-newkey", "rsa:2048", "-noenc", "-sha256",
            "-keyout", key, "-out", csr, "-subj", "/CN=ipv6.test")
    openssl("x509", "-req", "-in", csr, "-CA", directory / "intermediate.pem",
            "-CAkey", directory / "intermediate.key", "-set_serial", "101",
            "-sha256", "-out", leaf, "-days", "7", "-extfile", extensions)
    chain.write_bytes(leaf.read_bytes() +
                      (directory / "intermediate.pem").read_bytes())
    return chain, key


def create_ipv4_certificate(directory, san_kind):
    directory = Path(directory)
    prefix = "ipv4-" + san_kind.lower()
    key, csr, leaf = (directory / (prefix + suffix) for suffix in (".key", ".csr", ".pem"))
    chain, extensions = directory / (prefix + ".chain.pem"), directory / (prefix + ".ext")
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName={san_kind}:127.0.0.1\n")
    openssl("req", "-new", "-newkey", "rsa:2048", "-noenc", "-sha256",
            "-keyout", key, "-out", csr, "-subj", "/CN=127.0.0.1")
    openssl("x509", "-req", "-in", csr, "-CA", directory / "intermediate.pem",
            "-CAkey", directory / "intermediate.key", "-set_serial", "102" if san_kind == "IP" else "103",
            "-sha256", "-out", leaf, "-days", "7", "-extfile", extensions)
    chain.write_bytes(leaf.read_bytes() + (directory / "intermediate.pem").read_bytes())
    return chain, key


class UpstreamTLSClientTest(unittest.TestCase):
    def test_verified_identity_and_trust(self):
        self.assertTrue(BINARY.is_file(), f"build {BINARY} first")
        with tempfile.TemporaryDirectory(prefix="lean-net-gateway-tls-") as directory:
            certs = create_certificates(directory)
            with TLSServer(certs.chains[0], certs.keys[0]) as server:
                cases = (
                    (certs.ca, "alpha.test", "expected"),
                    (certs.ca, "beta.test", "rejected"),
                    (certs.unrelated_ca, "alpha.test", "rejected"),
                )
                for ca, name, outcome in cases:
                    with self.subTest(name=name, ca=ca.name):
                        result = subprocess.run(
                            [BINARY, str(server.port), str(ca), name, outcome],
                            capture_output=True, text=True, timeout=15)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn("VERIFIED" if outcome == "expected" else "REJECTED", result.stdout)

    def test_ipv4_requires_ip_san_not_dns_name_or_common_name(self):
        self.assertTrue(BINARY.is_file(), f"build {BINARY} first")
        with tempfile.TemporaryDirectory(prefix="lean-net-gateway-tls-ipv4-") as directory:
            certs = create_certificates(directory)
            for san_kind, name, outcome in (("IP", "127.0.0.1", "expected"),
                                            ("IP", "127.0.0.2", "rejected"),
                                            ("DNS", "127.0.0.1", "rejected")):
                chain, key = create_ipv4_certificate(directory, san_kind)
                with self.subTest(san_kind=san_kind, name=name), TLSServer(chain, key) as server:
                    result = subprocess.run(
                        [BINARY, str(server.port), str(certs.ca), name, outcome],
                        capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("VERIFIED" if outcome == "expected" else "REJECTED", result.stdout)

    def test_ipv6_ip_san(self):
        self.assertTrue(BINARY.is_file(), f"build {BINARY} first")
        with tempfile.TemporaryDirectory(prefix="lean-net-gateway-tls-ipv6-") as directory:
            certs = create_certificates(directory)
            chain, key = create_ipv6_certificate(directory)
            with TLSServer(chain, key) as server:
                for name, outcome in (("::1", "expected"), ("::2", "rejected")):
                    with self.subTest(name=name):
                        result = subprocess.run(
                            [BINARY, str(server.port), str(certs.ca), name, outcome],
                            capture_output=True, text=True, timeout=15)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
