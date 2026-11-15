#!/usr/bin/env python3
"""Completed TCP accept budgets reject excess peers before TLS handshakes."""

import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from tls_test_support import ROOT, create_certificates


SUFFIX = ".exe" if sys.platform == "win32" else ""
BINARY = ROOT / "tls" / ".lake" / "build" / "bin" / f"lean-net-tls{SUFFIX}"


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def request(port, context):
    with socket.create_connection(("127.0.0.1", port), timeout=1) as raw:
        raw.settimeout(2)
        with context.wrap_socket(raw, server_hostname="alpha.test") as secure:
            secure.sendall(b"GET /healthz HTTP/1.1\r\nHost: alpha.test\r\nConnection: close\r\n\r\n")
            response = bytearray()
            while True:
                block = secure.recv(4096)
                if not block:
                    break
                response.extend(block)
            return bytes(response)


class TLSConnectionRateTest(unittest.TestCase):
    def test_excess_accept_is_closed_before_tls(self):
        self.assertTrue(BINARY.is_file(), f"build {BINARY} first")
        with tempfile.TemporaryDirectory(prefix="lean-net-tls-conn-rate-") as directory:
            certs = create_certificates(directory)
            context = ssl.create_default_context(cafile=str(certs.ca))
            context.set_alpn_protocols(["http/1.1"])
            port = free_port()
            process = subprocess.Popen([
                str(BINARY), str(certs.chains[0]), str(certs.keys[0]),
                "--host", "127.0.0.1", "--workers", "2", "--max-clients", "8",
                "--health", "--connection-rate", "1/60000/2", str(port),
            ], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
               text=True)
            try:
                deadline = time.monotonic() + 8
                while True:
                    if process.poll() is not None:
                        self.fail(f"TLS server exited: {process.stdout.read()}")
                    try:
                        first = request(port, context)
                        break
                    except ConnectionRefusedError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.05)
                self.assertIn(b"HTTP/1.1 200", first)
                self.assertIn(b"HTTP/1.1 200", request(port, context))
                with self.assertRaises((ssl.SSLError, ConnectionResetError,
                                        ConnectionAbortedError, BrokenPipeError)):
                    request(port, context)
            finally:
                process.terminate()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
