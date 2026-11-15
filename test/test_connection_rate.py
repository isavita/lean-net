#!/usr/bin/env python3
"""Native per-IP accept limiting before any HTTP or TLS work."""

import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SUFFIX = ".exe" if sys.platform == "win32" else ""
BINARY = ROOT / ".lake" / "build" / "bin" / f"lean-net-http1{SUFFIX}"


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def request(port, source="127.0.0.1"):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1,
                                      source_address=(source, 0)) as connection:
            connection.settimeout(2)
            connection.sendall(
                b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            response = bytearray()
            while True:
                block = connection.recv(4096)
                if not block:
                    break
                response.extend(block)
            return bytes(response)
    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
        return b""


class ConnectionRateTest(unittest.TestCase):
    def test_shared_multicore_budget_and_per_ip_isolation(self):
        self.assertTrue(BINARY.is_file(), f"build {BINARY} first")
        port = free_port()
        process = subprocess.Popen([
            str(BINARY), "--host", "127.0.0.1", "--workers", "2",
            "--max-clients", "8", "--health", "--connection-rate",
            "1/60000/2", str(port),
        ], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
           text=True)
        try:
            deadline = time.monotonic() + 8
            while True:
                if process.poll() is not None:
                    self.fail(f"server exited: {process.stdout.read()}")
                try:
                    first = request(port)
                    break
                except (ConnectionRefusedError, TimeoutError):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.05)
            self.assertIn(b"HTTP/1.1 200", first)
            self.assertIn(b"HTTP/1.1 200", request(port))
            self.assertNotIn(b"HTTP/1.1 200", request(port),
                             "third accept exceeded the shared two-connection burst")

            # 127/8 aliases are not available on every Windows host. When
            # present, an independent peer address has its own budget.
            try:
                other = request(port, "127.0.0.2")
            except (OSError, TimeoutError):
                pass
            else:
                self.assertIn(b"HTTP/1.1 200", other)
        finally:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
