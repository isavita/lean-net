#!/usr/bin/env python3
"""Public CLI admin listener startup and bounded control-plane behavior."""
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / ".lake/build/bin" / ("lean-net-http1.exe" if sys.platform == "win32" else "lean-net-http1")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class AdminCLI(unittest.TestCase):
    def start(self, admin_port):
        port = free_port()
        log = tempfile.TemporaryFile(mode="w+")
        process = subprocess.Popen([str(BINARY), "--workers", "1", "--admin-port",
                                    str(admin_port), str(port)], stdout=log, stderr=log)
        self.addCleanup(log.close)
        self.addCleanup(lambda: self.stop(process))
        for _ in range(100):
            if process.poll() is not None:
                log.seek(0)
                self.fail("server exited during startup: " + log.read())
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.1).close()
                return process, port
            except OSError:
                time.sleep(0.05)
        self.fail("public listener did not start")

    @staticmethod
    def stop(process):
        if process.poll() is None:
            if sys.platform == "win32":
                process.kill()
            else:
                process.send_signal(signal.SIGINT)
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()

    def test_admin_bind_collision_prevents_public_startup(self):
        admin_port = free_port()
        public_port = free_port()
        with socket.socket() as occupied:
            occupied.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            occupied.bind(("127.0.0.1", admin_port))
            occupied.listen()
            with tempfile.TemporaryFile(mode="w+") as log:
                process = subprocess.Popen([str(BINARY), "--workers", "1", "--admin-port",
                                            str(admin_port), str(public_port)], stdout=log, stderr=log)
                self.addCleanup(lambda: self.stop(process))
                self.assertNotEqual(process.wait(timeout=5), 0)
                with self.assertRaises(OSError):
                    socket.create_connection(("127.0.0.1", public_port), timeout=0.2)

    def test_complete_8192_byte_head_is_last_accepted_size(self):
        admin_port = free_port()
        self.start(admin_port)
        prefix = b"GET /healthz HTTP/1.1\r\nX: "
        suffix = b"\r\n\r\n"
        accepted = prefix + b"a" * (8192 - len(prefix) - len(suffix)) + suffix
        self.assertEqual(len(accepted), 8192)
        with socket.create_connection(("127.0.0.1", admin_port), timeout=3) as sock:
            sock.settimeout(3)
            sock.sendall(accepted)
            self.assertTrue(sock.recv(4096).startswith(b"HTTP/1.1 200"))
        with socket.create_connection(("127.0.0.1", admin_port), timeout=3) as sock:
            sock.settimeout(3)
            sock.sendall(prefix + b"a" * (8193 - len(prefix) - len(suffix)) + suffix)
            try:
                self.assertEqual(sock.recv(4096), b"")
            except ConnectionResetError:
                pass

    @unittest.skipIf(sys.platform == "win32", "Windows test harness cannot send SIGINT to child")
    def test_slow_admin_peer_does_not_block_shutdown(self):
        admin_port = free_port()
        process, _ = self.start(admin_port)
        with socket.create_connection(("127.0.0.1", admin_port), timeout=3) as sock:
            sock.sendall(b"GET /stats HTTP/1.1\r\nHost: localhost\r\nX: ")
            started = time.monotonic()
            process.send_signal(signal.SIGINT)
            self.assertEqual(process.wait(timeout=4), 0)
            self.assertLess(time.monotonic() - started, 4)


if __name__ == "__main__":
    unittest.main()
