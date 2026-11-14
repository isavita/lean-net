#!/usr/bin/env python3
"""Black-box acceptance tests for the blocking TCP echo server.

Run after `lake build lean-net-echo` with `python3 test/test_echo.py -v`.
Set LEAN_NET_ECHO_BIN to test a different executable.
"""

import os
from pathlib import Path
import re
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("LEAN_NET_ECHO_BIN", ROOT / ".lake/build/bin/lean-net-echo"))
HOST = "127.0.0.1"


def unused_port():
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def connect(port):
    return socket.create_connection((HOST, port), timeout=2)


def recv_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise AssertionError(f"premature EOF after {len(result)} of {size} bytes")
        result.extend(chunk)
    return bytes(result)


def fd_count(pid):
    proc_fd = Path(f"/proc/{pid}/fd")
    if proc_fd.is_dir():
        return len(list(proc_fd.iterdir()))
    if shutil.which("lsof"):
        result = subprocess.run(
            ["lsof", "-nP", "-a", "-p", str(pid), "-Ff"],
            capture_output=True, text=True, check=True,
        )
        return sum(bool(re.fullmatch(r"f\d+", line)) for line in result.stdout.splitlines())
    raise unittest.SkipTest("descriptor accounting requires /proc or lsof")


class EchoAcceptance(unittest.TestCase):
    def setUp(self):
        if not BINARY.is_file():
            self.fail(f"echo executable not found at {BINARY}; run lake build lean-net-echo")
        self.port = unused_port()
        self.log = tempfile.TemporaryFile(mode="w+")
        self.server = subprocess.Popen([str(BINARY), str(self.port)], stdout=self.log, stderr=self.log)
        self.addCleanup(self.log.close)
        self.addCleanup(self.stop_server)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.server.poll() is not None:
                self.log.seek(0)
                self.fail(f"server exited during startup: {self.log.read()}")
            try:
                with connect(self.port):
                    return
            except OSError:
                time.sleep(0.02)
        self.fail("server did not start listening within five seconds")

    def stop_server(self):
        if self.server.poll() is None:
            self.server.send_signal(signal.SIGINT)
            try:
                self.server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait(timeout=3)

    def test_binary_echo_and_one_byte_then_pause(self):
        with connect(self.port) as sock:
            sock.sendall(b"\x00")
            # A server must respond to a short read without waiting for a full buffer.
            self.assertEqual(recv_exact(sock, 1), b"\x00")
            time.sleep(0.25)
            payload = bytes(range(256)) * 4
            sock.sendall(payload)
            self.assertEqual(recv_exact(sock, len(payload)), payload)
            sock.shutdown(socket.SHUT_WR)
            self.assertEqual(sock.recv(1), b"")

    def test_large_binary_stream(self):
        # Larger than the server read buffer and the typical socket buffer;
        # interleaving reads prevents a single-threaded echo deadlock.
        block = bytes(range(256)) * 64
        with connect(self.port) as sock:
            for _ in range(192):
                sock.sendall(block)
                self.assertEqual(recv_exact(sock, len(block)), block)
            sock.shutdown(socket.SHUT_WR)
            self.assertEqual(sock.recv(1), b"")

    def test_abrupt_disconnect_does_not_kill_listener(self):
        with connect(self.port) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            sock.sendall(b"reset me")
        # The next client must still be accepted even if recv/send saw ECONNRESET or EPIPE.
        with connect(self.port) as sock:
            payload = b"still alive\x00"
            sock.sendall(payload)
            self.assertEqual(recv_exact(sock, len(payload)), payload)

    def test_invalid_port_is_rejected(self):
        for port in ("0", "65536", "-1", "not-a-port"):
            with self.subTest(port=port):
                process = subprocess.run(
                    [str(BINARY), port], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=5,
                )
                self.assertNotEqual(process.returncode, 0)

    def test_port_collision_fails(self):
        other = subprocess.run(
            [str(BINARY), str(self.port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertNotEqual(other.returncode, 0, "a second listener unexpectedly bound the same port")
        self.assertIsNone(self.server.poll(), "original listener stopped after collision")

    def test_thousand_connections_do_not_leak_descriptors(self):
        # Wait for the readiness probe's accepted socket to be closed.
        time.sleep(0.1)
        baseline = fd_count(self.server.pid)
        for i in range(1000):
            with connect(self.port) as sock:
                payload = i.to_bytes(2, "big")
                sock.sendall(payload)
                self.assertEqual(recv_exact(sock, len(payload)), payload)
                sock.shutdown(socket.SHUT_WR)
                self.assertEqual(sock.recv(1), b"")
        deadline = time.monotonic() + 3
        observed = fd_count(self.server.pid)
        while observed > baseline and time.monotonic() < deadline:
            time.sleep(0.05)
            observed = fd_count(self.server.pid)
        self.assertLessEqual(observed, baseline, f"descriptor count grew from {baseline} to {observed}")

    def assert_interrupt_shutdown(self):
        self.server.send_signal(signal.SIGINT)
        try:
            code = self.server.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.fail("server did not exit after SIGINT")
        self.assertEqual(code, 0, f"server did not shut down normally (exit {code})")
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind((HOST, self.port))
            probe.listen()

    def test_ctrl_c_while_idle_in_accept(self):
        # Allow the readiness probe to be closed and the server to return to accept.
        time.sleep(0.1)
        self.assert_interrupt_shutdown()

    def test_ctrl_c_while_waiting_for_client_data(self):
        with connect(self.port) as sock:
            sock.sendall(b"ready")
            self.assertEqual(recv_exact(sock, 5), b"ready")
            time.sleep(0.1)
            self.assert_interrupt_shutdown()
            self.assertEqual(sock.recv(1), b"")


    def test_ctrl_c_with_blocked_writer(self):
        # Never read echoed data: eventually both directions' socket buffers fill,
        # leaving the server blocked in its send path.
        with connect(self.port) as sock:
            sock.settimeout(0.2)
            blocked = False
            block = bytes(range(256)) * 256
            for _ in range(1024):
                try:
                    sock.sendall(block)
                except TimeoutError:
                    blocked = True
                    break
            self.assertTrue(blocked, "test did not fill the socket buffers")
            self.assert_interrupt_shutdown()


if __name__ == "__main__":
    unittest.main()
