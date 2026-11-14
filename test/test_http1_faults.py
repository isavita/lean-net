#!/usr/bin/env python3
"""Deterministic accept-stage faults using a test-only dynamic interposer."""
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

from test_echo import connect, fd_count, unused_port
import test_http1_server as common
from test_http1_server import BINARY, HELLO, HttpReader


class AcceptStageFailures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        source = Path(__file__).with_name("accept_fault.c")
        cls.library = str(Path(cls.temp.name) / ("accept_fault.dylib" if sys.platform == "darwin" else "accept_fault.so"))
        flags = ["-dynamiclib"] if sys.platform == "darwin" else ["-shared", "-fPIC"]
        subprocess.run(["cc", *flags, str(source), "-o", cls.library], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def exercise(self, mode, fatal, markers, reconnect=False):
        with tempfile.TemporaryFile(mode="w+") as log:
            env = os.environ.copy()
            env["DYLD_INSERT_LIBRARIES" if sys.platform == "darwin" else "LD_PRELOAD"] = self.library
            env["LEAN_NET_TEST_SOCKET_FAULT"] = mode
            port = unused_port()
            server = subprocess.Popen([str(BINARY), str(port)], env=env, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 5
                while True:
                    if server.poll() is not None:
                        log.seek(0)
                        self.fail(f"listener stopped before connection: {log.read()}")
                    try:
                        sock = connect(port)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            self.fail("listener did not start")
                        time.sleep(0.02)
                with sock:
                    if fatal:
                        code = server.wait(timeout=3)
                        self.assertNotEqual(code, 0, "socket setup failure was silently ignored")
                    elif reconnect:
                        try:
                            self.assertEqual(sock.recv(1), b"")
                        except ConnectionResetError:
                            pass
                    else:
                        try:
                            sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                            self.assertEqual(HttpReader(sock).response()[::2], (200, HELLO))
                        except OSError as error:
                            log.seek(0)
                            self.fail(f"listener failed after injected accept error: {error}; log: {log.read()}")
                        self.assertIsNone(server.poll())
                if reconnect:
                    with connect(port) as healthy:
                        healthy.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                        self.assertEqual(HttpReader(healthy).response()[::2], (200, HELLO))
                    self.assertIsNone(server.poll())
                log.seek(0)
                output = log.read()
                for marker in markers:
                    self.assertIn(marker, output, f"fault {mode} did not reach {marker!r}")
            finally:
                if server.poll() is None:
                    server.send_signal(signal.SIGINT)
                    try:
                        server.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait(timeout=3)

    def test_connection_aborted_during_accept_is_retryable(self):
        self.exercise("accept_abort", False, ("TEST_ACCEPT_FAULT",))

    def test_network_error_during_accept_is_retryable(self):
        self.exercise("accept_proto", False, ("TEST_ACCEPT_FAULT",))

    def test_same_errno_during_socket_setup_is_fatal(self):
        self.exercise("option_proto", True, ("TEST_OPTION_FAULT",))

    def test_unrelated_setup_error_with_pending_peer_error_is_fatal(self):
        self.exercise("option_proto_peer", True, ("TEST_OPTION_FAULT", "TEST_PENDING_PEER_ERROR"))

    def test_einval_with_pending_peer_reset_is_connection_local(self):
        self.exercise("option_einval_peer", False, ("TEST_OPTION_FAULT", "TEST_PENDING_PEER_ERROR"), reconnect=True)

    def test_cleanup_close_failure_is_fatal(self):
        self.exercise("cleanup_fail", True, ("TEST_OPTION_FAULT", "TEST_CLEANUP_FAULT"))


class AbruptAcceptRace(unittest.TestCase):
    binary = BINARY
    setUp = common.HttpServerAcceptance.setUp
    stop_server = common.HttpServerAcceptance.stop_server

    def test_immediate_reset_accept_race_preserves_listener_and_fds(self):
        time.sleep(0.1)
        baseline = fd_count(self.server.pid)
        for index in range(3000):
            with socket.socket() as peer:
                peer.settimeout(3)
                peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                peer.connect(("127.0.0.1", self.port))
            if index % 50 == 0:
                with connect(self.port) as healthy:
                    healthy.settimeout(5)
                    healthy.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    self.assertEqual(HttpReader(healthy).response()[::2], (200, HELLO))
        with connect(self.port) as healthy:
            healthy.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            self.assertEqual(HttpReader(healthy).response()[::2], (200, HELLO))
        deadline = time.monotonic() + 4
        observed = fd_count(self.server.pid)
        while observed > baseline and time.monotonic() < deadline:
            time.sleep(0.05)
            observed = fd_count(self.server.pid)
        self.assertLessEqual(observed, baseline, f"descriptor count grew from {baseline} to {observed}")


if __name__ == "__main__":
    unittest.main()
