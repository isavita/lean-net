#!/usr/bin/env python3
"""Deterministic transport WANT direction and retry scheduler regressions."""
from pathlib import Path
import os
import signal
import socket
import subprocess
import tempfile
import time
import unittest

from test_echo import unused_port
from test_http1_server import HELLO, HttpReader
from test_http2_e2e import PREFACE, Peer, frame, headers

BINARY = Path(__file__).resolve().parents[1] / ".lake/build/bin/lean-net-transport-test"


class SchedulerAcceptance(unittest.TestCase):
    def launch(self, mode):
        if not BINARY.is_file():
            self.fail("run lake build lean-net-transport-test")
        port = unused_port()
        log = tempfile.TemporaryFile(mode="w+")
        self.addCleanup(log.close)
        server = subprocess.Popen([str(BINARY), mode, str(port)], stdout=log, stderr=log)
        def stop():
            if server.poll() is None:
                server.send_signal(signal.SIGINT)
                try:
                    server.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=3)
                    self.fail("scheduler fixture did not stop")
        self.addCleanup(stop)
        deadline = time.monotonic() + 5
        while True:
            if server.poll() is not None:
                log.seek(0)
                self.fail(f"scheduler fixture exited: {log.read()}")
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=1)
                sock.settimeout(3)
                return server, log, sock
            except OSError:
                if time.monotonic() >= deadline:
                    self.fail("scheduler fixture did not start")
                time.sleep(0.02)

    def test_read_want_write_and_exact_write_want_read_retry(self):
        server, log, sock = self.launch("retry")
        with sock:
            request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            # The mock reads exactly the request, leaving ! available for the
            # simulated SSL_write WANT_READ retry.
            sock.sendall(request + b"!")
            self.assertEqual(HttpReader(sock).response()[::2], (200, HELLO))
            self.assertEqual(sock.recv(1), b"")
        if server.poll() is not None:
            log.seek(0)
            self.fail(f"scheduler exited after transport retry: {log.read()}")
        trace = os.pread(log.fileno(), 65536, 0)
        for marker in (b"MOCK_READ_WANT_WRITE", b"MOCK_WRITE_WANT_READ", b"MOCK_RETRY_IDENTICAL"):
            self.assertIn(marker, trace, f"test did not exercise {marker!r}")

    def test_pending_write_retry_is_unchanged_when_timeout_appends_output(self):
        server, log, sock = self.launch("mutate")
        with sock:
            peer = Peer.__new__(Peer)
            peer.sock, peer.buffer = sock, b""
            sock.sendall(PREFACE + frame(4))
            settings = ack = False
            while not (settings and ack):
                kind, flags, stream, _ = peer.read()
                if kind == 4 and stream == 0:
                    if flags & 1:
                        ack = True
                    else:
                        settings = True
                        sock.sendall(frame(4, 1))
            # Stream 1 stays incomplete; stream 3 produces a response whose
            # first write is forced to WANT_READ.
            sock.sendall(headers(1, b"/echo", b"POST", False) + headers(3, b"/"))
            deadline = time.monotonic() + 2
            while b"MOCK_WRITE_WANT_READ" not in os.pread(log.fileno(), 65536, 0):
                if time.monotonic() >= deadline:
                    self.fail("fixture did not force WANT_READ")
                time.sleep(0.01)
            # The request deadline appends RST_STREAM to the already queued
            # output while the original TLS write still requires retry.
            time.sleep(1.0)
            sock.sendall(b"!")
            body = bytearray()
            reset = False
            for _ in range(12):
                kind, flags, stream, payload = peer.read()
                if kind == 0 and stream == 3:
                    body.extend(payload)
                if kind == 3 and stream == 1:
                    self.assertEqual(int.from_bytes(payload, "big"), 8)
                    reset = True
                if reset and bytes(body) == HELLO:
                    break
            self.assertTrue(reset, "incomplete stream did not time out")
            self.assertEqual(bytes(body), HELLO)
            self.assertIn(b"MOCK_RETRY_IDENTICAL", os.pread(log.fileno(), 65536, 0))
        if server.poll() is not None:
            log.seek(0)
            self.fail(f"scheduler exited during write retry: {log.read()}")

    def test_close_after_read_want_write_flushes_goaway(self):
        server, log, sock = self.launch("closing")
        with sock:
            sock.settimeout(2.5)
            # Start H2 and leave a partial frame plus a transport marker. The
            # mock forces WANT_WRITE longer than the absolute parse deadline.
            sock.sendall(PREFACE + frame(4) + b"\x00!")
            peer = Peer.__new__(Peer)
            peer.sock = sock
            peer.buffer = b""
            seen_settings = False
            seen_goaway = False
            start = time.monotonic()
            for _ in range(8):
                kind, flags, stream, payload = peer.read()
                if kind == 4 and stream == 0 and flags == 0:
                    seen_settings = True
                if kind == 7:
                    self.assertEqual(stream, 0)
                    self.assertGreaterEqual(len(payload), 8)
                    self.assertEqual(int.from_bytes(payload[4:8], "big"), 11)
                    seen_goaway = True
                    break
            self.assertTrue(seen_settings)
            self.assertTrue(seen_goaway, "deadline did not flush GOAWAY")
            self.assertLess(time.monotonic() - start, 2.5)
        if server.poll() is not None:
            log.seek(0)
            self.fail(f"scheduler exited during close: {log.read()}")
        trace = os.pread(log.fileno(), 65536, 0)
        self.assertIn(b"MOCK_CLOSING_READ_WANT_WRITE", trace)
        self.assertIn(b"MOCK_CLOSING_READ_RETRIED", trace)


if __name__ == "__main__":
    unittest.main()
