#!/usr/bin/env python3
"""Native bounded application completions on one shared HTTP/1+HTTP/2 worker.

Uses real TCP sockets and an independent HPACK implementation. Run after
`lake build lean-net-deferred-reply-fixture` (hpack pinned in requirements-http2).
"""
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

from http2_test_support import H2Client, frame
from test_echo import unused_port
from test_http1_reactor import Reader

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / (".lake/build/bin/lean-net-deferred-reply-fixture" + (".exe" if sys.platform == "win32" else ""))


class DeferredReplies(unittest.TestCase):
    def setUp(self):
        self.assertTrue(BINARY.exists(), f"build {BINARY}")
        self.port = unused_port()
        self.log = tempfile.TemporaryFile(mode="w+")
        self.server = subprocess.Popen([str(BINARY), str(self.port)], stdout=self.log, stderr=self.log,
                                      creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0)
        self.addCleanup(self.log.close)
        self.addCleanup(self.stop)
        for _ in range(200):
            if self.server.poll() is not None:
                self.log.seek(0)
                self.fail(f"server exited: {self.log.read()}")
            try:
                if self.get(b"/immediate").body == b"immediate":
                    return
            except (OSError, AssertionError):
                time.sleep(.01)
        self.fail("server startup timeout")

    def stop(self):
        if self.server.poll() is None:
            self.server.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
            try:
                self.server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait()
                self.fail("shutdown exceeded bound")
        if self.server.returncode:
            self.log.seek(0)
            self.fail(f"server exit {self.server.returncode}: {self.log.read()}")

    def connect(self):
        peer = socket.create_connection(("127.0.0.1", self.port), timeout=3)
        peer.settimeout(3)
        self.addCleanup(peer.close)
        return peer

    def get(self, path):
        with socket.create_connection(("127.0.0.1", self.port), timeout=3) as peer:
            peer.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: localhost\r\n\r\n")
            return Reader(peer).response()

    def h2(self):
        peer = H2Client(self.port)
        self.addCleanup(peer.close)
        return peer

    def test_owned_transport_facts_ignore_forwarded_headers_and_match_protocols(self):
        expected = b"false|127.0.0.1|none|"
        for path in (b"/transport", b"/transport-deferred"):
            peer = self.connect()
            peer.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: localhost\r\n"
                         b"Forwarded: for=198.51.100.20;proto=https\r\n"
                         b"X-Forwarded-For: 198.51.100.20\r\nX-Forwarded-Proto: https\r\n\r\n")
            self.assertEqual(Reader(peer).response().body, expected)
            h2 = self.h2()
            h2.request(1, path, headers=[(b"forwarded", b"for=198.51.100.20;proto=https"),
                (b"x-forwarded-for", b"198.51.100.20"), (b"x-forwarded-proto", b"https")])
            self.assertEqual(h2.response(1), expected)

    def test_early_header_checks_precede_body_and_continue_on_both_protocols(self):
        peer = self.connect()
        peer.sendall(b"POST /refuse HTTP/1.1\r\nHost: localhost\r\n"
                     b"Content-Length: 10\r\nExpect: 100-continue\r\n\r\n")
        reply = Reader(peer).response()
        self.assertEqual(reply.status, 403)
        self.assertEqual(reply.headers[b"x-early"], b"checked")
        self.assertIn(b"started=0;", self.get(b"/stats").body)
        h2 = self.h2()
        h2.request(1, b"/refuse", method=b"POST", end_stream=False,
                   headers=[(b"content-length", b"10"), (b"expect", b"100-continue")])
        h2.until(lambda: 1 in h2.ended)
        self.assertEqual(dict(h2.headers[1][0].headers)[b":status"], b"403")
        self.assertEqual(dict(h2.headers[1][0].headers)[b"x-early"], b"checked")
        self.assertFalse(any(dict(block.headers).get(b":status") == b"100" for block in h2.headers[1]))
        h2.request(3, b"/stats")
        self.assertIn(b"started=0;", h2.response(3))
        self.assertFalse(h2.goaways)

    def test_http1_pipeline_order_and_other_connection_progress(self):
        peer = self.connect()
        reader = Reader(peer)
        peer.sendall(b"GET /slow HTTP/1.1\r\nHost: localhost\r\n\r\n"
                     b"GET /fast HTTP/1.1\r\nHost: localhost\r\n\r\n")
        started = time.monotonic()
        self.assertEqual(self.get(b"/fast").body, b"/fast")
        self.assertLess(time.monotonic() - started, .25)
        self.assertEqual(reader.response().body, b"/slow")
        self.assertEqual(reader.response().body, b"/fast")

    def test_http2_independent_stream_completion(self):
        peer = self.h2()
        peer.request(1, b"/slow")
        peer.request(3, b"/fast")
        self.assertEqual(peer.response(3), b"/fast")
        self.assertNotIn(1, peer.ended)
        self.assertEqual(peer.response(1), b"/slow")

    def test_timeout_failure_and_retained_byte_overflow_parity(self):
        for path, expected, reason in [(b"/timeout", 504, b"timeout"),
                                       (b"/failed", 500, b"failed"),
                                       (b"/oversize", 503, b"overloaded")]:
            with self.subTest(path=path, protocol="HTTP/1"):
                self.assertEqual(self.get(path).status, expected)
                self.assertIn(reason, self.get(b"/stats").body)
            with self.subTest(path=path, protocol="HTTP/2"):
                peer = self.h2()
                peer.request(1, path)
                peer.until(lambda: 1 in peer.ended or bool(peer.resets) or bool(peer.goaways))
                self.assertFalse(peer.resets)
                self.assertFalse(peer.goaways)
                self.assertEqual(dict(peer.headers[1][0].headers)[b":status"], str(expected).encode())
                peer.close()

    def test_http2_stream_reset_cancels_exactly_once_and_releases_slot(self):
        peer = self.h2()
        peer.request(1, b"/hold")
        peer.ping_barrier()
        peer.send(frame(3, stream=1, payload=struct.pack(">I", 8)))
        peer.ping_barrier(b"resetack")
        peer.request(3, b"/stats")
        stats = peer.response(3)
        self.assertEqual(stats.count(b"streamReset"), 1, stats)
        peer.request(5, b"/fast")
        self.assertEqual(peer.response(5), b"/fast")
        self.assertNotIn(1, peer.headers)
        self.assertFalse(peer.goaways)

    def test_worker_queue_overflow_releases_on_cancellation(self):
        peer = self.h2()
        peer.request(1, b"/hold")
        peer.request(3, b"/hold")
        peer.ping_barrier()
        filling = self.h2()
        filling.request(1, b"/hold")
        filling.ping_barrier()
        other = self.h2()
        other.request(1, b"/fast")
        other.until(lambda: 1 in other.ended)
        self.assertEqual(dict(other.headers[1][0].headers)[b":status"], b"503")
        peer.send(frame(3, stream=1, payload=struct.pack(">I", 8)))
        peer.ping_barrier(b"released")
        other.request(3, b"/fast")
        self.assertEqual(other.response(3), b"/fast")

    def test_per_client_count_and_worker_byte_budgets(self):
        peer = self.h2()
        peer.request(1, b"/hold")
        peer.request(3, b"/hold")
        peer.request(5, b"/fast")
        peer.until(lambda: 5 in peer.ended)
        self.assertEqual(dict(peer.headers[5][0].headers)[b":status"], b"503")
        self.assertEqual(self.get(b"/fast").body, b"/fast")
        peer.send(frame(3, stream=1, payload=struct.pack(">I", 8)) +
                  frame(3, stream=3, payload=struct.pack(">I", 8)))
        peer.ping_barrier()
        peer.request(7, b"/big")
        peer.request(9, b"/big")
        peer.until(lambda: 9 in peer.ended)
        self.assertEqual(dict(peer.headers[9][0].headers)[b":status"], b"503")
        self.assertNotIn(7, peer.ended)

    def test_connection_reset_cancels_before_application_deadline(self):
        peer = self.h2()
        peer.request(1, b"/hold")
        peer.ping_barrier()
        linger = struct.pack("hh" if sys.platform == "win32" else "ii", 1, 0)
        peer.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
        peer.close()
        cutoff = time.monotonic() + .6
        while time.monotonic() < cutoff:
            stats = self.get(b"/stats").body
            if b"disconnected" in stats:
                self.assertEqual(stats.count(b"disconnected"), 1, stats)
                return
            time.sleep(.01)
        self.fail(f"disconnect not cancelled before 1-second deadline: {stats!r}")

    def test_http1_connection_reset_cancels_before_deadline(self):
        peer = self.connect()
        peer.sendall(b"GET /hold HTTP/1.1\r\nHost: localhost\r\n\r\n")
        # Synchronize with the owner without reading the held response.
        for _ in range(40):
            if b"started=1;" in self.get(b"/stats").body:
                break
            time.sleep(.01)
        linger = struct.pack("hh" if sys.platform == "win32" else "ii", 1, 0)
        peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
        peer.close()
        cutoff = time.monotonic() + .6
        while time.monotonic() < cutoff:
            stats = self.get(b"/stats").body
            if b"disconnected" in stats:
                self.assertEqual(stats.count(b"disconnected"), 1, stats)
                return
            time.sleep(.01)
        self.fail(f"HTTP/1 disconnect not cancelled before deadline: {stats!r}")

    def test_shutdown_cancels_unfinished_jobs_once(self):
        peer = self.h2()
        peer.request(1, b"/hold")
        peer.ping_barrier()
        self.stop()
        self.log.seek(0)
        text = self.log.read()
        self.assertEqual(text.count("cancel=LeanNet.HTTP.Deferred.CancelReason.shutdown"), 1, text)


if __name__ == "__main__":
    unittest.main()
