#!/usr/bin/env python3
"""HTTP event-loop concurrency and backpressure acceptance tests.

Run after `lake build lean-net-http1 lean-net-http1-fixture` with
`python3 test/test_http1_event.py -v`.
"""
import socket
import select
import os
import signal
import time
import unittest

from test_echo import connect, fd_count
import test_http1_server as common
from test_http1_server import BINARY, FIXTURE, GET, HELLO, HttpReader


class HttpEventAcceptance(unittest.TestCase):
    binary = BINARY
    setUp = common.HttpServerAcceptance.setUp
    stop_server = common.HttpServerAcceptance.stop_server
    assert_shutdown = common.HttpServerAcceptance.assert_shutdown

    def test_idle_client_does_not_block_another(self):
        with connect(self.port):
            with connect(self.port) as active:
                active.sendall(GET)
                self.assertEqual(HttpReader(active).response()[::2], (200, HELLO))

    def test_incomplete_headers_do_not_block_another(self):
        with connect(self.port) as slow:
            slow.sendall(b"GET / HTTP/1.1\r\nHost: local")
            with connect(self.port) as active:
                active.sendall(GET)
                self.assertEqual(HttpReader(active).response()[::2], (200, HELLO))
            slow.sendall(b"host\r\n\r\n")
            self.assertEqual(HttpReader(slow).response()[::2], (200, HELLO))

    def test_incomplete_body_does_not_block_another(self):
        with connect(self.port) as slow:
            reader = HttpReader(slow)
            slow.sendall(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\na")
            with connect(self.port) as active:
                active.sendall(GET)
                self.assertEqual(HttpReader(active).response()[::2], (200, HELLO))
            slow.sendall(b"bcd" + GET)
            reader.response()
            self.assertEqual(reader.response()[::2], (200, HELLO))

    def test_half_close_still_delivers_all_pipelined_responses(self):
        with connect(self.port) as sock:
            sock.sendall(GET + GET + GET)
            sock.shutdown(socket.SHUT_WR)
            reader = HttpReader(sock)
            for _ in range(3):
                self.assertEqual(reader.response()[::2], (200, HELLO))
            self.assertEqual(sock.recv(1), b"")

    def test_sigint_with_multiple_active_clients(self):
        clients = [connect(self.port) for _ in range(12)]
        try:
            for sock in clients[:6]:
                sock.sendall(b"GET / HTTP/1.1\r\nHost: local")
            time.sleep(0.1)
            self.assert_shutdown()
            for sock in clients:
                self.assertEqual(sock.recv(1), b"")
        finally:
            for sock in clients:
                sock.close()

    def test_simultaneous_connections_return_to_baseline(self):
        time.sleep(0.1)
        baseline = fd_count(self.server.pid)
        for _ in range(20):
            clients = [connect(self.port) for _ in range(50)]
            try:
                for sock in clients:
                    sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                for sock in clients:
                    self.assertEqual(HttpReader(sock).response()[::2], (200, HELLO))
                    self.assertEqual(sock.recv(1), b"")
            finally:
                for sock in clients:
                    sock.close()
        deadline = time.monotonic() + 3
        observed = fd_count(self.server.pid)
        while observed > baseline and time.monotonic() < deadline:
            time.sleep(0.05)
            observed = fd_count(self.server.pid)
        self.assertLessEqual(observed, baseline, f"descriptor count grew from {baseline} to {observed}")


class HttpEventBackpressure(unittest.TestCase):
    binary = FIXTURE
    setUp = common.HttpServerAcceptance.setUp
    stop_server = common.HttpServerAcceptance.stop_server
    assert_shutdown = common.HttpServerAcceptance.assert_shutdown

    def stalled_client(self):
        slow = socket.socket()
        slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        slow.settimeout(2)
        slow.connect(("127.0.0.1", self.port))
        slow.sendall(b"GET /large HTTP/1.1\r\nHost: localhost\r\n\r\n")
        header = HttpReader(slow).until(b"\r\n\r\n")
        self.assertIn(b"Content-Length: 8388608\r\n", header)
        return slow

    def test_stalled_response_does_not_block_another_client(self):
        with self.stalled_client():
            time.sleep(0.1)
            with connect(self.port) as active:
                active.sendall(b"GET /binary HTTP/1.1\r\nHost: localhost\r\n\r\n")
                self.assertEqual(HttpReader(active).response()[::2], (200, b"\x00\xff\r\nA"))

    def test_partial_writes_preserve_large_body_and_pipeline(self):
        with connect(self.port) as sock:
            sock.settimeout(10)
            sock.sendall(b"GET /large HTTP/1.1\r\nHost: localhost\r\n\r\n"
                         b"GET /binary HTTP/1.1\r\nHost: localhost\r\n\r\n")
            time.sleep(0.15)
            reader = HttpReader(sock)
            status, headers, body = reader.response()
            self.assertEqual(status, 200)
            self.assertEqual(int(headers[b"content-length"]), 8 * 1024 * 1024)
            self.assertEqual(body, b"A" * (8 * 1024 * 1024))
            self.assertEqual(reader.response()[::2], (200, b"\x00\xff\r\nA"))

    def test_application_failures_are_isolated_with_bounded_500(self):
        for route in (b"oversized", b"invalid", b"throw"):
            with self.subTest(route=route):
                with connect(self.port) as bad:
                    bad.settimeout(5)
                    bad.sendall(b"GET /" + route + b" HTTP/1.1\r\nHost: localhost\r\n\r\n"
                                b"GET /binary HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    status, headers, body = HttpReader(bad).response()
                    self.assertEqual((status, body), (500, b""))
                    self.assertEqual(headers.get(b"connection", b"").lower(), b"close")
                    self.assertEqual(bad.recv(1), b"")
                with connect(self.port) as good:
                    good.sendall(b"GET /binary HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    self.assertEqual(HttpReader(good).response()[::2], (200, b"\x00\xff\r\nA"))

    def test_sigint_during_backpressure(self):
        with self.stalled_client():
            time.sleep(0.1)
            self.assert_shutdown()


class HttpEventDeadlines(unittest.TestCase):
    binary = FIXTURE
    extra_args = ["deadlines"]
    setUp = common.HttpServerAcceptance.setUp
    stop_server = common.HttpServerAcceptance.stop_server

    def test_idle_client_timeout_releases_only_slot(self):
        with connect(self.port) as idle:
            time.sleep(0.1)
            with connect(self.port) as queued:
                queued.settimeout(3)
                queued.sendall(b"GET /binary HTTP/1.1\r\nHost: localhost\r\n\r\n")
                self.assertEqual(HttpReader(queued).response()[::2], (200, b"\x00\xff\r\nA"))
            idle.settimeout(1)
            self.assertEqual(idle.recv(1), b"")

    def test_request_readiness_after_deadline_does_not_resurrect_request(self):
        with connect(self.port) as slow:
            slow.settimeout(2)
            slow.sendall(b"POST /binary HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n"
                         b"Expect: 100-continue\r\n\r\n")
            self.assertEqual(HttpReader(slow).until(b"\r\n\r\n"), b"HTTP/1.1 100 Continue\r\n\r\n")
            os.kill(self.server.pid, signal.SIGSTOP)
            try:
                time.sleep(0.8)
                slow.sendall(b"data")
            finally:
                os.kill(self.server.pid, signal.SIGCONT)
            try:
                reply = slow.recv(4096)
            except ConnectionResetError:
                reply = b""
            self.assertFalse(reply.startswith(b"HTTP/1.1 200 "), reply)

    def test_idle_readiness_after_deadline_does_not_resurrect_client(self):
        with connect(self.port) as idle:
            idle.settimeout(2)
            idle.sendall(b"GET /binary HTTP/1.1\r\nHost: localhost\r\n\r\n")
            self.assertEqual(HttpReader(idle).response()[::2], (200, b"\x00\xff\r\nA"))
            os.kill(self.server.pid, signal.SIGSTOP)
            try:
                time.sleep(0.5)
                idle.sendall(b"GET /binary HTTP/1.1\r\nHost: localhost\r\n\r\n")
            finally:
                os.kill(self.server.pid, signal.SIGCONT)
            try:
                reply = idle.recv(4096)
            except ConnectionResetError:
                reply = b""
            self.assertFalse(reply.startswith(b"HTTP/1.1 200 "), reply)

    def test_trickle_header_hits_absolute_request_deadline(self):
        with connect(self.port) as slow:
            slow.sendall(b"GET / HTTP/1.1\r\nHost: ")
            start = time.monotonic()
            closed = False
            while time.monotonic() - start < 2:
                time.sleep(0.08)
                try:
                    slow.sendall(b"a")
                except (BrokenPipeError, ConnectionResetError):
                    closed = True
                    break
                readable, _, _ = select.select([slow], [], [], 0)
                if readable:
                    data = slow.recv(4096)
                    if data:
                        self.assertTrue(data.startswith(b"HTTP/1.1 408 "), data)
                    closed = True
                    break
            self.assertTrue(closed, "trickling bypassed the absolute request deadline")
            with connect(self.port) as active:
                active.sendall(b"GET /binary HTTP/1.1\r\nHost: localhost\r\n\r\n")
                self.assertEqual(HttpReader(active).response()[::2], (200, b"\x00\xff\r\nA"))


class HttpZeroOutputLimit(unittest.TestCase):
    binary = FIXTURE
    extra_args = ["zero"]
    setUp = common.HttpServerAcceptance.setUp
    stop_server = common.HttpServerAcceptance.stop_server

    def test_protocol_errors_survive_zero_application_limits(self):
        requests = (
            (b"GET / HTTP/1.1\r\nMalformed\r\n\r\n", 400),
            (b"GET / HTTP/1.1\r\nHost: localhost\r\nExpect: unsupported\r\n\r\n", 417),
        )
        for request, expected in requests:
            with self.subTest(expected=expected), connect(self.port) as sock:
                sock.sendall(request)
                status, headers, body = HttpReader(sock).response()
                self.assertEqual((status, body), (expected, b""))
                self.assertEqual(headers.get(b"connection", b"").lower(), b"close")
                self.assertEqual(sock.recv(1), b"")


if __name__ == "__main__":
    unittest.main()
