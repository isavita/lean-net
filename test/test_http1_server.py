#!/usr/bin/env python3
"""Black-box HTTP/1.1 server acceptance tests.

Run after `lake build lean-net-http1 lean-net-http1-fixture` with
`python3 test/test_http1_server.py -v`.
Set LEAN_NET_HTTP1_BIN to test a different executable.
"""
import os
from email.utils import format_datetime, parsedate_to_datetime
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import unittest

from test_echo import HOST, connect, fd_count, unused_port

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("LEAN_NET_HTTP1_BIN", ROOT / ".lake/build/bin/lean-net-http1"))
FIXTURE = ROOT / ".lake/build/bin/lean-net-http1-fixture"
HELLO = b"Hello from lean-net!\n"
GET = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"


class HttpReader:
    """Retain over-read bytes when multiple HTTP responses share a socket."""
    def __init__(self, sock):
        self.sock = sock
        self.buffer = bytearray()

    def until(self, marker):
        while marker not in self.buffer:
            part = self.sock.recv(16384)
            if not part:
                raise AssertionError("premature EOF in HTTP headers")
            self.buffer.extend(part)
            if len(self.buffer) > 65536:
                raise AssertionError("oversized response headers")
        end = self.buffer.index(marker) + len(marker)
        data = bytes(self.buffer[:end])
        del self.buffer[:end]
        return data

    def take(self, n):
        while len(self.buffer) < n:
            part = self.sock.recv(16384)
            if not part:
                raise AssertionError("premature EOF in HTTP body")
            self.buffer.extend(part)
        data = bytes(self.buffer[:n])
        del self.buffer[:n]
        return data

    def response(self, *, head=False):
        while True:
            head_bytes = self.until(b"\r\n\r\n")
            lines = head_bytes[:-4].split(b"\r\n")
            status = lines[0].split(b" ", 2)
            if len(status) < 2 or status[0] != b"HTTP/1.1":
                raise AssertionError(f"invalid status line: {lines[0]!r}")
            code = int(status[1])
            if code != 100:
                break
        headers = {}
        for line in lines[1:]:
            name, sep, value = line.partition(b":")
            if not sep:
                raise AssertionError(f"invalid header: {line!r}")
            key = name.lower()
            if key in headers and key in (b"content-length", b"transfer-encoding", b"date"):
                raise AssertionError(f"duplicate framing header: {key!r}")
            headers[key] = value.strip()
        if b"date" not in headers:
            raise AssertionError("response has no Date")
        date = headers[b"date"].decode("ascii")
        try:
            parsed = parsedate_to_datetime(date)
            if format_datetime(parsed, usegmt=True) != date:
                raise ValueError("noncanonical HTTP date")
        except (TypeError, ValueError, IndexError) as error:
            raise AssertionError(f"invalid Date header: {date!r}") from error
        if b"transfer-encoding" in headers:
            raise AssertionError("test fixture expected Content-Length response framing")
        if code in (204, 304):
            if b"content-length" in headers:
                raise AssertionError("204/304 response included Content-Length")
            return code, headers, b""
        if b"content-length" not in headers:
            raise AssertionError("response has no Content-Length")
        size = int(headers[b"content-length"])
        body = b"" if head or code in (204, 304) or 100 <= code < 200 else self.take(size)
        return code, headers, body


class HttpServerAcceptance(unittest.TestCase):
    binary = BINARY

    def setUp(self):
        if not self.binary.is_file():
            self.fail(f"HTTP executable not found at {self.binary}; build the corresponding Lake target")
        self.port = unused_port()
        self.log = tempfile.TemporaryFile(mode="w+")
        self.server = subprocess.Popen([str(self.binary), str(self.port), *getattr(self, "extra_args", [])],
                                       stdout=self.log, stderr=self.log)
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

    def assert_shutdown(self):
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

    def test_curl_http11_route(self):
        result = subprocess.run(
            ["curl", "--http1.1", "--fail", "--silent", "--show-error", "--verbose",
             f"http://{HOST}:{self.port}/"], capture_output=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stdout, HELLO)
        self.assertIn(b"HTTP/1.1 200", result.stderr)

    def test_keepalive_and_pipelining(self):
        with connect(self.port) as sock:
            reader = HttpReader(sock)
            sock.sendall(GET)
            self.assertEqual(reader.response()[::2], (200, HELLO))
            sock.sendall(GET + GET)
            self.assertEqual(reader.response()[::2], (200, HELLO))
            self.assertEqual(reader.response()[::2], (200, HELLO))

    def test_head_does_not_write_a_body(self):
        with connect(self.port) as sock:
            reader = HttpReader(sock)
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n" + GET)
            status, headers, body = reader.response(head=True)
            self.assertEqual((status, body), (200, b""))
            self.assertEqual(int(headers[b"content-length"]), len(HELLO))
            self.assertEqual(reader.response()[::2], (200, HELLO))

    def test_fragmented_body_is_consumed_before_next_request(self):
        with connect(self.port) as sock:
            reader = HttpReader(sock)
            payload = b"not a request\x00\xff"
            sock.sendall(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: " +
                         str(len(payload)).encode() + b"\r\n\r\n" + payload[:1])
            sock.settimeout(0.15)
            with self.assertRaises(TimeoutError):
                sock.recv(1)
            sock.settimeout(2)
            sock.sendall(payload[1:] + GET)
            reader.response()
            self.assertEqual(reader.response()[::2], (200, HELLO))

    def test_expect_continue_then_pipelined_request(self):
        with connect(self.port) as sock:
            reader = HttpReader(sock)
            sock.sendall(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n"
                         b"Expect: 100-continue\r\n\r\n")
            self.assertEqual(reader.until(b"\r\n\r\n"), b"HTTP/1.1 100 Continue\r\n\r\n")
            sock.sendall(b"data" + GET)
            reader.response()
            self.assertEqual(reader.response()[::2], (200, HELLO))

    def test_expect_continue_with_body_in_same_write(self):
        with connect(self.port) as sock:
            reader = HttpReader(sock)
            sock.sendall(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n"
                         b"Expect: 100-continue\r\n\r\ndata" + GET)
            reader.response()
            self.assertEqual(reader.response()[::2], (200, HELLO))

    def test_unsupported_expectation_without_body_returns_417_and_closes(self):
        with connect(self.port) as sock:
            reader = HttpReader(sock)
            sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n"
                         b"Expect: unsupported-example\r\n\r\n")
            status, headers, _ = reader.response()
            self.assertEqual(status, 417)
            self.assertEqual(headers.get(b"connection", b"").lower(), b"close")
            self.assertEqual(sock.recv(1), b"")

    def test_unsupported_expectation_returns_417_and_closes(self):
        with connect(self.port) as sock:
            reader = HttpReader(sock)
            sock.sendall(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n"
                         b"Expect: unsupported-example\r\n\r\n")
            status, headers, _ = reader.response()
            self.assertEqual(status, 417)
            self.assertEqual(headers.get(b"connection", b"").lower(), b"close")
            self.assertEqual(sock.recv(1), b"")

    def test_ambiguous_framing_rejected_and_connection_closed(self):
        with connect(self.port) as sock:
            sock.sendall(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n"
                         b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n" + GET)
            received = bytearray()
            while True:
                part = sock.recv(16384)
                if not part:
                    break
                received.extend(part)
                self.assertLess(len(received), 65536)
            self.assertNotIn(b"HTTP/1.1 200", received, "request after framing error was processed")
            if received:
                self.assertTrue(received.startswith(b"HTTP/1.1 400 "), received)

    def test_ctrl_c_while_idle(self):
        time.sleep(0.1)
        self.assert_shutdown()

    def test_ctrl_c_during_incomplete_request(self):
        with connect(self.port) as sock:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
            time.sleep(0.1)
            self.assert_shutdown()
            self.assertEqual(sock.recv(1), b"")

    def test_thousand_connections_do_not_leak_descriptors(self):
        time.sleep(0.1)
        baseline = fd_count(self.server.pid)
        for _ in range(1000):
            with connect(self.port) as sock:
                sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                self.assertEqual(HttpReader(sock).response()[::2], (200, HELLO))
                self.assertEqual(sock.recv(1), b"")
        deadline = time.monotonic() + 3
        observed = fd_count(self.server.pid)
        while observed > baseline and time.monotonic() < deadline:
            time.sleep(0.05)
            observed = fd_count(self.server.pid)
        self.assertLessEqual(observed, baseline, f"descriptor count grew from {baseline} to {observed}")


class HttpFixtureAcceptance(unittest.TestCase):
    binary = FIXTURE
    setUp = HttpServerAcceptance.setUp
    stop_server = HttpServerAcceptance.stop_server

    def test_binary_request_and_response_framing(self):
        payload = bytes(range(256)) * 4 + b"\x00\xff"
        with connect(self.port) as sock:
            reader = HttpReader(sock)
            request = (b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: " +
                       str(len(payload)).encode() + b"\r\n\r\n" + payload)
            sock.sendall(request + b"GET /binary HTTP/1.1\r\nHost: localhost\r\n\r\n")
            status, headers, body = reader.response()
            self.assertEqual((status, body), (200, payload))
            self.assertEqual(int(headers[b"content-length"]), len(payload))
            status, headers, body = reader.response()
            self.assertEqual((status, body), (200, b"\x00\xff\r\nA"))
            self.assertEqual(int(headers[b"content-length"]), 5)
            self.assertEqual(headers.get(b"content-type"), b"application/octet-stream")

    def test_application_date_is_preserved_without_duplicate(self):
        with connect(self.port) as sock:
            sock.sendall(b"GET /date HTTP/1.1\r\nHost: localhost\r\n\r\n")
            status, headers, _ = HttpReader(sock).response()
            self.assertEqual(status, 200)
            self.assertEqual(headers[b"date"], b"Sun, 06 Nov 1994 08:49:37 GMT")

    def test_chunked_binary_body_and_pipeline(self):
        with connect(self.port) as sock:
            reader = HttpReader(sock)
            sock.sendall(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
                         b"3\r\n\x00\xffA\r\n2\r\n\r\n\r\n0\r\nX-Trailer: yes\r\n\r\n"
                         b"GET /binary HTTP/1.1\r\nHost: localhost\r\n\r\n")
            self.assertEqual(reader.response()[::2], (200, b"\x00\xffA\r\n"))
            self.assertEqual(reader.response()[::2], (200, b"\x00\xff\r\nA"))

    def test_bodyless_statuses_and_head_preserve_pipeline_alignment(self):
        with connect(self.port) as sock:
            reader = HttpReader(sock)
            sock.sendall(b"HEAD /binary HTTP/1.1\r\nHost: localhost\r\n\r\n" +
                         b"".join(b"GET /" + str(status).encode() + b" HTTP/1.1\r\nHost: localhost\r\n\r\n"
                                  for status in (204, 205, 304)) +
                         b"GET /binary HTTP/1.1\r\nHost: localhost\r\n\r\n")
            status, headers, body = reader.response(head=True)
            self.assertEqual((status, body, int(headers[b"content-length"])), (200, b"", 5))
            for expected in (204, 205, 304):
                status, headers, body = reader.response()
                self.assertEqual((status, body), (expected, b""))
                if expected == 205:
                    self.assertEqual(headers[b"content-length"], b"0")
            self.assertEqual(reader.response()[::2], (200, b"\x00\xff\r\nA"))


if __name__ == "__main__":
    unittest.main()
