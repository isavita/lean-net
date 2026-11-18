#!/usr/bin/env python3
"""Real native-reactor HTTP/1.0/1.1 and raw-upgrade acceptance.

Build lean-net-http1-reactor-fixture first. Uses only the Python standard
library; protocol reads retain pipeline over-read bytes and validate framing.
"""
from collections import Counter
from dataclasses import dataclass
from email.utils import format_datetime, parsedate_to_datetime
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

from test_echo import HOST, connect, fd_count, unused_port

ROOT = Path(__file__).resolve().parents[1]
SUFFIX = ".exe" if sys.platform == "win32" else ""
BINARY = Path(os.environ.get("LEAN_NET_HTTP1_REACTOR_BIN", ROOT / f".lake/build/bin/lean-net-http1-reactor-fixture{SUFFIX}"))
BINARY_BODY = bytes([0, 255, 13, 10, 65])
GET = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"


def resource_count(pid):
    if sys.platform != "win32":
        return fd_count(pid)
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetProcessHandleCount.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        count = wintypes.DWORD()
        if not kernel.GetProcessHandleCount(handle, ctypes.byref(count)):
            raise ctypes.WinError(ctypes.get_last_error())
        return count.value
    finally:
        if not kernel.CloseHandle(handle):
            raise ctypes.WinError(ctypes.get_last_error())


@dataclass
class Response:
    version: bytes
    status: int
    reason: bytes
    headers: dict
    body: bytes
    trailers: dict


class Reader:
    def __init__(self, sock):
        self.sock = sock
        self.buffer = bytearray()

    def until(self, marker, maximum=65536):
        while marker not in self.buffer:
            part = self.sock.recv(65536)
            if not part:
                raise AssertionError("premature EOF before delimiter")
            self.buffer.extend(part)
            if marker not in self.buffer and len(self.buffer) > maximum:
                raise AssertionError("delimiter limit exceeded")
        end = self.buffer.index(marker) + len(marker)
        if end > maximum:
            raise AssertionError("delimiter limit exceeded")
        result = bytes(self.buffer[:end])
        del self.buffer[:end]
        return result

    def take(self, size):
        if size < 0 or size > 32 * 1024 * 1024:
            raise AssertionError("invalid body length")
        while len(self.buffer) < size:
            part = self.sock.recv(65536)
            if not part:
                raise AssertionError("premature EOF in body")
            self.buffer.extend(part)
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def eof(self):
        if self.buffer:
            raise AssertionError(f"unexpected trailing bytes: {bytes(self.buffer[:80])!r}")
        if self.sock.recv(1) != b"":
            raise AssertionError("expected connection closure")

    def response(self, *, head=False):
        lines = self.until(b"\r\n\r\n")[:-4].split(b"\r\n")
        status = lines[0].split(b" ", 2)
        if len(status) != 3 or status[0] not in (b"HTTP/1.0", b"HTTP/1.1") or len(status[1]) != 3 or not status[1].isdigit():
            raise AssertionError(f"invalid response status: {lines[0]!r}")
        code = int(status[1])
        headers = {}
        for line in lines[1:]:
            name, separator, value = line.partition(b":")
            if not separator or not name:
                raise AssertionError(f"invalid response header: {line!r}")
            name = name.lower()
            if name in headers and name in (b"content-length", b"transfer-encoding", b"date", b"trailer"):
                raise AssertionError(f"duplicate framing field {name!r}")
            headers[name] = value.strip()
        if b"content-length" in headers and b"transfer-encoding" in headers:
            raise AssertionError("response contains both CL and TE")
        if code >= 200:
            date = headers.get(b"date", b"").decode("ascii")
            parsed = parsedate_to_datetime(date)
            if format_datetime(parsed, usegmt=True) != date:
                raise AssertionError("noncanonical IMF-fixdate")
        body = b""
        trailers = {}
        if 100 <= code < 200 or code in (204, 304):
            if b"content-length" in headers or b"transfer-encoding" in headers:
                raise AssertionError("bodyless status carries framing fields")
        elif head:
            if b"content-length" not in headers:
                raise AssertionError("HEAD omitted representation length")
        elif b"transfer-encoding" in headers:
            if headers[b"transfer-encoding"].lower() != b"chunked" or status[0] != b"HTTP/1.1":
                raise AssertionError("unsupported response transfer coding")
            chunks = []
            while True:
                line = self.until(b"\r\n", 1024)[:-2]
                size = int(line.split(b";", 1)[0], 16)
                if size == 0:
                    while True:
                        line = self.until(b"\r\n")[:-2]
                        if not line:
                            break
                        name, separator, value = line.partition(b":")
                        if not separator:
                            raise AssertionError("malformed response trailer")
                        trailers[name.lower()] = value.strip()
                    break
                chunks.append(self.take(size))
                if self.take(2) != b"\r\n":
                    raise AssertionError("missing chunk-data terminator")
            body = b"".join(chunks)
        elif b"content-length" in headers:
            value = headers[b"content-length"]
            if not value.isdigit():
                raise AssertionError("invalid response Content-Length")
            body = self.take(int(value))
        else:
            if headers.get(b"connection", b"").lower() != b"close" and status[0] != b"HTTP/1.0":
                raise AssertionError("close-delimited response did not advertise close")
            chunks = [bytes(self.buffer)]
            self.buffer.clear()
            while True:
                part = self.sock.recv(65536)
                if not part:
                    break
                chunks.append(part)
                if sum(map(len, chunks)) > 32 * 1024 * 1024:
                    raise AssertionError("unbounded close-delimited response")
            body = b"".join(chunks)
        return Response(status[0], code, status[2], headers, body, trailers)


class ServerCase:
    mode = "normal"
    workers = 1

    def setUp(self):
        self.assertTrue(BINARY.is_file(), f"missing fixture: {BINARY}")
        self.port = unused_port()
        self.log = tempfile.TemporaryFile(mode="w+")
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        self.server = subprocess.Popen([str(BINARY), str(self.port), self.mode, str(self.workers)], stdout=self.log, stderr=self.log, creationflags=flags)
        self.addCleanup(self.log.close)
        self.addCleanup(self.stop_server)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.server.poll() is not None:
                self.log.seek(0)
                self.fail(f"startup exit {self.server.returncode}: {self.log.read()}")
            try:
                with connect(self.port) as sock:
                    sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                    reader = Reader(sock)
                    self.assertEqual(reader.response().body, b"ok")
                    reader.eof()
                    return
            except OSError:
                time.sleep(.02)
        self.fail("fixture failed to start")

    def stop_server(self):
        if self.server.poll() is None:
            self.server.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
            try:
                code = self.server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.server.kill(); self.server.wait(timeout=5)
                self.fail("fixture did not exit after SIGINT")
        code = self.server.returncode
        if code:
            self.log.seek(0)
            self.fail(f"fixture shutdown exit {code}: {self.log.read()}")

    def request(self, target=b"/", *, method=b"GET", version=b"HTTP/1.1", extra=b"", body=b"", shutdown=False):
        with connect(self.port) as sock:
            sock.sendall(method + b" " + target + b" " + version + b"\r\nHost: x\r\n" + extra + b"\r\n" + body)
            if shutdown:
                sock.shutdown(socket.SHUT_WR)
            return Reader(sock).response(head=method == b"HEAD")


class NormalAcceptance:
    def test_http10_and_http11_persistence(self):
        with connect(self.port) as sock:
            reader = Reader(sock)
            for _ in range(3):
                sock.sendall(b"GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n")
                response = reader.response()
                self.assertEqual((response.version, response.status, response.body), (b"HTTP/1.0", 200, b"ok"))
                self.assertEqual(response.headers[b"connection"].lower(), b"keep-alive")
            sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
            self.assertEqual(reader.response().body, b"ok")
            reader.eof()
        with connect(self.port) as sock:
            reader = Reader(sock)
            for _ in range(3):
                sock.sendall(GET)
                response = reader.response()
                self.assertEqual((response.version, response.body), (b"HTTP/1.1", b"ok"))
            sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, close\r\n\r\n")
            self.assertEqual(reader.response().headers[b"connection"].lower(), b"close")
            reader.eof()

    def test_ten_pipeline_requests_then_half_close(self):
        with connect(self.port) as sock:
            sock.sendall(b"GET /binary HTTP/1.1\r\nHost: x\r\n\r\n" * 10)
            sock.shutdown(socket.SHUT_WR)
            reader = Reader(sock)
            for _ in range(10):
                response = reader.response()
                self.assertEqual((response.status, response.body), (200, BINARY_BODY))
            reader.eof()

    def test_request_and_response_chunked_trailers(self):
        with connect(self.port) as sock:
            sock.sendall(b"POST /trailers HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
                         b"2;ext=\"yes\"\r\n\x00\xff\r\n3\r\nA\r\n\r\n0\r\nX-Check: yes\r\n\r\n" + GET)
            reader = Reader(sock)
            self.assertEqual(reader.response().body, b"\x00\xffA\r\n|yes")
            self.assertEqual(reader.response().body, b"ok")
            sock.sendall(b"GET /chunked HTTP/1.1\r\nHost: x\r\n\r\n")
            response = reader.response()
            self.assertEqual(response.body, BINARY_BODY)
            self.assertEqual(response.trailers, {b"x-finished": b"yes"})
            self.assertEqual(response.headers[b"trailer"].lower(), b"x-finished")

    def test_continue_and_body_supplied_with_head(self):
        head = b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n"
        for early_body in (False, True):
            with self.subTest(early_body=early_body), connect(self.port) as sock:
                sock.sendall(head + (b"data" + GET if early_body else b""))
                reader = Reader(sock)
                self.assertEqual(reader.response().status, 100)
                if not early_body:
                    sock.sendall(b"data" + GET)
                self.assertEqual(reader.response().body, b"data")
                self.assertEqual(reader.response().body, b"ok")

    def test_refusal_leaves_already_supplied_body_unhandled(self):
        with connect(self.port) as sock:
            sock.sendall(b"POST /refuse HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\ndata" + GET)
            reader = Reader(sock)
            response = reader.response()
            self.assertEqual((response.status, response.body), (417, b"refused"))
            self.assertEqual(response.headers[b"connection"].lower(), b"close")
            reader.eof()

    def test_head_204_304_and_custom_reason(self):
        with connect(self.port) as sock:
            sock.sendall(b"HEAD /head HTTP/1.1\r\nHost: x\r\n\r\n"
                         b"HEAD /head-known HTTP/1.1\r\nHost: x\r\n\r\n"
                         b"GET /204 HTTP/1.1\r\nHost: x\r\n\r\n"
                         b"GET /304 HTTP/1.1\r\nHost: x\r\n\r\n"
                         b"GET /custom HTTP/1.1\r\nHost: x\r\n\r\n" + GET)
            reader = Reader(sock)
            self.assertEqual(reader.response(head=True).headers[b"content-length"], b"14")
            self.assertEqual(reader.response(head=True).headers[b"content-length"], b"12345")
            self.assertEqual(reader.response().status, 204)
            self.assertEqual(reader.response().status, 304)
            custom = reader.response()
            self.assertEqual((custom.status, custom.reason, custom.body), (299, b"Custom Ready", b"ready"))
            self.assertEqual(reader.response().body, b"ok")

    def test_informational_and_invalid_application_metadata(self):
        with connect(self.port) as sock:
            sock.sendall(b"GET /informational HTTP/1.1\r\nHost: x\r\n\r\n" + GET)
            reader = Reader(sock)
            self.assertEqual(reader.response().status, 103)
            self.assertEqual(reader.response().status, 102)
            self.assertEqual(reader.response().body, b"ok")
            self.assertEqual(reader.response().body, b"ok")
        for path in (b"/invalid", b"/bad-info"):
            with self.subTest(path=path), connect(self.port) as sock:
                sock.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: x\r\n\r\n" + GET)
                reader = Reader(sock)
                response = reader.response()
                self.assertEqual(response.status, 500)
                self.assertNotIn(b"injected", response.headers)
                reader.eof()

    def test_explicit_legacy_eof_body_and_close_framing(self):
        body = b"\x00\xff\r\n" + GET
        response = self.request(b"/legacy", method=b"POST", version=b"HTTP/1.0", extra=b"Connection: keep-alive\r\n", body=body, shutdown=True)
        self.assertEqual((response.version, response.body), (b"HTTP/1.0", body))
        self.assertEqual(response.headers[b"connection"].lower(), b"close")
        response = self.request(b"/close")
        self.assertEqual(response.body, BINARY_BODY)
        self.assertNotIn(b"content-length", response.headers)
        self.assertNotIn(b"transfer-encoding", response.headers)
        response = self.request(b"/echo", method=b"POST", version=b"HTTP/1.0", body=b"unframed")
        self.assertEqual(response.body, b"")

    def test_upgrade_raw_tail_arrives_with_head(self):
        tail = b"\x00\xff\r\n" + GET
        with connect(self.port) as sock:
            sock.sendall(b"GET /upgrade HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n" + tail)
            reader = Reader(sock)
            response = reader.response()
            self.assertEqual(response.status, 101)
            self.assertEqual(response.headers[b"upgrade"], b"test-echo")
            self.assertEqual(reader.take(len(tail)), tail)
            second = b"raw\x00bytes, not an HTTP message\r\n"
            sock.sendall(second)
            self.assertEqual(reader.take(len(second)), second)
            sock.shutdown(socket.SHUT_WR)
            self.assertEqual(reader.take(7), b"raw-eof")
            reader.eof()

    def test_upgrade_fin_before_101_calls_raw_eof_once(self):
        for tail in (b"", b"early\x00raw\xff"):
            with self.subTest(tail=tail), connect(self.port) as sock:
                sock.sendall(b"GET /upgrade HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n" + tail)
                sock.shutdown(socket.SHUT_WR)
                reader = Reader(sock)
                self.assertEqual(reader.response().status, 101)
                self.assertEqual(reader.take(len(tail) + 7), tail + b"raw-eof")
                reader.eof()

    def test_malformed_and_truncated_requests(self):
        # HTTP/1.2 is served as HTTP/1.1 (RFC 9110 §6.2); see the parser suite.
        requests = [(b"GET /\r\n", 400), (b"GET / HTTP/2.0\r\nHost: x\r\n\r\n", 505),
                    (b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 400),
                    (b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\ndata", 400),
                    (b"GET / HTTP/1.1\r\nHost: x\r\nX: " + b"a" * 16384 + b"\r\n\r\n", 431),
                    (b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nda", 400),
                    (b"GET / HTTP/1.1\r\nHost: incomplete", 400)]
        for data, status in requests:
            with self.subTest(prefix=data[:80]), connect(self.port) as sock:
                sock.sendall(data); sock.shutdown(socket.SHUT_WR)
                reader = Reader(sock)
                self.assertEqual(reader.response().status, status)
                reader.eof()

    def test_h2c_prior_knowledge_preserves_shared_route(self):
        def frame(kind, flags, stream, payload=b""):
            return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + payload
        # Static HPACK method/scheme plus literal path and authority, no codec dependency.
        block = b"\x82\x86\x04\x07/binary\x01\x01x"
        with connect(self.port) as sock:
            sock.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0) + frame(1, 5, 1, block))
            reader = Reader(sock); body = bytearray(); saw_headers = False; ended = False
            for _ in range(64):
                header = reader.take(9)
                size = int.from_bytes(header[:3], "big"); kind, flags = header[3:5]
                stream = int.from_bytes(header[5:], "big") & 0x7fffffff
                self.assertLessEqual(size, 16384)
                payload = reader.take(size)
                self.assertNotIn(kind, (3, 7), f"HTTP/2 rejected basic route: frame{kind} payload{payload!r}")
                if kind == 4 and not flags & 1:
                    sock.sendall(frame(4, 1, 0))
                elif kind == 1 and stream == 1:
                    saw_headers = True
                    if flags & 1:
                        ended = True
                        break
                elif kind == 0 and stream == 1:
                    body.extend(payload)
                    if flags & 1:
                        ended = True
                        break
            self.assertTrue(ended and saw_headers, "HTTP/2 route did not finish")
            self.assertEqual(bytes(body), BINARY_BODY)
        self.assertEqual(self.request(b"/binary").body, BINARY_BODY)

    def test_worker_ownership_distribution(self):
        # Linux hashes connections rather than promising equal counts. Several
        # bounded batches exercise every worker without relying on one hash sample.
        batches = 8 if sys.platform == "linux" else 1
        counts = Counter()
        for _ in range(batches):
            peers = [connect(self.port) for _ in range(32)]
            try:
                for sock in peers:
                    sock.sendall(b"GET /who HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                for sock in peers:
                    reader = Reader(sock); response = reader.response()
                    worker = int(response.headers[b"x-worker"])
                    self.assertEqual(response.body, str(worker).encode())
                    counts[worker] += 1; reader.eof()
            finally:
                for sock in peers:
                    sock.close()
        self.assertEqual(set(counts), set(range(self.workers)), counts)
        self.assertEqual(sum(counts.values()), 32 * batches)
        print("HTTP worker counts:", dict(sorted(counts.items())), flush=True)
        # The acceptor skips full bounded worker queues. Busy HTTP dispatch
        # therefore need not produce equal counts even on handoff platforms.
        # Controlled native fixtures separately exercise available-capacity RR.

    def test_date_input_and_observable_second_cache(self):
        supplied = self.request(b"/date")
        self.assertEqual(supplied.headers[b"date"], b"Sun, 06 Nov 1994 08:49:37 GMT")
        with connect(self.port) as sock:
            before = time.time(); sock.sendall(GET * 10)
            reader = Reader(sock); dates = [reader.response().headers[b"date"] for _ in range(10)]; after = time.time()
            timestamps = [parsedate_to_datetime(value.decode("ascii")).timestamp() for value in dates]
            self.assertTrue(all(before - 2 <= value <= after + 1 for value in timestamps))
            if int(before) == int(after):
                self.assertEqual(len(set(dates)), 1)

    def test_blocked_reader_and_reset_do_not_stall_other_clients(self):
        slow = socket.socket(); slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024); slow.settimeout(3); slow.connect((HOST, self.port))
        try:
            slow.sendall(b"GET /large HTTP/1.1\r\nHost: x\r\n\r\n")
            time.sleep(.1)
            started = time.monotonic()
            for _ in range(20):
                self.assertEqual(self.request().body, b"ok")
            self.assertLess(time.monotonic() - started, 5, "one blocked writer stalled unrelated replies")
            slow.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("HH" if sys.platform == "win32" else "ii", 1, 0))
        finally:
            slow.close()
        self.assertEqual(self.request().body, b"ok")

    def test_connection_cycles_restore_descriptors(self):
        for _ in range(8):
            self.assertEqual(self.request(extra=b"Connection: close\r\n").body, b"ok")
        before = resource_count(self.server.pid)
        if before is None:
            self.skipTest("OS descriptor inventory unavailable")
        for _ in range(1000):
            self.assertEqual(self.request(extra=b"Connection: close\r\n").body, b"ok")
        deadline = time.monotonic() + 5; after = None
        while time.monotonic() < deadline:
            after = resource_count(self.server.pid)
            if after is not None and after <= before:
                break
            time.sleep(.05)
        self.assertIsNotNone(after)
        self.assertLessEqual(after, before, "HTTP connection cycles leaked descriptors/handles")


class OneWorker(ServerCase, NormalAcceptance, unittest.TestCase):
    workers = 1


class FourWorkers(ServerCase, NormalAcceptance, unittest.TestCase):
    workers = 4


class RawCallbackFailure(ServerCase, unittest.TestCase):
    def upgrade(self, callback):
        sock = connect(self.port)
        self.addCleanup(sock.close)
        sock.sendall(b"GET /upgrade-" + callback + b"-error HTTP/1.1\r\nHost: x\r\n"
                     b"Connection: Upgrade\r\nUpgrade: test-echo\r\n\r\n")
        reader = Reader(sock)
        self.assertEqual(reader.response().status, 101)
        sock.sendall(b"hello")
        self.assertEqual(reader.take(5), b"hello")
        return reader

    def test_write_callback_failure_closes_only_the_tunnel(self):
        reader = self.upgrade(b"written")
        reader.eof()
        self.assertEqual(self.request().body, b"ok")

    def test_timeout_callback_failure_closes_only_the_tunnel(self):
        reader = self.upgrade(b"timeout")
        reader.sock.settimeout(8)
        reader.eof()
        self.assertEqual(self.request().body, b"ok")

    def test_shutdown_callback_failure_preserves_clean_shutdown(self):
        reader = self.upgrade(b"shutdown")
        self.stop_server()
        reader.eof()


class StartupContract(unittest.TestCase):
    def test_oversized_deadlines_fail_before_binding(self):
        self.assertTrue(BINARY.is_file(), f"missing fixture: {BINARY}")
        with socket.socket() as listener:
            listener.bind((HOST, 0))
            listener.listen()
            port = listener.getsockname()[1]
            for name in ("idleTimeoutMs", "requestTimeoutMs", "writeTimeoutMs", "shutdownDrainMs",
                         "deferred.maxTimeoutMs", "http2.pingIntervalMs", "http2.pingTimeoutMs"):
                with self.subTest(timeout=name):
                    rejected = subprocess.run([str(BINARY), str(port), "bad-deadline", "1", name],
                                              capture_output=True, text=True, timeout=5)
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertIn(f"HTTP {name} exceeds native clock range", rejected.stderr)

    def test_output_credits_cover_admission_and_failure_releases_endpoint(self):
        self.assertTrue(BINARY.is_file(), f"missing fixture: {BINARY}")
        port = unused_port()
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        rejected = subprocess.run([str(BINARY), str(port), "bad-budget", "1"], capture_output=True, text=True, timeout=5, creationflags=flags)
        self.assertNotEqual(rejected.returncode, 0, "underbudget server unexpectedly started")
        self.assertIn("output buffer credits", (rejected.stdout + rejected.stderr).lower())
        with tempfile.TemporaryFile(mode="w+") as log:
            valid = subprocess.Popen([str(BINARY), str(port), "tiny", "1"], stdout=log, stderr=log, creationflags=flags)
            try:
                deadline = time.monotonic() + 5
                while True:
                    if valid.poll() is not None:
                        log.seek(0)
                        self.fail(f"valid endpoint reuse failed: {log.read()}")
                    try:
                        with connect(port) as sock:
                            sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                            reader = Reader(sock)
                            self.assertEqual(reader.response().body, b"ok")
                            reader.eof()
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(.01)
            finally:
                if valid.poll() is None:
                    valid.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
                try:
                    code = valid.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    valid.kill(); valid.wait(timeout=5)
                    self.fail("replacement server failed to join")
                if code:
                    log.seek(0)
                    self.fail(f"replacement shutdown failed: {log.read()}")


class TinyPool(ServerCase, unittest.TestCase):
    mode = "tiny"

    def test_large_binary_body_and_large_response_with_two_pool_cells(self):
        body = bytes(range(256)) * 4096
        response = self.request(b"/echo", method=b"POST", extra=b"Content-Length: 1048576\r\n", body=body)
        self.assertEqual(response.body, body)
        self.assertEqual(self.request(b"/large").body, b"A" * (2 * 1024 * 1024))
        self.assertEqual(self.request().body, b"ok")

    def test_partial_request_pause_does_not_discard_input(self):
        body = b"data" * 4096
        with connect(self.port) as sock:
            sock.sendall(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 16384\r\n\r\n" + body[:1])
            sock.settimeout(.1)
            with self.assertRaises(socket.timeout):
                sock.recv(1)
            sock.settimeout(5); sock.sendall(body[1:] + GET)
            reader = Reader(sock)
            self.assertEqual(reader.response().body, body)
            self.assertEqual(reader.response().body, b"ok")


class Deadlines(ServerCase, unittest.TestCase):
    mode = "deadlines"

    def test_idle_and_absolute_request_deadlines(self):
        with connect(self.port) as sock:
            sock.settimeout(2)
            self.assertEqual(sock.recv(1), b"")
        with connect(self.port) as sock:
            started = time.monotonic()
            sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nX: ")
            for _ in range(4):
                # Observe a ready timeout response during the trickle interval.
                # Delayed client sleeps must not hide an on-time server reply.
                if select.select([sock], [], [], .12)[0]:
                    break
                try:
                    sock.sendall(b"x")
                except OSError:
                    break
            reader = Reader(sock)
            self.assertEqual(reader.response().status, 408)
            self.assertLess(time.monotonic() - started, 1.0, "request deadline was reset by trickled input")
            try:
                reader.eof()
            except ConnectionResetError:
                # The complete 408 arrived before the deadline. Late bytes
                # already queued by this trickling peer can make TCP close
                # reset the connection while discarding that unread input.
                pass

    def test_absolute_write_deadline_survives_trickled_completions(self):
        # Four existing 2 MiB responses exceed ordinary TCP send buffers while
        # staying within the driver's declared output bounds. A single response
        # can fit entirely in an autotuned kernel send buffer on some platforms.
        response_size = 2 * 1024 * 1024
        slow = socket.socket()
        slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        slow.settimeout(1)
        slow.connect((HOST, self.port))
        with slow:
            started = time.monotonic()
            slow.sendall(b"GET /large HTTP/1.1\r\nHost: x\r\n\r\n" * 4)
            received = bytearray()
            admission_checked = False
            terminated = False
            trickle_deadline = started + 3.25
            while time.monotonic() < trickle_deadline:
                slow.settimeout(max(.001, min(.2, trickle_deadline - time.monotonic())))
                try:
                    part = slow.recv(16384)
                except socket.timeout:
                    part = None
                except ConnectionResetError:
                    self.assertGreaterEqual(time.monotonic() - started, 2.9,
                                            "blocked writer reset before its absolute deadline")
                    terminated = True
                    break
                if part == b"":
                    # Small kernel queues can finish draining during the final
                    # trickle after the configured 3s timer has already fired.
                    self.assertGreaterEqual(time.monotonic() - started, 2.9,
                                            "blocked writer closed before its absolute deadline")
                    terminated = True
                    break
                if part:
                    received.extend(part)
                    self.assertLess(len(received), response_size, "trickle consumed the entire blocked response")
                if not admission_checked and time.monotonic() - started >= .7:
                    # maxClients=1 must still be occupied before the deadline;
                    # otherwise this host did not exercise blocked native writes.
                    try:
                        with socket.create_connection((HOST, self.port), timeout=.2) as probe:
                            probe.settimeout(.15)
                            probe.sendall(GET)
                            try:
                                available = probe.recv(1)
                            except (socket.timeout, ConnectionResetError):
                                available = b""
                            self.assertFalse(available, "pipeline fit in kernel buffers; no blocked writer to test")
                    except OSError:
                        pass
                    admission_checked = True
                time.sleep(.05)
            self.assertTrue(admission_checked)
            self.assertGreater(len(received), 4096, "trickle did not permit partial write progress")
            # Check admission before draining the slow socket: progress from the
            # test's fast final reads must not be what frees the old client slot.
            health_deadline = started + 4.25
            with socket.create_connection((HOST, self.port), timeout=.7) as healthy:
                healthy.settimeout(max(.01, health_deadline - time.monotonic()))
                healthy.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                reader = Reader(healthy)
                self.assertEqual(reader.response().body, b"ok")
                reader.eof()
            self.assertLess(time.monotonic(), health_deadline,
                            "write deadline was restarted by trickled completions")
            slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
            drain_deadline = time.monotonic() + 3
            while not terminated:
                remaining = drain_deadline - time.monotonic()
                self.assertGreater(remaining, 0, "timed-out writer did not reach bounded termination")
                slow.settimeout(remaining)
                try:
                    part = slow.recv(65536)
                except ConnectionResetError:
                    self.assertGreaterEqual(time.monotonic() - started, 2.9,
                                            "writer reset before its absolute deadline")
                    terminated = True
                    break
                if not part:
                    terminated = True
                    break
                received.extend(part)
                self.assertLess(len(received), 4 * response_size,
                                "all response bodies completed despite the blocked write deadline")
            # A deadline abort may end with FIN or RST. Parse all bytes that
            # survived either termination without changing graceful EOF checks.
            class CapturedEnd:
                def recv(self, _size):
                    return b""
            reader = Reader(CapturedEnd())
            reader.buffer = received
            complete = 0
            truncated = False
            for _ in range(4):
                try:
                    response = reader.response()
                except AssertionError as error:
                    if str(error) == "premature EOF in body":
                        self.assertEqual(reader.buffer, b"A" * len(reader.buffer))
                    elif str(error) == "premature EOF before delimiter":
                        prefix = bytes(reader.buffer)
                        self.assertTrue(not prefix or b"HTTP/1.1 200 ".startswith(prefix) or
                                        prefix.startswith(b"HTTP/1.1 200 "), "invalid partial response header")
                    else:
                        raise
                    truncated = True
                    break
                self.assertEqual((response.status, response.body), (200, b"A" * response_size))
                complete += 1
            self.assertTrue(truncated, "write timeout did not truncate the blocked pipeline")
            self.assertLess(complete, 4)


class FoldPolicy(ServerCase, unittest.TestCase):
    mode = "fold"

    def test_configured_obs_fold(self):
        response = self.request(b"/fold", extra=b"X-Fold: one\r\n \ttwo\r\n")
        self.assertEqual(response.body, b"one two")


if __name__ == "__main__":
    unittest.main()
