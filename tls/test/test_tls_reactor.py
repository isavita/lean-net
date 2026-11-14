#!/usr/bin/env python3
"""Verified black-box acceptance of native reactors plus off-loop TLS.

Build lean-net-tls-reactor-fixture in the tls package first. Every client uses
the isolated CA and hostname verification. No system trust is changed, and
there is no load/soak benchmark in this suite. Each network operation and child
process has a deadline. LEAN_NET_TLS_CYCLES defaults to the 1,000-cycle gate.
"""
from collections import Counter
import hashlib
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from tls_test_support import (BINARY_BODY, HOST, NAMES, ROOT, MemoryTLSClient,
                              context, create_certificates, curl_binary,
                              openssl_binary, request, tls_socket)

sys.path.insert(0, str(ROOT / "test"))
from test_echo import unused_port
from test_http1_reactor import Reader, resource_count
from test_http2_e2e import Peer, PREFACE, frame

SUFFIX = ".exe" if sys.platform == "win32" else ""
BINARY = Path(os.environ.get("LEAN_NET_TLS_REACTOR_BIN", ROOT / f"tls/.lake/build/bin/lean-net-tls-reactor-fixture{SUFFIX}"))
HELLO = b"Hello from lean-net!\n"


def h2_headers(stream=1, path=b"/", name=NAMES[0]):
    authority = name.encode()
    assert len(path) < 127 and len(authority) < 127
    # Literal values/static names only: method GET, scheme https, path, authority.
    block = b"\x82\x87\x04" + bytes([len(path)]) + path + b"\x01" + bytes([len(authority)]) + authority
    return frame(1, 5, stream, block)


def h2_peer(port, ctx, name=NAMES[0]):
    peer = Peer.__new__(Peer)
    peer.sock = tls_socket(port, ctx, name)
    peer.buffer = b""
    try:
        if peer.sock.selected_alpn_protocol() != "h2":
            raise AssertionError("TLS did not select h2")
        peer.sock.sendall(PREFACE + frame(4))
        settings = ack = False
        for _ in range(32):
            kind, flags, stream, payload = peer.read()
            if kind == 7:
                raise AssertionError(f"GOAWAY before request: {payload.hex()}")
            if kind == 4 and stream == 0:
                if flags & 1:
                    ack = True
                else:
                    settings = True
                    peer.sock.sendall(frame(4, 1))
            if settings and ack:
                return peer
        raise AssertionError("HTTP/2 settings handshake exceeded frame budget")
    except BaseException:
        peer.close()
        raise


def reset_socket(sock):
    # Winsock uses two unsigned shorts; POSIX uses two ints.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                    struct.pack("HH" if sys.platform == "win32" else "ii", 1, 0))
    sock.close()


def process_cpu_seconds(pid):
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
        kernel.GetProcessTimes.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            creation, exit_time, system, user = (wintypes.FILETIME() for _ in range(4))
            if not kernel.GetProcessTimes(handle, creation, exit_time, system, user):
                raise ctypes.WinError(ctypes.get_last_error())
            return sum((part.dwHighDateTime << 32) | part.dwLowDateTime for part in (system, user)) / 10_000_000
        finally:
            kernel.CloseHandle(handle)
    result = subprocess.run(["ps", "-p", str(pid), "-o", "time="], capture_output=True, text=True, check=True, timeout=5)
    seconds = 0.0
    for part in result.stdout.strip().split(":"):
        seconds = seconds * 60 + float(part)
    return seconds


class ServerCase:
    mode = "normal"
    workers = 4

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.directory = tempfile.TemporaryDirectory(prefix="lean-net-native-tls-")
        try:
            cls.certificates = create_certificates(Path(cls.directory.name))
        except BaseException:
            cls.directory.cleanup()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()
        super().tearDownClass()

    def setUp(self):
        self.assertTrue(BINARY.is_file(), f"missing native TLS fixture: {BINARY}")
        self.port = unused_port()
        self.log = tempfile.TemporaryFile(mode="w+")
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        self.server = subprocess.Popen([str(BINARY), *self.certificates.fixture_arguments(), str(self.port),
                                        self.mode, str(self.workers)], stdout=self.log, stderr=self.log,
                                       creationflags=flags)
        self.addCleanup(self.log.close)
        self.addCleanup(self.stop_server)
        self.http1 = context(self.certificates)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.server.poll() is not None:
                self.log.seek(0)
                self.fail(f"native TLS startup exit {self.server.returncode}: {self.log.read()}")
            try:
                self.assertEqual(self.get().body, HELLO)
                return
            except (ConnectionError, ssl.SSLError, socket.timeout):
                time.sleep(.025)
        self.fail("native TLS fixture did not become ready")

    def stop_server(self):
        if self.server.poll() is None:
            self.server.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
            try:
                self.server.wait(timeout=6)
            except subprocess.TimeoutExpired:
                self.server.kill(); self.server.wait(timeout=5)
                self.fail("native TLS workers did not stop/join within six seconds")
        if self.server.returncode:
            self.log.seek(0)
            self.fail(f"native TLS exit {self.server.returncode}: {self.log.read()}")

    def connect(self, ctx=None, name=NAMES[0], **kwargs):
        return tls_socket(self.port, ctx or self.http1, name, **kwargs)

    def get(self, path=b"/", *, ctx=None, name=NAMES[0], method=b"GET", headers=b"", version=b"HTTP/1.1"):
        with self.connect(ctx, name) as sock:
            sock.sendall(request(path, method=method, name=name, headers=headers, version=version, close=True))
            reader = Reader(sock)
            response = reader.response(head=method == b"HEAD")
            reader.eof()
            return response

    def assert_healthy(self):
        self.assertIsNone(self.server.poll())
        reply = self.get(b"/binary")
        self.assertEqual((reply.status, reply.body), (200, BINARY_BODY))


class TLSReactorAcceptance(ServerCase, unittest.TestCase):
    def test_verified_tls12_and_tls13(self):
        self.assertTrue(ssl.HAS_TLSv1_3, "acceptance client must support TLS 1.3")
        for version, wire in ((ssl.TLSVersion.TLSv1_2, "TLSv1.2"), (ssl.TLSVersion.TLSv1_3, "TLSv1.3")):
            for name in NAMES:
                with self.subTest(version=wire, name=name):
                    with self.connect(context(self.certificates, version=version), name) as sock:
                        self.assertEqual(sock.version(), wire)
                        self.assertGreaterEqual(sock.cipher()[2], 128)
                        sock.sendall(request(b"/binary", name=name, close=True))
                        reader = Reader(sock)
                        self.assertEqual(reader.response().body, BINARY_BODY)
                        reader.eof()

    def test_alpn_preference_fallback_and_no_overlap(self):
        for protocols, selected in ((["h2", "http/1.1"], "h2"), (["http/1.1", "h2"], "h2"),
                                    (["h2"], "h2"), (["unsupported", "http/1.1"], "http/1.1"),
                                    (["http/1.1"], "http/1.1"), (None, None)):
            with self.subTest(protocols=protocols):
                ctx = context(self.certificates, protocols)
                if selected == "h2":
                    peer = h2_peer(self.port, ctx)
                    try:
                        peer.sock.sendall(h2_headers(path=b"/binary"))
                        self.assertEqual(peer.response(1), BINARY_BODY)
                    finally:
                        peer.close()
                else:
                    with self.connect(ctx) as sock:
                        self.assertEqual(sock.selected_alpn_protocol(), selected)
                        sock.sendall(request(close=True))
                        self.assertEqual(Reader(sock).response().body, HELLO)
        with self.assertRaises(ssl.SSLError):
            with self.connect(context(self.certificates, ["unsupported"])) as sock:
                sock.sendall(request()); sock.recv(1)
        self.assert_healthy()

    def test_two_sni_certificates_and_verification_failures(self):
        for index, name in enumerate(NAMES):
            with self.subTest(name=name), self.connect(name=name) as sock:
                fingerprint = hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest()
                self.assertEqual(fingerprint, self.certificates.fingerprints[index])
                sock.sendall(request(name=name, close=True))
                self.assertEqual(Reader(sock).response().body, HELLO)
        for ctx, name in ((self.http1, "unknown.test"),
                          (context(self.certificates, cafile=self.certificates.unrelated_ca), NAMES[0])):
            with self.subTest(name=name), self.assertRaises(ssl.SSLError):
                self.connect(ctx, name).close()
        self.assert_healthy()

    def test_obsolete_protocol_handshakes_are_rejected_by_server(self):
        # s_client can refuse obsolete protocols locally under its default
        # security policy. Lower only the CLIENT policy, and require an actual
        # received server alert rather than accepting an arbitrary nonzero exit.
        for flag in ("-tls1", "-tls1_1"):
            with self.subTest(flag=flag):
                command = [openssl_binary(), "s_client", "-connect", f"{HOST}:{self.port}",
                           "-servername", NAMES[0], flag, "-cipher", "ALL:@SECLEVEL=0",
                           "-CAfile", str(self.certificates.ca), "-verify_return_error", "-verify_hostname", NAMES[0]]
                result = subprocess.run(command, input=b"", capture_output=True, timeout=8)
                self.assertNotEqual(result.returncode, 0)
                diagnostic = result.stderr.lower()
                self.assertTrue(b"alert protocol version" in diagnostic or b"alert number 70" in diagnostic,
                                f"no server protocol-version alert; client limitation is not evidence: {result.stderr!r}")
        self.assert_healthy()

    def test_verified_curl_same_route_http10_http11_h2(self):
        curl = curl_binary()
        version = subprocess.run([curl, "--version"], capture_output=True, text=True, timeout=5, check=True)
        self.assertIn("HTTP2", version.stdout, f"acceptance curl lacks HTTP/2: {curl}")
        for name in NAMES:
            for flag, wire in (("--http1.0", b"1"), ("--http1.1", b"1.1"), ("--http2", b"2")):
                with self.subTest(name=name, flag=flag):
                    command = [curl, flag, "--noproxy", "*", "--fail", "--silent", "--show-error",
                               "--cacert", str(self.certificates.ca), "--resolve", f"{name}:{self.port}:{HOST}",
                               "--write-out", "\nHTTP_VERSION:%{http_version}", f"https://{name}:{self.port}/binary"]
                    result = subprocess.run(command, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                    self.assertEqual(result.stdout, BINARY_BODY + b"\nHTTP_VERSION:" + wire)

    def test_negotiated_protocol_cannot_switch(self):
        with self.connect() as sock:
            sock.sendall(PREFACE + frame(4))
            try: data = sock.recv(1024)
            except ssl.SSLError: data = b""
            self.assertFalse(len(data) >= 4 and data[3] == 4)
        with self.connect(context(self.certificates, ["h2"])) as sock:
            sock.sendall(request())
            try: data = sock.recv(1024)
            except ssl.SSLError: data = b""
            self.assertFalse(data.startswith(b"HTTP/1.1 200"))
        self.assert_healthy()

    def test_fragmented_handshake_and_tls_records(self):
        client = MemoryTLSClient(self.port, self.http1, fragment=1)
        self.addCleanup(client.close)
        payload = bytes(range(256)) * 16 + b"\x00\xff"
        client.engine.write(request(b"/echo", method=b"POST", headers=f"Content-Length: {len(payload)}\r\n".encode(), body=payload))
        client.drain(fragment=3)
        reader = Reader(client)
        self.assertEqual(reader.response().body, payload)
        for _ in range(40):
            client.engine.write(request(b"/binary"))
        client.drain()
        for _ in range(40):
            self.assertEqual(reader.response().body, BINARY_BODY)

    def test_partial_application_record_waits_without_busy_spin(self):
        client = MemoryTLSClient(self.port, self.http1)
        self.addCleanup(client.close)
        client.engine.write(request(b"/binary"))
        encrypted = client.outgoing.read()
        self.assertGreater(len(encrypted), 6)
        client.raw.sendall(encrypted[:6])
        time.sleep(.1)
        before = process_cpu_seconds(self.server.pid)
        time.sleep(.7)
        used = process_cpu_seconds(self.server.pid) - before
        self.assertLess(used, .3, f"partial record used {used:.2f}s CPU while stalled")
        self.assert_healthy()
        client.raw.sendall(encrypted[6:])
        self.assertEqual(Reader(client).response().body, BINARY_BODY)

    def test_expect_continue_barrier_and_buffered_refusal(self):
        head = request(b"/echo", method=b"POST", headers=b"Content-Length: 4\r\nExpect: 100-continue\r\n")
        with self.connect() as sock:
            sock.sendall(head)
            reader = Reader(sock)
            self.assertEqual(reader.response().status, 100)
            sock.sendall(b"data" + request(b"/binary"))
            self.assertEqual(reader.response().body, b"data")
            self.assertEqual(reader.response().body, BINARY_BODY)
        with self.connect() as sock:
            sock.sendall(request(b"/refuse", method=b"POST", headers=b"Content-Length: 4\r\nExpect: 100-continue\r\n",
                                 body=b"data" + request()))
            reader = Reader(sock)
            self.assertEqual((reader.response().status), 417)
            reader.eof()

    def test_http_framing_status_pipeline_and_metadata(self):
        with self.connect() as sock:
            sock.sendall(request(b"/head", method=b"HEAD") + request(b"/204") + request(b"/304") +
                         request(b"/custom") + request(b"/chunked", close=True))
            reader = Reader(sock)
            head = reader.response(head=True)
            self.assertEqual(head.headers[b"content-length"], b"14")
            self.assertEqual(reader.response().status, 204)
            self.assertEqual(reader.response().status, 304)
            custom = reader.response()
            self.assertEqual((custom.status, custom.reason, custom.body), (299, b"Custom Ready", b"ready"))
            chunked = reader.response()
            self.assertEqual((chunked.body, chunked.trailers), (BINARY_BODY, {b"x-finished": b"yes"}))
            reader.eof()
        with self.connect() as sock:
            sock.sendall(request(b"/informational", close=True))
            reader = Reader(sock)
            self.assertEqual([reader.response().status for _ in range(3)], [103, 102, 200])
            reader.eof()
        invalid = self.get(b"/invalid")
        self.assertEqual(invalid.status, 500)
        self.assertNotIn(b"injected", invalid.headers)

    def test_ten_pipelined_requests_and_tls_eof(self):
        client = MemoryTLSClient(self.port, self.http1)
        self.addCleanup(client.close)
        client.sendall(request(b"/binary") * 10)
        client.send_close_notify()
        reader = Reader(client)
        for _ in range(10):
            self.assertEqual(reader.response().body, BINARY_BODY)
        reader.eof()

    def test_http10_persistence_and_chunked_rejection(self):
        with self.connect() as sock:
            reader = Reader(sock)
            for _ in range(3):
                sock.sendall(request(b"/binary", version=b"HTTP/1.0", headers=b"Connection: keep-alive\r\n"))
                response = reader.response()
                self.assertEqual((response.version, response.body), (b"HTTP/1.0", BINARY_BODY))
                self.assertEqual(response.headers[b"connection"], b"keep-alive")
            sock.sendall(request(b"/binary", version=b"HTTP/1.0"))
            self.assertEqual(reader.response().body, BINARY_BODY)
            reader.eof()
        with self.connect() as sock:
            sock.sendall(request(b"/echo", method=b"POST", version=b"HTTP/1.0", headers=b"Transfer-Encoding: chunked\r\n", body=b"0\r\n\r\n"))
            reader = Reader(sock)
            self.assertEqual(reader.response().status, 400)
            reader.eof()

    def test_request_trailers_and_close_delimited_response(self):
        with self.connect() as sock:
            sock.sendall(request(b"/trailers", method=b"POST", headers=b"Transfer-Encoding: chunked\r\nTrailer: X-Check\r\n",
                                 body=b"3\r\na\x00b\r\n2\r\n\xffc\r\n0\r\nX-Check: yes\r\n\r\n") + request(b"/close"))
            reader = Reader(sock)
            self.assertEqual(reader.response().body, b"a\x00b\xffc|yes")
            closed = reader.response()
            self.assertEqual(closed.body, BINARY_BODY)
            self.assertEqual(closed.headers[b"connection"], b"close")
            self.assertNotIn(b"content-length", closed.headers)
            self.assertNotIn(b"transfer-encoding", closed.headers)
            reader.eof()

    def test_opt_in_http10_eof_body_is_not_parsed_as_pipeline(self):
        client = MemoryTLSClient(self.port, self.http1)
        self.addCleanup(client.close)
        payload = b"body\x00\xff\r\nGET /binary HTTP/1.1\r\nHost: alpha.test\r\n\r\n"
        client.sendall(request(b"/legacy", method=b"POST", version=b"HTTP/1.0", body=payload))
        client.send_close_notify()
        reader = Reader(client)
        self.assertEqual(reader.response().body, payload)
        reader.eof()

    def test_upgrade_raw_tail_and_early_tls_close_notify(self):
        for tail in (b"", b"early\x00raw\xff"):
            with self.subTest(tail=tail):
                client = MemoryTLSClient(self.port, self.http1)
                try:
                    client.sendall(request(b"/upgrade", headers=b"Connection: Upgrade\r\nUpgrade: test-echo\r\n", body=tail))
                    # close_notify arrives before the client reads 101. The driver
                    # must retain EOF across the protocol ownership transition.
                    client.send_close_notify()
                    reader = Reader(client)
                    self.assertEqual(reader.response().status, 101)
                    self.assertEqual(reader.take(len(tail) + 7), tail + b"raw-eof")
                    reader.eof()
                finally:
                    client.close()

    def test_raw_upgrade_held_views_and_blocked_writes_allow_same_worker_progress(self):
        client = MemoryTLSClient(self.port, self.http1)
        client.raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        sender = None
        errors = []
        # Every 4K block differs, so premature reuse of a borrowed plaintext
        # cell cannot hide behind identical repeated wire data.
        payload = b"".join(struct.pack(">I", block) + bytes([(block * 17) & 255]) * 4092
                           for block in range(256))
        try:
            client.raw.settimeout(10)
            client.sendall(request(b"/upgrade", headers=b"Connection: Upgrade\r\nUpgrade: test-echo\r\n"))
            reader = Reader(client)
            response = reader.response()
            self.assertEqual(response.status, 101)
            owner = int(response.headers[b"x-worker"])
            offset = 0
            while offset < len(payload):
                offset += client.engine.write(payload[offset:])
            encrypted = client.outgoing.read()
            def send_raw():
                # The helper thread transports pre-encrypted bytes only. It
                # never touches the SSLObject; concurrent SSL_read/SSL_write on
                # the same client SSL object would invalidate this test.
                try:
                    with client.write_lock:
                        client.raw.sendall(encrypted)
                except BaseException as error: errors.append(error)
            sender = threading.Thread(target=send_raw, daemon=True)
            sender.start()
            # Retain the raw echo views while ciphertext backs up behind this
            # small receive window, then exercise a second session on the same
            # reactor/TLS worker rather than relying on another core to help.
            time.sleep(.15)
            matched = False
            for _ in range(256):
                reply = self.get(b"/worker")
                if int(reply.body) == owner:
                    matched = True; break
            self.assertTrue(matched, "no healthy connection reached the blocked peer's worker")
            self.assertEqual(reader.take(len(payload)), payload)
            sender.join(timeout=5)
            self.assertFalse(sender.is_alive(), "raw sender did not finish after output resumed")
            self.assertEqual(errors, [])
        finally:
            client.close()
            if sender is not None:
                sender.join(timeout=5)

    def test_underfunded_tls_pool_rejected_and_endpoint_reusable(self):
        port = unused_port()
        command = [str(BINARY), *self.certificates.fixture_arguments(), str(port), "bad-budget", "1"]
        result = subprocess.run(command, capture_output=True, timeout=8)
        self.assertNotEqual(result.returncode, 0, "three-cell TLS pool accepted without independent plaintext credit")
        self.assertTrue(b"credit" in (result.stdout + result.stderr).lower() or
                        b"buffer" in (result.stdout + result.stderr).lower(), result.stdout + result.stderr)
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        with tempfile.TemporaryFile(mode="w+") as log:
            replacement = subprocess.Popen([str(BINARY), *self.certificates.fixture_arguments(), str(port), "tiny", "1"],
                                           stdout=log, stderr=log, creationflags=flags)
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if replacement.poll() is not None:
                        log.seek(0); self.fail(f"valid TLS endpoint reuse failed: {log.read()}")
                    try:
                        with tls_socket(port, self.http1) as sock:
                            sock.sendall(request(b"/binary", close=True))
                            reader = Reader(sock)
                            self.assertEqual(reader.response().body, BINARY_BODY)
                            reader.eof()
                            break
                    except (ConnectionError, ssl.SSLError, socket.timeout):
                        time.sleep(.025)
                else:
                    self.fail("valid TLS server failed to reuse rejected configuration's endpoint")
            finally:
                if replacement.poll() is None:
                    replacement.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
                    try: replacement.wait(timeout=6)
                    except subprocess.TimeoutExpired:
                        replacement.kill(); replacement.wait(timeout=3)
                        self.fail("replacement TLS fixture did not stop")
                self.assertEqual(replacement.returncode, 0)

    def test_slow_handshake_reader_and_resets_isolate_other_peers(self):
        slow = socket.create_connection((HOST, self.port), timeout=3)
        reader_peer = self.connect(receive_buffer=4096)
        try:
            slow.sendall(b"\x16")
            reader_peer.sendall(request(b"/large"))
            time.sleep(.1)
            self.assert_healthy()
            reset_socket(reader_peer)
            reset_socket(slow)
            self.assert_healthy()
        finally:
            reader_peer.close(); slow.close()
        for content in (b"not tls", b"\x16\x03\x03\x00\x20\x00"):
            with socket.create_connection((HOST, self.port), timeout=3) as raw:
                raw.sendall(content)
                reset_socket(raw)
        self.assert_healthy()

    def test_large_response_exact_after_slow_reader(self):
        with self.connect(receive_buffer=16384) as sock:
            sock.settimeout(15)
            sock.sendall(request(b"/large", close=True))
            time.sleep(.1)
            reader = Reader(sock)
            self.assertEqual(reader.response().body, b"A" * (2 * 1024 * 1024))
            reader.eof()

    def test_all_workers_serve_verified_connections(self):
        counts = Counter()
        # Linux hashes new TCP connections. Handoff platforms skip full worker
        # queues, so real server dispatch need not produce equal counts there
        # either; available-capacity RR is covered by controlled native tests.
        total = 256 if sys.platform.startswith("linux") else 32
        for _ in range(total):
            reply = self.get(b"/worker")
            self.assertEqual(reply.headers[b"x-worker"], reply.body)
            counts[int(reply.body)] += 1
        self.assertEqual(set(counts), set(range(self.workers)), counts)
        self.assertEqual(sum(counts.values()), total)
        print("TLS worker counts:", dict(sorted(counts.items())), flush=True)

    def test_all_workers_execute_ssl_off_loop_with_exclusive_ownership(self):
        observed = set()
        for _ in range(256):
            reply = self.get(b"/stats")
            self.assertEqual(reply.headers[b"x-worker"], reply.body)
            observed.add(int(reply.body))
            self.assertGreater(int(reply.headers[b"x-ssl-calls"]), 0)
            self.assertEqual(int(reply.headers[b"x-owner-violations"]), 0)
            self.assertEqual(int(reply.headers[b"x-active-tls-threads"]), 1)
            if observed == set(range(self.workers)):
                break
        self.assertEqual(observed, set(range(self.workers)))

    def test_thousand_cycles_and_aborts_release_resources(self):
        cycles = int(os.environ.get("LEAN_NET_TLS_CYCLES", "1000"))
        self.assertGreaterEqual(cycles, 1)
        contexts = [context(self.certificates, version=version) for version in
                    (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)]
        for _ in range(8):
            self.get(b"/binary")
        time.sleep(.15)
        baseline = resource_count(self.server.pid)
        for index in range(cycles):
            response = self.get(b"/binary", ctx=contexts[index % 2], name=NAMES[index % 2])
            self.assertEqual(response.body, BINARY_BODY)
        for index in range(100):
            raw = socket.create_connection((HOST, self.port), timeout=3)
            raw.sendall(b"\x16" if index % 2 else b"not tls")
            reset_socket(raw)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            observed = resource_count(self.server.pid)
            if observed <= baseline:
                break
            time.sleep(.05)
        self.assertLessEqual(observed, baseline, f"resource count grew {baseline} -> {observed}")
        self.assert_healthy()

    def test_shutdown_joins_active_and_blocked_tls_workers(self):
        slow = socket.create_connection((HOST, self.port), timeout=3)
        peers = [self.connect(receive_buffer=4096) for _ in range(5)]
        try:
            slow.sendall(b"\x16")
            peers[0].sendall(request(b"/large"))
            peers[1].sendall(b"GET / HTTP/1.1\r\nHost: alpha")
            start = time.monotonic()
            self.stop_server()
            self.assertLess(time.monotonic() - start, 6)
            # Reuse through a new fixture, not SO_REUSEADDR alone: verifies the
            # process endpoint claim was released as well as the listen socket.
            command = [str(BINARY), *self.certificates.fixture_arguments(), str(self.port), "normal", "1"]
            flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
            replacement = subprocess.Popen(command, stdout=self.log, stderr=self.log, creationflags=flags)
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if replacement.poll() is not None:
                        self.fail("replacement TLS server failed after endpoint release")
                    try:
                        with self.connect() as sock:
                            sock.sendall(request(close=True))
                            self.assertEqual(Reader(sock).response().body, HELLO)
                            break
                    except (ConnectionError, ssl.SSLError, socket.timeout):
                        time.sleep(.025)
                else:
                    self.fail("replacement TLS server never became ready")
            finally:
                if replacement.poll() is None:
                    replacement.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
                    replacement.wait(timeout=6)
                self.assertEqual(replacement.returncode, 0)
        finally:
            for sock in peers: sock.close()
            slow.close()

    def test_immediate_shutdown_after_verified_handshakes_sends_close_notify(self):
        # Client wrap_socket can return before the server reactor has observed
        # the TLS worker's wire-fenced READY. Do not send HTTP or add a delay:
        # shutdown must finish those accepted handshakes before close_notify.
        peers = []
        try:
            for _ in range(8):
                peers.append(self.connect())
            started = time.monotonic()
            self.stop_server()
            self.assertLess(time.monotonic() - started, 4,
                            "immediate TLS shutdown exceeded the bounded stop interval")
            for index, sock in enumerate(peers):
                with self.subTest(client=index):
                    # suppress_ragged_eofs=False makes missing close_notify an
                    # SSLEOFError instead of silently accepting a TCP EOF.
                    self.assertEqual(sock.recv(1), b"")
        finally:
            for sock in peers:
                sock.close()


class TLSReactorTiny(ServerCase, unittest.TestCase):
    mode = "tiny"
    workers = 1

    def test_bounded_queues_preserve_large_binary_pipeline(self):
        payload = b"".join(struct.pack(">I", block) + bytes([(block * 29) & 255]) * 4092
                           for block in range(64)) + b"\x00\xff"
        with self.connect() as sock:
            sock.settimeout(15)
            sock.sendall(request(b"/echo", method=b"POST", headers=f"Content-Length: {len(payload)}\r\n".encode(), body=payload) +
                         request(b"/large") + request(b"/binary", close=True))
            time.sleep(.1)
            reader = Reader(sock)
            self.assertEqual(reader.response().body, payload)
            self.assertEqual(reader.response().body, b"A" * (2 * 1024 * 1024))
            self.assertEqual(reader.response().body, BINARY_BODY)
            reader.eof()


class TLSReactorQueue3(TLSReactorTiny):
    mode = "queue3"


class TLSReactorDeadlines(ServerCase, unittest.TestCase):
    mode = "deadlines"

    def test_absolute_handshake_deadline_under_clienthello_trickle(self):
        inbound, outbound = ssl.MemoryBIO(), ssl.MemoryBIO()
        engine = self.http1.wrap_bio(inbound, outbound, server_side=False, server_hostname=NAMES[0])
        with self.assertRaises(ssl.SSLWantReadError):
            engine.do_handshake()
        hello = outbound.read()
        self.assertGreater(len(hello), 100)
        with socket.create_connection((HOST, self.port), timeout=2) as slow:
            start = time.monotonic()
            stopped = False
            for byte in hello[:32]:
                try:
                    slow.sendall(bytes([byte]))
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    stopped = True; break
                time.sleep(.04)
            if not stopped:
                slow.settimeout(2)
                try: self.assertEqual(slow.recv(1), b"")
                except (ConnectionResetError, ConnectionAbortedError): pass
            self.assertLess(time.monotonic() - start, 2.5)
        self.assert_healthy()

    def test_request_deadline_after_continue(self):
        with self.connect() as sock:
            sock.sendall(request(b"/echo", method=b"POST", headers=b"Content-Length: 4\r\nExpect: 100-continue\r\n"))
            reader = Reader(sock)
            self.assertEqual(reader.response().status, 100)
            self.assertEqual(reader.response().status, 408)
            reader.eof()
        self.assert_healthy()


class ResumptionMixin:
    def resume(self, version, *, tickets):
        ctx = context(self.certificates, version=version, tickets=tickets)
        with self.connect(ctx) as sock:
            sock.sendall(request(b"/worker"))
            response = Reader(sock).response()
            initial_worker = int(response.body)
            # Receiving application data processes TLS 1.3 NewSessionTicket.
            session = sock.session
            self.assertFalse(sock.session_reused)
            if tickets:
                self.assertTrue(session.has_ticket, "application read did not capture a session ticket")
            else:
                self.assertFalse(session.has_ticket)
            sock.sendall(request(close=True))
            reader = Reader(sock)
            self.assertEqual(reader.response().body, HELLO)
            reader.eof()
        workers = set()
        resumed = 0
        for _ in range(64):
            with self.connect(ctx, session=session) as sock:
                sock.sendall(request(b"/worker"))
                response = Reader(sock).response()
                worker = int(response.body)
                self.assertEqual(response.headers[b"x-worker"], response.body)
                workers.add(worker)
                self.assertTrue(sock.session_reused, f"resumption failed on worker {worker}; first {initial_worker}")
                resumed += 1
                session = sock.session
                sock.sendall(request(close=True))
                reader = Reader(sock)
                self.assertEqual(reader.response().body, HELLO)
                reader.eof()
            if len(workers | {initial_worker}) == self.workers:
                break
        self.assertEqual(workers | {initial_worker}, set(range(self.workers)), workers)
        self.assertGreater(resumed, 0)


class TLSReactorTickets(ResumptionMixin, ServerCase, unittest.TestCase):
    def test_tls12_ticket_resume_across_workers(self):
        self.resume(ssl.TLSVersion.TLSv1_2, tickets=True)

    def test_tls13_ticket_resume_across_workers(self):
        self.resume(ssl.TLSVersion.TLSv1_3, tickets=True)

    def test_sni_change_cannot_resume_another_hosts_identity(self):
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            with self.subTest(version=version):
                ctx = context(self.certificates, version=version)
                with self.connect(ctx, NAMES[0]) as first:
                    first.sendall(request(b"/binary", close=True))
                    reader = Reader(first)
                    self.assertEqual(reader.response().body, BINARY_BODY)
                    reader.eof()
                    session = first.session
                with self.connect(ctx, NAMES[1], session=session) as second:
                    self.assertFalse(second.session_reused, "alpha session resumed under beta SNI")
                    fingerprint = hashlib.sha256(second.getpeercert(binary_form=True)).hexdigest()
                    self.assertEqual(fingerprint, self.certificates.fingerprints[1])
                    second.sendall(request(b"/binary", name=NAMES[1], close=True))
                    self.assertEqual(Reader(second).response().body, BINARY_BODY)

    def test_alpn_change_selects_current_connection_protocol(self):
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            with self.subTest(version=version):
                ctx = context(self.certificates, version=version)
                with self.connect(ctx) as first:
                    first.sendall(request(b"/binary", close=True))
                    reader = Reader(first)
                    self.assertEqual(reader.response().body, BINARY_BODY)
                    reader.eof()
                    session = first.session
                ctx.set_alpn_protocols(["h2"])
                # Ordinary resumption may succeed or fall back; the negotiated
                # protocol and protocol-machine dispatch must describe this
                # connection rather than the old HTTP/1.1 session.
                peer = Peer.__new__(Peer)
                peer.sock = self.connect(ctx, session=session)
                peer.buffer = b""
                try:
                    self.assertEqual(peer.sock.selected_alpn_protocol(), "h2")
                    peer.sock.sendall(PREFACE + frame(4))
                    settings = ack = False
                    for _ in range(32):
                        kind, flags, stream, payload = peer.read()
                        self.assertNotEqual(kind, 7, f"GOAWAY after ALPN change: {payload.hex()}")
                        if kind == 4 and stream == 0:
                            if flags & 1: ack = True
                            else:
                                settings = True
                                peer.sock.sendall(frame(4, 1))
                        if settings and ack: break
                    self.assertTrue(settings and ack)
                    peer.sock.sendall(h2_headers(path=b"/binary"))
                    self.assertEqual(peer.response(1), BINARY_BODY)
                finally:
                    peer.close()


class TLSReactorSessionCache(ResumptionMixin, ServerCase, unittest.TestCase):
    mode = "cache-only"

    def test_tls12_cache_only_resume_across_workers(self):
        self.resume(ssl.TLSVersion.TLSv1_2, tickets=False)

    def test_openssl_verified_reconnect(self):
        command = [openssl_binary(), "s_client", "-connect", f"{HOST}:{self.port}", "-servername", NAMES[0],
                   "-verify_hostname", NAMES[0], "-verify_return_error", "-CAfile", str(self.certificates.ca),
                   "-tls1_2", "-no_ticket", "-alpn", "http/1.1", "-reconnect"]
        result = subprocess.run(command, input=b"", capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stdout.count(b"Reused, TLSv1.2"), 5, result.stdout[-5000:])
        self.assertIn(b"Verify return code: 0 (ok)", result.stdout)


if __name__ == "__main__":
    unittest.main()
