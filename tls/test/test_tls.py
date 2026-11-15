#!/usr/bin/env python3
"""TLS end-to-end tests with an ephemeral CA; never touch the system trust store.

Run after building the separate tls package. OpenSSL, curl with HTTP/2 support,
and Python's ssl module are required for the corresponding client tests.
"""
import os
import select
from pathlib import Path
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test"))
from test_echo import fd_count, recv_exact, unused_port
from test_http1_server import HELLO, HttpReader
from test_http2_e2e import Peer, PREFACE, frame, window

BINARY = Path(os.environ.get("LEAN_NET_TLS_BIN", ROOT / "tls/.lake/build/bin/lean-net-tls"))
FIXTURE = ROOT / "tls/.lake/build/bin/lean-net-tls-fixture"
INTERRUPTIBLE = ROOT / "tls/.lake/build/bin/lean-net-tls-interruptible-test"


def find_openssl():
    try:
        result = subprocess.run(["pkg-config", "--variable=prefix", "openssl"],
                                capture_output=True, text=True, check=True)
        candidate = Path(result.stdout.strip()) / "bin/openssl"
        if result.stdout.strip() and candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    except (OSError, subprocess.CalledProcessError):
        pass
    return shutil.which("openssl") or "openssl"


OPENSSL = find_openssl()


def supports_hostname_verification():
    result = subprocess.run([OPENSSL, "s_client", "-help"], capture_output=True, text=True)
    return "-verify_hostname" in result.stdout + result.stderr


def run_openssl(*args):
    return subprocess.run([OPENSSL, *map(str, args)], check=True, capture_output=True)


def create_certificates(directory):
    ca_key, ca_cert = directory / "ca.key", directory / "ca.pem"
    key, csr, cert = directory / "server.key", directory / "server.csr", directory / "server.pem"
    other_key, other_cert = directory / "other.key", directory / "other.pem"
    extensions = directory / "server.ext"
    extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                          "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
    run_openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", ca_key, "-out", ca_cert,
                "-days", "1", "-subj", "/CN=lean-net test CA", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run_openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr,
                "-subj", "/CN=localhost")
    run_openssl("x509", "-req", "-in", csr, "-CA", ca_cert, "-CAkey", ca_key,
                "-CAcreateserial", "-out", cert, "-days", "1", "-extfile", extensions)
    run_openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", other_key,
                "-out", other_cert, "-days", "1", "-subj", "/CN=unrelated test CA")
    return ca_cert, cert, key, other_cert, other_key


def context(cafile, protocols=None):
    ctx = ssl.create_default_context(cafile=str(cafile))
    if protocols is not None:
        ctx.set_alpn_protocols(protocols)
    return ctx


def tls_socket(port, ctx, name="localhost", receive_buffer=None):
    raw = socket.socket()
    if receive_buffer is not None:
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, receive_buffer)
    raw.settimeout(3)
    try:
        raw.connect(("127.0.0.1", port))
        return ctx.wrap_socket(raw, server_hostname=name, suppress_ragged_eofs=False)
    except BaseException:
        raw.close()
        raise


class MemoryTLSClient:
    """Verified TLS client that can control exact ciphertext write boundaries."""
    def __init__(self, port, ctx):
        self.raw = socket.create_connection(("127.0.0.1", port), timeout=3)
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.engine = ctx.wrap_bio(self.incoming, self.outgoing, server_side=False,
                                   server_hostname="localhost")
        while True:
            try:
                self.engine.do_handshake()
                self.flush()
                break
            except ssl.SSLWantReadError:
                self.flush()
                encrypted = self.raw.recv(16384)
                if not encrypted:
                    raise EOFError("TLS handshake ended prematurely")
                self.incoming.write(encrypted)

    def flush(self):
        data = self.outgoing.read()
        if data:
            self.raw.sendall(data)

    def recv(self, size):
        while True:
            try:
                return self.engine.read(size)
            except ssl.SSLWantReadError:
                self.flush()
                encrypted = self.raw.recv(16384)
                if not encrypted:
                    self.incoming.write_eof()
                else:
                    self.incoming.write(encrypted)

    def close(self):
        self.raw.close()


def process_cpu_seconds(pid):
    result = subprocess.run(["ps", "-p", str(pid), "-o", "time="], capture_output=True, text=True, check=True)
    parts = result.stdout.strip().split(":")
    value = 0.0
    for part in parts:
        value = value * 60 + float(part)
    return value


def h2_peer(port, ctx, receive_buffer=None):
    peer = Peer.__new__(Peer)
    peer.sock = tls_socket(port, ctx, receive_buffer=receive_buffer)
    if peer.sock.selected_alpn_protocol() != "h2":
        peer.sock.close()
        raise AssertionError("server did not negotiate h2")
    peer.buffer = b""
    peer.sock.sendall(PREFACE + frame(4))
    settings = ack = False
    while not (settings and ack):
        kind, flags, stream, payload = peer.read()
        if kind == 7:
            raise AssertionError(f"unexpected GOAWAY during handshake: {payload.hex()}")
        if kind == 4 and stream == 0:
            if flags & 1:
                ack = True
            else:
                settings = True
                peer.sock.sendall(frame(4, 1))
    return peer


def h2_get(stream=1, path=b"/"):
    # GET, https, :path and :authority, encoded without dynamic state.
    assert len(path) < 127
    path_field = b"\x84" if path == b"/" else b"\x04" + bytes([len(path)]) + path
    return frame(1, 5, stream, b"\x82\x87" + path_field + b"\x01\x09localhost")


class TLSAcceptance(unittest.TestCase):
    binary = BINARY
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="lean-net-tls-test-")
        cls.ca, cls.cert, cls.key, cls.other_ca, cls.other_key = create_certificates(Path(cls.temp.name))
        cls.valid_context = context(cls.ca, ["h2", "http/1.1"])
        cls.http1_context = context(cls.ca, ["http/1.1"])

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        if not self.binary.is_file():
            self.fail(f"TLS executable not found: {self.binary}; build the tls package")
        self.port = unused_port()
        self.log = tempfile.TemporaryFile(mode="w+")
        self.server = subprocess.Popen([str(self.binary), str(self.cert), str(self.key), str(self.port),
                                        *getattr(self, "extra_args", [])],
                                       stdout=self.log, stderr=self.log)
        self.addCleanup(self.log.close)
        self.addCleanup(self.stop_server)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.server.poll() is not None:
                self.log.seek(0)
                self.fail(f"server failed to start: {self.log.read()}")
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.1).close()
                return
            except OSError:
                time.sleep(0.02)
        self.fail("TLS server did not listen")

    def stop_server(self):
        if self.server.poll() is None:
            self.server.send_signal(signal.SIGINT)
            try:
                self.server.wait(timeout=4)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait(timeout=3)
                self.fail("TLS server did not stop after SIGINT")

    def get_http1(self):
        with tls_socket(self.port, self.http1_context) as sock:
            self.assertEqual(sock.selected_alpn_protocol(), "http/1.1")
            sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            return HttpReader(sock).response()

    def test_curl_verified_http1_and_h2(self):
        for option, version in (("--http1.1", b"1.1"), ("--http2", b"2")):
            with self.subTest(version=version):
                cmd = ["curl", option, "--noproxy", "*", "--fail", "--silent", "--show-error",
                       "--cacert", str(self.ca), "--resolve", f"localhost:{self.port}:127.0.0.1",
                       "--write-out", "\\nHTTP_VERSION:%{http_version}", f"https://localhost:{self.port}/"]
                result = subprocess.run(cmd, capture_output=True, timeout=8)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                self.assertEqual(result.stdout, HELLO + b"\nHTTP_VERSION:" + version)

    def test_openssl_verified_alpn_h2(self):
        if not supports_hostname_verification():
            self.skipTest(f"{OPENSSL} s_client lacks -verify_hostname; verified curl/Python tests cover hostname")
        result = subprocess.run([OPENSSL, "s_client", "-connect", f"127.0.0.1:{self.port}",
                                 "-servername", "localhost", "-verify_hostname", "localhost",
                                 "-verify_return_error", "-CAfile", str(self.ca), "-alpn", "h2"],
                                input=b"", capture_output=True, timeout=6)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertIn(b"ALPN protocol: h2", result.stdout)
        self.assertIn(b"Verify return code: 0 (ok)", result.stdout)

    def test_verified_tls_and_no_alpn_fallback(self):
        with tls_socket(self.port, context(self.ca)) as sock:
            self.assertIsNone(sock.selected_alpn_protocol())
            sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            self.assertEqual(HttpReader(sock).response()[::2], (200, HELLO))

    def test_verified_h2_and_http1_concurrently(self):
        peer = h2_peer(self.port, self.valid_context)
        self.addCleanup(peer.close)
        self.assertEqual(self.get_http1()[::2], (200, HELLO))
        peer.sock.sendall(h2_get())
        self.assertEqual(peer.response(1), HELLO)

    def test_no_alpn_overlap_is_fatal(self):
        unsupported = context(self.ca, ["not-a-supported-protocol"])
        with self.assertRaises(ssl.SSLError):
            with tls_socket(self.port, unsupported) as sock:
                # TLS 1.3 may deliver a fatal alert only on the first I/O.
                sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                sock.recv(1)
        self.assertEqual(self.get_http1()[::2], (200, HELLO))

    def test_orderly_tls_close_notify(self):
        with tls_socket(self.port, self.http1_context) as sock:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            self.assertEqual(HttpReader(sock).response()[::2], (200, HELLO))
            # suppress_ragged_eofs=False makes a TCP EOF without close_notify an error.
            self.assertEqual(sock.recv(1), b"")
        if not supports_hostname_verification():
            self.skipTest(f"{OPENSSL} s_client lacks -verify_hostname; verified curl/Python tests cover hostname")
        result = subprocess.run([OPENSSL, "s_client", "-quiet", "-connect", f"127.0.0.1:{self.port}",
                                 "-servername", "localhost", "-verify_hostname", "localhost",
                                 "-verify_return_error", "-CAfile", str(self.ca), "-alpn", "http/1.1"],
                                input=b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                                capture_output=True, timeout=6)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertIn(b"HTTP/1.1 200", result.stdout)
        self.assertTrue(result.stdout.endswith(HELLO))

    def test_certificate_and_hostname_verification_failures_do_not_kill_server(self):
        for ctx, host in ((context(self.other_ca), "localhost"), (context(self.ca), "wrong.example")):
            with self.subTest(host=host), self.assertRaises(ssl.SSLCertVerificationError):
                with tls_socket(self.port, ctx, host):
                    pass
        self.assertIsNone(self.server.poll())
        self.assertEqual(self.get_http1()[::2], (200, HELLO))

    def test_slow_handshake_and_peer_abort_do_not_block_other_clients(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as slow:
            slow.sendall(b"\x16")
            self.assertEqual(self.get_http1()[::2], (200, HELLO))
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as bad:
            bad.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            bad.sendall(b"not a TLS handshake")
        self.assertEqual(self.get_http1()[::2], (200, HELLO))

    def test_negotiated_protocol_is_not_silently_switched(self):
        with tls_socket(self.port, self.http1_context) as sock:
            sock.sendall(PREFACE + frame(4))
            try:
                data = sock.recv(1024)
            except ssl.SSLError:
                data = b""
            self.assertFalse(len(data) >= 4 and data[3] == 4, "h2 selected after http/1.1 ALPN")
        with tls_socket(self.port, context(self.ca, ["h2"])) as sock:
            self.assertEqual(sock.selected_alpn_protocol(), "h2")
            sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            try:
                data = sock.recv(1024)
            except ssl.SSLError:
                data = b""
            self.assertFalse(data.startswith(b"HTTP/1.1 200"), "HTTP/1 served after h2 ALPN")
        self.assertEqual(self.get_http1()[::2], (200, HELLO))

    def test_fragmented_http1_inside_tls(self):
        with tls_socket(self.port, self.http1_context) as sock:
            reader = HttpReader(sock)
            sock.sendall(b"G")
            time.sleep(0.05)
            sock.sendall(b"ET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
                         b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            self.assertEqual(reader.response()[::2], (200, HELLO))
            self.assertEqual(reader.response()[::2], (200, HELLO))

    def test_coalesced_tls_records_are_all_processed(self):
        client = MemoryTLSClient(self.port, self.http1_context)
        try:
            request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
            for _ in range(40):
                self.assertEqual(client.engine.write(request), len(request))
            ciphertext = client.outgoing.read()
            self.assertGreater(len(ciphertext), 40 * len(request))
            client.raw.sendall(ciphertext)
            reader = HttpReader(client)
            for _ in range(40):
                self.assertEqual(reader.response()[::2], (200, HELLO))
        finally:
            client.close()

    def test_partial_tls_record_waits_without_busy_spin(self):
        client = MemoryTLSClient(self.port, self.http1_context)
        try:
            request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
            self.assertEqual(client.engine.write(request), len(request))
            ciphertext = client.outgoing.read()
            self.assertGreater(len(ciphertext), 6)
            client.raw.sendall(ciphertext[:6])
            time.sleep(0.1)
            before = process_cpu_seconds(self.server.pid)
            time.sleep(0.7)
            used = process_cpu_seconds(self.server.pid) - before
            self.assertLess(used, 0.3, f"partial TLS record consumed {used:.2f}s CPU while stalled")
            client.raw.sendall(ciphertext[6:])
            self.assertEqual(HttpReader(client).response()[::2], (200, HELLO))
        finally:
            client.close()

    def test_many_pipelined_requests_across_tls_records(self):
        with tls_socket(self.port, self.http1_context) as sock:
            sock.settimeout(10)
            reader = HttpReader(sock)
            request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
            sock.sendall(request * 500)
            for _ in range(500):
                self.assertEqual(reader.response()[::2], (200, HELLO))

    def test_tls12_with_verified_certificate(self):
        ctx = context(self.ca, ["http/1.1"])
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        with tls_socket(self.port, ctx) as sock:
            self.assertEqual(sock.version(), "TLSv1.2")
            sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            self.assertEqual(HttpReader(sock).response()[::2], (200, HELLO))

    @unittest.skipUnless(ssl.HAS_TLSv1_3, "Python SSL does not support TLS 1.3")
    def test_tls13_with_verified_certificate(self):
        ctx = context(self.ca, ["http/1.1"])
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        with tls_socket(self.port, ctx) as sock:
            self.assertEqual(sock.version(), "TLSv1.3")
            sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            self.assertEqual(HttpReader(sock).response()[::2], (200, HELLO))

    def test_thousand_tls_connections_do_not_leak_descriptors(self):
        time.sleep(0.1)
        baseline = fd_count(self.server.pid)
        for _ in range(1000):
            self.assertEqual(self.get_http1()[::2], (200, HELLO))
        deadline = time.monotonic() + 4
        observed = fd_count(self.server.pid)
        while observed > baseline and time.monotonic() < deadline:
            time.sleep(0.05)
            observed = fd_count(self.server.pid)
        self.assertLessEqual(observed, baseline, f"descriptor count grew from {baseline} to {observed}")

    def test_malformed_handshakes_do_not_leak_descriptors(self):
        time.sleep(0.1)
        baseline = fd_count(self.server.pid)
        for _ in range(100):
            with socket.create_connection(("127.0.0.1", self.port), timeout=2) as sock:
                sock.sendall(b"not a TLS handshake")
        deadline = time.monotonic() + 4
        observed = fd_count(self.server.pid)
        while observed > baseline and time.monotonic() < deadline:
            time.sleep(0.05)
            observed = fd_count(self.server.pid)
        self.assertLessEqual(observed, baseline, f"descriptor count grew from {baseline} to {observed}")
        self.assertEqual(self.get_http1()[::2], (200, HELLO))

    def test_sigint_closes_multiple_active_connections(self):
        sockets = [tls_socket(self.port, self.http1_context) for _ in range(8)]
        raw = socket.create_connection(("127.0.0.1", self.port), timeout=2)
        try:
            raw.sendall(b"\x16")
            for sock in sockets[:4]:
                sock.sendall(b"GET / HTTP/1.1\r\nHost: local")
            # A received Continue proves the request reached the HTTP parser,
            # rather than depending on SIGINT racing unread TLS application data.
            continued = tls_socket(self.port, self.http1_context)
            sockets.append(continued)
            continued.sendall(b"POST / HTTP/1.1\r\nHost: localhost\r\n"
                              b"Content-Length: 1\r\nExpect: 100-continue\r\n\r\n")
            reader = HttpReader(continued)
            self.assertEqual(reader.until(b"\r\n\r\n").split(b"\r\n", 1)[0],
                             b"HTTP/1.1 100 Continue")
            self.assertEqual(reader.buffer, b"")
            self.server.send_signal(signal.SIGINT)
            self.assertEqual(self.server.wait(timeout=4), 0)
            for index, sock in enumerate(sockets):
                with self.subTest(client=index, partial_request=index < 4, partial_body=index == 8):
                    self.assertEqual(sock.recv(1), b"", "TLS connection did not close cleanly")
        finally:
            for sock in sockets:
                sock.close()
            raw.close()

    def test_interruptible_io_cannot_bypass_installed_tls(self):
        if not INTERRUPTIBLE.is_file():
            self.fail(f"build TLS interruptible test target: {INTERRUPTIBLE}")
        port = unused_port()
        with tempfile.TemporaryFile(mode="w+") as log:
            process = subprocess.Popen([str(INTERRUPTIBLE), str(self.cert), str(self.key), str(port)],
                                       stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 4
                while True:
                    if process.poll() is not None:
                        log.seek(0)
                        self.fail(f"transport fixture exited early: {log.read()}")
                    try:
                        client = socket.create_connection(("127.0.0.1", port), timeout=1)
                        break
                    except OSError:
                        if time.monotonic() > deadline:
                            self.fail("transport fixture did not start")
                        time.sleep(0.02)
                with client:
                    self.assertEqual(recv_exact(client, 5), b"READY")
                    try:
                        client.sendall(b"X")
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    try:
                        leaked = client.recv(256)
                    except ConnectionResetError:
                        leaked = b""
                    self.assertNotIn(b"PLAINTEXT-LEAK", leaked)
                code = process.wait(timeout=3)
                log.seek(0)
                self.assertEqual(code, 0, log.read())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=3)

    def exercise_tls_setup_fault(self, mode, fatal):
        # Native TLS consumes the reactor's accepted socket. Inject the first
        # accepted TCP_NODELAY setup rather than counting SO_NOSIGPIPE calls
        # from the old listener/session adapter. Both macOS and Linux exercise
        # the same native peer-versus-unrelated-setup-error classification.
        source = ROOT / "test/accept_fault.c"
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryFile(mode="w+") as log:
            library = Path(temp) / ("fault.dylib" if sys.platform == "darwin" else "fault.so")
            flags = ["-dynamiclib"] if sys.platform == "darwin" else ["-shared", "-fPIC"]
            subprocess.run(["cc", *flags, str(source), "-o", str(library)], check=True, capture_output=True)
            env = os.environ.copy()
            env["DYLD_INSERT_LIBRARIES" if sys.platform == "darwin" else "LD_PRELOAD"] = str(library)
            env["LEAN_NET_TEST_SOCKET_FAULT"] = mode
            port = unused_port()
            process = subprocess.Popen([str(self.binary), str(self.cert), str(self.key), str(port)],
                                       stdout=log, stderr=log, env=env)
            try:
                deadline = time.monotonic() + 4
                while True:
                    if process.poll() is not None:
                        log.seek(0)
                        self.fail(f"TLS fault fixture exited before accept: {log.read()}")
                    try:
                        first = socket.create_connection(("127.0.0.1", port), timeout=1)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            self.fail("TLS fault fixture did not start")
                        time.sleep(0.02)
                with first:
                    if fatal:
                        self.assertNotEqual(process.wait(timeout=3), 0, "TLS setup error was ignored")
                    else:
                        try:
                            self.assertEqual(first.recv(1), b"")
                        except ConnectionResetError:
                            pass
                if not fatal:
                    with tls_socket(port, self.http1_context) as healthy:
                        healthy.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                        self.assertEqual(HttpReader(healthy).response()[::2], (200, HELLO))
                    self.assertIsNone(process.poll())
                log.seek(0)
                output = log.read()
                self.assertIn("TEST_OPTION_FAULT", output)
                self.assertIn("TEST_PENDING_PEER_ERROR", output)
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGINT)
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)

    def test_tls_einval_with_peer_reset_is_isolated(self):
        self.exercise_tls_setup_fault("option_einval_peer", False)

    def test_tls_unrelated_setup_error_with_peer_reset_is_fatal(self):
        self.exercise_tls_setup_fault("option_proto_peer", True)

    def test_invalid_certificate_and_key_fail_startup(self):
        invalid = Path(self.temp.name) / "invalid.pem"
        invalid.write_text("not a certificate\n")
        pairs = ((invalid, self.key), (self.cert, self.other_key),
                 (Path(self.temp.name) / "missing.pem", self.key), (self.cert, invalid))
        for cert, key in pairs:
            with self.subTest(cert=cert, key=key):
                result = subprocess.run([str(BINARY), str(cert), str(key), str(unused_port())],
                                        capture_output=True, timeout=5)
                self.assertNotEqual(result.returncode, 0, "invalid key material was accepted")


class TLSFixtureAcceptance(unittest.TestCase):
    binary = FIXTURE
    setUpClass = classmethod(TLSAcceptance.setUpClass.__func__)
    tearDownClass = classmethod(TLSAcceptance.tearDownClass.__func__)
    setUp = TLSAcceptance.setUp
    stop_server = TLSAcceptance.stop_server
    get_http1 = TLSAcceptance.get_http1

    def test_binary_roundtrip_and_pipeline(self):
        payload = bytes(range(256)) * 8 + b"\x00\xff"
        with tls_socket(self.port, self.http1_context) as sock:
            reader = HttpReader(sock)
            sock.sendall(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: " +
                         str(len(payload)).encode() + b"\r\n\r\n" + payload +
                         b"GET /binary HTTP/1.1\r\nHost: localhost\r\n\r\n")
            self.assertEqual(reader.response()[::2], (200, payload))
            self.assertEqual(reader.response()[::2], (200, b"\x00\xff\r\nA"))

    def stalled_h2_peer(self):
        peer = h2_peer(self.port, self.valid_context, receive_buffer=4096)
        # Open both windows so flow control does not mask a blocked TLS write.
        peer.sock.sendall(frame(4, payload=struct.pack(">HI", 4, 4 * 1024 * 1024)) +
                          window(0, 4 * 1024 * 1024) + h2_get(1, b"/large"))
        while True:
            kind, flags, stream, payload = peer.read()
            if kind == 1 and stream == 1:
                return peer
            if kind == 7:
                raise AssertionError(f"unexpected GOAWAY: {payload.hex()}")

    def test_stalled_tls_writer_does_not_block_other_client(self):
        peer = self.stalled_h2_peer()
        try:
            time.sleep(0.15)
            self.assertEqual(self.get_http1()[::2], (200, HELLO))
        finally:
            peer.close()

    def test_large_tls_h2_response_survives_partial_writes(self):
        peer = h2_peer(self.port, self.valid_context)
        try:
            peer.sock.settimeout(10)
            peer.sock.sendall(h2_get(1, b"/large"))
            time.sleep(0.15)
            self.assertEqual(peer.response(1), b"A" * (4 * 1024 * 1024))
        finally:
            peer.close()

    def test_sigint_while_tls_write_is_backpressured(self):
        peer = self.stalled_h2_peer()
        try:
            time.sleep(0.15)
            start = time.monotonic()
            self.server.send_signal(signal.SIGINT)
            self.assertEqual(self.server.wait(timeout=4), 0)
            self.assertLess(time.monotonic() - start, 4, "shutdown exceeded the bounded deadline")
            # A blocked peer may require a forced close; the listener must still be released.
            with socket.socket() as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind(("127.0.0.1", self.port))
                probe.listen()
        finally:
            peer.close()


class TLSHandshakeDeadline(unittest.TestCase):
    binary = FIXTURE
    extra_args = ["deadlines"]
    setUpClass = classmethod(TLSAcceptance.setUpClass.__func__)
    tearDownClass = classmethod(TLSAcceptance.tearDownClass.__func__)
    setUp = TLSAcceptance.setUp
    stop_server = TLSAcceptance.stop_server
    get_http1 = TLSAcceptance.get_http1

    def test_idle_handshake_times_out_and_releases_only_slot(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as slow:
            slow.sendall(b"\x16")
            time.sleep(0.1)
            self.assertEqual(self.get_http1()[::2], (200, HELLO))
            slow.settimeout(2)
            try:
                data = slow.recv(1)
            except ConnectionResetError:
                data = b""
            self.assertEqual(data, b"")

    def test_clienthello_trickle_cannot_extend_absolute_handshake_deadline(self):
        inbound, outbound = ssl.MemoryBIO(), ssl.MemoryBIO()
        engine = self.http1_context.wrap_bio(inbound, outbound, server_side=False, server_hostname="localhost")
        try:
            engine.do_handshake()
        except ssl.SSLWantReadError:
            pass
        hello = outbound.read()
        self.assertGreater(len(hello), 20)
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as slow:
            start = time.monotonic()
            closed = False
            for byte in hello:
                try:
                    slow.sendall(bytes([byte]))
                except (BrokenPipeError, ConnectionResetError):
                    closed = True
                    break
                time.sleep(0.08)
                readable, _, _ = select.select([slow], [], [], 0)
                if readable:
                    try:
                        slow.recv(1024)
                    except ConnectionResetError:
                        pass
                    closed = True
                    break
                if time.monotonic() - start > 2:
                    break
            self.assertTrue(closed, "trickled ClientHello bypassed handshake deadline")
            self.assertEqual(self.get_http1()[::2], (200, HELLO))


if __name__ == "__main__":
    unittest.main()
