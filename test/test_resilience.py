"""Production resilience checks against the public cleartext server binary.

Covers descriptor exhaustion, signal-driven graceful shutdown, precise HTTP/1
error statuses, request-smuggling probes, health endpoints, secure default
headers, access-log fields and W3C trace propagation.
"""
import json
import base64
import os
import re
import resource
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / ".lake" / "build" / "bin" / "lean-net-http1"


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_listening(port, process, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"server exited early: {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("server did not start listening")


def read_response(sock, timeout=5.0):
    """Read one HTTP/1 response (Content-Length or close framed)."""
    sock.settimeout(timeout)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines or not lines[0].startswith(b"HTTP/"):
        return None, {}, data
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        headers.setdefault(name.strip().lower().decode(), []).append(value.strip().decode())
    length = int(headers.get("content-length", ["-1"])[0])
    if length >= 0:
        while len(body) < length:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body += chunk
    return status, headers, body


def request(port, raw, timeout=5.0):
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.sendall(raw)
        return read_response(sock, timeout)


class ServerCase(unittest.TestCase):
    args = []
    nofile = None

    def setUp(self):
        self.port = free_port()
        self.temp = tempfile.TemporaryDirectory()
        limit = self.nofile

        def preexec():
            if limit is not None:
                resource.setrlimit(resource.RLIMIT_NOFILE, (limit, limit))

        self.server = subprocess.Popen(
            [str(BINARY), *self.extra_args(), str(self.port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=preexec)
        wait_listening(self.port, self.server)

    def extra_args(self):
        return list(self.args)

    def tearDown(self):
        if self.server.poll() is None:
            self.server.send_signal(signal.SIGINT)
            try:
                self.server.wait(10)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait()
        self.server.stdout.close()
        self.server.stderr.close()
        self.temp.cleanup()


@unittest.skipIf(sys.platform == "win32", "POSIX resource limits")
class DescriptorExhaustion(ServerCase):
    args = ["--workers", "1", "--max-clients", "128"]
    nofile = 64

    def test_emfile_pauses_accepts_and_recovers(self):
        peers = []
        try:
            for _ in range(120):
                peer = socket.socket()
                peer.settimeout(5)
                peer.connect(("127.0.0.1", self.port))
                peers.append(peer)
            time.sleep(0.5)
            self.assertIsNone(self.server.poll(), "server must survive descriptor exhaustion")
        finally:
            for peer in peers:
                peer.close()
        deadline = time.monotonic() + 10
        status = None
        while time.monotonic() < deadline:
            try:
                status, _, body = request(self.port, b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", 2)
                if status == 200:
                    break
            except OSError:
                pass
            time.sleep(0.1)
        self.assertEqual(status, 200)
        self.assertIsNone(self.server.poll())


def exchange_all(port, raw, timeout=3.0):
    """Send raw bytes, then read until the server closes the connection."""
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.sendall(raw)
        sock.settimeout(timeout)
        data = b""
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    return data, True
                data += chunk
        except socket.timeout:
            return data, False


SMUGGLED = b"GET /smuggled HTTP/1.1\r\nHost: localhost\r\n\r\n"


class ProtocolErrors(ServerCase):
    args = ["--workers", "1", "--max-clients", "32"]

    def status_of(self, raw):
        data, closed = exchange_all(self.port, raw)
        self.assertTrue(closed, f"connection must close after rejection: {data!r}")
        self.assertEqual(data.count(b"HTTP/1.1 "), 1, f"exactly one response expected: {data!r}")
        return int(data.split(b" ", 2)[1])

    def test_precise_error_statuses(self):
        cases = [
            (b"GET / HTTP/2.0\r\nHost: x\r\n\r\n", 505),
            (b"GET / HTTP/1.1\r\nHost: x\r\nX: " + b"a" * 20000 + b"\r\n\r\n", 431),
            (b"GET /" + b"a" * 20000 + b" HTTP/1.1\r\nHost: x\r\n\r\n", 414),
            (b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 999999999\r\n\r\n", 413),
            (b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n", 501),
            (b"GET / HTTP/1.1\r\n\r\n", 400),
        ]
        for raw, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(self.status_of(raw), expected)

    def test_oversized_expect_continue_gets_417_before_body(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(b"POST / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n"
                         b"Content-Length: 999999999\r\n\r\n")
            status, _, _ = read_response(sock)
            self.assertEqual(status, 417)

    def test_http12_is_served_as_http11(self):
        status, _, body = request(self.port, b"GET / HTTP/1.2\r\nHost: x\r\nConnection: close\r\n\r\n")
        self.assertEqual(status, 200)

    def test_smuggling_probes_are_rejected_without_desync(self):
        probes = {
            "CL.TE": b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
            "TE.CL": b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n",
            "TE.TE duplicate": b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n0\r\n\r\n",
            "TE.TE list": b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n",
            "TE.TE xchunked": b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n",
            "TE space before colon": b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n",
            "TE obs-fold": b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding:\r\n chunked\r\n\r\n0\r\n\r\n",
            "TE bare LF": b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\n\r\n0\r\n\r\n",
            "TE in HTTP/1.0": b"POST / HTTP/1.0\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "CL.CL conflict": b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: 44\r\n\r\n",
            "CL list": b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0, 44\r\n\r\n",
            "CL plus sign": b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +0\r\n\r\n",
            "CL hex": b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0x0\r\n\r\n",
            "chunk size overflow": b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n10000000000000000000000001\r\n",
            "chunk bare LF": b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1\na\r\n0\r\n\r\n",
            "duplicate Host": b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
            "NUL in header": b"GET / HTTP/1.1\r\nHost: x\r\nX: a\x00b\r\n\r\n",
        }
        for name, probe in probes.items():
            with self.subTest(probe=name):
                data, closed = exchange_all(self.port, probe + SMUGGLED)
                self.assertTrue(closed, f"{name}: connection left open: {data!r}")
                self.assertEqual(data.count(b"HTTP/1."), 1, f"{name}: desync, multiple responses: {data!r}")
                status = int(data.split(b" ", 2)[1])
                self.assertIn(status, (400, 413, 501), f"{name}: unexpected status {status}")
                self.assertNotIn(b"smuggled", data.lower())

    def test_valid_pipeline_keeps_order(self):
        raw = b"".join(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n" for _ in range(5))
        data, _ = exchange_all(self.port, raw + b"GET /missing HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        statuses = [int(m) for m in re.findall(rb"HTTP/1\.1 (\d{3})", data)]
        self.assertEqual(statuses, [200] * 5 + [404])


class OperationsEndpoints(ServerCase):
    def extra_args(self):
        self.admin = free_port()
        return ["--workers", "2", "--max-clients", "32", "--health", "--metrics",
                "--admin-port", str(self.admin), "--pin-workers"]

    def test_health_endpoints(self):
        status, headers, body = request(self.port, b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        self.assertEqual((status, body), (200, b"ok\n"))
        self.assertEqual(headers["cache-control"], ["no-store"])
        status, _, body = request(self.port, b"GET /readyz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        self.assertEqual((status, body), (200, b"ready\n"))
        status, _, _ = request(self.port, b"POST /healthz HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        self.assertEqual(status, 405)

    def test_readiness_turns_503_while_draining(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            self.assertEqual(read_response(sock)[0], 200)
            sock.sendall(b"GET /readyz HTTP/1.1\r\nHost: x\r\n")
            time.sleep(0.1)
            self.server.send_signal(signal.SIGTERM)
            time.sleep(0.1)
            sock.sendall(b"\r\n")
            status, _, body = read_response(sock)
            self.assertEqual((status, body), (503, b"draining\n"))
        self.assertEqual(self.server.wait(10), 0)

    def test_admin_port_reports_stats_and_metrics(self):
        for _ in range(3):
            request(self.port, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        deadline = time.monotonic() + 5
        while True:
            status, headers, body = request(self.admin, b"GET /stats HTTP/1.1\r\nHost: x\r\n\r\n")
            stats = json.loads(body)
            if stats["successful_requests_total"] >= 3 or time.monotonic() > deadline:
                break
            time.sleep(0.2)
        self.assertEqual(status, 200)
        self.assertEqual(stats["workers"], 2)
        self.assertGreaterEqual(stats["successful_requests_total"], 3)
        self.assertGreater(stats["resident_memory_bytes"], 0)
        self.assertGreater(stats["open_fds"], 0)
        self.assertFalse(stats["draining"])
        status, _, body = request(self.admin, b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertEqual(status, 200)
        self.assertIn(b"lean_net_process_resident_memory_bytes", body)
        self.assertIn(b"lean_net_successful_completed_requests_total", body)
        status, _, _ = request(self.admin, b"GET /missing HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertEqual(status, 404)
        # The public metrics endpoint carries the process gauges too.
        status, _, body = request(self.port, b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        self.assertIn(b"lean_net_process_open_fds", body)

    def test_admin_port_is_loopback_only(self):
        addresses = {info[4][0] for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)}
        addresses.discard("127.0.0.1")
        for address in addresses:
            with self.assertRaises(OSError):
                socket.create_connection((address, self.admin), timeout=0.5).close()

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux affinity introspection")
    def test_workers_are_pinned(self):
        allowed = []
        for task in Path(f"/proc/{self.server.pid}/task").iterdir():
            text = (task / "status").read_text()
            allowed.append(re.search(r"Cpus_allowed_list:\s*(\S+)", text).group(1))
        single = [value for value in allowed if value.isdigit()]
        self.assertGreaterEqual(len(single), min(2, os.cpu_count() or 1))

    def test_secure_default_headers(self):
        status, headers, _ = request(self.port, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        self.assertEqual(status, 200)
        self.assertEqual(headers["x-content-type-options"], ["nosniff"])
        self.assertEqual(headers["x-frame-options"], ["SAMEORIGIN"])
        self.assertIn("default-src 'self'", headers["content-security-policy"][0])
        self.assertNotIn("strict-transport-security", headers, "HSTS must not be sent over cleartext")


class SecurityHeadersDisabled(ServerCase):
    args = ["--workers", "1", "--no-security-headers"]

    def test_headers_can_be_disabled(self):
        status, headers, _ = request(self.port, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        self.assertEqual(status, 200)
        self.assertNotIn("x-content-type-options", headers)


class AccessLogAndTracing(ServerCase):
    def extra_args(self):
        self.log = Path(self.temp.name) / "access.jsonl"
        return ["--workers", "1", "--access-log", str(self.log)]

    def records(self):
        self.server.send_signal(signal.SIGTERM)
        self.assertEqual(self.server.wait(10), 0)
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_structured_fields_and_trace_propagation(self):
        incoming = "4bf92f3577b34da6a3ce929d0e0e4736"
        request(self.port, b"GET /?token=secret HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        request(self.port, ("GET /missing HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                            f"traceparent: 00-{incoming}-00f067aa0ba902b7-01\r\n\r\n").encode())
        # Invalid contexts (all-zero trace-id, uppercase hex) are replaced.
        request(self.port, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                           b"traceparent: 00-00000000000000000000000000000000-00f067aa0ba902b7-01\r\n\r\n")
        first, second, third = self.records()
        for record in (first, second, third):
            self.assertEqual(record["remote_ip"], "127.0.0.1")
            self.assertRegex(record["trace_id"], r"^[0-9a-f]{32}$")
            self.assertRegex(record["timestamp"], r"Z$")
            self.assertIn("duration_ms", record)
        self.assertEqual((first["method"], first["path"], first["status"]), ("GET", "/", 200))
        self.assertNotIn("secret", json.dumps(first))
        self.assertEqual((second["path"], second["status"], second["trace_id"]), ("/missing", 404, incoming))
        self.assertNotEqual(third["trace_id"], "0" * 32)
        self.assertNotEqual(first["trace_id"], third["trace_id"])


class H2CUpgrade(ServerCase):
    args = ["--workers", "1"]
    # Base64url SETTINGS payload: MAX_CONCURRENT_STREAMS=100, INITIAL_WINDOW=65535.
    SETTINGS = b"AAMAAABkAAQAAP__"

    def test_curl_upgrade_serves_http2(self):
        curl = os.environ.get("LEAN_NET_TEST_CURL", "curl")
        result = subprocess.run([curl, "-sS", "--noproxy", "*", "--http2", "-v",
                                 "-w", "\n%{http_version} %{http_code}", f"http://127.0.0.1:{self.port}/"],
                                capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"101 Switching Protocols", result.stderr)
        self.assertTrue(result.stdout.endswith(b"Hello from lean-net!\n\n2 200"), result.stdout)

    def test_raw_upgrade_switches_after_101(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, HTTP2-Settings\r\n"
                         b"Upgrade: h2c\r\nHTTP2-Settings: " + self.SETTINGS + b"\r\n\r\n")
            data = b""
            while b"\r\n\r\n" not in data:
                data += sock.recv(4096)
            head, _, rest = data.partition(b"\r\n\r\n")
            self.assertTrue(head.startswith(b"HTTP/1.1 101 "), head)
            self.assertIn(b"upgrade: h2c", head.lower())
            # Server SETTINGS must be the first HTTP/2 frame.
            sock.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
            frames, buffer, deadline = [], rest, time.monotonic() + 5
            while time.monotonic() < deadline and not any(k == 0 and f & 1 and sid == 1 for k, f, sid, _ in frames):
                while len(buffer) >= 9 and len(buffer) >= 9 + int.from_bytes(buffer[:3], "big"):
                    length = int.from_bytes(buffer[:3], "big")
                    frames.append((buffer[3], buffer[4], int.from_bytes(buffer[5:9], "big") & 0x7fffffff, buffer[9:9 + length]))
                    buffer = buffer[9 + length:]
                if any(k == 0 and f & 1 and sid == 1 for k, f, sid, _ in frames):
                    break
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buffer += chunk
            self.assertEqual(frames[0][0], 4, "first frame after 101 must be SETTINGS")
            self.assertTrue(any(k == 1 and sid == 1 for k, _, sid, _ in frames), "stream 1 HEADERS")
            body = b"".join(p for k, _, sid, p in frames if k == 0 and sid == 1)
            self.assertEqual(body, b"Hello from lean-net!\n")

    def test_ineligible_upgrades_stay_on_http11(self):
        cases = [
            # Missing HTTP2-Settings nomination in Connection.
            b"GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: h2c\r\nHTTP2-Settings: " + self.SETTINGS + b"\r\n",
            # Invalid base64url settings.
            b"GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: !!!\r\n",
            # Request with a body.
            b"POST / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: " + self.SETTINGS + b"\r\nContent-Length: 1\r\n\r\nx",
        ]
        for raw in cases:
            with self.subTest(raw=raw[:60]):
                if not raw.endswith(b"x"):
                    raw += b"\r\n"
                with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
                    sock.sendall(raw)
                    status, _, _ = read_response(sock)
                    self.assertIn(status, (200, 404))

    def test_invalid_settings_values_do_not_switch_protocols(self):
        # These values must have the same validation as a wire SETTINGS frame.
        # In particular, setting 9 was previously omitted from the upgrade path.
        for identifier, value in ((9, 2), (2, 2), (4, 0x80000000),
                                  (5, 16383), (5, 16777216)):
            with self.subTest(identifier=identifier, value=value):
                payload = identifier.to_bytes(2, "big") + value.to_bytes(4, "big")
                settings = base64.urlsafe_b64encode(payload).rstrip(b"=")
                raw = (b"GET / HTTP/1.1\r\nHost: x\r\n"
                       b"Connection: Upgrade, HTTP2-Settings\r\n"
                       b"Upgrade: h2c\r\nHTTP2-Settings: " + settings + b"\r\n\r\n")
                with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
                    sock.sendall(raw)
                    status, _, body = read_response(sock)
                    self.assertEqual(status, 200, "invalid settings must not produce 101")
                    self.assertEqual(body, b"Hello from lean-net!\n")

    def test_noncanonical_settings_header_does_not_switch_protocols(self):
        # Empty SETTINGS frames remain valid HTTP/2, but the HTTP2-Settings
        # header is a nonempty token68 and RFC 7540 omits all '=' padding.
        for settings in (b"", b"====", self.SETTINGS + b"=", b"AAkAAAAB==",
                         b"AB", b"AAB", b"!!!", b"AA+_"):
            with self.subTest(settings=settings):
                raw = (b"GET / HTTP/1.1\r\nHost: x\r\n"
                       b"Connection: Upgrade, HTTP2-Settings\r\n"
                       b"Upgrade: h2c\r\nHTTP2-Settings: " + settings + b"\r\n\r\n")
                with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
                    sock.sendall(raw)
                    status, _, body = read_response(sock)
                    self.assertEqual(status, 200, "malformed header must not produce 101")
                    self.assertEqual(body, b"Hello from lean-net!\n")


@unittest.skipIf(sys.platform == "win32", "POSIX signals")
class Signals(ServerCase):
    args = ["--workers", "2", "--max-clients", "64"]

    def test_sighup_does_not_terminate(self):
        self.server.send_signal(signal.SIGHUP)
        time.sleep(0.3)
        self.assertIsNone(self.server.poll(), "SIGHUP must request reload, not terminate")
        status, _, _ = request(self.port, b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        self.assertEqual(status, 200)

    def test_sigterm_drains_in_flight_request_and_exits_cleanly(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as client:
            # A partial request is in flight when SIGTERM arrives; it must be
            # allowed to finish within the drain deadline.
            client.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
            time.sleep(0.2)
            self.server.send_signal(signal.SIGTERM)
            time.sleep(0.1)
            client.sendall(b"\r\n")
            status, headers, _ = read_response(client)
            self.assertEqual(status, 200)
            self.assertIn("close", headers.get("connection", [""])[0].lower())
        self.assertEqual(self.server.wait(10), 0)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", self.port), timeout=0.5).close()


if __name__ == "__main__":
    unittest.main()
