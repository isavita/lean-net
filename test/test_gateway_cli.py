#!/usr/bin/env python3
"""Public CLI gateway acceptance with a real persistent HTTP/1.1 backend."""

import http.client
import json
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / ".lake" / "build" / "bin" / ("lean-net-http1.exe" if sys.platform == "win32" else "lean-net-http1")


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def h2_frame(kind, flags=0, stream=0, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes((kind, flags)) + struct.pack(">I", stream) + payload


def h2_read(sock, buffered):
    while len(buffered) < 9:
        data = sock.recv(65536)
        if not data:
            raise EOFError("HTTP/2 peer closed before a frame header")
        buffered += data
    length = int.from_bytes(buffered[:3], "big")
    while len(buffered) < 9 + length:
        data = sock.recv(65536)
        if not data:
            raise EOFError("HTTP/2 peer closed during a frame")
        buffered += data
    header, payload = buffered[:9], bytes(buffered[9:9 + length])
    del buffered[:9 + length]
    return header[3], header[4], int.from_bytes(header[5:9], "big") & 0x7fffffff, payload


class Backend(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address):
        super().__init__(address, Handler)
        self.accepted = 0
        self.requests = []
        self.lock = threading.Lock()

    def get_request(self):
        result = super().get_request()
        with self.lock:
            self.accepted += 1
        return result


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle_request(self):
        size = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(size).decode("ascii")
        record = {
            "method": self.command,
            "path": self.path,
            "host": self.headers.get("host"),
            "forwarded": self.headers.get("forwarded"),
            "xff": self.headers.get("x-forwarded-for"),
            "via": self.headers.get("via"),
            "secret": self.headers.get("x-secret"),
            "body": body,
        }
        with self.server.lock:
            self.server.requests.append(record)
        large = self.path == "/large"
        payload = b"x" * (2 * 1024 * 1024) if large else json.dumps(record).encode("ascii")
        # Let the upstream client's write completion settle before replying;
        # this makes the second request a meaningful idle reuse check.
        time.sleep(0.02)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream" if large else "application/json")
        self.send_header("Connection", "x-hide")
        self.send_header("X-Hide", "must-not-cross")
        self.send_header("X-Useful", "preserved")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = handle_request
    do_POST = handle_request

    def log_message(self, *_):
        pass


class GatewayCLI(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.backend = Backend(("127.0.0.1", 0))
        self.addCleanup(self.backend.server_close)
        self.backend_thread = threading.Thread(target=self.backend.serve_forever, daemon=True)
        self.backend_thread.start()
        self.addCleanup(self.backend.shutdown)
        self.port = free_port()
        policy = Path(self.temp.name) / "gateway.policy"
        policy.write_text(
            f"backend local {{ http 127.0.0.1:{self.backend.server_port} ; serves proxy.test }}\n"
            "host proxy.test { route * /* -> proxy local }\n"
            "on unknown-host 421\n"
        )
        self.server = subprocess.Popen(
            [str(BINARY), "--workers", "1", "--gate", str(policy), str(self.port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        self.addCleanup(self.stop)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.server.poll() is not None:
                self.fail("gateway exited: " + self.server.stderr.read().decode(errors="replace"))
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            self.fail("gateway did not listen")

    def stop(self):
        if self.server.poll() is None:
            self.server.terminate()
            try:
                self.server.wait(10)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait()
        self.server.stderr.close()

    def request(self, method, target, host="proxy.test", body=None, headers=()):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.putrequest(method, target, skip_host=True)
            connection.putheader("Host", host)
            for name, value in headers:
                connection.putheader(name, value)
            if body is not None:
                connection.putheader("Content-Length", str(len(body)))
            connection.endheaders(body)
            reply = connection.getresponse()
            return reply.status, {name.lower(): value for name, value in reply.getheaders()}, reply.read()
        finally:
            connection.close()

    def test_route_binding_forwarding_and_pool_reuse(self):
        status, fields, payload = self.request(
            "GET", "/%61dmin?x=1", headers=(
                ("Forwarded", "for=203.0.113.9"),
                ("X-Forwarded-For", "203.0.113.9"),
                ("Connection", "x-secret"),
                ("X-Secret", "must-not-cross"),
            ),
        )
        self.assertEqual(status, 200)
        value = json.loads(payload)
        self.assertEqual(value["path"], "/admin?x=1")
        self.assertEqual(value["host"], "proxy.test")
        self.assertEqual(value["xff"], "127.0.0.1")
        self.assertIn('for="127.0.0.1"', value["forwarded"])
        self.assertNotIn("203.0.113.9", value["forwarded"])
        self.assertEqual(value["secret"], None)
        self.assertEqual(value["via"], "1.1 lean-net")
        self.assertEqual(fields.get("x-useful"), "preserved")
        self.assertNotIn("x-hide", fields)
        self.assertNotIn("connection", fields)

        status, _, payload = self.request("POST", "/submit", body=b"hello")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["body"], "hello")
        with self.backend.lock:
            self.assertEqual(self.backend.accepted, 1, "upstream idle connection was not reused")

    def test_unknown_host_never_reaches_backend(self):
        status, fields, _ = self.request("GET", "/", host="other.test")
        self.assertEqual(status, 421)
        self.assertEqual(fields.get("x-content-type-options"), "nosniff")
        with self.backend.lock:
            self.assertEqual(self.backend.requests, [])

    def test_http1_request_trailer_is_rejected_before_proxy(self):
        wire = (b"POST /submit HTTP/1.1\r\nHost: proxy.test\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Trailer: X-Forwarded-Client-Cert\r\nConnection: close\r\n\r\n"
                b"1\r\nx\r\n0\r\nX-Forwarded-Client-Cert: spoof\r\n\r\n")
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as peer:
            peer.settimeout(5)
            peer.sendall(wire)
            response = bytearray()
            while b"\r\n" not in response and len(response) < 4096:
                chunk = peer.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
        self.assertTrue(response.startswith(b"HTTP/1.1 400 "), response)
        with self.backend.lock:
            self.assertEqual(self.backend.requests, [])

    def test_http2_request_trailer_is_rejected_before_proxy(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as peer:
            peer.settimeout(5)
            buffered = bytearray()
            peer.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + h2_frame(4))
            for _ in range(32):
                kind, flags, stream, _ = h2_read(peer, buffered)
                if kind == 4 and stream == 0 and not flags & 1:
                    peer.sendall(h2_frame(4, 1))
                    break
            else:
                self.fail("HTTP/2 settings did not arrive")
            # Static :method POST/:scheme http, then literal :path/:authority.
            head = b"\x83\x86\x04\x07/submit\x01\x0aproxy.test"
            trailer = b"\x10\x17x-forwarded-client-cert\x05spoof"
            peer.sendall(h2_frame(1, 4, 1, head) + h2_frame(1, 5, 1, trailer))
            for _ in range(64):
                kind, _, stream, payload = h2_read(peer, buffered)
                if stream == 1 and kind == 1:
                    # HPACK static table index 12 is `:status: 400`.
                    self.assertEqual(payload[:1], b"\x8c", payload)
                    break
            else:
                self.fail("HTTP/2 trailer rejection did not arrive")
        with self.backend.lock:
            self.assertEqual(self.backend.requests, [])

    def test_large_response_streams_to_downstream(self):
        status, fields, payload = self.request("GET", "/large")
        self.assertEqual(status, 200)
        self.assertEqual(len(payload), 2 * 1024 * 1024)
        self.assertEqual(payload[:16], b"x" * 16)
        self.assertEqual(fields.get("content-length"), str(len(payload)))

    def test_http2_large_response_obeys_flow_control(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as peer:
            peer.settimeout(5)
            buffered = bytearray()
            peer.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + h2_frame(4))
            saw_settings = saw_ack = False
            for _ in range(32):
                kind, flags, stream, payload = h2_read(peer, buffered)
                self.assertNotEqual(kind, 7, "gateway sent GOAWAY during handshake")
                if kind == 4 and stream == 0:
                    if flags & 1:
                        saw_ack = True
                    else:
                        saw_settings = True
                        peer.sendall(h2_frame(4, 1))
                if saw_settings and saw_ack:
                    break
            else:
                self.fail("HTTP/2 gateway handshake did not complete")
            # Static HPACK :method GET and :scheme http; literal :path and
            # :authority values keep this wire test free of Python h2 deps.
            block = b"\x82\x86\x04\x06/large\x01\x0aproxy.test"
            peer.sendall(h2_frame(1, 5, 1, block))
            body = bytearray()
            saw_headers = False
            for _ in range(1000):
                kind, flags, stream, payload = h2_read(peer, buffered)
                self.assertNotEqual(kind, 7, "gateway sent GOAWAY during response")
                if stream != 1:
                    continue
                self.assertNotEqual(kind, 3, "gateway reset proxied stream")
                if kind == 1:
                    saw_headers = True
                elif kind == 0:
                    self.assertTrue(saw_headers, "DATA preceded response HEADERS")
                    body.extend(payload)
                    if payload:
                        increment = struct.pack(">I", len(payload))
                        peer.sendall(h2_frame(8, stream=0, payload=increment) +
                                     h2_frame(8, stream=1, payload=increment))
                if flags & 1:
                    break
            else:
                self.fail("proxied HTTP/2 response never ended")
            self.assertEqual(len(body), 2 * 1024 * 1024)
            self.assertEqual(body[:16], b"x" * 16)


if __name__ == "__main__":
    unittest.main()
