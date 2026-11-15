#!/usr/bin/env python3
"""Public HTTP/1 and RFC8441 WebSocket wire acceptance, including TLS and flow control."""
import base64
import hashlib
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest

import hpack

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tls/test"))
from tls_test_support import create_certificates  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SUFFIX = ".exe" if sys.platform == "win32" else ""
PLAIN = ROOT / f".lake/build/bin/lean-net-http1{SUFFIX}"
TLS = ROOT / f"tls/.lake/build/bin/lean-net-tls{SUFFIX}"
ORIGIN = "https://lean-net.test"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def exact(sock, size):
    data = b""
    while len(data) < size:
        more = sock.recv(size - len(data))
        if not more:
            raise EOFError(f"expected {size} bytes, got {len(data)}")
        data += more
    return data


def h2frame(kind, flags, stream, data=b""):
    return len(data).to_bytes(3, "big") + bytes((kind, flags)) + stream.to_bytes(4, "big") + data


def websocket_frame(opcode, payload=b"", *, mask=b"\x01\x02\x03\x04", fin=True):
    head = bytes(((0x80 if fin else 0) | opcode, 0x80))
    if len(payload) < 126:
        head = head[:-1] + bytes((0x80 | len(payload),))
    elif len(payload) < 65536:
        head = head[:-1] + b"\xfe" + len(payload).to_bytes(2, "big")
    else:
        head = head[:-1] + b"\xff" + len(payload).to_bytes(8, "big")
    return head + mask + bytes(value ^ mask[i % 4] for i, value in enumerate(payload))


def read_ws(sock):
    first, second = exact(sock, 2)
    assert second & 0x80 == 0, "server must not mask"
    size = second & 127
    if size == 126:
        size = int.from_bytes(exact(sock, 2), "big")
    elif size == 127:
        size = int.from_bytes(exact(sock, 8), "big")
    return first, exact(sock, size)


class Server:
    def __init__(self, binary, flags, websocket=True):
        self.port = free_port()
        self.log = tempfile.TemporaryFile(mode="w+")
        self.process = subprocess.Popen([str(binary), "--workers", "2",
                                         *(["--websocket-origin", ORIGIN] if websocket else []),
                                         *map(str, flags), str(self.port)], stdout=self.log, stderr=self.log)
        for _ in range(150):
            if self.process.poll() is not None:
                self.log.seek(0)
                raise AssertionError("server exited early: " + self.log.read())
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.1).close()
                return
            except OSError:
                time.sleep(0.04)
        raise AssertionError("server did not listen")

    def close(self):
        if self.process.poll() is None:
            if sys.platform == "win32":
                self.process.kill()
            else:
                self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(8)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait()
        self.log.close()


class H2:
    def __init__(self, sock):
        self.sock = sock
        self.encoder = hpack.Encoder()
        self.decoder = hpack.Decoder()
        self.settings = None

    def send(self, kind, flags, stream, data=b""):
        self.sock.sendall(h2frame(kind, flags, stream, data))

    def read(self):
        head = exact(self.sock, 9)
        return head[3], head[4], int.from_bytes(head[5:], "big") & 0x7fffffff, exact(self.sock, int.from_bytes(head[:3], "big"))

    def preface(self, initial_window=None):
        settings = b"" if initial_window is None else b"\x00\x04" + initial_window.to_bytes(4, "big")
        self.sock.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + h2frame(4, 0, 0, settings))

    def headers(self, stream, fields, end=False):
        self.send(1, 4 | (1 if end else 0), stream, self.encoder.encode(fields, huffman=False))

    def open_websocket(self, scheme="http", path="/ws"):
        self.headers(1, [(":method", "CONNECT"), (":protocol", "websocket"),
                         (":scheme", scheme), (":path", path), (":authority", "localhost"),
                         ("sec-websocket-version", "13"), ("origin", ORIGIN)])
        for _ in range(12):
            kind, flags, stream, data = self.read()
            if kind == 4 and flags == 0:
                self.settings = data
            if kind == 1 and stream == 1:
                assert flags & 4 and not flags & 1
                fields = self.decoder.decode(data)
                assert (":status", "200") in fields, fields
                assert self.settings is not None and b"\x00\x08\x00\x00\x00\x01" in self.settings
                return fields
        raise AssertionError("no RFC8441 response")


class WebSocketWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="lean-net-websocket-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.certs = create_certificates(Path(cls.temp.name))

    def start(self, tls=False, websocket=True):
        server = Server(TLS if tls else PLAIN,
                        [self.certs.chains[0], self.certs.keys[0]] if tls else [], websocket)
        self.addCleanup(server.close)
        return server

    def connect(self, server, tls=False, h2=False):
        raw = socket.create_connection(("127.0.0.1", server.port), timeout=4)
        raw.settimeout(4)
        if not tls:
            return raw
        context = ssl.create_default_context(cafile=str(self.certs.ca))
        context.set_alpn_protocols(["h2" if h2 else "http/1.1"])
        wrapped = context.wrap_socket(raw, server_hostname="alpha.test")
        self.assertEqual(wrapped.selected_alpn_protocol(), "h2" if h2 else "http/1.1")
        return wrapped

    def handshake_h1(self, sock, origin=ORIGIN, expect_upgrade=True):
        key = base64.b64encode(b"0123456789abcdef")
        head = (b"GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive, Upgrade\r\n"
                b"Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + b"\r\n" +
                (b"Origin: " + origin.encode() + b"\r\n" if origin is not None else b"") + b"\r\n")
        sock.sendall(head)
        response = b""
        while b"\r\n\r\n" not in response:
            response += sock.recv(4096)
        if origin == ORIGIN and expect_upgrade:
            self.assertTrue(response.startswith(b"HTTP/1.1 101"), response)
            digest = base64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
            self.assertIn(b"Sec-WebSocket-Accept: " + digest, response)
        return response

    def test_h1_plain_and_tls_echo_ping_close(self):
        for tls in (False, True):
            with self.subTest(tls=tls):
                server = self.start(tls)
                with self.connect(server, tls) as sock:
                    self.handshake_h1(sock)
                    sock.sendall(websocket_frame(1, b"hel", fin=False) +
                                 websocket_frame(9, b"p") + websocket_frame(0, b"lo"))
                    self.assertEqual(read_ws(sock), (0x8a, b"p"))
                    self.assertEqual(read_ws(sock), (0x81, b"hello"))
                    sock.sendall(websocket_frame(8, b"\x03\xe8"))
                    self.assertEqual(read_ws(sock), (0x88, b"\x03\xe8"))
                    self.assertEqual(sock.recv(1), b"")

    def test_h1_origin_and_mask_fail_closed(self):
        server = self.start()
        for origin in (None, "https://other.test"):
            with self.connect(server) as sock:
                response = self.handshake_h1(sock, origin)
                self.assertTrue(response.startswith(b"HTTP/1.1 403"), response)
        with self.connect(server) as sock:
            self.handshake_h1(sock)
            sock.sendall(b"\x81\x05hello")
            self.assertEqual(read_ws(sock), (0x88, b"\x03\xea"))

    def test_websocket_is_disabled_by_default(self):
        server = self.start(websocket=False)
        with self.connect(server) as sock:
            response = self.handshake_h1(sock, expect_upgrade=False)
            self.assertTrue(response.startswith(b"HTTP/1.1 404"), response)
        with self.connect(server, h2=True) as sock:
            h2 = H2(sock); h2.preface()
            for _ in range(4):
                kind, flags, stream, data = h2.read()
                if kind == 4 and flags == 0:
                    self.assertNotIn(b"\x00\x08\x00\x00\x00\x01", data)
                    break
            else:
                self.fail("server did not send SETTINGS")

    def test_h2_plain_and_tls_multiplex_and_clean_close(self):
        for tls in (False, True):
            with self.subTest(tls=tls):
                server = self.start(tls)
                with self.connect(server, tls, h2=True) as sock:
                    h2 = H2(sock); h2.preface(); h2.open_websocket("https" if tls else "http")
                    h2.headers(3, [(":method", "GET"), (":scheme", "https" if tls else "http"),
                                   (":authority", "localhost"), (":path", "/")], end=True)
                    h2.send(0, 0, 1, websocket_frame(2, b"abc"))
                    saw_echo = saw_get = saw_get_done = False
                    for _ in range(12):
                        kind, flags, stream, data = h2.read()
                        if (kind, stream) == (0, 1):
                            self.assertEqual(data, b"\x82\x03abc"); saw_echo = True
                        if (kind, stream) == (1, 3):
                            self.assertIn((":status", "200"), h2.decoder.decode(data)); saw_get = True
                        if (kind, stream) == (0, 3) and flags & 1:
                            self.assertEqual(data, b"Hello from lean-net!\n"); saw_get_done = True
                        if saw_echo and saw_get_done: break
                    self.assertTrue(saw_echo and saw_get and saw_get_done)
                    h2.send(0, 1, 1, websocket_frame(8, b"\x03\xe8"))
                    self.assertEqual(h2.read(), (0, 0, 1, b"\x88\x02\x03\xe8"))
                    self.assertEqual(h2.read(), (0, 1, 1, b""))

    def test_h2_zero_window_backpressures_one_tunnel(self):
        server = self.start()
        with self.connect(server, h2=True) as sock:
            h2 = H2(sock); h2.preface(initial_window=0); h2.open_websocket()
            h2.send(0, 0, 1, websocket_frame(1, b"blocked"))
            h2.headers(3, [(":method", "GET"), (":scheme", "http"),
                           (":authority", "localhost"), (":path", "/")], end=True)
            kind, flags, stream, head = h2.read()
            self.assertEqual((kind, stream), (1, 3))
            self.assertIn((":status", "200"), h2.decoder.decode(head))
            sock.settimeout(0.2)
            with self.assertRaises(socket.timeout):
                h2.read()
            sock.settimeout(4)
            h2.send(8, 0, 3, (65535).to_bytes(4, "big"))
            self.assertEqual(h2.read(), (0, 1, 3, b"Hello from lean-net!\n"))
            sock.settimeout(0.2)
            with self.assertRaises(socket.timeout):
                h2.read()
            sock.settimeout(4)
            h2.send(8, 0, 1, (65535).to_bytes(4, "big"))
            self.assertEqual(h2.read(), (0, 0, 1, b"\x81\x07blocked"))
            h2.send(0, 1, 1, websocket_frame(8, b"\x03\xe8"))
            self.assertEqual(h2.read(), (0, 0, 1, b"\x88\x02\x03\xe8"))
            self.assertEqual(h2.read(), (0, 1, 1, b""))

    def test_h2_origin_rejection_and_invalid_pseudo_field(self):
        server = self.start()
        with self.connect(server, h2=True) as sock:
            h2 = H2(sock); h2.preface()
            h2.headers(1, [(":method", "CONNECT"), (":protocol", "websocket"),
                           (":scheme", "http"), (":path", "/ws"),
                           (":authority", "localhost"), ("sec-websocket-version", "13"),
                           ("origin", "https://other.test")])
            for _ in range(6):
                kind, flags, stream, data = h2.read()
                if (kind, stream) == (1, 1):
                    self.assertTrue(flags & 1)
                    self.assertIn((":status", "403"), h2.decoder.decode(data))
                    break
            else:
                self.fail("missing rejected CONNECT response")
            h2.headers(3, [(":method", "GET"), (":protocol", "websocket"),
                           (":scheme", "http"), (":authority", "localhost"),
                           (":path", "/")], end=True)
            for _ in range(6):
                kind, _, stream, data = h2.read()
                if (kind, stream) == (3, 3):
                    self.assertEqual(data, (1).to_bytes(4, "big"))
                    break
            else:
                self.fail("invalid :protocol request was not reset")

    def test_h2_malformed_tunnel_frame_resets_only_its_stream(self):
        server = self.start()
        with self.connect(server, h2=True) as sock:
            h2 = H2(sock); h2.preface(); h2.open_websocket()
            # PRIORITY payloads must be five bytes. This is a parser-level,
            # stream-scoped error after the tunnel has already been accepted.
            h2.send(2, 0, 1, b"x")
            self.assertEqual(h2.read(), (3, 0, 1, (6).to_bytes(4, "big")))
            h2.headers(3, [(":method", "GET"), (":scheme", "http"),
                           (":authority", "localhost"), (":path", "/")], end=True)
            kind, flags, stream, data = h2.read()
            self.assertEqual((kind, stream), (1, 3))
            self.assertIn((":status", "200"), h2.decoder.decode(data))
            self.assertEqual(h2.read(), (0, 1, 3, b"Hello from lean-net!\n"))

    def test_h2_extended_connect_scheme_matches_transport(self):
        for tls in (False, True):
            with self.subTest(tls=tls):
                server = self.start(tls)
                with self.connect(server, tls, h2=True) as sock:
                    h2 = H2(sock); h2.preface()
                    h2.headers(1, [(":method", "CONNECT"), (":protocol", "websocket"),
                                   (":scheme", "http" if tls else "https"),
                                   (":authority", "localhost"), (":path", "/ws"),
                                   ("sec-websocket-version", "13"), ("origin", ORIGIN)])
                    for _ in range(8):
                        kind, flags, stream, data = h2.read()
                        if (kind, stream) == (1, 1):
                            self.assertTrue(flags & 1)
                            self.assertIn((":status", "400"), h2.decoder.decode(data))
                            break
                    else:
                        self.fail("wrong-scheme CONNECT was not rejected")


if __name__ == "__main__":
    unittest.main()
