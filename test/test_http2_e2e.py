"""End-to-end h2c tests using only stdlib plus optional HTTP/2 curl.

Run after `lake build lean-net-http1 lean-net-http2-fixture`.
"""

import os
from pathlib import Path
import signal
import shutil
import socket
import struct
import subprocess
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / ".lake/build/bin/lean-net-http2-fixture"
MAIN = ROOT / ".lake/build/bin/lean-net-http1"
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def frame(kind, flags=0, stream=0, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + struct.pack(">I", stream) + payload


def headers(stream, path=b"/binary", method=b"GET", end=True):
    # RFC 7541 static names: :method, :scheme, :path and :authority. Literal
    # values are uncompressed to keep this test independent of Python h2.
    assert len(path) < 127
    block = (b"\x82" if method == b"GET" else b"\x83") + b"\x86"
    block += b"\x04" + bytes([len(path)]) + path
    block += b"\x01\x09localhost"
    return frame(1, 4 | (1 if end else 0), stream, block)


def window(stream, increment):
    return frame(8, 0, stream, struct.pack(">I", increment))


class Peer:
    def __init__(self, port, initial_window=None, receive_buffer=None):
        self.sock = socket.socket()
        if receive_buffer is not None:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, receive_buffer)
        self.sock.settimeout(3)
        self.sock.connect(("127.0.0.1", port))
        self.sock.settimeout(3)
        self.buffer = b""
        self.server_settings = {}
        payload = b"" if initial_window is None else struct.pack(">HI", 4, initial_window)
        self.sock.sendall(PREFACE + frame(4, payload=payload))
        settings = ack = False
        while not (settings and ack):
            kind, flags, stream, payload = self.read()
            if kind == 7:
                raise AssertionError(f"unexpected GOAWAY during handshake: {payload.hex()}")
            if kind == 4 and stream == 0:
                if flags & 1:
                    ack = True
                else:
                    if len(payload) % 6:
                        raise AssertionError("invalid server SETTINGS payload")
                    for offset in range(0, len(payload), 6):
                        key, value = struct.unpack(">HI", payload[offset:offset + 6])
                        self.server_settings[key] = value
                    settings = True
                    self.sock.sendall(frame(4, 1))

    def close(self):
        self.sock.close()

    def read(self):
        while len(self.buffer) < 9:
            data = self.sock.recv(65536)
            if not data:
                raise EOFError("connection closed before frame header")
            self.buffer += data
        length = int.from_bytes(self.buffer[:3], "big")
        while len(self.buffer) < 9 + length:
            data = self.sock.recv(65536)
            if not data:
                raise EOFError("connection closed before frame payload")
            self.buffer += data
        header, payload = self.buffer[:9], self.buffer[9:9 + length]
        self.buffer = self.buffer[9 + length:]
        return header[3], header[4], int.from_bytes(header[5:9], "big") & 0x7fffffff, payload

    def response(self, stream):
        body = bytearray()
        saw_headers = False
        for _ in range(500):
            kind, flags, sid, payload = self.read()
            if kind == 7:
                raise AssertionError(f"unexpected GOAWAY: {payload.hex()}")
            if kind == 3 and sid == stream:
                raise AssertionError(f"unexpected RST_STREAM: {payload.hex()}")
            if sid != stream:
                continue
            if kind == 1:
                saw_headers = True
                # The fixture returns status 200, static-table index 8.
                assert payload and payload[0] == 0x88, payload.hex()
                if flags & 1:
                    return bytes(body)
            if kind == 0:
                assert saw_headers
                body.extend(payload)
                if payload:
                    self.sock.sendall(window(0, len(payload)) + window(stream, len(payload)))
                if flags & 1:
                    return bytes(body)
        raise AssertionError("response exceeded frame count")


class ServerHarness(unittest.TestCase):
    binary = FIXTURE

    def setUp(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.server = subprocess.Popen([str(self.binary), str(self.port)], cwd=ROOT,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.addCleanup(self.stop)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.server.poll() is not None:
                self.fail(f"server exited on startup: {self.server.stderr.read()!r}")
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.1).close()
                return
            except OSError:
                time.sleep(0.02)
        self.fail("server did not start")

    def stop(self):
        if self.server.poll() is None:
            self.server.send_signal(signal.SIGINT)
            try:
                self.server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait(timeout=3)
                self.fail("server did not stop")
        if self.server.stderr:
            self.server.stderr.close()

    def peer(self, **kwargs):
        peer = Peer(self.port, **kwargs)
        self.addCleanup(peer.close)
        return peer


class H2EndToEnd(ServerHarness):
    def test_mixed_http1_and_http2_concurrent(self):
        peer = self.peer()
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as h1:
            h1.sendall(b"GET /binary HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            reply = b""
            while True:
                chunk = h1.recv(4096)
                if not chunk:
                    break
                reply += chunk
            self.assertIn(b"HTTP/1.1 200", reply)
            self.assertTrue(reply.endswith(b"\x00\xff\r\nA"))
        peer.sock.sendall(headers(1))
        self.assertEqual(peer.response(1), b"\x00\xff\r\nA")

    def test_multiplex_while_another_stream_is_incomplete(self):
        peer = self.peer()
        peer.sock.sendall(headers(1, b"/echo", b"POST", False) + headers(3))
        self.assertEqual(peer.response(3), b"\x00\xff\r\nA")
        peer.sock.sendall(frame(0, 1, 1, b"hello\x00\xff"))
        self.assertEqual(peer.response(1), b"hello\x00\xff")

    def test_large_binary_upload_and_response_flow_control(self):
        peer = self.peer()
        payload = bytes(range(256)) * 4096
        connection_credit = 65535
        stream_credit = peer.server_settings.get(4, 65535)
        self.assertLessEqual(stream_credit, 0x7fffffff)
        peer.sock.sendall(headers(1, b"/echo", b"POST", False))
        offset = 0
        while offset < len(payload):
            # Consumed-byte updates can be batched and need not arrive in pairs.
            # Spend existing credit before waiting, including a final short frame.
            while min(connection_credit, stream_credit) <= 0:
                kind, flags, sid, data = peer.read()
                if kind == 7:
                    self.fail(f"unexpected GOAWAY {data.hex()}")
                if kind == 3:
                    self.fail(f"unexpected RST_STREAM {sid}: {data.hex()}")
                if kind == 8:
                    self.assertEqual(len(data), 4)
                    increment = int.from_bytes(data, "big") & 0x7fffffff
                    self.assertGreater(increment, 0)
                    self.assertIn(sid, (0, 1))
                    if sid == 0:
                        connection_credit += increment
                        self.assertLessEqual(connection_credit, 0x7fffffff)
                    else:
                        stream_credit += increment
                        self.assertLessEqual(stream_credit, 0x7fffffff)
                elif kind == 4:
                    self.assertEqual(sid, 0)
                    self.assertEqual(len(data) % 6, 0)
                    if flags & 1:
                        self.assertEqual(data, b"")
                    else:
                        for setting_offset in range(0, len(data), 6):
                            key, value = struct.unpack(">HI", data[setting_offset:setting_offset + 6])
                            if key == 4:
                                self.assertLessEqual(value, 0x7fffffff)
                                stream_credit += value - peer.server_settings.get(4, 65535)
                            peer.server_settings[key] = value
                        peer.sock.sendall(frame(4, 1))
                elif kind == 6:
                    self.assertEqual((sid, len(data)), (0, 8))
                    if not flags & 1:
                        peer.sock.sendall(frame(6, 1, payload=data))
                elif kind in (0, 1, 9):
                    self.fail("echo response arrived before upload END_STREAM")
            size = min(8192, len(payload) - offset, connection_credit, stream_credit)
            chunk = payload[offset:offset + size]
            offset += size
            connection_credit -= len(chunk)
            stream_credit -= len(chunk)
            peer.sock.sendall(frame(0, 1 if offset == len(payload) else 0, 1, chunk))
        # END_STREAM can omit stream credit; receiving the complete binary echo
        # and then another response is the progress and connection-health proof.
        self.assertEqual(len(payload), 1024 * 1024)
        self.assertEqual(peer.response(1), payload)
        peer.sock.sendall(headers(3))
        self.assertEqual(peer.response(3), b"\x00\xff\r\nA")

    def test_zero_stream_window_blocks_data_but_not_ping_or_other_stream(self):
        peer = self.peer(initial_window=0)
        peer.sock.sendall(headers(1, b"/large") + frame(6, payload=b"abcdefgh") + headers(3))
        seen_headers = set()
        ping = False
        while seen_headers != {1, 3} or not ping:
            kind, flags, sid, data = peer.read()
            self.assertNotEqual(kind, 0, "DATA sent without stream credit")
            if kind == 1:
                seen_headers.add(sid)
            if kind == 6 and flags & 1:
                self.assertEqual(data, b"abcdefgh")
                ping = True
        peer.sock.sendall(window(3, 5))
        kind, flags, sid, data = peer.read()
        self.assertEqual((kind, sid, data), (0, 3, b"\x00\xff\r\nA"))
        self.assertTrue(flags & 1)
        peer.sock.sendall(window(1, 16384))
        kind, _, sid, data = peer.read()
        self.assertEqual((kind, sid, len(data)), (0, 1, 16384))

    def test_reset_preserves_other_stream(self):
        peer = self.peer()
        peer.sock.sendall(headers(1, b"/echo", b"POST", False) + frame(3, 0, 1, struct.pack(">I", 8)) + headers(3))
        self.assertEqual(peer.response(3), b"\x00\xff\r\nA")

    def test_malformed_data_stream_zero_sends_goaway(self):
        peer = self.peer()
        peer.sock.sendall(frame(0, 0, 0))
        kind, _, stream, payload = peer.read()
        self.assertEqual((kind, stream), (7, 0))
        self.assertEqual(int.from_bytes(payload[4:8], "big"), 1)

    def test_reset_on_never_opened_even_stream_sends_goaway(self):
        peer = self.peer()
        peer.sock.sendall(headers(3))
        self.assertEqual(peer.response(3), b"\x00\xff\r\nA")
        peer.sock.sendall(frame(3, 0, 2, struct.pack(">I", 8)))
        kind, _, stream, payload = peer.read()
        self.assertEqual((kind, stream), (7, 0))
        self.assertEqual(int.from_bytes(payload[4:8], "big"), 1)

    def test_fragmented_headers_and_continuation(self):
        peer = self.peer()
        whole = headers(1)
        block = whole[9:]
        peer.sock.sendall(frame(1, 1, 1, block[:3]) + frame(9, 4, 1, block[3:]))
        self.assertEqual(peer.response(1), b"\x00\xff\r\nA")

    def test_interleaved_header_block_sends_goaway(self):
        peer = self.peer()
        peer.sock.sendall(frame(1, 1, 1, b"\x82") + frame(6, payload=b"abcdefgh"))
        kind, _, stream, payload = peer.read()
        self.assertEqual((kind, stream), (7, 0))
        self.assertEqual(int.from_bytes(payload[4:8], "big"), 1)

    def test_invalid_hpack_sends_compression_error(self):
        peer = self.peer()
        peer.sock.sendall(frame(1, 5, 1, b"\x80"))  # HPACK index zero is invalid.
        kind, _, stream, payload = peer.read()
        self.assertEqual((kind, stream), (7, 0))
        self.assertEqual(int.from_bytes(payload[4:8], "big"), 9)

    def test_reset_stream_keeps_dynamic_hpack_synchronized(self):
        peer = self.peer()
        # This block inserts x-test: value but omits :method, causing a
        # stream-local rejection after its HPACK table update is applied.
        invalid = b"\x86\x84\x01\x09localhost\x40\x06x-test\x05value"
        peer.sock.sendall(frame(1, 5, 1, invalid))
        kind, _, stream, _ = peer.read()
        self.assertEqual((kind, stream), (3, 1))
        # DATA already in flight after the reset must be safely discarded;
        # index 62 below refers to the entry inserted by the rejected stream.
        good = headers(3) + b""  # append indexed entry to the HPACK block
        block = good[9:] + b"\xbe"
        peer.sock.sendall(frame(0, 0, 1, b"late") + frame(1, 5, 3, block))
        self.assertEqual(peer.response(3), b"\x00\xff\r\nA")

    def test_control_frames_progress_while_large_response_is_backpressured(self):
        peer = self.peer(initial_window=8 * 1024 * 1024, receive_buffer=16384)
        peer.sock.sendall(window(0, 8 * 1024 * 1024 - 65535) + headers(1, b"/huge"))
        # Stop reading until the server's TCP send buffer and bounded queue
        # have filled, then send control and another stream on that connection.
        self.assertTrue(peer.sock.recv(1, socket.MSG_PEEK))
        time.sleep(0.35)
        peer.sock.sendall(frame(6, payload=b"pingpong") +
                          frame(3, 0, 1, struct.pack(">I", 8)) + headers(3))
        seen_ping = False
        seen_headers = False
        body = bytearray()
        data_before_ping = 0
        for _ in range(2000):
            kind, flags, sid, data = peer.read()
            if kind == 7:
                self.fail(f"unexpected GOAWAY: {data.hex()}")
            if kind == 0 and sid == 1 and not seen_ping:
                data_before_ping += len(data)
            if kind == 6 and flags & 1:
                self.assertEqual(data, b"pingpong")
                seen_ping = True
            if kind == 1 and sid == 3:
                seen_headers = True
            if kind == 0 and sid == 3:
                body.extend(data)
                if flags & 1:
                    break
        self.assertTrue(seen_ping, "PING response was starved by queued DATA")
        self.assertTrue(seen_headers, "new stream was starved by queued DATA")
        self.assertGreater(data_before_ping, 65536, "large response did not reach the blocked write path")
        self.assertLess(data_before_ping, 8 * 1024 * 1024)
        self.assertEqual(body, b"\x00\xff\r\nA")

    def test_request_deadline_resets_only_stalled_stream(self):
        peer = self.peer()
        peer.sock.settimeout(5)
        peer.sock.sendall(headers(1, b"/echo", b"POST", False))
        kind, _, stream, payload = peer.read()
        self.assertEqual((kind, stream, int.from_bytes(payload, "big")), (3, 1, 8))
        peer.sock.sendall(headers(3))
        self.assertEqual(peer.response(3), b"\x00\xff\r\nA")

    def test_incomplete_header_block_deadline_sends_goaway(self):
        peer = self.peer()
        peer.sock.settimeout(5)
        peer.sock.sendall(frame(1, 1, 1, b"\x82"))
        kind, _, stream, payload = peer.read()
        self.assertEqual((kind, stream), (7, 0))
        self.assertEqual(int.from_bytes(payload[4:8], "big"), 11)

    def test_expect_continue_before_upload(self):
        peer = self.peer()
        request = headers(1, b"/echo", b"POST", False)
        expect = b"\x00\x06expect\x0c100-continue"
        peer.sock.sendall(frame(1, 4, 1, request[9:] + expect))
        kind, flags, sid, block = peer.read()
        self.assertEqual((kind, sid), (1, 1))
        self.assertFalse(flags & 1)
        # Literal :status=100, HPACK Huffman encoding on a fresh context.
        self.assertTrue(block.startswith(bytes.fromhex("48820801")), block.hex())
        peer.sock.sendall(frame(0, 1, 1, b"upload"))
        self.assertEqual(peer.response(1), b"upload")

    def test_unsupported_expectation_returns_417_before_upload(self):
        peer = self.peer()
        request = headers(1, b"/echo", b"POST", False)
        expect = b"\x00\x06expect\x0bunsupported"
        peer.sock.sendall(frame(1, 4, 1, request[9:] + expect))
        kind, _, sid, block = peer.read()
        self.assertEqual((kind, sid), (1, 1))
        # Literal :status=417 on a fresh context, with either HPACK string form.
        self.assertTrue(block.startswith(bytes.fromhex("4803343137")) or
                        block.startswith(bytes.fromhex("4883682eff")), block.hex())

    def test_unsupported_expectation_on_bodyless_request_returns_417(self):
        peer = self.peer()
        request = headers(1)
        expect = b"\x00\x06expect\x0bunsupported"
        peer.sock.sendall(frame(1, 5, 1, request[9:] + expect))
        kind, _, sid, block = peer.read()
        self.assertEqual((kind, sid), (1, 1))
        self.assertTrue(block.startswith(bytes.fromhex("4803343137")) or
                        block.startswith(bytes.fromhex("4883682eff")), block.hex())

    def test_incomplete_preface_deadline(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as sock:
            sock.settimeout(4)
            sock.sendall(b"PRI * HT")
            self.assertEqual(sock.recv(1), b"")

    def test_sigint_closes_active_h2_connection(self):
        peer = self.peer()
        # Ensure the peer's SETTINGS ACK has been processed before shutdown,
        # so unread setup bytes cannot turn a graceful close into a TCP reset.
        peer.sock.sendall(frame(6, payload=b"stopping"))
        self.assertEqual(peer.read(), (6, 1, 0, b"stopping"))
        deadline = time.monotonic() + 3
        self.server.send_signal(signal.SIGINT)
        received = bytearray(peer.buffer)
        peer.buffer = b""
        while True:
            remaining = deadline - time.monotonic()
            self.assertGreater(remaining, 0, "shutdown did not reach bounded EOF")
            peer.sock.settimeout(remaining)
            data = peer.sock.recv(65536)
            if not data:
                break
            received.extend(data)
            self.assertLessEqual(len(received), 65536, "unbounded shutdown output")
        offset = 0
        goaways = 0
        while offset < len(received):
            self.assertGreaterEqual(len(received) - offset, 9, "truncated shutdown frame header")
            header = received[offset:offset + 9]
            length = int.from_bytes(header[:3], "big")
            self.assertLessEqual(offset + 9 + length, len(received), "truncated shutdown frame payload")
            data = received[offset + 9:offset + 9 + length]
            self.assertEqual((header[3], header[4], int.from_bytes(header[5:9], "big") & 0x7fffffff), (7, 0, 0))
            self.assertGreaterEqual(len(data), 8)
            last_stream, code = struct.unpack(">II", data[:8])
            self.assertEqual(last_stream & 0x7fffffff, 0)
            self.assertEqual(code, 0, "shutdown GOAWAY was not NO_ERROR")
            goaways += 1
            offset += 9 + length
        self.assertGreater(goaways, 0, "shutdown omitted GOAWAY")
        self.assertEqual(offset, len(received))
        self.assertEqual(self.server.wait(timeout=max(0.1, deadline - time.monotonic())), 0)


class CurlH2EndToEnd(ServerHarness):
    binary = MAIN

    def test_curl_prior_knowledge(self):
        curl = shutil.which("curl")
        if curl is None:
            self.skipTest("curl is not installed")
        version = subprocess.run([curl, "--version"], capture_output=True, text=True, check=True)
        if "HTTP2" not in version.stdout:
            self.skipTest("curl was built without HTTP/2")
        result = subprocess.run([curl, "--http2-prior-knowledge", "--max-time", "3",
                                 "-sS", "-w", "\n%{http_version} %{http_code}",
                                 f"http://127.0.0.1:{self.port}/"],
                                capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, "Hello from lean-net!\n\n2 200")


if __name__ == "__main__":
    unittest.main()
