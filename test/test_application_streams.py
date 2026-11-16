#!/usr/bin/env python3
"""Actual HTTP/1 chunks/trailers and independently flow-controlled HTTP/2 streams."""
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from http2_test_support import H2Client, frame, window
from test_echo import unused_port
from test_http1_reactor import Reader
from test_websocket import read_ws

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / (".lake/build/bin/lean-net-stream-fixture" + (".exe" if sys.platform == "win32" else ""))

class ApplicationStreams(unittest.TestCase):
    def setUp(self):
        self.port = unused_port()
        self.log = tempfile.TemporaryFile(mode="w+")
        self.process = subprocess.Popen([str(BINARY), str(self.port)], stdout=self.log, stderr=self.log,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0)
        self.addCleanup(self.log.close)
        self.addCleanup(self.stop)
        for _ in range(200):
            if self.process.poll() is not None:
                self.log.seek(0); self.fail(self.log.read())
            try:
                self.assertEqual(self.get(b"/immediate").body, b"ok")
                return
            except OSError:
                time.sleep(.01)
        self.fail("stream fixture startup timeout")

    def stop(self):
        if self.process.poll() is None:
            self.process.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
            try: self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait(); self.fail("stream shutdown exceeded bound")
        if self.process.returncode:
            self.log.seek(0); self.fail(self.log.read())

    def connect(self):
        peer = socket.create_connection(("127.0.0.1", self.port), timeout=3)
        self.addCleanup(peer.close)
        return peer

    def get(self, path, method=b"GET"):
        with socket.create_connection(("127.0.0.1", self.port), timeout=3) as peer:
            peer.sendall(method + b" " + path + b" HTTP/1.1\r\nHost: localhost\r\n\r\n")
            return Reader(peer).response(head=method == b"HEAD")

    def h2(self, **kwargs):
        peer = H2Client(self.port, **kwargs)
        self.addCleanup(peer.close)
        return peer

    def test_trace_provenance_cannot_be_spoofed_and_matches_protocols(self):
        remote = b"00-1234567890abcdef1234567890abcdef-1234567890abcdef-01"
        for value, generated in [(None, b"true"), (b"invalid", b"true"), (remote, b"false")]:
            for protocol in [1, 2]:
                headers = [(b"trace-generated", b"false")]
                if value is not None: headers.append((b"traceparent", value))
                if protocol == 1:
                    peer = self.connect()
                    peer.sendall(b"GET /trace HTTP/1.1\r\nHost: localhost\r\n" + b"".join(k+b": "+v+b"\r\n" for k,v in headers) + b"\r\n")
                    result = Reader(peer).response().headers
                else:
                    peer = self.h2(); peer.request(1, b"/trace", headers=headers); peer.response(1)
                    result = dict(peer.headers[1][0].headers)
                self.assertEqual(result[b"x-generated"], generated)
                self.assertEqual(len(result[b"x-trace"]), 55)
                if value == remote: self.assertEqual(result[b"x-trace"], remote)

    def test_idle_worker_ticks_and_shared_drain_deadline(self):
        stats = self.get(b"/stats").headers
        first = int(stats[b"x-ticks"])
        interval = int(stats[b"x-tick-interval-ms"]) / 1000
        self.assertGreater(interval, 0)
        # Intervals are nominal, not a count guarantee for one short sleep:
        # Windows GetTickCount64 normally advances in 10--16ms steps, and the
        # driver coalesces missed ticks. Require several callbacks during one
        # quiet window, retrying within a bounded allowance for scheduler jitter.
        # No HTTP traffic is sent inside a window, and failed samples are not
        # accumulated, so request-triggered loop iterations cannot supply all
        # of the required idle progress across repeated observations.
        deadline = time.monotonic() + max(2.0, interval * 200)
        quiet = max(.05, interval * 8)
        samples = []
        progress = 0
        while time.monotonic() < deadline:
            window = min(quiet, deadline - time.monotonic())
            if window <= 0: break
            time.sleep(window)
            second = int(self.get(b"/stats").headers[b"x-ticks"])
            progress = second - first
            samples.append((window, progress))
            if progress >= 3: break
            first = second
            quiet = min(.5, quiet * 2)
        self.assertGreaterEqual(progress, 3, f"idle maintenance did not progress within its bound: {samples}")
        self.stop()
        self.log.seek(0)
        lines = self.log.read().splitlines()
        drain = [line.split() for line in lines if line.startswith("DRAIN ")]
        shutdown = [line.split() for line in lines if line.startswith("SHUTDOWN ")]
        self.assertEqual(len(drain), 1); self.assertEqual(len(shutdown), 1)
        start, cutoff = map(int, drain[0][1:3]); end = int(shutdown[0][1])
        self.assertGreaterEqual(end - start, 40)
        self.assertLessEqual(end, cutoff + 25)

    def test_unsolicited_websocket_push_without_inbound_browser_message(self):
        peer = self.connect()
        peer.sendall(b"GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nOrigin: https://stream.test\r\n\r\n")
        # Read the handshake bytewise so an adjacent pushed frame stays in socket.
        headers = b""
        while not headers.endswith(b"\r\n\r\n"): headers += peer.recv(1)
        self.assertIn(b"101", headers.split(b"\r\n", 1)[0])
        opcode, payload = read_ws(peer)
        self.assertEqual((opcode, payload), (0x81, b"unsolicited"))
        ping = self.connect()
        ping.sendall(b"GET /ws-ping HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nOrigin: https://stream.test\r\n\r\n")
        head = b""
        while not head.endswith(b"\r\n\r\n"): head += ping.recv(1)
        self.assertEqual(read_ws(ping), (0x89, b"unsolicited"))
        close = self.connect()
        close.sendall(b"GET /ws-close HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nOrigin: https://stream.test\r\n\r\n")
        head = b""
        while not head.endswith(b"\r\n\r\n"): head += close.recv(1)
        self.assertEqual(read_ws(close), (0x88, b"\x11\x38"))
        h2 = self.h2()
        h2.request(1, b"/ws", method=b"CONNECT", end_stream=False,
                   headers=[(b":protocol", b"websocket"), (b"sec-websocket-version", b"13"),
                            (b"origin", b"https://stream.test")])
        h2.until(lambda: len(h2.bodies[1]) >= 13)
        self.assertEqual(h2.bodies[1], b"\x81\x0bunsolicited")
        h2.request(3, b"/ws-close", method=b"CONNECT", end_stream=False,
                   headers=[(b":protocol", b"websocket"), (b"sec-websocket-version", b"13"),
                            (b"origin", b"https://stream.test")])
        h2.until(lambda: len(h2.bodies[3]) >= 4)
        self.assertEqual(h2.bodies[3], b"\x88\x02\x11\x38")

    def test_http1_chunks_arrive_before_producer_finishes_and_trailers_follow(self):
        peer = self.connect(); reader = Reader(peer)
        started = time.monotonic()
        peer.sendall(b"GET /chunks HTTP/1.1\r\nHost: localhost\r\n\r\n")
        headers = reader.until(b"\r\n\r\n")
        self.assertIn(b"transfer-encoding: chunked", headers.lower())
        size = int(reader.until(b"\r\n")[:-2], 16)
        self.assertEqual(reader.take(size + 2), b"first\r\n")
        self.assertLess(time.monotonic() - started, .17)
        result = bytearray(b"first")
        while True:
            size = int(reader.until(b"\r\n")[:-2], 16)
            if not size: break
            result += reader.take(size); self.assertEqual(reader.take(2), b"\r\n")
        trailers = reader.until(b"\r\n\r\n")
        self.assertEqual(result, b"firstsecond")
        self.assertIn(b"x-finished: yes", trailers.lower())

    def test_http1_pipeline_stays_ordered_while_streaming(self):
        peer = self.connect(); reader = Reader(peer)
        peer.sendall(b"GET /chunks HTTP/1.1\r\nHost: localhost\r\n\r\nGET /immediate HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertEqual(reader.response().body, b"firstsecond")
        self.assertEqual(reader.response().body, b"ok")

    def test_http2_streams_complete_independently_with_trailers(self):
        peer = self.h2(); peer.request(1, b"/chunks")
        peer.until(lambda: len(peer.bodies[1]) >= 5)
        self.assertEqual(peer.bodies[1], b"first")
        self.assertNotIn(1, peer.ended)
        peer.request(3, b"/immediate")
        self.assertEqual(peer.response(3), b"ok")
        self.assertNotIn(1, peer.ended)
        self.assertEqual(peer.response(1), b"firstsecond")
        self.assertIn((b"x-finished", b"yes"), peer.headers[1][-1].headers)

    def test_known_length_and_head_metadata_match_both_protocols(self):
        response = self.get(b"/known")
        self.assertEqual(response.body, b"firstsecond")
        self.assertEqual(response.headers[b"content-length"], b"11")
        response = self.get(b"/known", b"HEAD")
        self.assertEqual(response.body, b""); self.assertEqual(response.headers[b"content-length"], b"11")
        peer = self.h2(); peer.request(1, b"/known")
        self.assertEqual(peer.response(1), b"firstsecond")
        self.assertEqual(dict(peer.headers[1][0].headers)[b"content-length"], b"11")
        peer.request(3, b"/known", method=b"HEAD")
        self.assertEqual(peer.response(3), b"")
        self.assertEqual(dict(peer.headers[3][0].headers)[b"content-length"], b"11")

    def test_unknown_stream_head_omits_length_and_preserves_both_connections(self):
        get = self.get(b"/chunks")
        self.assertEqual(get.body, b"firstsecond")
        self.assertNotIn(b"content-length", get.headers)
        before = self.get(b"/stats").headers
        peer = self.connect(); reader = Reader(peer)
        peer.sendall(b"HEAD /chunks HTTP/1.1\r\nHost: localhost\r\n\r\nGET /immediate HTTP/1.1\r\nHost: localhost\r\n\r\n")
        # This HEAD deliberately has no length. Reader.response(head=True)
        # keeps its stricter known-length fixture checks, so read this head
        # independently without interpreting the next response as body bytes.
        lines = reader.until(b"\r\n\r\n")[:-4].split(b"\r\n")
        self.assertTrue(lines[0].startswith(b"HTTP/1.1 200 "))
        headers = {name.lower(): value.strip() for name, value in (line.split(b":", 1) for line in lines[1:])}
        self.assertNotIn(b"content-length", headers)
        self.assertNotIn(b"transfer-encoding", headers)
        self.assertNotIn(b"trailer", headers)
        self.assertEqual(reader.response().body, b"ok")
        after = self.get(b"/stats").headers
        self.assertEqual(after[b"x-produced"], before[b"x-produced"])
        self.assertEqual(after[b"x-closed"].count(b"complete"), before[b"x-closed"].count(b"complete") + 1)

        h2 = self.h2(); h2.request(1, b"/chunks")
        self.assertEqual(h2.response(1), b"firstsecond")
        self.assertNotIn(b"content-length", dict(h2.headers[1][0].headers))
        before = self.get(b"/stats").headers
        h2.request(3, b"/chunks", method=b"HEAD")
        self.assertEqual(h2.response(3), b"")
        headers = dict(h2.headers[3][0].headers)
        self.assertNotIn(b"content-length", headers)
        self.assertNotIn(b"transfer-encoding", headers)
        self.assertFalse(any(f.kind == 0 and f.stream == 3 for f in h2.frames))
        after = self.get(b"/stats").headers
        self.assertEqual(after[b"x-produced"], before[b"x-produced"])
        self.assertEqual(after[b"x-closed"].count(b"complete"), before[b"x-closed"].count(b"complete") + 1)
        h2.request(5, b"/immediate"); self.assertEqual(h2.response(5), b"ok")

        # A known stream length never overrides bodyless status semantics,
        # including when the request is HEAD.
        for index, status in enumerate([204, 205, 304]):
            path = f"/status{status}".encode()
            for method in [b"GET", b"HEAD"]:
                response = self.get(path, method)
                self.assertEqual(response.status, status)
                self.assertEqual(response.body, b"")
                self.assertEqual(response.headers.get(b"content-length"), b"0" if status == 205 else None)
                stream = 7 + index * 4 + (2 if method == b"HEAD" else 0)
                h2.request(stream, path, method=method)
                h2.until(lambda: stream in h2.ended or stream in h2.resets or bool(h2.goaways))
                self.assertIn(stream, h2.ended)
                self.assertNotIn(stream, h2.resets)
                self.assertEqual(bytes(h2.bodies[stream]), b"")
                self.assertEqual(dict(h2.headers[stream][0].headers)[b":status"], str(status).encode())
                self.assertEqual(dict(h2.headers[stream][0].headers).get(b"content-length"), b"0" if status == 205 else None)
        self.assertFalse(h2.goaways)

    def test_zero_window_prevents_producer_data_and_rst_cancels_once(self):
        peer = self.h2(settings_values=[(4, 0)], auto_window=False)
        peer.request(1, b"/big"); peer.ping_barrier()
        peer.request(3, b"/stats", method=b"HEAD")
        peer.response(3)
        self.assertEqual(dict(peer.headers[3][0].headers)[b"x-produced"], b"0")
        peer.send(window(1, 100)); peer.until(lambda: len(peer.bodies[1]) == 100)
        self.assertNotIn(1, peer.ended)
        peer.send(frame(3, stream=1, payload=struct.pack(">I", 8))); peer.ping_barrier(b"canceled")
        peer.request(5, b"/stats", method=b"HEAD"); peer.response(5)
        self.assertEqual(dict(peer.headers[5][0].headers)[b"x-closed"].count(b"streamReset"), 1)
        peer.request(7, b"/empty"); self.assertEqual(peer.response(7), b"")

    def test_bidirectional_upload_echoes_before_request_end_and_preserves_trailers(self):
        peer = self.h2()
        peer.request(1, b"/bidi", method=b"POST", end_stream=False,
                     headers=[(b"content-length", b"6")])
        peer.send(frame(0, stream=1, payload=b"one"))
        peer.until(lambda: len(peer.bodies[1]) == 3)
        self.assertEqual(peer.bodies[1], b"one")
        self.assertNotIn(1, peer.ended, "bidi response prematurely ended")
        peer.request(3, b"/immediate")
        self.assertEqual(peer.response(3), b"ok")
        peer.send(frame(0, stream=1, payload=b"two"))
        peer.send(frame(1, 5, 1, peer.encoder.encode([(b"x-client-finished", b"yes")])))
        self.assertEqual(peer.response(1), b"onetwo")
        self.assertIn((b"x-finished", b"yes"), peer.headers[1][-1].headers)
        self.assertFalse(peer.goaways)

    def test_large_client_upload_returns_credit_only_as_application_reads(self):
        peer = self.h2()
        data = bytes(range(256)) * 1024
        peer.request(1, b"/upload", method=b"POST", end_stream=False,
                     headers=[(b"content-length", str(len(data)).encode())])
        connection_credit, stream_credit = 65535, peer.server_settings.get(4, 65535)
        offset = 0
        while offset < len(data):
            count = min(16384, connection_credit, stream_credit, len(data) - offset)
            if count:
                peer.send(frame(0, stream=1, payload=data[offset:offset + count]))
                offset += count; connection_credit -= count; stream_credit -= count
            else:
                received = peer.read()
                if received.kind == 8:
                    increment = int.from_bytes(received.payload, "big")
                    if received.stream == 0: connection_credit += increment
                    if received.stream == 1: stream_credit += increment
                self.assertFalse(peer.goaways)
                self.assertFalse(peer.resets)
        peer.send(frame(1, 5, 1, peer.encoder.encode([(b"x-client-finished", b"yes")])))
        self.assertEqual(peer.response(1), data)
        self.assertIn((b"x-client-finished", b"yes"), peer.headers[1][0].headers)

    def test_early_response_discards_remaining_upload_without_killing_connection(self):
        peer = self.h2()
        peer.request(1, b"/early", method=b"POST", end_stream=False)
        self.assertEqual(peer.response(1), b"accepted")
        peer.send(frame(0, 1, 1, b"discarded upload"))
        peer.request(3, b"/immediate")
        self.assertEqual(peer.response(3), b"ok")
        self.assertFalse(peer.goaways)

    def test_large_stream_survives_small_output_budget(self):
        self.assertEqual(self.get(b"/big").body, b"A" * (2 * 1024 * 1024))
        peer = self.h2(); peer.request(1, b"/big")
        self.assertEqual(peer.response(1), b"A" * (2 * 1024 * 1024))

    def test_invalid_stream_trailer_cancels_once_without_injection(self):
        peer = self.h2(); peer.request(1, b"/bad-trailer")
        peer.until(lambda: 1 in peer.resets)
        self.assertTrue(all(b"x-injected" not in str(block.headers).encode() for block in peer.headers[1]))
        peer.request(3, b"/stats", method=b"HEAD"); peer.response(3)
        self.assertEqual(dict(peer.headers[3][0].headers)[b"x-closed"].count(b"failed"), 1)
        peer.request(5, b"/immediate"); self.assertEqual(peer.response(5), b"ok")

    def test_idle_timeout_resets_only_affected_http2_stream(self):
        peer = self.h2(); peer.request(1, b"/timeout")
        peer.until(lambda: 1 in peer.resets)
        peer.request(3, b"/immediate"); self.assertEqual(peer.response(3), b"ok")
        peer.request(5, b"/stats", method=b"HEAD"); peer.response(5)
        self.assertEqual(dict(peer.headers[5][0].headers)[b"x-closed"].count(b"timeout"), 1)
        self.assertFalse(peer.goaways)

if __name__ == "__main__": unittest.main()
