#!/usr/bin/env python3
"""Strict native HTTP/2 wire acceptance beyond the RFC7540 h2spec baseline.

Uses a pinned independent HPACK codec, bounded reads, and actual native server
processes. Stream-error tests require RST_STREAM and preservation of a healthy
stream; a GOAWAY accepted by h2spec is not a substitute in these probes.
"""
from collections import Counter
import os
from pathlib import Path
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import unittest

from http2_test_support import BINARY, H2Client, PREFACE, frame, priority_update, settings, window
from test_echo import unused_port
from test_http1_reactor import Reader, resource_count

ROOT = Path(__file__).resolve().parents[1]
SUFFIX = ".exe" if sys.platform == "win32" else ""
BINARY_PATH = Path(os.environ.get("LEAN_NET_HTTP2_REACTOR_BIN", ROOT / f".lake/build/bin/lean-net-http2-reactor-fixture{SUFFIX}"))
sys.path.insert(0, str(ROOT / "tls/test"))
import test_tls_reactor as tls_cases
from tls_test_support import NAMES, context as tls_context, curl_binary


class ServerCase:
    mode = "h2-only"
    workers = 1

    def setUp(self):
        self.assertTrue(BINARY_PATH.is_file(), f"build the HTTP/2 reactor fixture: {BINARY_PATH}")
        self.port = unused_port(); self.log = tempfile.TemporaryFile(mode="w+")
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        self.server = subprocess.Popen([str(BINARY_PATH), str(self.port), self.mode, str(self.workers)],
                                       stdout=self.log, stderr=self.log, creationflags=flags)
        self.stop_requested = False
        self.addCleanup(self.log.close); self.addCleanup(self.stop_server)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.server.poll() is not None:
                self.log.seek(0); self.fail(f"fixture startup exit {self.server.returncode}: {self.log.read()}")
            try:
                peer = H2Client(self.port)
                try:
                    peer.request(1); self.assertEqual(peer.response(1), BINARY)
                finally: peer.close()
                return
            except (ConnectionError, socket.timeout): time.sleep(.025)
        self.fail("native HTTP/2 fixture did not become ready")

    def stop_server(self):
        if self.server.poll() is None:
            self.request_stop()
            try: self.server.wait(timeout=6)
            except subprocess.TimeoutExpired:
                self.server.kill(); self.server.wait(timeout=5)
                self.fail("native HTTP/2 shutdown exceeded bound")
        if self.server.returncode:
            self.log.seek(0); self.fail(f"fixture exit {self.server.returncode}: {self.log.read()}")

    def request_stop(self):
        if not self.stop_requested:
            self.stop_requested = True
            self.server.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)

    def peer(self, **kwargs):
        peer = H2Client(self.port, **kwargs); self.addCleanup(peer.close); return peer

    def assert_rst(self, peer, stream, code):
        peer.until(lambda: stream in peer.resets or bool(peer.goaways))
        self.assertFalse(peer.goaways, f"stream error killed connection: {peer.goaways}")
        self.assertEqual(peer.resets[stream], code)

    def assert_goaway(self, peer, code):
        peer.until(lambda: bool(peer.goaways))
        self.assertEqual(peer.goaways[-1][1], code, peer.goaways)

    def queued_pair(self, headers1=(), headers3=()):
        peer = self.peer(settings_values=[(4, 0)], auto_window=False)
        peer.send(window(0, 4 * 1024 * 1024))
        peer.request(1, b"/priority-a", headers=headers1)
        peer.request(3, b"/priority-b", headers=headers3)
        peer.ping_barrier()
        peer.until(lambda: bool(peer.headers[1] and peer.headers[3]) or bool(peer.goaways) or bool(peer.resets))
        self.assertEqual(peer.data_order, [], "zero stream windows did not gate response DATA")
        self.assertTrue(peer.headers[1] and peer.headers[3])
        return peer

    def open_windows(self, peer, size=512 * 1024):
        peer.send(settings([(4, size)]))


class HTTP2Acceptance(ServerCase, unittest.TestCase):
    def test_h2_only_invalid_preface_uses_goaway(self):
        peer = self.peer(handshake=False, auto_ack=False)
        peer.send(PREFACE[:-1] + b"X" + settings())
        self.assert_goaway(peer, 1)

    def test_defaults_and_multiplexed_exact_binary_bodies(self):
        peer = self.peer()
        self.assertEqual(peer.server_settings[3], 128)
        self.assertEqual(peer.server_settings[6], 65536)
        peer.send(b"".join(frame(1, 5, stream, peer.encode_request()) for stream in range(1, 200, 2)))
        for stream in range(1, 200, 2):
            self.assertEqual(peer.response(stream), BINARY)
        self.assertFalse(peer.resets); self.assertFalse(peer.goaways)

    def test_every_request_header_block_split_and_fragmented_preface(self):
        for cut in range(1, 25):
            with self.subTest(preface_cut=cut):
                raw = socket.create_connection(("127.0.0.1", self.port), timeout=5)
                peer = H2Client(sock=raw, handshake=False)
                try:
                    peer.send(PREFACE[:cut]); peer.send(PREFACE[cut:] + settings())
                    peer.request(1); self.assertEqual(peer.response(1), BINARY)
                finally: peer.close()
        first = self.peer(); encoded = first.encode_request(b"/binary", headers=[(b"x-fragment", b"abcdef")]); first.close()
        for cut in range(len(encoded) + 1):
            with self.subTest(header_cut=cut):
                peer = self.peer()
                block = peer.encode_request(b"/binary", headers=[(b"x-fragment", b"abcdef")])
                peer.send(frame(1, 1, 1, block[:cut]) + frame(9, 4, 1, block[cut:]))
                self.assertEqual(peer.response(1), BINARY)
                peer.close()

    def test_large_upload_and_response_flow_control(self):
        peer = self.peer()
        payload = b"".join(struct.pack(">I", i) + bytes([i & 255]) * 4092 for i in range(40)) + b"\x00\xff"
        peer.request(1, b"/echo", method=b"POST", end_stream=False)
        offset = 0; connection_credit = 65535; stream_credit = peer.server_settings.get(4, 65535)
        while offset < len(payload):
            # A conforming peer may batch WINDOW_UPDATE until a consumption
            # threshold. Spend the advertised credit rather than requiring an
            # update after every small DATA frame.
            if min(connection_credit, stream_credit) == 0:
                current = peer.read()
                self.assertFalse(peer.goaways); self.assertFalse(peer.resets)
                if current.kind == 8:
                    credit = int.from_bytes(current.payload, "big") & 0x7FFFFFFF
                    if current.stream == 0: connection_credit += credit
                    if current.stream == 1: stream_credit += credit
                continue
            count = min(8192, connection_credit, stream_credit, len(payload) - offset)
            part = payload[offset:offset + count]
            peer.send(frame(0, int(offset + count == len(payload)), 1, part))
            offset += count; connection_credit -= count; stream_credit -= count
        self.assertEqual(peer.response(1), payload)
        peer.request(3, b"/huge"); self.assertEqual(peer.response(3), b"A" * (2 * 1024 * 1024))

    def test_request_trailers_are_not_merged_into_headers(self):
        peer = self.peer(); peer.request(1, b"/trailers", method=b"POST", end_stream=False)
        peer.send(frame(0, 0, 1, b"body\x00\xff") + frame(1, 5, 1, peer.encoder.encode([(b"x-check", b"yes")])))
        self.assertEqual(peer.response(1), b"body\x00\xff|yes")

    def test_response_trailers_end_stream_after_data(self):
        peer = self.peer(); peer.request(1, b"/response-trailers")
        self.assertEqual(peer.response(1), BINARY)
        self.assertEqual(len(peer.headers[1]), 2)
        self.assertEqual(dict(peer.headers[1][1].headers), {b"x-finished": b"yes"})
        self.assertTrue(peer.headers[1][1].end_stream)
        self.assertTrue(all(not f.flags & 1 for f in peer.frames if f.kind == 0 and f.stream == 1))

    def test_informational_headers_do_not_end_the_final_response(self):
        peer = self.peer(); peer.request(1, b"/informational")
        peer.until(lambda: 1 in peer.ended)
        self.assertEqual([dict(block.headers)[b":status"] for block in peer.headers[1]], [b"103", b"102", b"200"])
        self.assertTrue(all(not block.end_stream for block in peer.headers[1][:2]))
        self.assertEqual(bytes(peer.bodies[1]), b"ok")

    def test_head_and_bodyless_statuses_do_not_emit_body(self):
        peer = self.peer(); peer.request(1, b"/head", method=b"HEAD")
        peer.request(3, b"/204"); peer.request(5, b"/304")
        peer.until(lambda: {1, 3, 5} <= peer.ended)
        self.assertFalse(peer.goaways); self.assertFalse(peer.resets)
        self.assertEqual(dict(peer.headers[1][0].headers)[b"content-length"], b"14")
        for stream, status in [(3, b"204"), (5, b"304")]:
            fields = dict(peer.headers[stream][0].headers)
            self.assertEqual(fields[b":status"], status); self.assertNotIn(b"content-length", fields)
        self.assertTrue(all(not peer.bodies[stream] for stream in (1, 3, 5)))

    def test_stream_frame_size_errors_reset_only_the_offending_stream(self):
        # RFC9113 §6.3 makes malformed PRIORITY lengths stream errors.
        # RST_STREAM / WINDOW_UPDATE length errors are connection errors (§6.4/6.9).
        cases = [(2, b"\x00" * 4), (2, b"\x00" * 6)]
        for kind, payload in cases:
            with self.subTest(kind=kind, length=len(payload)):
                peer = self.peer(settings_values=[(4, 0)], auto_window=False)
                peer.request(1, b"/echo", method=b"POST", end_stream=False)
                peer.request(3); peer.ping_barrier()
                peer.send(frame(kind, 0, 1, payload)); self.assert_rst(peer, 1, 6)
                peer.send(window(3, 5)); self.assertEqual(peer.response(3), BINARY)
                peer.close()

    def test_zero_stream_window_increment_is_stream_scoped(self):
        peer = self.peer(settings_values=[(4, 0)], auto_window=False)
        peer.request(1, b"/large"); peer.request(3); peer.ping_barrier()
        peer.send(window(1, 0)); self.assert_rst(peer, 1, 1)
        peer.send(window(3, 5)); self.assertEqual(peer.response(3), BINARY)

    def test_stream_frame_error_consumes_its_bytes_and_preserves_coalesced_request(self):
        peer = self.peer(); peer.request(1, b"/echo", method=b"POST", end_stream=False)
        healthy = frame(1, 5, 3, peer.encode_request())
        peer.send(frame(2, 0, 1, b"bad!") + healthy)
        self.assert_rst(peer, 1, 6)
        self.assertEqual(peer.response(3), BINARY)

    def test_stream_window_overflow_preserves_another_stream(self):
        peer = self.peer(settings_values=[(4, 0)], auto_window=False)
        # Keep stream1 awaiting its request body, so its send window cannot be
        # spent between updates. Overflow must not rely on TCP coalescing.
        peer.request(1, b"/echo", method=b"POST", end_stream=False)
        peer.request(3); peer.ping_barrier()
        peer.send(window(1, 0x7FFFFFFF) + window(1, 1)); self.assert_rst(peer, 1, 3)
        peer.send(window(3, 5)); self.assertEqual(peer.response(3), BINARY)

    def test_connection_window_overflow_is_goaway_flow_control_error(self):
        peer = self.peer(); peer.send(window(0, 0x7FFFFFFF)); self.assert_goaway(peer, 3)

    def test_invalid_connection_frame_sizes_and_settings(self):
        cases = [(frame(8, payload=b"abc"), 6), (frame(4, 1, payload=b"123456"), 6),
                 (frame(3, stream=1, payload=b"abc"), 6), (frame(8, stream=1, payload=b"abc"), 6),
                 (frame(8, stream=1, payload=b"abcde"), 6),
                 (settings([(2, 2)]), 1), (settings([(4, 0x80000000)]), 3),
                 (settings([(5, 16383)]), 1), (frame(6, payload=b"short"), 6)]
        for wire, code in cases:
            with self.subTest(wire=wire.hex(), code=code):
                peer = self.peer()
                if int.from_bytes(wire[5:9], "big") & 0x7FFFFFFF:
                    peer.request(1, b"/echo", method=b"POST", end_stream=False)
                peer.send(wire); self.assert_goaway(peer, code); peer.close()

    def test_unknown_frame_and_setting_are_ignored_and_acknowledged(self):
        peer = self.peer(); before = len(peer.frames)
        peer.send(frame(0xFA, 0xFF, 0, b"future extension") + settings([(0xF0F0, 123)]))
        peer.until(lambda: any(f.kind == 4 and f.flags & 1 for f in peer.frames[before:]))
        peer.request(1); self.assertEqual(peer.response(1), BINARY)

    def test_continuation_interleaving_is_connection_error(self):
        peer = self.peer(); block = peer.encode_request()
        peer.send(frame(1, 1, 1, block[:2]) + frame(6, payload=b"abcdefgh") + frame(9, 4, 1, block[2:]))
        self.assert_goaway(peer, 1)

    def test_large_response_header_block_uses_valid_continuations(self):
        peer = self.peer(); peer.request(1, b"/big-headers")
        self.assertEqual(peer.response(1), BINARY)
        headers = dict(peer.headers[1][0].headers)
        self.assertEqual(headers[b"x-large"], b"x" * 32000)
        self.assertTrue(any(f.kind == 9 for f in peer.frames))

    def test_sensitive_response_headers_are_never_indexed(self):
        peer = self.peer()
        for stream in (1, 3):
            peer.request(stream, b"/sensitive"); self.assertEqual(peer.response(stream), BINARY)
            fields = [h for h in peer.headers[stream][0].headers if h[0] in (b"authorization", b"cookie", b"set-cookie")]
            self.assertEqual(len(fields), 3)
            self.assertTrue(all(not h.indexable for h in fields), fields)
            self.assertFalse(any(name in (b"authorization", b"cookie", b"set-cookie") for name, _ in peer.decoder.header_table.dynamic_entries))

    def test_hpack_table_size_update_and_huffman_peer_decode(self):
        peer = self.peer(); peer.decoder.max_allowed_table_size = 128
        peer.send(settings([(1, 128)])); peer.ping_barrier()
        for stream in range(1, 20, 2):
            peer.request(stream); self.assertEqual(peer.response(stream), BINARY)
            self.assertLessEqual(peer.decoder.header_table_size, 128)

    def test_peer_frame_size_change_bounds_response_header_fragments(self):
        peer = self.peer(settings_values=[(5, 32768)])
        peer.request(1, b"/big-headers"); self.assertEqual(peer.response(1), BINARY)
        peer.send(settings([(5, 16384)])); peer.ping_barrier()
        peer.max_frame_size = 16384
        before = len(peer.frames)
        peer.request(3, b"/big-headers"); self.assertEqual(peer.response(3), BINARY)
        response_frames = peer.frames[before:]
        self.assertTrue(any(current.kind == 9 for current in response_frames))
        self.assertTrue(all(len(current.payload) <= 16384 for current in response_frames))
        self.assertEqual(dict(peer.headers[3][0].headers)[b"x-large"], b"x" * 32000)

    def test_peer_header_list_limit_falls_back_without_killing_other_streams(self):
        # Large enough for ordinary responses with default security headers.
        peer = self.peer(settings_values=[(6, 1024)])
        peer.request(1, b"/big-headers"); peer.request(3)
        peer.until(lambda: 1 in peer.ended or 1 in peer.resets or bool(peer.goaways))
        self.assertFalse(peer.goaways); self.assertNotIn(1, peer.resets)
        self.assertEqual(dict(peer.headers[1][0].headers)[b":status"], b"500")
        for block in peer.headers[1]:
            self.assertLessEqual(sum(len(name) + len(value) + 32 for name, value in block.headers), 1024)
        self.assertEqual(peer.response(3), BINARY)

    def test_push_is_off_by_default(self):
        peer = self.peer(); peer.request(1, b"/push-parent")
        self.assertEqual(peer.response(1), b"parent"); peer.ping_barrier()
        self.assertEqual(peer.promises, {})

    def test_sigint_goaway_drains_existing_streams(self):
        peer = self.peer(settings_values=[(4, 0)], auto_window=False)
        peer.send(window(0, 1024 * 1024)); peer.request(1, b"/large"); peer.request(3)
        peer.ping_barrier(); peer.until(lambda: bool(peer.headers[1] and peer.headers[3]))
        self.request_stop()
        peer.until(lambda: bool(peer.goaways))
        self.assertEqual(peer.goaways[-1][1], 0); self.assertGreaterEqual(peer.goaways[-1][0], 3)
        peer.send(settings([(4, 512 * 1024)]))
        peer.until(lambda: {1, 3} <= peer.ended)
        self.assertEqual(bytes(peer.bodies[1]), b"A" * (256 * 1024)); self.assertEqual(bytes(peer.bodies[3]), BINARY)
        self.assertEqual(self.server.wait(timeout=5), 0)

    def test_peer_goaway_preserves_existing_client_streams_until_drained(self):
        peer = self.peer(settings_values=[(4, 0)], auto_window=False)
        peer.send(window(0, 1024 * 1024)); peer.request(1, b"/large"); peer.request(3)
        peer.until(lambda: bool(peer.headers[1] and peer.headers[3]))
        # The last-stream field limits server-initiated push IDs. A zero value
        # must not discard the already admitted odd client streams.
        peer.send(frame(7, payload=struct.pack(">II", 0, 0)) + settings([(4, 512 * 1024)]))
        peer.until(lambda: {1, 3} <= peer.ended)
        self.assertEqual(bytes(peer.bodies[1]), b"A" * (256 * 1024))
        self.assertEqual(bytes(peer.bodies[3]), BINARY)
        self.assertFalse(peer.resets)

    def test_peer_goaway_and_split_ping_keep_control_frames_live(self):
        # Peer-only GOAWAY keeps connection-control frames live until EOF or
        # local shutdown. Require the ACK even though h2spec also permits EOF.
        for mode in ("split", "coalesced"):
            for code in (0, 255):
                for attempt in range(10):
                    with self.subTest(mode=mode, code=code, attempt=attempt):
                        peer = self.peer()
                        try:
                            goaway = frame(7, payload=struct.pack(">II", 0, code) + b"h2spec")
                            ping = frame(6, payload=b"h2spec\0\0")
                            if mode == "split":
                                peer.send(goaway); peer.send(ping)
                            else:
                                peer.send(goaway + ping)
                            peer.until(lambda: any(current.kind == 6 and current.flags & 1 and
                                                   current.payload == b"h2spec\0\0" for current in peer.frames))
                            peer.request(1); self.assert_rst(peer, 1, 7)
                            peer.ping_barrier(b"afterrst")
                        finally:
                            peer.close()

    def test_connection_cycles_release_native_resources(self):
        for _ in range(8):
            peer = self.peer(); peer.request(1); peer.response(1); peer.close()
        before = resource_count(self.server.pid)
        for _ in range(1000):
            peer = H2Client(self.port)
            try: peer.request(1); self.assertEqual(peer.response(1), BINARY)
            finally: peer.close()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            after = resource_count(self.server.pid)
            if after <= before: break
            time.sleep(.05)
        self.assertLessEqual(after, before)


class PriorityAcceptance(ServerCase, unittest.TestCase):
    def test_priority_header_urgency_controls_first_data(self):
        peer = self.queued_pair([(b"priority", b"u=7")], [(b"priority", b"u=0")])
        self.open_windows(peer); peer.until(lambda: bool(peer.data_order))
        self.assertEqual(peer.data_order[0][0], 3)
        self.assertEqual(peer.response(1), b"A" * (256 * 1024)); self.assertEqual(peer.response(3), b"B" * (256 * 1024))

    def test_active_priority_update_overrides_header(self):
        peer = self.queued_pair([(b"priority", b"u=7")], [(b"priority", b"u=1")])
        peer.send(priority_update(1, b"u=0")); peer.ping_barrier(); self.open_windows(peer)
        peer.until(lambda: bool(peer.data_order)); self.assertEqual(peer.data_order[0][0], 1)

    def test_idle_update_precedes_later_request_header(self):
        peer = self.peer(settings_values=[(4, 0)], auto_window=False)
        peer.send(window(0, 4 * 1024 * 1024) + priority_update(1, b"u=0"))
        peer.request(1, b"/priority-a", headers=[(b"priority", b"u=7")])
        peer.request(3, b"/priority-b", headers=[(b"priority", b"u=1")]); peer.ping_barrier()
        self.open_windows(peer); peer.until(lambda: bool(peer.data_order)); self.assertEqual(peer.data_order[0][0], 1)

    def test_closed_priority_updates_and_malformed_fields_are_ignored(self):
        peer = self.peer(); peer.request(1); self.assertEqual(peer.response(1), BINARY)
        peer.send(priority_update(1, b"u=0") + priority_update(3, b'u="unterminated'))
        peer.request(3, headers=[(b"priority", b"u=1,")]); self.assertEqual(peer.response(3), BINARY)
        self.assertFalse(peer.goaways)

    def test_malformed_priority_update_envelopes_fail_connection(self):
        cases = [(frame(0x10, 0, 1, struct.pack(">I", 1) + b"u=0"), 1),
                 (frame(0x10, payload=b"abc"), 6), (priority_update(0, b"u=0"), 1)]
        for wire, code in cases:
            with self.subTest(wire=wire.hex()):
                peer = self.peer(); peer.send(wire); self.assert_goaway(peer, code); peer.close()

    def test_equal_urgency_incremental_streams_round_robin(self):
        peer = self.queued_pair([(b"priority", b"u=3, i")], [(b"priority", b"u=3, i")])
        self.open_windows(peer); peer.until(lambda: len(peer.data_order) >= 8)
        ids = [stream for stream, _, _ in peer.data_order[:8]]
        self.assertEqual(set(ids), {1, 3}); self.assertTrue(all(a != b for a, b in zip(ids, ids[1:])), ids)

    def test_nonincremental_burst_does_not_starve_equal_urgency_incremental(self):
        peer = self.queued_pair([(b"priority", b"u=3")], [(b"priority", b"u=3, i")])
        self.open_windows(peer); peer.until(lambda: any(stream == 3 for stream, _, _ in peer.data_order))
        prefix = []
        for current in peer.data_order:
            if current[0] == 3: break
            prefix.append(current)
        self.assertTrue(prefix and all(stream == 1 for stream, _, _ in prefix))
        self.assertLessEqual(sum(size for _, size, _ in prefix), 65536)
        self.assertFalse(any(ended for _, _, ended in prefix), "incremental peer starved until other response ended")

    def test_equal_urgency_nonincremental_streams_serialize(self):
        peer = self.queued_pair([(b"priority", b"u=3")], [(b"priority", b"u=3")])
        self.open_windows(peer); peer.until(lambda: 1 in peer.ended or 3 in peer.ended)
        ids = [stream for stream, _, _ in peer.data_order]
        first = ids[0]; self.assertTrue(all(stream == first for stream in ids), ids)


class LimitsAcceptance(ServerCase, unittest.TestCase):
    mode = "limits"

    def test_advertised_concurrency_limit_and_refused_stream_isolated(self):
        peer = self.peer(); self.assertEqual(peer.server_settings[3], 2); self.assertEqual(peer.server_settings[4], 1024)
        peer.request(1, b"/echo", method=b"POST", end_stream=False)
        peer.request(3, b"/echo", method=b"POST", end_stream=False)
        peer.request(5); self.assert_rst(peer, 5, 7)
        peer.send(frame(0, 1, 1, b"one") + frame(0, 1, 3, b"three"))
        self.assertEqual(peer.response(1), b"one"); self.assertEqual(peer.response(3), b"three")
        peer.request(7); self.assertEqual(peer.response(7), BINARY)

    def test_receive_stream_window_violation_preserves_healthy_stream(self):
        peer = self.peer(); peer.request(1, b"/echo", method=b"POST", end_stream=False); peer.request(3)
        peer.send(frame(0, 0, 1, b"A" * 1025)); self.assert_rst(peer, 1, 3)
        self.assertEqual(peer.response(3), BINARY)

    def test_idle_priority_state_is_bounded(self):
        peer = self.peer(); peer.send(priority_update(1, b"u=1") + priority_update(3, b"u=2") + priority_update(5, b"u=3"))
        self.assert_goaway(peer, 1)

    def test_compressed_header_and_continuation_budgets_are_bounded(self):
        peer = self.peer(); block = peer.encode_request(headers=[(b"x-large", b"a" * 8000)])
        peer.send(frame(1, 5, 1, block)); self.assert_goaway(peer, 11)
        second = self.peer(); block = second.encode_request()
        second.send(frame(1, 1, 1, b"") + b"".join(frame(9, 0, 1, b"") for _ in range(5)) + frame(9, 4, 1, block))
        self.assert_goaway(second, 11)


class PushAcceptance(ServerCase, unittest.TestCase):
    mode = "push"

    def test_peer_disabled_push_emits_no_promise(self):
        peer = self.peer(settings_values=[(2, 0)]); peer.request(1, b"/push-parent")
        self.assertEqual(peer.response(1), b"parent"); peer.ping_barrier(); self.assertFalse(peer.promises)

    def test_promises_are_even_same_origin_and_never_index_sensitive_fields(self):
        peer = self.peer(); peer.request(1, b"/push-parent")
        self.assertEqual(peer.response(1), b"parent"); peer.until(lambda: len(peer.promises) == 2)
        self.assertEqual(set(peer.promises), {2, 4})
        targets = {}
        for stream, promise in peer.promises.items():
            values = dict(promise.headers); self.assertEqual(promise.parent, 1)
            self.assertEqual(values[b":method"], b"GET"); self.assertEqual(values[b":scheme"], b"http")
            self.assertEqual(values[b":authority"], b"localhost"); targets[values[b":path"]] = stream
            for field in promise.headers:
                if field[0] in (b"authorization", b"cookie"): self.assertFalse(field.indexable)
        self.assertEqual(peer.response(targets[b"/pushed-a"]), b"pushed-a")
        self.assertEqual(peer.response(targets[b"/pushed-b"]), b"pushed-b")
        parent_end = next(index for index, item in enumerate(peer.frames) if item.stream == 1 and item.kind in (0, 1) and item.flags & 1)
        self.assertTrue(all(index < parent_end for index, item in enumerate(peer.frames) if item.kind == 5),
                        "PUSH_PROMISE was sent after the parent stream closed")
        cookie = [field for field in peer.headers[targets[b"/pushed-a"]][0].headers if field[0] == b"set-cookie"]
        self.assertTrue(cookie and all(not field.indexable for field in cookie))
        self.assertFalse(any(name in (b"authorization", b"cookie", b"set-cookie") for name, _ in peer.decoder.header_table.dynamic_entries))

    def test_pushed_data_respects_stream_window_and_cancel_isolated(self):
        peer = self.peer(settings_values=[(4, 0)], auto_window=False); peer.request(1, b"/push-parent")
        peer.until(lambda: {2, 4} <= peer.promises.keys() and bool(peer.headers[1]))
        self.assertEqual(set(peer.promises), {2, 4}); self.assertEqual(peer.data_order, [])
        peer.send(frame(3, stream=2, payload=struct.pack(">I", 8)) + settings([(4, 1024)]))
        self.assertEqual(peer.response(1), b"parent"); self.assertEqual(peer.response(4), b"pushed-b")
        peer.ping_barrier(); self.assertFalse(any(stream == 2 for stream, _, _ in peer.data_order))
        peer.request(3); self.assertEqual(peer.response(3), BINARY)


class MixedAcceptance(ServerCase, unittest.TestCase):
    mode = "mixed"

    def test_verified_binary_curl_cleartext_matrix(self):
        curl = os.environ.get("LEAN_NET_TEST_CURL", "/opt/homebrew/opt/curl/bin/curl" if Path("/opt/homebrew/opt/curl/bin/curl").is_file() else "curl")
        for flag, version in (("--http1.0", b"1"), ("--http1.1", b"1.1"), ("--http2-prior-knowledge", b"2")):
            result = subprocess.run([curl, flag, "--noproxy", "*", "--fail", "--silent", "--show-error", "--write-out", "\nVERSION:%{http_version}", f"http://127.0.0.1:{self.port}/binary"], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, BINARY + b"\nVERSION:" + version)

    def test_http_and_h2_native_clients_progress_together(self):
        peer = self.peer(); peer.request(1, b"/large")
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(b"GET /binary HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            self.assertEqual(Reader(sock).response().body, BINARY)
        self.assertEqual(peer.response(1), b"A" * (256 * 1024))


class FourWorkers(ServerCase, unittest.TestCase):
    workers = 4

    def test_real_h2_requests_reach_all_worker_owners(self):
        counts = Counter(); total = 256 if sys.platform.startswith("linux") else 32
        for _ in range(total):
            peer = self.peer(); peer.request(1, b"/worker"); body = peer.response(1)
            headers = dict(peer.headers[1][0].headers); self.assertEqual(headers[b"x-worker"], body)
            counts[int(body)] += 1; peer.close()
        self.assertEqual(set(counts), set(range(self.workers)), counts); self.assertEqual(sum(counts.values()), total)
        print("HTTP/2 worker counts:", dict(sorted(counts.items())), flush=True)


class TLSMatrixAcceptance(tls_cases.ServerCase, unittest.TestCase):
    def test_verified_tls_peer_goaway_keeps_control_frames_live(self):
        for mode in ("split", "coalesced"):
            for code in (0, 255):
                with self.subTest(mode=mode, code=code):
                    sock = self.connect(tls_context(self.certificates, ["h2"]))
                    peer = H2Client(sock=sock, authority=NAMES[0].encode(), scheme=b"https")
                    try:
                        self.assertEqual(sock.selected_alpn_protocol(), "h2")
                        goaway = frame(7, payload=struct.pack(">II", 0, code))
                        ping = frame(6, payload=b"h2spec\0\0")
                        if mode == "split":
                            peer.send(goaway); peer.send(ping)
                        else:
                            peer.send(goaway + ping)
                        peer.until(lambda: any(current.kind == 6 and current.flags & 1 and
                                               current.payload == b"h2spec\0\0" for current in peer.frames))
                    finally:
                        peer.close()

    def test_verified_tls12_http2_required_cipher_and_p256(self):
        ctx = tls_context(self.certificates, ["h2"], version=ssl.TLSVersion.TLSv1_2)
        ctx.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
        ctx.set_ecdh_curve("prime256v1")
        sock = self.connect(ctx)
        peer = H2Client(sock=sock, authority=NAMES[0].encode(), scheme=b"https")
        try:
            self.assertEqual(sock.version(), "TLSv1.2")
            self.assertEqual(sock.cipher()[0], "ECDHE-RSA-AES128-GCM-SHA256")
            self.assertEqual(sock.selected_alpn_protocol(), "h2")
            peer.request(1); self.assertEqual(peer.response(1), BINARY)
        finally: peer.close()

    def test_verified_tls_http2_is_fourth_binary_curl_matrix_leg(self):
        for name in NAMES:
            with self.subTest(name=name):
                result = subprocess.run([curl_binary(), "--http2", "--noproxy", "*", "--fail", "--silent", "--show-error",
                                         "--cacert", str(self.certificates.ca), "--resolve", f"{name}:{self.port}:127.0.0.1",
                                         "--write-out", "\nVERSION:%{http_version}", f"https://{name}:{self.port}/binary"],
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, BINARY + b"\nVERSION:2")

    def test_verified_tls_priority_update_and_multiplexed_flow(self):
        sock = self.connect(tls_context(self.certificates, ["h2"]))
        peer = H2Client(sock=sock, authority=NAMES[0].encode(), scheme=b"https", settings_values=[(4, 0)], auto_window=False)
        try:
            self.assertEqual(sock.selected_alpn_protocol(), "h2")
            peer.send(window(0, 5 * 1024 * 1024))
            peer.request(1, b"/large", headers=[(b"priority", b"u=0")])
            peer.request(3, headers=[(b"priority", b"u=7")])
            peer.send(priority_update(3, b"u=0") + priority_update(1, b"u=7")); peer.ping_barrier()
            self.assertEqual(peer.data_order, [])
            peer.send(settings([(4, 3 * 1024 * 1024)])); peer.until(lambda: bool(peer.data_order))
            self.assertEqual(peer.data_order[0][0], 3)
            self.assertEqual(peer.response(3), BINARY)
            self.assertEqual(peer.response(1), b"A" * (2 * 1024 * 1024))
        finally: peer.close()


if __name__ == "__main__":
    unittest.main()
