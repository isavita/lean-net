#!/usr/bin/env python3
"""Periodic native-wheel PINGs, exact ACKs and physical write completion."""
from contextlib import closing
from pathlib import Path
import os
import tempfile
import time
import unittest

from http2_test_support import frame
from test_observability import BINARY, ROOT, SUFFIX, Reader, Running, request
from tls_test_support import create_certificates


class KeepaliveCases:
    @classmethod
    def setUpClass(cls):
        cls.pki = tempfile.TemporaryDirectory(prefix="lean-net-ping-pki-")
        cls.certificates = create_certificates(Path(cls.pki.name))

    @classmethod
    def tearDownClass(cls):
        cls.pki.cleanup()

    def start(self, *, enabled=True):
        return Running(self, kind=self.kind, extra_args=(
            ["--http2-ping-ms", "80", "--http2-ping-timeout-ms", "500"] if enabled else []))

    def next_ping(self, peer):
        for _ in range(256):
            current = peer.read()
            if current.kind == 6 and not current.flags & 1:
                self.assertEqual((current.stream, len(current.payload)), (0, 8))
                return current.payload
            self.assertFalse(peer.goaways, peer.goaways)
        self.fail("server PING exceeded frame budget")

    def test_periodic_probes_continue_during_application_traffic(self):
        server = self.start()
        peer = server.h2()
        count = 0
        deadline = time.monotonic() + 3
        while peer.pings_received < 2 and time.monotonic() < deadline:
            peer.request(2 * count + 1, b"/binary.bin")
            self.assertEqual(peer.response(2 * count + 1), BINARY)
            count += 1
            time.sleep(.02)
        self.assertGreaterEqual(peer.pings_received, 2)
        self.assertEqual(peer.pings_received, peer.pings_acknowledged)
        metrics, records = server.wait(success=count, started=count, logs=count)
        self.assertEqual(sum(record['bytes_sent'] for record in records), count * len(BINARY))
        self.assertEqual(metrics['lean_net_request_timeouts_total'], 0)

    def test_unanswered_probe_closes_only_its_connection(self):
        server = self.start()
        peer = server.h2(auto_ping_ack=False)
        self.next_ping(peer)
        peer.until(lambda: bool(peer.goaways))
        self.assertEqual(peer.goaways[-1][1], 1)
        server.wait(success=0, started=0, logs=0)
        healthy = server.h2()
        healthy.request(1, b"/binary.bin")
        self.assertEqual(healthy.response(1), BINARY)
        server.wait(success=1, started=1, logs=1)

    def test_wrong_ack_and_non_ack_ping_do_not_clear_probe(self):
        server = self.start()
        peer = server.h2(auto_ping_ack=False)
        token = self.next_ping(peer)
        wrong = bytes([token[0] ^ 1]) + token[1:]
        peer.send(frame(6, 1, payload=wrong) + frame(6, payload=token))
        peer.until(lambda: any(item.kind == 6 and item.flags & 1 and item.payload == token for item in peer.frames))
        peer.until(lambda: bool(peer.goaways))
        self.assertEqual(peer.goaways[-1][1], 1)
        server.wait(success=0, started=0, logs=0)

    def test_ping_timeout_marks_incomplete_upload_once(self):
        server = self.start()
        peer = server.h2(auto_ping_ack=False)
        peer.request(1, b"/binary.bin", method=b"POST", headers=[(b"content-length", b"2")], end_stream=False)
        self.next_ping(peer)
        peer.until(lambda: bool(peer.goaways))
        metrics, records = server.wait(success=0, errors=1, started=1, logs=1)
        self.assertEqual(metrics['lean_net_request_timeouts_total'], 1)
        self.assertEqual((records[0]['outcome'], records[0]['status'], records[0]['bytes_sent']), ('timeout', 0, 0))

    def test_http1_never_receives_ping_frames(self):
        server = self.start()
        with closing(server.connect()) as sock:
            reader = Reader(sock)
            sock.sendall(request(b"/binary.bin"))
            self.assertEqual(reader.response().body, BINARY)
            time.sleep(.2)
            sock.sendall(request(b"/binary.bin"))
            self.assertEqual(reader.response().body, BINARY)
        server.wait(success=2, started=2, logs=2)

    def test_shutdown_cancels_pending_probe_and_drains_cleanly(self):
        server = self.start()
        peer = server.h2(auto_ping_ack=False)
        self.next_ping(peer)
        server.stop()
        peer.until(lambda: bool(peer.goaways))
        self.assertEqual(peer.goaways[-1][1], 0)


class PlainKeepalive(KeepaliveCases, unittest.TestCase):
    kind = "plain"


class TLSKeepalive(KeepaliveCases, unittest.TestCase):
    kind = "tls"


class DeferredPingCompletion(unittest.TestCase):
    def test_early_ack_and_late_old_write_cannot_expire_a_later_probe(self):
        import test_observability
        binary = Path(os.environ.get("LEAN_NET_KEEPALIVE_TRANSPORT_BIN",
            ROOT / f".lake/build/bin/lean-net-keepalive-transport-fixture{SUFFIX}"))
        previous = test_observability.FIXTURE
        test_observability.FIXTURE = binary
        try:
            server = Running(self)
        finally:
            test_observability.FIXTURE = previous
        peer = server.h2(auto_ping_ack=False)
        tokens = []
        def next_ping():
            for _ in range(256):
                item = peer.read()
                if item.kind == 6 and not item.flags & 1:
                    tokens.append(item.payload)
                    return item.payload
                self.assertFalse(peer.goaways)
            self.fail("missing deferred PING")
        first = next_ping()
        started = time.monotonic()
        time.sleep(.22)  # ACK timeout is150ms, completion is delayed800ms.
        peer.send(frame(6, 1, payload=first))
        second = next_ping()
        self.assertNotEqual(first, second)
        peer.send(frame(6, 1, payload=first))  # A stale ACK cannot clear probe2.
        remaining = 1.02 - (time.monotonic() - started)
        if remaining > 0:
            time.sleep(remaining)
        # Probe1's late WN arrived at~800ms. Probe2's own WN is still delayed.
        peer.send(frame(6, 1, payload=second))
        peer.request(1)
        self.assertEqual(peer.response(1), BINARY)
        self.assertFalse(peer.goaways)
        server.wait(success=1, started=1, logs=1)


if __name__ == "__main__":
    unittest.main()
