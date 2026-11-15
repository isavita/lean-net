#!/usr/bin/env python3
"""Actual HTTP wire completion, fixed-label metrics and private access logs.

Build lean-net-observability-fixture, both public CLIs and their log helper.
The six TLS cases verify the isolated CA, hostname and negotiated ALPN. The
HTTP/2 client uses the pinned independent HPACK dependency in requirements-http2.
No throughput/soak claim is made by this bounded acceptance suite.
"""
from collections import Counter
from contextlib import closing
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

from http2_test_support import H2Client, PREFACE, frame, window
from test_echo import unused_port
from test_http1_reactor import Reader, resource_count

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tls/test"))
from tls_test_support import create_certificates, context, tls_socket

SUFFIX = ".exe" if sys.platform == "win32" else ""
FIXTURE = Path(os.environ.get("LEAN_NET_OBSERVABILITY_BIN", ROOT / f".lake/build/bin/lean-net-observability-fixture{SUFFIX}"))
PLAIN = Path(os.environ.get("LEAN_NET_OBSERVABILITY_HTTP_BIN", ROOT / f".lake/build/bin/lean-net-http1{SUFFIX}"))
TLS = Path(os.environ.get("LEAN_NET_OBSERVABILITY_TLS_BIN", ROOT / f"tls/.lake/build/bin/lean-net-tls{SUFFIX}"))
HELPER = Path(os.environ.get("LEAN_NET_LOG_HELPER_BIN", ROOT / f".lake/build/bin/lean-net-access-log-helper{SUFFIX}"))
BINARY = b"\x00\xff\r\nA"
LARGE = b"A" * (2 * 1024 * 1024)


def request(path=b"/binary", method=b"GET", *, headers=(), body=b"", version=b"HTTP/1.1"):
    fields = [(b"Host", b"alpha.test"), *headers]
    if body and not any(name.lower() in (b"content-length", b"transfer-encoding") for name, _ in fields):
        fields.append((b"Content-Length", str(len(body)).encode()))
    return method + b" " + path + b" " + version + b"\r\n" + b"".join(
        name + b": " + value + b"\r\n" for name, value in fields) + b"\r\n" + body


class Running:
    def __init__(self, case, *, kind="fixture", workers=1, mode="normal", helper=None, env=None, extra_args=()):
        self.case, self.kind = case, kind
        self.directory = Path(tempfile.mkdtemp(prefix="lean-net-observe-wire-"))
        self.port = unused_port()
        self.log = self.directory / "access.jsonl"
        self.diagnostics = self.directory / "server.log"
        self.output = self.diagnostics.open("wb")
        self.stopped = False
        helper = helper or HELPER
        binary = {"fixture": FIXTURE, "plain": PLAIN, "tls": TLS}[kind]
        case.assertTrue(binary.is_file(), f"missing executable: {binary}")
        case.assertTrue(helper.is_file(), f"missing log helper: {helper}")
        if kind == "fixture":
            command = [str(binary), str(self.port), str(self.log), str(helper), str(workers), mode]
        else:
            static = self.directory / "public"
            static.mkdir()
            (static / "binary.bin").write_bytes(BINARY)
            (static / "large.bin").write_bytes(LARGE)
            command = [str(binary)]
            if kind == "tls":
                command += [str(case.certificates.chains[0]), str(case.certificates.keys[0])]
            command += [str(self.port), "--static", str(static), "--metrics", "--access-log", str(self.log),
                        "--log-helper", str(helper), "--workers", str(workers), "--max-clients", "64"]
            command += list(extra_args)
        options = {"start_new_session": True} if sys.platform != "win32" else {
            "creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        child_env = os.environ.copy()
        child_env.update(env or {})
        self.process = subprocess.Popen(command, stdout=self.output, stderr=subprocess.STDOUT, env=child_env, **options)
        (self.directory / "case.json").write_text(json.dumps({
            "case": case.id(), "kind": kind, "workers": workers, "mode": mode,
            "command": command, "pid": self.process.pid}, indent=2) + "\n")
        case.addCleanup(self.cleanup)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError(f"server exited at startup: {self.text()}")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=.2):
                    break
            except OSError:
                time.sleep(.01)
        else:
            raise AssertionError(f"server did not listen: {self.text()}")
        self.http_context = context(case.certificates, ["http/1.1"]) if kind == "tls" else None

    def text(self):
        return self.diagnostics.read_text(errors="replace")

    def connect(self, *, h2=False, receive_buffer=None):
        if self.kind == "tls":
            ctx = context(self.case.certificates, ["h2"]) if h2 else self.http_context
            sock = tls_socket(self.port, ctx, receive_buffer=receive_buffer, timeout=5)
            self.case.assertEqual(sock.selected_alpn_protocol(), "h2" if h2 else "http/1.1")
            return sock
        sock = socket.socket()
        sock.settimeout(5)
        if receive_buffer is not None:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, receive_buffer)
        sock.connect(("127.0.0.1", self.port))
        return sock

    def http(self, path=b"/binary", method=b"GET", **options):
        with closing(self.connect()) as sock:
            sock.sendall(request(path, method, **options))
            return Reader(sock).response(head=method == b"HEAD")

    def h2(self, **options):
        client = H2Client(sock=self.connect(h2=True), authority=b"alpha.test",
                          scheme=b"https" if self.kind == "tls" else b"http", **options)
        self.case.addCleanup(client.close)
        return client

    def metrics(self, path=b"/metrics"):
        response = self.http(path)
        self.case.assertEqual(response.status, 200)
        self.case.assertEqual(response.headers.get(b"content-type"), b"text/plain; version=0.0.4; charset=utf-8")
        self.case.assertLess(len(response.body), 16384)
        result = {}
        for line in response.body.decode("ascii").splitlines():
            if line and not line.startswith("#"):
                name, value = line.rsplit(" ", 1)
                self.case.assertNotIn(name, result, "duplicate Prometheus sample")
                result[name] = float(value) if "." in value else int(value)
        return result

    def records(self, *, complete=False):
        data = self.log.read_bytes() if self.log.exists() else b""
        if complete and data:
            self.case.assertTrue(data.endswith(b"\n"), "partial JSON record after joined shutdown")
        lines = data.split(b"\n")[:-1]
        records = [json.loads(line) for line in lines]
        for record in records:
            self.case.assertEqual(set(record), {"timestamp", "timestamp_ms", "worker", "protocol", "status", "outcome",
                "bytes_sent", "duration_ms", "duration_us", "remote_ip", "trace_id", "route", "reject_reason",
                "method", "path", "target",
                "method_truncated", "target_truncated", "target_redacted"})
            self.case.assertRegex(record["timestamp"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
            self.case.assertEqual(record["path"], record["target"])
            self.case.assertAlmostEqual(record["duration_ms"], record["duration_us"] / 1000, places=3)
            if record["trace_id"] is not None:
                self.case.assertRegex(record["trace_id"], r"^[0-9a-f]{32}$")
            self.case.assertGreater(record["timestamp_ms"], 1700000000000)
            self.case.assertLessEqual(record["timestamp_ms"], int(time.time() * 1000) + 5000)
            self.case.assertGreaterEqual(record["duration_us"], 0)
            self.case.assertLessEqual(len(record["method"]), 32)
            self.case.assertLessEqual(len(record["target"]), 256)
        return records

    def wait(self, *, success=None, errors=0, cancelled=0, active=0, started=None, body_bytes=None, logs=None, timeout=8):
        expected = {"request_errors_total": errors, "requests_cancelled_total": cancelled, "active_requests": active}
        for key, value in (("successful_completed_requests_total", success), ("requests_started_total", started)):
            if value is not None:
                expected[key] = value
        deadline, last = time.monotonic() + timeout, {}
        while time.monotonic() < deadline:
            last = self.metrics()
            matched = all(last.get("lean_net_" + key) == value for key, value in expected.items())
            records = self.records()
            # Counter bytes are plaintext HTTP wire bytes, including framing,
            # control and metrics traffic. Exact body totals belong to records.
            wire_ok = body_bytes is None or last.get("lean_net_response_bytes_total", 0) >= body_bytes
            payload_ok = body_bytes is None or logs is None or sum(r["bytes_sent"] for r in records) == body_bytes
            if matched and wire_ok and payload_ok and (logs is None or len(records) == logs):
                return last, records
            time.sleep(.02)
        self.case.fail(f"completion did not settle: expected {expected}, logs={logs}; actual {last}, records={self.records()[:5]}\n{self.text()}")

    def stop(self):
        if self.stopped:
            return
        self.stopped = True
        start = time.monotonic()
        if self.process.poll() is None:
            if sys.platform == "win32":
                self.process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                os.killpg(self.process.pid, signal.SIGINT)
        try:
            result = self.process.wait(timeout=6)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=3)
            self.case.fail(f"server/helper failed bounded shutdown: {self.text()}")
        self.case.assertEqual(result, 0, self.text())
        self.case.assertLess(time.monotonic() - start, 6)
        self.output.close()

    def cleanup(self):
        try:
            self.stop()
        finally:
            self.output.close()
            # Keep diagnostics only on explicit request, with no private keys.
            if os.environ.get("LEAN_NET_KEEP_OBSERVABILITY_REPORTS") != "1":
                import shutil
                shutil.rmtree(self.directory)


class ObservabilityWire(unittest.TestCase):
    def start(self, **options):
        return Running(self, **options)

    def test_binary_http10_http11_and_resident_file(self):
        server = self.start()
        for version in (b"HTTP/1.0", b"HTTP/1.1"):
            response = server.http(version=version)
            self.assertEqual(response.body, BINARY)
        self.assertEqual(server.http(b"/file").body, b"A" * (1024 * 1024))
        self.assertEqual(server.http(b"/file", b"HEAD").headers[b"content-length"], b"1048576")
        metrics, records = server.wait(success=4, started=4, body_bytes=1048586, logs=4)
        self.assertEqual({r["protocol"] for r in records}, {"HTTP/1.0", "HTTP/1.1"})
        self.assertEqual([r["bytes_sent"] for r in records], [5, 5, 1048576, 0])
        self.assertEqual(metrics['lean_net_completed_requests_by_protocol_total{protocol="http10"}'], 1)

    def test_chunk_framing_and_trailers_are_not_body_bytes(self):
        server = self.start()
        response = server.http(b"/chunked")
        self.assertEqual((response.body, response.trailers), (BINARY, {b"x-finished": b"yes"}))
        response = server.http(b"/trailers", b"POST", headers=[(b"Transfer-Encoding", b"chunked"), (b"Trailer", b"x-check")],
                               body=b"3\r\nabc\r\n0\r\nx-check: done\r\n\r\n")
        self.assertEqual(response.body, b"abc|done")
        _, records = server.wait(success=2, started=2, body_bytes=13, logs=2)
        self.assertEqual([r["bytes_sent"] for r in records], [5, 8])

    def test_head_204_304_have_zero_payload(self):
        server = self.start()
        response = server.http(b"/head", b"HEAD")
        self.assertEqual(response.headers[b"content-length"], b"14")
        self.assertEqual(response.body, b"")
        self.assertEqual(server.http(b"/204").status, 204)
        self.assertEqual(server.http(b"/304").status, 304)
        _, records = server.wait(success=3, started=3, body_bytes=0, logs=3)
        self.assertEqual([r["bytes_sent"] for r in records], [0, 0, 0])
        self.assertEqual([r["status"] for r in records], [200, 204, 304])

    def test_informational_and_custom_reason_log_only_final(self):
        server = self.start()
        with closing(server.connect()) as sock:
            sock.sendall(request(b"/informational"))
            reader = Reader(sock)
            self.assertEqual([reader.response().status, reader.response().status], [103, 102])
            self.assertEqual(reader.response().body, b"ok")
        response = server.http(b"/custom")
        self.assertEqual((response.status, response.reason, response.body), (299, b"Custom Ready", b"ready"))
        response = server.http(b"/refuse", b"POST", headers=[(b"Expect", b"100-continue")], body=b"already buffered")
        self.assertEqual((response.status, response.body), (417, b"refused"))
        _, records = server.wait(success=2, errors=1, started=3, body_bytes=14, logs=3)
        self.assertEqual([r["status"] for r in records], [200, 299, 417])

    def test_invalid_metadata_logs_actual_500(self):
        server = self.start()
        response = server.http(b"/invalid")
        self.assertEqual((response.status, response.body), (500, b""))
        self.assertNotIn(b"injected", response.headers)
        _, records = server.wait(success=0, errors=1, started=1, body_bytes=0, logs=1)
        self.assertEqual((records[0]["status"], records[0]["outcome"]), (500, "completed"))

    def test_pipeline_records_keep_request_order(self):
        server = self.start()
        with closing(server.connect()) as sock:
            sock.sendall(b"".join(request(f"/item/{i}".encode()) for i in range(10)))
            reader = Reader(sock)
            self.assertEqual([reader.response().body for _ in range(10)], [str(i).encode() for i in range(10)])
        _, records = server.wait(success=10, started=10, body_bytes=10, logs=10)
        self.assertEqual([r["target"] for r in records], [f"/item/{i}" for i in range(10)])

    def test_metrics_is_excluded_and_has_bounded_labels(self):
        server = self.start()
        first = server.metrics(b"/metrics?private_scrape=yes")
        response = server.http(b"/metrics", b"HEAD")
        self.assertEqual((response.status, response.body), (200, b""))
        last, records = server.wait(success=0, started=0, body_bytes=0, logs=0)
        self.assertEqual(records, [])
        self.assertEqual(first.keys(), last.keys())
        self.assertGreater(last["lean_net_request_bytes_total"], first["lean_net_request_bytes_total"])
        self.assertGreater(last["lean_net_response_bytes_total"], first["lean_net_response_bytes_total"])
        self.assertTrue(all('target=' not in name and 'path=' not in name for name in last))
        self.assertEqual(last['lean_net_request_duration_seconds_bucket{le="+Inf"}'], 0)

    def test_log_privacy_and_truncation(self):
        server = self.start()
        secrets = [b"private_query_123", b"private_auth_123", b"private_cookie_123", b"private_password_123"]
        response = server.http(b"/binary?token=" + secrets[0], headers=[
            (b"Authorization", b"Bearer " + secrets[1]), (b"Cookie", b"session=" + secrets[2])])
        self.assertEqual(response.body, BINARY)
        self.assertEqual(server.http(b"/" + b"x" * 300, b"M" * 40).status, 200)
        absolute = server.http(b"http://user:" + secrets[3] + b"@alpha.test/binary?token=" + secrets[0])
        self.assertEqual(absolute.status, 400)  # HTTP URI userinfo is rejected by the parser.
        # Generic absolute URI grammar allows userinfo; it must still never be logged.
        generic = server.http(b"ftp://user:" + secrets[3] + b"@alpha.test/binary?token=" + secrets[0])
        self.assertEqual(generic.status, 200)
        metrics, records = server.wait(success=3, errors=1, started=4, logs=4)
        raw = server.log.read_bytes()
        for secret in secrets:
            self.assertNotIn(secret, raw)
        self.assertEqual(records[0]["target"], "/binary")
        self.assertTrue(records[1]["target_truncated"])
        self.assertTrue(records[1]["method_truncated"])
        self.assertEqual((len(records[1]["target"]), len(records[1]["method"])), (256, 32))
        self.assertEqual(records[3]["target"], "[non-origin-target]")
        self.assertTrue(records[3]["target_redacted"])
        self.assertGreaterEqual(metrics['lean_net_completed_requests_by_method_total{method="OTHER"}'], 1)
        self.assertTrue(all("M" * 40 not in name for name in metrics))

    def test_http2_multiplex_counts_completed_streams(self):
        server = self.start()
        client = server.h2()
        for stream in range(1, 10, 2):
            client.request(stream)
        for stream in range(1, 10, 2):
            self.assertEqual(client.response(stream), BINARY)
        client.request(11, b"/head", method=b"HEAD")
        self.assertEqual(client.response(11), b"")
        self.assertEqual(dict(client.headers[11][0].headers)[b"content-length"], b"14")
        for stream, path, code in ((13, b"/204", b"204"), (15, b"/304", b"304")):
            client.request(stream, path)
            client.until(lambda: stream in client.ended)
            self.assertEqual(dict(client.headers[stream][0].headers)[b":status"], code)
            self.assertEqual(client.bodies[stream], b"")
        client.request(17, b"/chunked")
        self.assertEqual(client.response(17), BINARY)
        self.assertEqual(dict(client.headers[17][-1].headers), {b"x-finished": b"yes"})
        _, records = server.wait(success=9, started=9, body_bytes=30, logs=9)
        self.assertTrue(all(r["protocol"] == "HTTP/2" for r in records))
        self.assertEqual(Counter(r["bytes_sent"] for r in records), {5: 6, 0: 3})

    def test_h2c_upgrade_preserves_one_observation_after_prior_http11(self):
        server = self.start(kind="plain")
        with closing(server.connect()) as sock:
            reader = Reader(sock)
            sock.sendall(request(b"/binary.bin"))
            self.assertEqual(reader.response().body, BINARY)
            server.wait(success=1, started=1, logs=1)

            sock.sendall(request(b"/binary.bin", headers=[
                (b"Connection", b"Upgrade, HTTP2-Settings"),
                (b"Upgrade", b"h2c"),
                # Hold stream 1's DATA until the client advertises credit.
                (b"HTTP2-Settings", b"AAQAAAAA")]))
            self.assertEqual(reader.response().status, 101)
            # The switching response has no final application result. Stream
            # 1 can start immediately, but its zero peer window prevents its
            # final DATA from completing this same request yet.
            server.wait(success=1, started=2, active=1, logs=1)

            client = H2Client(sock=sock, authority=b"alpha.test", handshake=False)
            client.buffer.extend(reader.buffer)
            reader.buffer.clear()
            client.send(PREFACE + frame(4, 0, 0, struct.pack("!HI", 4, 65535)))
            self.assertEqual(client.response(1), BINARY)
            client.request(3, b"/binary.bin")
            self.assertEqual(client.response(3), BINARY)
            _, records = server.wait(success=3, started=3, body_bytes=15, logs=3)
            self.assertEqual([r["status"] for r in records], [200, 200, 200])
            self.assertEqual([r["protocol"] for r in records],
                             ["HTTP/1.1", "HTTP/2", "HTTP/2"])
            self.assertEqual([r["bytes_sent"] for r in records], [5, 5, 5])

    def test_http2_flow_blocked_response_is_not_completed_on_handler_return(self):
        server = self.start()
        client = server.h2(settings_values=[(4, 0)])
        client.request(1, b"/large")
        client.until(lambda: bool(client.headers[1]))
        client.ping_barrier()
        server.wait(success=0, started=1, active=1, body_bytes=0, logs=0)
        time.sleep(.1)
        server.metrics()  # Refresh the cached owner clock while output is blocked.
        client.send(window(1, len(LARGE)))
        self.assertEqual(client.response(1), LARGE)
        _, records = server.wait(success=1, started=1, body_bytes=len(LARGE), logs=1)
        self.assertEqual(records[0]["bytes_sent"], len(LARGE))
        self.assertGreaterEqual(records[0]["duration_us"], 50000)

    def test_http2_partial_upload_reset_is_cancelled_and_other_stream_progresses(self):
        server = self.start()
        client = server.h2()
        client.request(1, b"/echo", method=b"POST", headers=[(b"content-length", b"1000")], end_stream=False)
        client.send(frame(0, stream=1, payload=b"partial"))
        client.ping_barrier()
        client.send(frame(3, stream=1, payload=struct.pack(">I", 8)))
        client.request(3)
        self.assertEqual(client.response(3), BINARY)
        _, records = server.wait(success=1, cancelled=1, started=2, body_bytes=5, logs=2)
        cancelled = [r for r in records if r["outcome"] == "cancelled"]
        self.assertEqual([(r["status"], r["bytes_sent"]) for r in cancelled], [(0, 0)])

    def test_http2_blocked_response_reset_is_not_success(self):
        server = self.start()
        client = server.h2(settings_values=[(4, 0)])
        client.request(1, b"/large")
        client.until(lambda: bool(client.headers[1]))
        client.ping_barrier()
        client.send(frame(3, stream=1, payload=struct.pack(">I", 8)))
        client.request(3)
        client.send(window(3, 5))
        self.assertEqual(client.response(3), BINARY)
        _, records = server.wait(success=1, cancelled=1, started=2, body_bytes=5, logs=2)
        cancelled = [r for r in records if r["outcome"] == "cancelled"]
        self.assertEqual([(r["status"], r["bytes_sent"]) for r in cancelled], [(200, 0)])

    def test_http2_partial_body_counts_only_acknowledged_payload(self):
        server = self.start()
        client = server.h2(settings_values=[(4, 8192)], auto_window=False)
        client.request(1, b"/large")
        client.until(lambda: len(client.bodies[1]) == 8192)
        self.assertEqual(client.bodies[1], b"A" * 8192)
        client.ping_barrier()
        client.send(frame(3, stream=1, payload=struct.pack(">I", 8)))
        client.request(3)
        self.assertEqual(client.response(3), BINARY)
        _, records = server.wait(success=1, cancelled=1, started=2, body_bytes=8197, logs=2)
        cancelled = [r for r in records if r["outcome"] == "cancelled"]
        self.assertEqual([(r["status"], r["bytes_sent"]) for r in cancelled], [(200, 8192)])

    def test_slow_reader_does_not_stall_healthy_peer(self):
        server = self.start()
        slow = server.connect(receive_buffer=1024)
        self.addCleanup(slow.close)
        slow.sendall(request(b"/large"))
        time.sleep(.05)
        start = time.monotonic()
        self.assertEqual(server.http().body, BINARY)
        self.assertLess(time.monotonic() - start, 2)
        slow.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("hh" if sys.platform == "win32" else "ii", 1, 0))
        slow.close()
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            metrics = server.metrics()
            records = server.records()
            if len(records) == 2 and metrics["lean_net_active_requests"] == 0:
                break
            time.sleep(.02)
        self.assertEqual(len(records), 2, server.text())
        self.assertEqual(next(r for r in records if r["target"] == "/binary")["bytes_sent"], 5)
        self.assertLessEqual(next(r for r in records if r["target"] == "/large")["bytes_sent"], len(LARGE))
        self.assertGreaterEqual(metrics["lean_net_response_bytes_total"], sum(r["bytes_sent"] for r in records))

    def test_one_thousand_connections_have_exact_counts_and_flat_handles(self):
        server = self.start()
        # Warm lazy platform runtime state before the resource baseline.
        self.assertEqual(server.http().body, BINARY)
        server.wait(success=1, started=1, body_bytes=5, logs=1)
        time.sleep(.1)
        before = resource_count(server.process.pid)
        for _ in range(1000):
            self.assertEqual(server.http().body, BINARY)
        _, records = server.wait(success=1001, started=1001, body_bytes=5005, logs=1001)
        time.sleep(.1)
        after = resource_count(server.process.pid)
        (server.directory / "resources.json").write_text(json.dumps({
            "warmup_connections": 1, "measured_connections": 1000, "handles_before": before,
            "handles_after": after, "completed_requests": len(records)}, indent=2) + "\n")
        self.assertLessEqual(after, before)
        self.assertTrue(all(r["bytes_sent"] == 5 and r["outcome"] == "completed" for r in records))

    def test_four_worker_snapshot_aggregates_and_logs_actual_owner(self):
        server = self.start(workers=4)
        owners = Counter()
        for _ in range(8):
            peers = [server.connect() for _ in range(32)]
            try:
                for sock in peers:
                    sock.sendall(request(b"/worker"))
                for sock in peers:
                    response = Reader(sock).response()
                    self.assertEqual(response.headers[b"x-worker"], response.body)
                    owners[int(response.body)] += 1
            finally:
                for sock in peers:
                    sock.close()
        self.assertEqual(set(owners), {0, 1, 2, 3})
        self.assertEqual(sum(owners.values()), 256)
        metrics, records = server.wait(success=256, started=256, body_bytes=256, logs=256)
        (server.directory / "workers.json").write_text(json.dumps({"response_owners": owners,
            "log_owners": Counter(record["worker"] for record in records)}, indent=2) + "\n")
        self.assertEqual(Counter(record["worker"] for record in records), owners)
        self.assertEqual(metrics['lean_net_request_duration_seconds_bucket{le="+Inf"}'], 256)

    def test_sigint_joins_helper_and_drains_final_records(self):
        server = self.start()
        with closing(server.connect()) as sock:
            sock.sendall(b"".join(request(f"/item/{i}".encode()) for i in range(10)))
            reader = Reader(sock)
            self.assertEqual([reader.response().body for _ in range(10)], [str(i).encode() for i in range(10)])
        server.stop()  # No sleep/scrape before actual process-group interrupt.
        records = server.records(complete=True)
        self.assertEqual([r["target"] for r in records], [f"/item/{i}" for i in range(10)])
        self.assertTrue(all(r["outcome"] == "completed" for r in records))

    def test_full_log_queue_drops_visibly_without_stalling_requests(self):
        with tempfile.TemporaryDirectory(prefix="lean-net-observe-helper-") as temporary:
            helper = Path(temporary) / ("stall-helper" + SUFFIX)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-O2"]
            if sys.platform != "win32":
                flags += ["-pthread"]
            if sys.platform == "linux":
                flags += ["-lrt"]
            built = subprocess.run([os.environ.get("CC", "gcc" if sys.platform == "win32" else "cc"), *flags,
                "-DOB_NO_LEAN_FFI", "-DOB_TESTING", str(ROOT / "c/access_log.c"),
                str(ROOT / "c/access_log_helper.c"), "-o", str(helper)], capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            server = self.start(mode="overflow", helper=helper, env={"LEAN_NET_LOG_TEST_STALL_MS": "1500"})
            peers = [server.connect() for _ in range(32)]
            try:
                for sock in peers:
                    sock.sendall(request() * 2)
                for sock in peers:
                    reader = Reader(sock)
                    self.assertEqual([reader.response().body, reader.response().body], [BINARY, BINARY])
                metrics, records = server.wait(success=64, started=64, body_bytes=320)
                self.assertGreater(metrics["lean_net_access_log_dropped_total"], 0)
                self.assertEqual(metrics["lean_net_access_log_accepted_total"] + metrics["lean_net_access_log_dropped_total"], 64)
                deadline = time.monotonic() + 5
                while metrics["lean_net_access_log_pending_records"] and time.monotonic() < deadline:
                    time.sleep(.02)
                    metrics = server.metrics()
                self.assertEqual(metrics["lean_net_access_log_pending_records"], 0)
                self.assertEqual(metrics["lean_net_access_log_io_errors_total"], 0)
                (server.directory / "overflow.json").write_text(json.dumps({
                    name: value for name, value in metrics.items()
                    if name.startswith("lean_net_access_log_") or name == "lean_net_successful_completed_requests_total"
                }, indent=2) + "\n")
                server.stop()
                self.assertEqual(len(server.records(complete=True)), metrics["lean_net_access_log_written_total"])
            finally:
                for sock in peers:
                    sock.close()
                server.stop()

    def test_partial_request_eof_logs_actual_error(self):
        server = self.start()
        with closing(server.connect()) as sock:
            sock.sendall(request(b"/echo", b"POST", headers=[(b"Content-Length", b"10")], body=b"x"))
            sock.shutdown(socket.SHUT_WR)
            response = Reader(sock).response()
            self.assertEqual((response.status, response.body), (400, b""))
        _, records = server.wait(success=0, errors=1, started=1, body_bytes=0, logs=1)
        self.assertEqual(records[0]["status"], 400)

    def test_accepted_upgrade_is_success_and_raw_bytes_are_not_second_request(self):
        server = self.start()
        with closing(server.connect()) as sock:
            sock.sendall(request(b"/upgrade", headers=[(b"Connection", b"Upgrade"), (b"Upgrade", b"obs-echo")]) + b"raw-first")
            reader = Reader(sock)
            self.assertEqual(reader.response().status, 101)
            self.assertEqual(reader.take(9), b"raw-first")
            sock.sendall(b"raw-second")
            self.assertEqual(reader.take(10), b"raw-second")
            metrics, records = server.wait(success=1, started=1, body_bytes=0, logs=1)
            self.assertEqual(metrics['lean_net_completed_requests_by_status_class_total{status_class="1xx"}'], 1)
            self.assertEqual((records[0]["status"], records[0]["outcome"], records[0]["bytes_sent"]), (101, "completed", 0))
            sock.shutdown(socket.SHUT_WR)
            self.assertEqual(reader.take(7), b"raw-eof")
            reader.eof()
        server.wait(success=1, started=1, body_bytes=0, logs=1)

    def test_tcp_reset_after_100_continue_is_counted_once(self):
        server = self.start()
        sock = server.connect()
        self.addCleanup(sock.close)
        sock.sendall(request(b"/echo", b"POST", headers=[(b"Expect", b"100-continue"), (b"Content-Length", b"1000")]))
        self.assertEqual(Reader(sock).response().status, 100)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("hh" if sys.platform == "win32" else "ii", 1, 0))
        sock.close()
        self.assertEqual(server.http().body, BINARY)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            metrics, records = server.metrics(), server.records()
            if (metrics["lean_net_requests_started_total"] == 2 and metrics["lean_net_active_requests"] == 0 and
                metrics["lean_net_successful_completed_requests_total"] == 1 and
                metrics["lean_net_connection_resets_total"] == 1 and len(records) == 2):
                break
            time.sleep(.02)
        self.assertEqual(metrics["lean_net_connection_resets_total"], 1)
        self.assertEqual(metrics["lean_net_requests_started_total"], 2)
        self.assertEqual(metrics["lean_net_active_requests"], 0)
        self.assertEqual(metrics["lean_net_successful_completed_requests_total"], 1)
        self.assertEqual(metrics["lean_net_request_errors_total"] + metrics["lean_net_requests_cancelled_total"], 1)
        self.assertEqual(metrics["lean_net_request_timeouts_total"], 0)
        self.assertEqual(len(records), 2)
        reset = [r for r in records if r["target"] == "/echo"]
        self.assertEqual(len(reset), 1)
        self.assertIn(reset[0]["outcome"], ("error", "cancelled"))
        self.assertEqual((reset[0]["status"], reset[0]["bytes_sent"]), (0, 0))
        time.sleep(.05)
        self.assertEqual(server.metrics()["lean_net_connection_resets_total"], 1)
        self.assertEqual(len(server.records()), 2)

    def test_public_cli_static_range_head_and_conditional(self):
        server = self.start(kind="plain", extra_args=("--access-log-queue-capacity", "4096"))
        response = server.http(b"/binary.bin", headers=[(b"Range", b"bytes=1-3")])
        self.assertEqual((response.status, response.body), (206, BINARY[1:4]))
        etag = response.headers[b"etag"]
        self.assertEqual(server.http(b"/binary.bin", b"HEAD").headers[b"content-length"], b"5")
        self.assertEqual(server.http(b"/binary.bin", headers=[(b"If-None-Match", etag)]).status, 304)
        _, records = server.wait(success=3, started=3, body_bytes=3, logs=3)
        self.assertEqual([r["bytes_sent"] for r in records], [3, 0, 0])


class TLSObservabilityWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki_directory = tempfile.TemporaryDirectory(prefix="lean-net-observe-pki-")
        cls.certificates = create_certificates(cls.pki_directory.name)

    @classmethod
    def tearDownClass(cls):
        cls.pki_directory.cleanup()

    def start(self):
        return Running(self, kind="tls")

    def test_verified_http1_file_and_head(self):
        server = Running(self, kind="tls", extra_args=("--access-log-queue-capacity", "4096"))
        self.assertEqual(server.http(b"/binary.bin").body, BINARY)
        self.assertEqual(server.http(b"/binary.bin", b"HEAD").headers[b"content-length"], b"5")
        _, records = server.wait(success=2, started=2, body_bytes=5, logs=2)
        self.assertEqual([r["bytes_sent"] for r in records], [5, 0])
        self.assertTrue(all(r["protocol"] == "HTTP/1.1" for r in records))

    def test_verified_http2_file_completion(self):
        server = self.start()
        client = server.h2()
        client.request(1, b"/binary.bin")
        self.assertEqual(client.response(1), BINARY)
        _, records = server.wait(success=1, started=1, body_bytes=5, logs=1)
        self.assertEqual((records[0]["protocol"], records[0]["bytes_sent"]), ("HTTP/2", 5))

    def test_verified_http2_file_flow_fence(self):
        server = self.start()
        client = server.h2(settings_values=[(4, 0)])
        client.request(1, b"/large.bin")
        client.until(lambda: bool(client.headers[1]))
        client.ping_barrier()
        server.wait(success=0, started=1, active=1, body_bytes=0, logs=0)
        client.send(window(1, len(LARGE)))
        self.assertEqual(client.response(1), LARGE)
        _, records = server.wait(success=1, started=1, body_bytes=len(LARGE), logs=1)
        self.assertEqual(records[0]["bytes_sent"], len(LARGE))

    def test_verified_http2_partial_upload_cancel(self):
        server = self.start()
        client = server.h2()
        client.request(1, b"/binary.bin", method=b"POST", headers=[(b"content-length", b"1000")], end_stream=False)
        client.send(frame(0, stream=1, payload=b"partial"))
        client.ping_barrier()
        client.send(frame(3, stream=1, payload=struct.pack(">I", 8)))
        client.request(3, b"/binary.bin")
        self.assertEqual(client.response(3), BINARY)
        _, records = server.wait(success=1, cancelled=1, started=2, body_bytes=5, logs=2)
        self.assertEqual([(r["status"], r["bytes_sent"]) for r in records if r["outcome"] == "cancelled"], [(0, 0)])

    def test_verified_tls_range_and_not_modified(self):
        server = self.start()
        response = server.http(b"/binary.bin", headers=[(b"Range", b"bytes=2-3")])
        self.assertEqual((response.status, response.body), (206, BINARY[2:4]))
        response = server.http(b"/binary.bin", headers=[(b"If-None-Match", response.headers[b"etag"])])
        self.assertEqual((response.status, response.body), (304, b""))
        _, records = server.wait(success=2, started=2, body_bytes=2, logs=2)
        self.assertEqual([r["bytes_sent"] for r in records], [2, 0])

    def test_verified_tls_privacy_and_graceful_log_drain(self):
        server = self.start()
        secret = b"tls_private_query_cookie_auth"
        with closing(server.connect()) as sock:
            wire = request(b"/binary.bin?token=" + secret, headers=[
                (b"Authorization", b"Bearer " + secret), (b"Cookie", b"sid=" + secret)])
            sock.sendall(wire * 10)
            reader = Reader(sock)
            self.assertEqual([reader.response().body for _ in range(10)], [BINARY] * 10)
        server.stop()
        self.assertNotIn(secret, server.log.read_bytes())
        records = server.records(complete=True)
        self.assertEqual(len(records), 10)
        self.assertTrue(all(r["target"] == "/binary.bin" and r["bytes_sent"] == 5 and r["outcome"] == "completed" for r in records))


if __name__ == "__main__":
    unittest.main()
