#!/usr/bin/env python3
"""Verified two-host certificate replacement on actual native TLS workers."""
import hashlib
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest

from tls_test_support import ROOT, NAMES, context, create_certificates, openssl, request, tls_socket

sys.path.insert(0, str(ROOT / "test"))
from test_echo import unused_port
from test_http1_reactor import Reader, resource_count

SUFFIX = ".exe" if sys.platform == "win32" else ""
BINARY = Path(os.environ.get("LEAN_NET_TLS_RELOAD_BIN", ROOT / f"tls/.lake/build/bin/lean-net-tls-reload-fixture{SUFFIX}"))
PUBLIC_BINARY = Path(os.environ.get("LEAN_NET_TLS_RELOAD_PUBLIC_BIN", ROOT / f"tls/.lake/build/bin/lean-net-tls{SUFFIX}"))
FIELDS = ("generation", "attempts", "publications", "failures", "last_error", "live_versions",
          "loader_threads", "requested", "completed")


class TLSReload(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki_directory = tempfile.TemporaryDirectory(prefix="lean-net-reload-pki-")
        cls.addClassCleanup(cls.pki_directory.cleanup)
        directory = Path(cls.pki_directory.name)
        cls.certificates = create_certificates(directory)
        cls.rotated = []
        cls.rotated_fingerprints = []
        for serial, name in enumerate(NAMES, 100):
            key, csr = directory / f"{name}-new.key", directory / f"{name}-new.csr"
            leaf, chain = directory / f"{name}-new.pem", directory / f"{name}-new.chain.pem"
            openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-sha256", "-keyout", key, "-out", csr, "-subj", f"/CN={name}")
            openssl("x509", "-req", "-in", csr, "-CA", directory / "intermediate.pem",
                    "-CAkey", directory / "intermediate.key", "-set_serial", str(serial),
                    "-sha256", "-out", leaf, "-days", "90", "-extfile", directory / f"{name}.ext")
            chain.write_bytes(leaf.read_bytes() + (directory / "intermediate.pem").read_bytes())
            cls.rotated.append((chain, key))
            cls.rotated_fingerprints.append(hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf.read_text())).hexdigest())

    def setUp(self):
        self.assertTrue(BINARY.is_file(), f"missing TLS reload executable: {BINARY}")
        self.directory = tempfile.TemporaryDirectory(prefix="lean-net-reload-wire-")
        self.addCleanup(self.directory.cleanup)
        directory = Path(self.directory.name)
        self.paths = [(directory / f"{name}.pem", directory / f"{name}.key") for name in NAMES]
        self.publish(1)
        self.ctx = context(self.certificates)
        self.server = None
        self.log = tempfile.TemporaryFile(mode="w+")
        self.addCleanup(self.log.close)
        self.addCleanup(self.stop)
        self.start(0)

    def publish(self, version):
        sources = list(zip(self.certificates.chains, self.certificates.keys)) if version == 1 else self.rotated
        for (certificate, key), (target_certificate, target_key) in zip(sources, self.paths):
            shutil.copyfile(certificate, target_certificate)
            shutil.copyfile(key, target_key)

    def output(self):
        self.log.flush(); self.log.seek(0); return self.log.read()

    def start(self, interval):
        self.port = unused_port()
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        self.server = subprocess.Popen([str(BINARY), *[str(path) for pair in self.paths for path in pair],
                                        str(self.port), str(interval)], stdout=self.log, stderr=self.log, creationflags=flags)
        cutoff = time.monotonic() + 15
        while time.monotonic() < cutoff:
            if self.server.poll() is not None:
                self.fail(f"reload server startup exit {self.server.returncode}: {self.output()}")
            try:
                self.assertEqual(self.get().body, b"reload-ok")
                return
            except (ConnectionError, OSError, ssl.SSLError):
                time.sleep(.025)
        self.fail("reload server readiness deadline: " + self.output())

    def stop(self):
        if self.server is None:
            return
        process, self.server = self.server, None
        if process.poll() is None:
            process.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=3)
                self.fail("TLS loader/worker shutdown exceeded four seconds: " + self.output())
        self.assertEqual(process.returncode, 0, self.output())

    def connect(self, name=NAMES[0], *, ctx=None, session=None):
        return tls_socket(self.port, ctx or self.ctx, name, session=session)

    def get(self, path=b"/", name=NAMES[0]):
        with self.connect(name) as sock:
            sock.sendall(request(path, name=name, close=True))
            reader = Reader(sock); reply = reader.response(); reader.eof(); return reply

    def status(self):
        reply = self.get(b"/status")
        self.assertEqual(reply.headers[b"x-owner-violations"], b"0")
        values = [int(part) for part in reply.body.split(b",")]
        self.assertEqual(len(values), len(FIELDS))
        return dict(zip(FIELDS, values))

    def wait_status(self, predicate):
        cutoff = time.monotonic() + 8
        while time.monotonic() < cutoff:
            status = self.status()
            if predicate(status):
                return status
            time.sleep(.005)
        self.fail("reload status deadline: " + repr(status))

    def reload(self):
        ticket = int(self.get(b"/reload").body)
        self.assertGreater(ticket, 0)
        return self.wait_status(lambda status: status["completed"] >= ticket)

    def fingerprint(self, index):
        with self.connect(NAMES[index]) as sock:
            fingerprint = hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest()
            sock.sendall(request(name=NAMES[index], close=True))
            reader = Reader(sock); self.assertEqual(reader.response().body, b"reload-ok"); reader.eof()
            return fingerprint

    def test_two_sni_hosts_rotate_while_existing_connection_keeps_working(self):
        for index in range(2):
            self.assertEqual(self.fingerprint(index), self.certificates.fingerprints[index])
        with self.connect() as old:
            old.sendall(request())
            self.assertEqual(Reader(old).response().body, b"reload-ok")
            old_certificate = old.getpeercert(binary_form=True)
            self.publish(2)
            status = self.reload()
            self.assertEqual((status["generation"], status["last_error"]), (2, 0))
            self.assertEqual(status["live_versions"], 2)
            for index in range(2):
                self.assertEqual(self.fingerprint(index), self.rotated_fingerprints[index])
            with self.connect(NAMES[1], ctx=context(self.certificates, ["h2", "http/1.1"])) as h2:
                self.assertEqual(h2.selected_alpn_protocol(), "h2")
                self.assertEqual(hashlib.sha256(h2.getpeercert(binary_form=True)).hexdigest(), self.rotated_fingerprints[1])
            old.sendall(request(close=True))
            reader = Reader(old); self.assertEqual(reader.response().body, b"reload-ok"); reader.eof()
            self.assertEqual(old.getpeercert(binary_form=True), old_certificate)
        self.wait_status(lambda status: status["live_versions"] == 1)

    def test_partial_key_mismatch_and_wrong_sni_keep_last_good_bundle(self):
        original = [self.fingerprint(index) for index in range(2)]
        self.paths[0][1].write_bytes(b"partial private key")
        status = self.reload()
        self.assertEqual(status["generation"], 1); self.assertLess(status["last_error"], 0)
        for index in range(2):
            self.assertEqual(self.fingerprint(index), original[index])
        self.publish(1)
        for index in range(2):
            shutil.copyfile(self.rotated[index][0], self.paths[index][0])
        status = self.reload()
        self.assertEqual(status["generation"], 1); self.assertLess(status["last_error"], 0)
        self.publish(1)
        shutil.copyfile(self.certificates.chains[1], self.paths[0][0])
        shutil.copyfile(self.certificates.keys[1], self.paths[0][1])
        status = self.reload()
        self.assertEqual(status["generation"], 1); self.assertLess(status["last_error"], 0)
        for index in range(2):
            self.assertEqual(self.fingerprint(index), original[index])
        self.publish(2)
        self.assertEqual(self.reload()["generation"], 2)
        for index in range(2):
            self.assertEqual(self.fingerprint(index), self.rotated_fingerprints[index])

    def test_existing_incomplete_handshake_retains_original_snapshot(self):
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        client = self.ctx.wrap_bio(incoming, outgoing, server_side=False, server_hostname=NAMES[1])
        with self.assertRaises(ssl.SSLWantReadError):
            client.do_handshake()
        hello = outgoing.read()
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as raw:
            raw.settimeout(5); raw.sendall(hello[:1])
            # The first record byte starts the reactor-owned TLS session but
            # deliberately withholds ClientHello completion and SNI dispatch.
            time.sleep(.2)
            self.publish(2); self.assertEqual(self.reload()["generation"], 2)
            raw.sendall(hello[1:])
            while True:
                try:
                    client.do_handshake()
                    pending = outgoing.read()
                    if pending: raw.sendall(pending)
                    break
                except ssl.SSLWantReadError:
                    pending = outgoing.read()
                    if pending: raw.sendall(pending)
                    incoming.write(raw.recv(65536))
            self.assertEqual(hashlib.sha256(client.getpeercert(binary_form=True)).hexdigest(),
                             self.certificates.fingerprints[1])
        self.assertEqual(self.fingerprint(1), self.rotated_fingerprints[1])

    def test_periodic_detection_and_failed_replacement_retention(self):
        self.stop(); self.start(25)
        self.paths[0][0].write_bytes(b"-----BEGIN CERTIFICATE-----\npartial")
        status = self.wait_status(lambda status: status["failures"] > 0)
        self.assertEqual(status["generation"], 1)
        self.assertEqual(self.fingerprint(0), self.certificates.fingerprints[0])
        self.publish(2)
        status = self.wait_status(lambda status: status["generation"] == 2)
        self.assertEqual((status["requested"], status["last_error"]), (0, 0))
        for index in range(2):
            self.assertEqual(self.fingerprint(index), self.rotated_fingerprints[index])
        attempts = status["attempts"]
        self.wait_status(lambda status: status["attempts"] >= attempts + 3)
        self.assertEqual(self.status()["generation"], 2)

    def test_public_cli_periodic_reload_in_default_and_static_modes(self):
        self.assertTrue(PUBLIC_BINARY.is_file(), f"missing public TLS executable: {PUBLIC_BINARY}")
        self.stop()
        static = Path(self.directory.name) / "public"
        static.mkdir(); (static / "asset.bin").write_bytes(b"CLI static reload")
        for use_static in (False, True):
            self.publish(1); self.port = unused_port()
            command = [str(PUBLIC_BINARY), str(self.paths[0][0]), str(self.paths[0][1]), str(self.port),
                       "--reload-certs-ms", "25"]
            if use_static:
                command += ["--static", str(static), "--static-memory", "1"]
            flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
            self.server = subprocess.Popen(command, stdout=self.log, stderr=self.log, creationflags=flags)
            path = b"/asset.bin" if use_static else b"/"
            expected_body = b"CLI static reload" if use_static else b"Hello from lean-net!\n"

            def fingerprint():
                with self.connect() as sock:
                    value = hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest()
                    sock.sendall(request(path, close=True)); reader = Reader(sock)
                    reply = reader.response(); reader.eof()
                    self.assertEqual((reply.status, reply.body), (200, expected_body))
                    return value

            deadline = time.monotonic() + 15
            while True:
                if self.server.poll() is not None:
                    self.fail("public reload startup failed: " + self.output())
                try:
                    self.assertEqual(fingerprint(), self.certificates.fingerprints[0])
                    break
                except (ConnectionError, OSError):
                    if time.monotonic() >= deadline: raise
                    time.sleep(.025)
            self.paths[0][1].write_bytes(b"incomplete replacement")
            time.sleep(.1)
            self.assertEqual(fingerprint(), self.certificates.fingerprints[0])
            self.publish(2); deadline = time.monotonic() + 8
            while fingerprint() != self.rotated_fingerprints[0]:
                if time.monotonic() >= deadline: self.fail("public CLI did not publish replacement certificate")
                time.sleep(.01)
            self.stop()

    def test_hundred_rotations_keep_file_handles_and_retired_versions_flat(self):
        for _ in range(24): self.get()
        before = resource_count(self.server.pid)
        for cycle in range(100):
            self.publish(2 if cycle % 2 == 0 else 1)
            status = self.reload()
            self.assertEqual((status["generation"], status["last_error"]), (cycle + 2, 0))
            self.assertLessEqual(status["live_versions"], 2)
        self.wait_status(lambda status: status["live_versions"] == 1)
        deadline = time.monotonic() + 3
        while resource_count(self.server.pid) > before and time.monotonic() < deadline: time.sleep(.01)
        self.assertLessEqual(resource_count(self.server.pid), before)
        self.assertEqual(self.status()["loader_threads"], 1)

    def test_unchanged_reload_preserves_cross_worker_resumption(self):
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            ctx = context(self.certificates, version=version)
            with self.connect(ctx=ctx) as sock:
                sock.sendall(request()); reader = Reader(sock); self.assertEqual(reader.response().body, b"reload-ok")
                session = sock.session
                sock.sendall(request(close=True)); self.assertEqual(reader.response().body, b"reload-ok"); reader.eof()
            self.assertEqual(self.reload()["generation"], 1)
            workers = set()
            for _ in range(64):
                with self.connect(ctx=ctx, session=session) as sock:
                    self.assertTrue(sock.session_reused)
                    sock.sendall(request(close=True)); reader = Reader(sock); reply = reader.response(); reader.eof()
                    workers.add(int(reply.headers[b"x-worker"]))
                    session = sock.session
                if len(workers) == 4: break
            self.assertEqual(workers, set(range(4)))

    def test_changed_certificate_invalidates_old_ticket_then_new_tickets_resume(self):
        clients = []
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            ctx = context(self.certificates, version=version)
            with self.connect(ctx=ctx) as sock:
                sock.sendall(request()); reader = Reader(sock); reader.response(); old_session = sock.session
                self.assertTrue(old_session.has_ticket)
                sock.sendall(request(close=True)); reader.response(); reader.eof()
            clients.append((ctx, old_session))
        self.publish(2); self.assertEqual(self.reload()["generation"], 2)
        for ctx, old_session in clients:
            with self.connect(ctx=ctx, session=old_session) as sock:
                self.assertFalse(sock.session_reused)
                self.assertEqual(hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest(), self.rotated_fingerprints[0])
                sock.sendall(request()); reader = Reader(sock); reader.response(); new_session = sock.session
                sock.sendall(request(close=True)); reader.response(); reader.eof()
            with self.connect(ctx=ctx, session=new_session) as sock:
                self.assertTrue(sock.session_reused)
                sock.sendall(request(close=True)); reader = Reader(sock); reader.response(); reader.eof()


if __name__ == "__main__":
    unittest.main()
