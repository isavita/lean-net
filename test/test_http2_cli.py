#!/usr/bin/env python3
"""Exercise the public server CLI's HTTP/2 push option on the wire."""
from contextlib import contextmanager
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from http2_test_support import H2Client
from test_echo import unused_port

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tls/test"))
from tls_test_support import NAMES, context, create_certificates, tls_socket

SUFFIX = ".exe" if sys.platform == "win32" else ""
HTTP_BIN = Path(os.environ.get("LEAN_NET_HTTP1_BIN", ROOT / f".lake/build/bin/lean-net-http1{SUFFIX}"))
TLS_BIN = Path(os.environ.get("LEAN_NET_TLS_BIN", ROOT / f"tls/.lake/build/bin/lean-net-tls{SUFFIX}"))
PARENT = b"Hello from lean-net!\n"
PUSHED = b"Optional server push from lean-net.\n"


class PublicCliPushAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="lean-net-cli-tls-")
        try:
            cls.certificates = create_certificates(cls.directory.name)
        except BaseException:
            cls.directory.cleanup()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    @contextmanager
    def server(self, secure, enabled):
        binary = TLS_BIN if secure else HTTP_BIN
        self.assertTrue(binary.is_file(), f"build the public server executable: {binary}")
        port = unused_port()
        args = [str(binary)]
        if secure:
            args += [str(self.certificates.chains[0]), str(self.certificates.keys[0])]
        if enabled:
            args.append("--enable-push")
        args.append(str(port))
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        with tempfile.TemporaryFile(mode="w+") as log:
            process = subprocess.Popen(args, stdout=log, stderr=log, creationflags=flags)
            try:
                deadline = time.monotonic() + 15
                while True:
                    if process.poll() is not None:
                        log.seek(0)
                        self.fail(f"server exited during startup ({process.returncode}): {log.read()}")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                            break
                    except (ConnectionError, socket.timeout):
                        if time.monotonic() >= deadline:
                            self.fail("server startup exceeded 15 seconds")
                        time.sleep(0.025)
                yield port
            finally:
                if process.poll() is None:
                    process.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                        self.fail("server shutdown exceeded 10 seconds")
                if process.returncode:
                    log.seek(0)
                    self.fail(f"server exited with {process.returncode}: {log.read()}")

    @contextmanager
    def peer(self, port, secure, settings_values=()):
        if secure:
            sock = tls_socket(port, context(self.certificates, protocols=("h2",)))
            if sock.selected_alpn_protocol() != "h2":
                sock.close()
                self.fail("verified TLS connection did not negotiate h2")
            client = H2Client(sock=sock, settings_values=settings_values,
                              authority=NAMES[0].encode(), scheme=b"https")
        else:
            client = H2Client(port, settings_values=settings_values)
        try:
            yield client
        finally:
            client.close()

    def check_transport(self, secure):
        with self.server(secure, enabled=False) as port:
            with self.peer(port, secure) as peer:
                peer.request(1, b"/")
                self.assertEqual(peer.response(1), PARENT)
                peer.ping_barrier()
                self.assertEqual(peer.promises, {})

        with self.server(secure, enabled=True) as port:
            with self.peer(port, secure) as peer:
                peer.request(1, b"/")
                self.assertEqual(peer.response(1), PARENT)
                peer.until(lambda: bool(peer.promises))
                self.assertEqual(len(peer.promises), 1)
                stream, promise = next(iter(peer.promises.items()))
                self.assertGreater(stream, 0)
                self.assertEqual(stream % 2, 0)
                self.assertEqual(promise.parent, 1)
                headers = dict(promise.headers)
                self.assertEqual(headers[b":method"], b"GET")
                self.assertEqual(headers[b":path"], b"/pushed.txt")
                self.assertEqual(headers[b":scheme"], b"https" if secure else b"http")
                self.assertEqual(headers[b":authority"], NAMES[0].encode() if secure else b"localhost")
                self.assertEqual(peer.response(stream), PUSHED)
                peer.ping_barrier()
                self.assertEqual(len(peer.promises), 1)
            with self.peer(port, secure, settings_values=[(2, 0)]) as peer:
                peer.request(1, b"/")
                self.assertEqual(peer.response(1), PARENT)
                peer.ping_barrier()
                self.assertEqual(peer.promises, {})

    def check_log_queue_rejections(self, secure):
        binary = TLS_BIN if secure else HTTP_BIN
        prefix = [str(binary)]
        if secure:
            prefix += [str(self.certificates.chains[0]), str(self.certificates.keys[0])]
        for options in (
            ["--access-log-queue-capacity"],
            ["--access-log-queue-capacity", "4096"],
            *[["--access-log", os.devnull, "--access-log-queue-capacity", value]
              for value in ("0", "3", "65537", "-1", "1.5", "abc", "")],
            ["--access-log", os.devnull, "--access-log-queue-capacity", "1024",
             "--access-log-queue-capacity", "4096"],
        ):
            with self.subTest(secure=secure, options=options):
                result = subprocess.run(prefix + [str(unused_port())] + options,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        timeout=10, check=False)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(b"--access-log-queue-capacity", result.stdout)

    def test_plaintext_public_cli(self):
        self.check_log_queue_rejections(secure=False)
        self.check_transport(secure=False)

    def test_verified_tls_public_cli(self):
        self.check_log_queue_rejections(secure=True)
        self.check_transport(secure=True)


if __name__ == "__main__":
    unittest.main()
