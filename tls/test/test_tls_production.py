#!/usr/bin/env python3
"""Production TLS policy on the public lean-net-tls executable.

mTLS (required, optional, foreign CA) and client identity exposure, OCSP
stapling, HSTS, TLS 1.2 cipher policy and legacy protocol refusal, session
resumption, ALPN selection, TLS metrics and the four-mode curl matrix.
"""
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

from tls_test_support import ROOT, HOST, NAMES, context, create_certificates, openssl, openssl_binary, curl_binary, request, tls_socket

SUFFIX = ".exe" if sys.platform == "win32" else ""
TLS_BINARY = ROOT / f"tls/.lake/build/bin/lean-net-tls{SUFFIX}"
PLAIN_BINARY = ROOT / f".lake/build/bin/lean-net-http1{SUFFIX}"
ADMISSION_BINARY = ROOT / f"tls/.lake/build/bin/lean-net-tls-admission-fixture{SUFFIX}"


def free_port():
    with socket.socket() as probe:
        probe.bind((HOST, 0))
        return probe.getsockname()[1]


def read_http(sock):
    data = b""
    while True:
        try:
            chunk = sock.recv(65536)
        except (ssl.SSLError, ConnectionError, socket.timeout):
            break
        if not chunk:
            break
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split()[1]) if lines and lines[0].startswith(b"HTTP/") else None
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        headers[name.strip().lower().decode()] = value.strip().decode()
    return status, headers, body


class Server:
    def __init__(self, binary, arguments, port):
        self.port = port
        self.log = tempfile.TemporaryFile(mode="w+")
        self.process = subprocess.Popen([str(binary), *map(str, arguments), str(port)],
                                        stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                return
            try:
                socket.create_connection((HOST, port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise AssertionError("server did not start")

    def output(self):
        self.log.flush(); self.log.seek(0); return self.log.read()

    def stop(self):
        if self.process.poll() is None:
            if sys.platform == "win32":
                self.process.kill()
            else:
                self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(10)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait()
        self.log.close()


class TLSProduction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="lean-net-tls-production-")
        cls.addClassCleanup(cls.directory.cleanup)
        root = Path(cls.directory.name)
        cls.certs = create_certificates(root)
        # A client certificate issued by the same intermediate (mTLS CA bundle
        # = root + intermediate), with URI and DNS SANs.
        cls.client_key, cls.client_cert = root / "client.key", root / "client.pem"
        csr, extensions = root / "client.csr", root / "client.ext"
        extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                              "extendedKeyUsage=clientAuth\n"
                              "subjectAltName=URI:spiffe://lean-net.test/worker,DNS:client.lean-net.test\n")
        openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                "-keyout", cls.client_key, "-out", csr, "-subj", "/O=lean-net/CN=test-client")
        openssl("x509", "-req", "-in", csr, "-CA", root / "intermediate.pem", "-CAkey", root / "intermediate.key",
                "-set_serial", "77", "-sha256", "-out", cls.client_cert, "-days", "30", "-extfile", extensions)
        cls.client_chain = root / "client.chain.pem"
        cls.client_chain.write_bytes(cls.client_cert.read_bytes() + (root / "intermediate.pem").read_bytes())
        cls.client_ca = root / "clients-ca.pem"
        cls.client_ca.write_bytes(cls.certs.ca.read_bytes() + (root / "intermediate.pem").read_bytes())
        # These CA-signed identities exercise separator preservation and both
        # former fixed-buffer truncation boundaries through the public server.
        cls.identity_cases = {}
        for serial, label, subject, sans in (
            (78, "comma", "/O=lean-net/CN=comma-client",
             ["URI:spiffe://lean-net.test/al,ice", "URI:spiffe://lean-net.test/admin"]),
            (79, "large-san", "/O=lean-net/CN=large-san-client",
             ["URI:spiffe://lean-net.test/" + "x" * 1010,
              "URI:spiffe://lean-net.test/last"]),
            (80, "long-subject", "/CN=long-subject/OU=last-marker" +
             "".join(f"/OU=division-{i:02d}-" + "z" * 20 for i in range(20)),
             ["URI:spiffe://lean-net.test/long-subject"]),
            (81, "over-limit", "/CN=over-limit-client",
             [f"URI:spiffe://lean-net.test/{i:03d}/" + "x" * 240 for i in range(256)]),
        ):
            key, cert = root / f"{label}.key", root / f"{label}.pem"
            csr, ext = root / f"{label}.csr", root / f"{label}.ext"
            ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                           "extendedKeyUsage=clientAuth\nsubjectAltName=@names\n[names]\n" +
                           "".join(f"URI.{i}={name.removeprefix('URI:')}\n"
                                   for i, name in enumerate(sans, 1)))
            openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-keyout", key, "-out", csr, "-subj", subject)
            openssl("x509", "-req", "-in", csr, "-CA", root / "intermediate.pem",
                    "-CAkey", root / "intermediate.key", "-set_serial", str(serial),
                    "-sha256", "-out", cert, "-days", "30", "-extfile", ext)
            chain = root / f"{label}.chain.pem"
            chain.write_bytes(cert.read_bytes() + (root / "intermediate.pem").read_bytes())
            if label == "over-limit":
                cls.over_limit_identity = (key, chain)
            else:
                cls.identity_cases[label] = (key, chain, cert, sans)
        # Foreign client certificate (self-signed, unrelated CA).
        cls.foreign_key, cls.foreign_cert = root / "foreign.key", root / "foreign.pem"
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                "-keyout", cls.foreign_key, "-out", cls.foreign_cert, "-days", "2", "-subj", "/CN=intruder")
        # A GOOD OCSP response for the first leaf, signed by its issuer.
        serial = openssl("x509", "-in", cls.certs.leaves[0], "-noout", "-serial").stdout.decode().strip().split("=")[1]
        index = root / "index.txt"
        index.write_text(f"V\t301231000000Z\t\t{serial}\tunknown\t/CN={NAMES[0]}\n")
        cls.ocsp = root / "ocsp.der"
        openssl("ocsp", "-index", index, "-rsigner", root / "intermediate.pem", "-rkey", root / "intermediate.key",
                "-CA", root / "intermediate.pem", "-issuer", root / "intermediate.pem", "-cert", cls.certs.leaves[0],
                "-respout", cls.ocsp, "-ndays", "1")

    def start(self, *flags, binary=TLS_BINARY, prefix=True):
        port = free_port()
        arguments = ([self.certs.chains[0], self.certs.keys[0]] if prefix else []) + ["--workers", "2", *flags]
        server = Server(binary, arguments, port)
        self.addCleanup(server.stop)
        if server.process.poll() is not None:
            self.fail("server failed to start: " + server.output())
        return server

    def client(self, *, certificate=None, key=None, protocols=("http/1.1",)):
        ctx = context(self.certs, protocols)
        if certificate:
            ctx.load_cert_chain(str(certificate), str(key))
        return ctx

    def get(self, server, ctx, path=b"/"):
        with tls_socket(server.port, ctx) as sock:
            sock.sendall(request(path, close=True))
            return read_http(sock)

    def test_required_client_certificate(self):
        server = self.start("--client-ca", self.client_ca, "--require-client-cert")
        status, _, body = self.get(server, self.client(certificate=self.client_chain, key=self.client_key), b"/client-certificate")
        self.assertEqual(status, 200)
        self.assertIn(b"subject=CN=test-client,O=lean-net", body)
        self.assertIn(b"URI:spiffe://lean-net.test/worker", body)
        self.assertIn(b"DNS:client.lean-net.test", body)
        # No certificate: the handshake (or first read under TLS 1.3) fails.
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
            with tls_socket(server.port, self.client()) as sock:
                sock.sendall(request(b"/", close=True))
                if read_http(sock)[0] is None:
                    raise ssl.SSLError("rejected")
        # A certificate from an unrelated CA is rejected.
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
            with tls_socket(server.port, self.client(certificate=self.foreign_cert, key=self.foreign_key)) as sock:
                sock.sendall(request(b"/", close=True))
                if read_http(sock)[0] is None:
                    raise ssl.SSLError("rejected")
        self.assertIsNone(server.process.poll())

    def test_verified_identity_is_complete_and_separate(self):
        server = self.start("--client-ca", self.client_ca, "--require-client-cert")
        for label, (key, chain, cert, sans) in self.identity_cases.items():
            with self.subTest(label=label):
                status, _, body = self.get(server, self.client(certificate=chain, key=key),
                                           b"/client-certificate")
                self.assertEqual(status, 200)
                subject = openssl("x509", "-in", cert, "-noout", "-subject",
                                  "-nameopt", "RFC2253").stdout.decode().strip().removeprefix("subject=")
                self.assertIn(b"subject=" + subject.encode() + b"\n", body)
                actual_sans = [line.removeprefix(b"san=") for line in body.splitlines()
                               if line.startswith(b"san=")]
                self.assertEqual(actual_sans, [name.encode() for name in sans])
                if label == "long-subject":
                    self.assertGreater(len(subject), 511)

    def test_oversized_verified_identity_fails_closed(self):
        server = self.start("--client-ca", self.client_ca, "--require-client-cert")
        key, chain = self.over_limit_identity
        try:
            status, _, _ = self.get(server, self.client(certificate=chain, key=key),
                                    b"/client-certificate")
            self.assertIsNone(status)
        except (ssl.SSLError, ConnectionError, OSError):
            pass
        time.sleep(0.5)
        try:
            self.assertEqual(self.get(server, self.client(certificate=self.client_chain,
                                                          key=self.client_key))[0], 200)
        except OSError:
            self.fail(f"server stopped after oversized identity ({server.process.poll()}): " + server.output())

    def test_optional_client_certificate(self):
        server = self.start("--client-ca", self.client_ca)
        status, _, _ = self.get(server, self.client(), b"/client-certificate")
        self.assertEqual(status, 404)
        status, _, body = self.get(server, self.client(), b"/")
        self.assertEqual((status, body), (200, b"Hello from lean-net!\n"))
        status, _, body = self.get(server, self.client(certificate=self.client_chain, key=self.client_key), b"/client-certificate")
        self.assertEqual(status, 200)
        self.assertIn(b"test-client", body)

    def test_client_certificate_is_not_exposed_without_mtls(self):
        server = self.start()
        status, _, _ = self.get(server, self.client(certificate=self.client_chain, key=self.client_key), b"/client-certificate")
        self.assertEqual(status, 404)

    def s_client(self, server, *arguments, data=b"Q\n"):
        command = [openssl_binary(), "s_client", "-connect", f"{HOST}:{server.port}", "-servername", NAMES[0],
                   "-CAfile", str(self.certs.ca), *arguments]
        return subprocess.run(command, input=data, capture_output=True, timeout=20)

    def test_ocsp_stapling(self):
        server = self.start("--ocsp-response", self.ocsp)
        result = self.s_client(server, "-status")
        text = result.stdout.decode(errors="replace")
        self.assertIn("OCSP Response Status: successful", text)
        self.assertIn("Cert Status: good", text)
        plain = self.s_client(self.start(), "-status").stdout.decode(errors="replace")
        self.assertRegex(plain, r"OCSP responses?: no responses? sent")

    def test_invalid_ocsp_response_fails_startup(self):
        bogus = Path(self.directory.name) / "bogus.der"
        bogus.write_bytes(b"not an ocsp response")
        port = free_port()
        server = Server(TLS_BINARY, [self.certs.chains[0], self.certs.keys[0], "--ocsp-response", bogus], port)
        self.addCleanup(server.stop)
        self.assertNotEqual(server.process.wait(10), 0)
        self.assertIn("TLS certificate bundle", server.output())

    def test_hsts_and_security_headers_over_tls(self):
        server = self.start()
        status, headers, _ = self.get(server, self.client())
        self.assertEqual(status, 200)
        self.assertEqual(headers["strict-transport-security"], "max-age=31536000; includeSubDomains")
        self.assertEqual(headers["x-content-type-options"], "nosniff")

    def test_cipher_and_protocol_policy(self):
        server = self.start()
        for cipher in ("AES128-SHA", "AES256-GCM-SHA384", "ECDHE-RSA-AES128-SHA", "DHE-RSA-AES128-GCM-SHA256"):
            result = self.s_client(server, "-tls1_2", "-cipher", cipher)
            self.assertNotIn(b"Cipher is " + cipher.encode(), result.stdout, cipher)
            self.assertNotEqual(result.returncode, 0, cipher)
        accepted = self.s_client(server, "-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256")
        self.assertIn(b"ECDHE-RSA-AES128-GCM-SHA256", accepted.stdout)
        tls13 = self.s_client(server, "-tls1_3")
        self.assertIn(b"TLSv1.3", tls13.stdout)
        for legacy in ("-tls1", "-tls1_1"):
            result = self.s_client(server, legacy, "-cipher", "DEFAULT@SECLEVEL=0")
            self.assertNotEqual(result.returncode, 0, legacy)

    def test_session_resumption_and_alpn(self):
        server = self.start()
        session = Path(self.directory.name) / f"session-{server.port}.pem"
        first = self.s_client(server, "-tls1_2", "-sess_out", str(session))
        self.assertIn(b"New, TLSv1.2", first.stdout)
        second = self.s_client(server, "-tls1_2", "-sess_in", str(session))
        self.assertIn(b"Reused, TLSv1.2", second.stdout)
        h2 = self.s_client(server, "-alpn", "h2,http/1.1")
        self.assertIn(b"ALPN protocol: h2", h2.stdout)
        h1 = self.s_client(server, "-alpn", "http/1.1")
        self.assertIn(b"ALPN protocol: http/1.1", h1.stdout)

    def test_tls_handshake_metrics(self):
        server = self.start("--metrics")
        for _ in range(3):
            self.get(server, self.client())
        _, _, body = self.get(server, self.client(), b"/metrics")
        values = {line.split()[0]: int(line.split()[1]) for line in body.decode().splitlines()
                  if line.startswith("lean_net_tls_")}
        self.assertGreaterEqual(values["lean_net_tls_handshakes_total"], 4)
        self.assertIn("lean_net_tls_resumed_handshakes_total", values)

    def test_curl_four_mode_matrix_serves_one_route(self):
        curl = curl_binary()
        tls = self.start()
        plain_port = free_port()
        plain = Server(PLAIN_BINARY, ["--workers", "2"], plain_port)
        self.addCleanup(plain.stop)
        resolve = f"{NAMES[0]}:{tls.port}:{HOST}"
        modes = [
            (["--http1.0", f"http://{HOST}:{plain_port}/"], "1.0"),
            (["--http1.1", f"http://{HOST}:{plain_port}/"], "1.1"),
            (["--http2-prior-knowledge", f"http://{HOST}:{plain_port}/"], "2"),
            (["--http2", "--cacert", str(self.certs.ca), "--resolve", resolve, f"https://{NAMES[0]}:{tls.port}/"], "2"),
        ]
        for arguments, version in modes:
            with self.subTest(mode=arguments[0]):
                result = subprocess.run([curl, "-sS", "--noproxy", "*", "-w", "\n%{http_version} %{http_code}", *arguments],
                                        capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                body, _, summary = result.stdout.rpartition(b"\n")
                self.assertEqual(body, b"Hello from lean-net!\n")
                # curl reports HTTP/1.0 as "1.0" or "1" depending on version.
                self.assertIn(summary.decode(), {f"{version} 200", f"{version.split('.')[0] if version == '1.0' else version} 200"})

    def test_admission_receives_tls_transport_facts(self):
        port = free_port()
        command = [str(ADMISSION_BINARY), str(self.certs.chains[0]), str(self.certs.keys[0]), str(port), str(self.client_ca)]
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.addCleanup(lambda: (process.kill(), process.wait(), process.stderr.close()))
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                socket.create_connection((HOST, port), timeout=0.2).close(); break
            except OSError:
                time.sleep(0.05)
        # SNI and ALPN from the handshake, verified identity from the certificate.
        for protocols, alpn in ((("h2",), "h2"), (("http/1.1",), "http/1.1")):
            with self.subTest(alpn=alpn):
                ctx = self.client(certificate=self.client_chain, key=self.client_key, protocols=protocols)
                if alpn == "h2":
                    curl = curl_binary()
                    result = subprocess.run([curl, "-sS", "--noproxy", "*", "--http2", "--cacert", str(self.certs.ca),
                        "--cert", str(self.client_chain), "--key", str(self.client_key),
                        "--resolve", f"{NAMES[0]}:{port}:{HOST}", f"https://{NAMES[0]}:{port}/"],
                        capture_output=True, timeout=20)
                    body = result.stdout
                else:
                    with tls_socket(port, ctx) as sock:
                        sock.sendall(request(b"/", close=True))
                        body = read_http(sock)[2]
                text = body.decode()
                self.assertIn(f"secure=true sni={NAMES[0]} alpn={alpn} peer=4", text)
                self.assertIn("URI:spiffe://lean-net.test/worker", text)
                self.assertIn(f"authority={NAMES[0]}", text)
        # Without SNI (IP literal), the fact is absent rather than guessed.
        ctx = context(self.certs, ("http/1.1",))
        ctx.check_hostname = False
        raw = socket.create_connection((HOST, port), timeout=5)
        with ctx.wrap_socket(raw) as sock:
            sock.sendall(request(b"/", close=True))
            text = read_http(sock)[2].decode()
        self.assertIn("sni=none", text)
        self.assertIn("principal=none", text)

    def test_mtls_curl_acceptance_and_rejection(self):
        curl = curl_binary()
        server = self.start("--client-ca", self.client_ca, "--require-client-cert")
        base = [curl, "-sS", "--noproxy", "*", "--cacert", str(self.certs.ca), "--resolve", f"{NAMES[0]}:{server.port}:{HOST}",
                f"https://{NAMES[0]}:{server.port}/client-certificate"]
        accepted = subprocess.run(base + ["--cert", str(self.client_chain), "--key", str(self.client_key)],
                                  capture_output=True, timeout=20)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertIn(b"CN=test-client", accepted.stdout)
        rejected = subprocess.run(base, capture_output=True, timeout=20)
        self.assertNotEqual(rejected.returncode, 0)


if __name__ == "__main__":
    unittest.main()
