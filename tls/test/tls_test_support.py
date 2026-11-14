"""Independent verified TLS clients and isolated certificates for acceptance.

Nothing is added to the operating system trust store. The generated server
chains contain leaf + intermediate, never the root. This module uses stdlib
plus an explicit OpenSSL executable; it does not import the production shim.
"""
from dataclasses import dataclass
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
HOST = "127.0.0.1"
NAMES = ("alpha.test", "beta.test")
BINARY_BODY = b"\x00\xff\r\nA"


def openssl_binary():
    configured = os.environ.get("LEAN_NET_TEST_OPENSSL")
    if configured:
        return configured
    versioned = Path("/opt/homebrew/opt/openssl@3/bin/openssl")
    return str(versioned) if versioned.is_file() else (shutil.which("openssl") or "openssl")


def curl_binary():
    configured = os.environ.get("LEAN_NET_TEST_CURL")
    if configured:
        return configured
    homebrew = Path("/opt/homebrew/opt/curl/bin/curl")
    return str(homebrew) if homebrew.is_file() else (shutil.which("curl") or "curl")


def openssl(*arguments, timeout=20):
    return subprocess.run([openssl_binary(), *map(str, arguments)], check=True,
                          capture_output=True, timeout=timeout)


@dataclass(frozen=True)
class Certificates:
    ca: Path
    chains: tuple
    keys: tuple
    leaves: tuple
    fingerprints: tuple
    unrelated_ca: Path

    def fixture_arguments(self):
        return [str(self.chains[0]), str(self.keys[0]), str(self.chains[1]), str(self.keys[1])]


def create_certificates(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    root_key, root = directory / "ca.key", directory / "ca.pem"
    intermediate_key, intermediate = directory / "intermediate.key", directory / "intermediate.pem"
    csr = directory / "intermediate.csr"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-noenc", "-sha256",
            "-keyout", root_key, "-out", root, "-days", "365", "-subj", "/CN=lean-net isolated test CA",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    openssl("req", "-new", "-newkey", "rsa:2048", "-noenc", "-sha256",
            "-keyout", intermediate_key, "-out", csr, "-subj", "/CN=lean-net test intermediate")
    extensions = directory / "intermediate.ext"
    extensions.write_text("basicConstraints=critical,CA:TRUE,pathlen:0\n"
                          "keyUsage=critical,keyCertSign,cRLSign\n"
                          "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
    openssl("x509", "-req", "-in", csr, "-CA", root, "-CAkey", root_key,
            "-set_serial", "2", "-sha256", "-out", intermediate, "-days", "180", "-extfile", extensions)
    chains, keys, leaves, fingerprints = [], [], [], []
    for serial, name in enumerate(NAMES, 10):
        key, leaf = directory / f"{name}.key", directory / f"{name}.pem"
        chain, csr = directory / f"{name}.chain.pem", directory / f"{name}.csr"
        extensions = directory / f"{name}.ext"
        extensions.write_text("basicConstraints=critical,CA:FALSE\n"
                              "keyUsage=critical,digitalSignature,keyEncipherment\n"
                              "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\n"
                              f"authorityKeyIdentifier=keyid:always\nsubjectAltName=DNS:{name}\n")
        openssl("req", "-new", "-newkey", "rsa:2048", "-noenc", "-sha256",
                "-keyout", key, "-out", csr, "-subj", f"/CN={name}")
        openssl("x509", "-req", "-in", csr, "-CA", intermediate, "-CAkey", intermediate_key,
                "-set_serial", str(serial), "-sha256", "-out", leaf, "-days", "90", "-extfile", extensions)
        chain.write_bytes(leaf.read_bytes() + intermediate.read_bytes())
        der = ssl.PEM_cert_to_DER_cert(leaf.read_text())
        chains.append(chain); keys.append(key); leaves.append(leaf)
        fingerprints.append(hashlib.sha256(der).hexdigest())
    unrelated_key, unrelated = directory / "unrelated.key", directory / "unrelated.pem"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-noenc", "-sha256",
            "-keyout", unrelated_key, "-out", unrelated, "-days", "2", "-subj", "/CN=unrelated test CA",
            "-addext", "basicConstraints=critical,CA:TRUE")
    for key in (root_key, intermediate_key, unrelated_key, *keys):
        key.chmod(0o600)
    return Certificates(root, tuple(chains), tuple(keys), tuple(leaves), tuple(fingerprints), unrelated)


def context(certificates, protocols=("http/1.1",), version=None, *, tickets=True, cafile=None):
    ctx = ssl.create_default_context(cafile=str(cafile or certificates.ca))
    if protocols is not None:
        ctx.set_alpn_protocols(list(protocols))
    if version is not None:
        ctx.minimum_version = ctx.maximum_version = version
    if not tickets:
        ctx.options |= ssl.OP_NO_TICKET
    return ctx


def tls_socket(port, ctx, name=NAMES[0], *, session=None, receive_buffer=None, timeout=5):
    raw = socket.socket()
    raw.settimeout(timeout)
    if receive_buffer is not None:
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, receive_buffer)
    try:
        raw.connect((HOST, port))
        return ctx.wrap_socket(raw, server_hostname=name, session=session, suppress_ragged_eofs=False)
    except BaseException:
        raw.close()
        raise


def request(path=b"/", *, method=b"GET", name=NAMES[0], close=False, headers=b"", body=b"", version=b"HTTP/1.1"):
    connection = b"Connection: close\r\n" if close else b""
    return method + b" " + path + b" " + version + b"\r\nHost: " + name.encode() + b"\r\n" + connection + headers + b"\r\n" + body


class MemoryTLSClient:
    """TLS engine with controllable ciphertext boundaries and close-notify.

    Reads remain bounded by the underlying socket timeout. drain() deliberately
    coalesces all ciphertext pending in the outgoing BIO into one TCP write.
    """
    def __init__(self, port, ctx, name=NAMES[0], *, fragment=0):
        self.raw = socket.create_connection((HOST, port), timeout=5)
        self.write_lock = threading.Lock()
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.engine = ctx.wrap_bio(self.incoming, self.outgoing, server_side=False, server_hostname=name)
        try:
            deadline = time.monotonic() + 8
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError("fragmented TLS handshake exceeded deadline")
                try:
                    self.engine.do_handshake()
                    self.drain(fragment)
                    break
                except ssl.SSLWantReadError:
                    self.drain(fragment)
                    self._receive_ciphertext()
                except ssl.SSLWantWriteError:
                    self.drain(fragment)
        except BaseException:
            self.raw.close()
            raise

    def _receive_ciphertext(self):
        encrypted = self.raw.recv(65536)
        if encrypted:
            self.incoming.write(encrypted)
        else:
            self.incoming.write_eof()

    def drain(self, fragment=0):
        encrypted = self.outgoing.read()
        if encrypted:
            with self.write_lock:
                if fragment:
                    for offset in range(0, len(encrypted), fragment):
                        self.raw.sendall(encrypted[offset:offset + fragment])
                else:
                    self.raw.sendall(encrypted)

    def sendall(self, plaintext):
        offset = 0
        while offset < len(plaintext):
            try:
                offset += self.engine.write(plaintext[offset:])
                self.drain()
            except ssl.SSLWantReadError:
                self.drain(); self._receive_ciphertext()
            except ssl.SSLWantWriteError:
                self.drain()

    def recv(self, size):
        while True:
            try:
                return self.engine.read(size)
            except ssl.SSLZeroReturnError:
                return b""
            except ssl.SSLWantReadError:
                self.drain(); self._receive_ciphertext()
            except ssl.SSLWantWriteError:
                self.drain()

    def send_close_notify(self):
        try:
            self.engine.unwrap()
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            pass
        self.drain()

    def close(self):
        self.raw.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate an isolated two-SNI TLS test PKI")
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    certs = create_certificates(args.directory)
    print(json.dumps({"ca": str(certs.ca), "names": NAMES, "chains": list(map(str, certs.chains)),
                      "keys": list(map(str, certs.keys)), "sha256": certs.fingerprints}, indent=2))
