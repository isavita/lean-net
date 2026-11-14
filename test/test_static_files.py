#!/usr/bin/env python3
"""Real static-file acceptance across HTTP/1.0, HTTP/1.1, h2c and verified h2.

Build the public HTTP/TLS CLIs plus lean-net-static-fixture and
lean-net-tls-static-fixture. Uses the pinned independent HPACK test dependency,
stdlib gzip and the installed native Brotli decoder; it installs no packages.
"""
import ctypes
import ctypes.util
import gzip
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

from http2_test_support import H2Client, frame, settings, window, priority_update
from test_echo import unused_port
from test_http1_reactor import Reader, resource_count

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tls/test"))
from tls_test_support import NAMES, context, create_certificates, curl_binary, tls_socket

SUFFIX = ".exe" if sys.platform == "win32" else ""
PLAIN = Path(os.environ.get("LEAN_NET_STATIC_BIN", ROOT / f".lake/build/bin/lean-net-static-fixture{SUFFIX}"))
TLS = Path(os.environ.get("LEAN_NET_TLS_STATIC_BIN", ROOT / f"tls/.lake/build/bin/lean-net-tls-static-fixture{SUFFIX}"))
PUBLIC = Path(os.environ.get("LEAN_NET_STATIC_HTTP_BIN", ROOT / f".lake/build/bin/lean-net-http1{SUFFIX}"))
PUBLIC_TLS = Path(os.environ.get("LEAN_NET_STATIC_HTTPS_BIN", ROOT / f"tls/.lake/build/bin/lean-net-tls{SUFFIX}"))
ASSET = bytes(range(256)) * 32
SMALL = b"\x00\xffsmall\r\n"
LARGE = (bytes(range(256)) * 4) * 4096
MEDIUM_A, MEDIUM_B = b"A" * 196608, b"B" * 196608
INDEX = b"<!doctype html><title>Nested index</title>\x00\xff"


def request(path=b"/asset.bin", *, method=b"GET", fields=(), close=True, version=b"HTTP/1.1"):
    headers = b"".join(name + b": " + value + b"\r\n" for name, value in fields)
    return method + b" " + path + b" " + version + b"\r\nHost: " + NAMES[0].encode() + b"\r\n" + headers + (
        b"Connection: close\r\n" if close else b"") + b"\r\n"


def decode_brotli(encoded, expected_length):
    candidates = [os.environ.get("LEAN_NET_TEST_BROTLI_DECODER"), ctypes.util.find_library("brotlidec"),
                  "/opt/homebrew/opt/brotli/lib/libbrotlidec.dylib", "libbrotlidec.dll", "brotlidec.dll"]
    try:
        directory = Path(subprocess.check_output(
            ["pkg-config", "--variable=libdir", "libbrotlidec"], text=True, timeout=5).strip())
        candidates.insert(1, str(directory.parent / "bin/libbrotlidec.dll" if sys.platform == "win32" else
                                 directory / ("libbrotlidec.dylib" if sys.platform == "darwin" else "libbrotlidec.so")))
    except (OSError, subprocess.SubprocessError):
        pass
    library = None
    for candidate in candidates:
        if candidate:
            try:
                library = ctypes.CDLL(candidate)
                break
            except OSError:
                pass
    if library is None:
        raise RuntimeError("independent libbrotlidec is required for static-file acceptance")
    decode = library.BrotliDecoderDecompress
    decode.argtypes = [ctypes.c_size_t, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p]
    decode.restype = ctypes.c_int
    source = ctypes.create_string_buffer(encoded)
    output = ctypes.create_string_buffer(max(1, expected_length))
    length = ctypes.c_size_t(expected_length)
    if decode(len(encoded), source, ctypes.byref(length), output) != 1 or length.value != expected_length:
        raise AssertionError("independent Brotli decoder rejected the selected representation")
    return output.raw[:length.value]


class Tree:
    def __init__(self, directory):
        self.root = Path(directory) / "public"
        self.root.mkdir()
        (self.root / "nested").mkdir()
        (self.root / "listing").mkdir()
        self.files = {
            "asset.bin": ASSET, "small.bin": SMALL, "large.bin": LARGE,
            "priority-a.bin": MEDIUM_A, "priority-b.bin": MEDIUM_B,
            "recent.bin": ASSET, "empty.bin": b"", "nested/index.html": INDEX,
            "listing/amp&'name.txt": b"escaped name", "listing/snow-雪.txt": b"unicode name"}
        self.old_time = int(time.time()) - 3600
        for name, data in self.files.items():
            target = self.root / name
            target.write_bytes(data)
            if name != "recent.bin":
                os.utime(target, (self.old_time, self.old_time))
        outside = Path(directory) / "outside"
        outside.mkdir()
        (outside / "secret.bin").write_bytes(b"OUTSIDE-ROOT-SECRET")
        try:
            os.symlink(outside / "secret.bin", self.root / "file-link")
            os.symlink(outside, self.root / "directory-link", target_is_directory=True)
        except OSError:
            if sys.platform != "win32":
                raise
            # Directory junctions exercise the same native reparse-point guard
            # on Windows machines without symbolic-link creation privilege.
            result = subprocess.run(["cmd", "/d", "/c", "mklink", "/J", str(self.root / "directory-link"), str(outside)],
                                    capture_output=True, text=True, timeout=5)
            if result.returncode:
                raise RuntimeError("cannot create the required Windows reparse-point fixture: " + result.stdout + result.stderr)
        if sys.platform != "win32":
            os.mkfifo(self.root / "named-pipe")


class Server:
    def __init__(self, tree, certificates, *, tls=False, public=False, port=None, memory=None, root=None):
        self.tls = tls
        self.certificates = certificates
        self.port = port or unused_port()
        self.log = tempfile.TemporaryFile(mode="w+")
        binary = PUBLIC_TLS if public and tls else PUBLIC if public else TLS if tls else PLAIN
        if not binary.is_file():
            self.log.close()
            raise AssertionError(f"missing static-file executable: {binary}")
        chosen_root = Path(root) if root is not None else tree.root
        if public:
            command = [str(binary)] + ([str(certificates.chains[0]), str(certificates.keys[0])] if tls else [])
            command += [str(self.port), "--static", str(chosen_root)]
            if memory is not None:
                command += ["--static-memory", str(memory)]
        else:
            command = [str(binary), str(chosen_root)] + ([str(certificates.chains[0]), str(certificates.keys[0])] if tls else []) + [str(self.port)]
        self.command = command
        self.stopped = False
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        self.process = subprocess.Popen(command, stdout=self.log, stderr=self.log, creationflags=flags)
        self.http1 = context(certificates)

    def connect(self, *, h2=False, receive_buffer=None, timeout=8):
        if self.tls:
            return tls_socket(self.port, context(self.certificates, ["h2"]) if h2 else self.http1,
                              receive_buffer=receive_buffer, timeout=timeout)
        sock = socket.socket()
        try:
            if receive_buffer is not None:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, receive_buffer)
            sock.settimeout(timeout)
            sock.connect(("127.0.0.1", self.port))
            return sock
        except BaseException:
            sock.close()
            raise

    def get(self, path=b"/asset.bin", *, method=b"GET", fields=(), version=b"HTTP/1.1"):
        with self.connect() as sock:
            sock.sendall(request(path, method=method, fields=fields, version=version))
            reader = Reader(sock)
            response = reader.response(head=method == b"HEAD")
            reader.eof()
            return response

    def peer(self, **kwargs):
        sock = self.connect(h2=True)
        if self.tls and sock.selected_alpn_protocol() != "h2":
            sock.close()
            raise AssertionError("verified TLS static server did not select h2")
        return H2Client(sock=sock, authority=NAMES[0].encode(), scheme=b"https" if self.tls else b"http", **kwargs)

    def ready(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError(f"static startup exit {self.process.returncode}: {self.output()}")
            try:
                response = self.get(b"/small.bin")
                if (response.status, response.body) != (200, SMALL):
                    raise AssertionError(f"static fixture served unexpected route: {response}")
                return
            except (ConnectionError, OSError, ssl.SSLError):
                time.sleep(.025)
        raise AssertionError("static server startup deadline: " + self.output())

    def output(self):
        self.log.flush()
        self.log.seek(0)
        return self.log.read()

    def stop(self):
        if self.stopped:
            return
        self.stopped = True
        try:
            if self.process.poll() is None:
                self.process.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
                try:
                    self.process.wait(timeout=7)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
                    raise AssertionError("static worker shutdown exceeded seven seconds: " + self.output())
            if self.process.returncode:
                raise AssertionError(f"static server exit {self.process.returncode}: {self.output()}")
        finally:
            self.log.close()


class AssetsCase:
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.directory = tempfile.TemporaryDirectory(prefix="lean-net-static-wire-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.tree = Tree(cls.directory.name)
        cls.certificates = create_certificates(Path(cls.directory.name) / "pki")


class StaticBehavior(AssetsCase):
    tls = False

    def setUp(self):
        super().setUp()
        now = time.time()
        os.utime(self.tree.root / "recent.bin", (now, now))
        self.server = Server(self.tree, self.certificates, tls=self.tls)
        self.addCleanup(self.server.stop)
        self.server.ready()

    def get(self, *args, **kwargs):
        return self.server.get(*args, **kwargs)

    def peer(self, **kwargs):
        peer = self.server.peer(**kwargs)
        self.addCleanup(peer.close)
        return peer

    def test_identity_gzip_brotli_negotiation_and_variant_validators(self):
        representations = {}
        for coding in (b"identity", b"gzip", b"br"):
            with self.subTest(coding=coding):
                reply = self.get(fields=[(b"Accept-Encoding", coding)])
                self.assertEqual(reply.status, 200)
                self.assertEqual(reply.headers.get(b"vary", b"").lower(), b"accept-encoding")
                self.assertEqual(int(reply.headers[b"content-length"]), len(reply.body))
                self.assertEqual(reply.headers.get(b"content-encoding"), None if coding == b"identity" else coding)
                decoded = reply.body if coding == b"identity" else gzip.decompress(reply.body) if coding == b"gzip" else decode_brotli(reply.body, len(ASSET))
                self.assertEqual(decoded, ASSET)
                etag = reply.headers[b"etag"]
                self.assertTrue(etag.startswith(b'"') and etag.endswith(b'"'))
                again = self.get(fields=[(b"Accept-Encoding", coding)])
                self.assertEqual((again.body, again.headers[b"etag"]), (reply.body, etag))
                head = self.get(method=b"HEAD", fields=[(b"Accept-Encoding", coding)])
                self.assertEqual((head.body, head.headers[b"content-length"]), (b"", str(len(reply.body)).encode()))
                representations[coding] = etag
        self.assertEqual(len(set(representations.values())), 3)
        for offered, expected in ((b"br;q=0, gzip;q=1", b"gzip"), (b"br;q=0, gzip;q=0", None),
                                  (b"identity;q=1, gzip;q=0.5, br;q=0.1", None), (b"gzip;q=0, br;q=1", b"br")):
            reply = self.get(fields=[(b"Accept-Encoding", offered)])
            self.assertEqual((reply.status, reply.headers.get(b"content-encoding")), (200, expected))
        for offered in (b"identity;q=0, gzip;q=0, br;q=0", b"*;q=0"):
            self.assertEqual(self.get(fields=[(b"Accept-Encoding", offered)]).status, 406)

    def test_head_preconditions_and_representation_matching(self):
        current = self.get()
        etag, modified = current.headers[b"etag"], current.headers[b"last-modified"]
        head = self.get(method=b"HEAD")
        self.assertEqual((head.status, head.body, head.headers[b"content-length"]), (200, b"", str(len(ASSET)).encode()))
        head_range = self.get(method=b"HEAD", fields=[(b"Range", b"bytes=0-7")])
        self.assertEqual((head_range.status, head_range.body, head_range.headers[b"content-length"]),
                         (200, b"", str(len(ASSET)).encode()))
        for value in (etag, b"W/" + etag, b"*", b'"other", W/' + etag):
            reply = self.get(fields=[(b"If-None-Match", value)])
            self.assertEqual((reply.status, reply.body), (304, b""))
            self.assertNotIn(b"content-length", reply.headers)
            self.assertNotIn(b"transfer-encoding", reply.headers)
        self.assertEqual(self.get(fields=[(b"If-Modified-Since", modified)]).status, 304)
        self.assertEqual(self.get(fields=[(b"If-None-Match", b'"different"'),
                                         (b"If-Modified-Since", modified)]).status, 200)
        compressed = self.get(fields=[(b"Accept-Encoding", b"gzip")])
        self.assertEqual(self.get(fields=[(b"If-None-Match", compressed.headers[b"etag"])]).status, 200)
        self.assertEqual(self.get(fields=[(b"Accept-Encoding", b"gzip"),
                                         (b"If-None-Match", compressed.headers[b"etag"])]).status, 304)
        self.assertEqual(self.get(fields=[(b"If-Match", etag)]).status, 200)
        self.assertEqual(self.get(fields=[(b"If-Match", b"W/" + etag)]).status, 412)
        self.assertEqual(self.get(fields=[(b"If-Match", b'"different"'), (b"If-None-Match", b"*")]).status, 412)

    def test_single_ranges_and_if_range_dates(self):
        full = self.get()
        for value, start, stop in ((b"bytes=2-10", 2, 11), (b"bytes=17-", 17, len(ASSET)),
                                   (b"bytes=-19", len(ASSET) - 19, len(ASSET)),
                                   (b"bytes=0-999999", 0, len(ASSET))):
            reply = self.get(fields=[(b"Range", value)])
            self.assertEqual((reply.status, reply.body), (206, ASSET[start:stop]))
            self.assertEqual(reply.headers[b"content-range"], f"bytes {start}-{stop - 1}/{len(ASSET)}".encode())
            self.assertEqual(int(reply.headers[b"content-length"]), stop - start)
        unsatisfied = self.get(fields=[(b"Range", b"bytes=999999-")])
        self.assertEqual(unsatisfied.status, 416)
        self.assertEqual(unsatisfied.headers[b"content-range"], f"bytes */{len(ASSET)}".encode())
        for value in (b"bytes=0-1,4-5", b"bytes=invalid", b"other=0-1"):
            reply = self.get(fields=[(b"Range", value)])
            self.assertEqual((reply.status, reply.body), (200, ASSET))
        for validator, expected in ((full.headers[b"etag"], 206), (b"W/" + full.headers[b"etag"], 200),
                                    (b'"different"', 200), (full.headers[b"last-modified"], 206),
                                    (b"Thu, 01 Jan 1970 00:00:00 GMT", 200)):
            reply = self.get(fields=[(b"Range", b"bytes=1-3"), (b"If-Range", validator)])
            self.assertEqual((reply.status, reply.body), (expected, ASSET[1:4] if expected == 206 else ASSET))
        recent = self.get(b"/recent.bin")
        reply = self.get(b"/recent.bin", fields=[(b"Range", b"bytes=1-3"), (b"If-Range", recent.headers[b"last-modified"])])
        self.assertEqual((reply.status, reply.body), (200, ASSET), "recent timestamps must not become strong validators")
        compressed = self.get(fields=[(b"Accept-Encoding", b"gzip")])
        reply = self.get(fields=[(b"Accept-Encoding", b"gzip"), (b"Range", b"bytes=2-10"),
                                 (b"If-Range", compressed.headers[b"etag"])])
        self.assertEqual((reply.status, reply.body, reply.headers[b"content-encoding"]), (206, compressed.body[2:11], b"gzip"))
        self.assertEqual(reply.headers[b"content-range"], f"bytes 2-10/{len(compressed.body)}".encode())

    def test_pipelined_file_ranges_and_binary_tails(self):
        with self.server.connect() as sock:
            sock.sendall(request(fields=[(b"Range", b"bytes=0-7")], close=False) +
                         request(b"/priority-a.bin", fields=[(b"Range", b"bytes=-129")], close=False) +
                         request(b"/small.bin"))
            reader = Reader(sock)
            first, second = reader.response(), reader.response()
            self.assertEqual((first.status, first.body), (206, ASSET[:8]))
            self.assertEqual((second.status, second.body), (206, MEDIUM_A[-129:]))
            self.assertEqual(reader.response().body, SMALL)
            reader.eof()

    def test_empty_file_keeps_length_and_pipeline_boundaries(self):
        empty = self.get(b"/empty.bin")
        self.assertEqual((empty.status, empty.body, empty.headers[b"content-length"]), (200, b"", b"0"))
        head = self.get(b"/empty.bin", method=b"HEAD")
        self.assertEqual((head.status, head.body, head.headers[b"content-length"]), (200, b"", b"0"))
        unsatisfied = self.get(b"/empty.bin", fields=[(b"Range", b"bytes=0-")])
        self.assertEqual((unsatisfied.status, unsatisfied.headers[b"content-range"]), (416, b"bytes */0"))
        with self.server.connect() as sock:
            sock.sendall(request(b"/empty.bin", close=False) + request(b"/small.bin"))
            reader = Reader(sock)
            self.assertEqual(reader.response().body, b"")
            self.assertEqual(reader.response().body, SMALL)
            reader.eof()
        peer = self.peer()
        peer.request(1, b"/empty.bin")
        peer.request(3, b"/small.bin")
        self.assertEqual(peer.response(1), b"")
        self.assertEqual(dict(peer.headers[1][0].headers)[b"content-length"], b"0")
        self.assertEqual(peer.response(3), SMALL)

    def test_representation_hashes_and_bytes_survive_catalog_rebuild(self):
        before = {coding: self.get(fields=[(b"Accept-Encoding", coding)])
                  for coding in (b"identity", b"gzip", b"br")}
        self.server.stop()
        self.server = Server(self.tree, self.certificates, tls=self.tls)
        self.addCleanup(self.server.stop)
        self.server.ready()
        for coding, previous in before.items():
            current = self.get(fields=[(b"Accept-Encoding", coding)])
            self.assertEqual((current.body, current.headers[b"etag"]),
                             (previous.body, previous.headers[b"etag"]))

    def test_directory_index_redirect_listing_and_path_boundaries(self):
        alias, direct = self.get(b"/nested/"), self.get(b"/nested/index.html")
        self.assertEqual((alias.body, alias.headers[b"etag"]), (INDEX, direct.headers[b"etag"]))
        redirect = self.get(b"/nested?x=a%26b")
        self.assertEqual((redirect.status, redirect.headers[b"location"]), (308, b"/nested/?x=a%26b"))
        listing = self.get(b"/listing/")
        self.assertEqual(listing.status, 200)
        self.assertIn(b"amp&amp;&#39;name.txt", listing.body)
        self.assertIn(b"amp%26%27name.txt", listing.body)
        self.assertIn("snow-雪.txt".encode(), listing.body)
        self.assertIn(b"snow-%E9%9B%AA.txt", listing.body)
        self.assertEqual(self.get(b"/listing/snow-%E9%9B%AA.txt").body, b"unicode name")
        for path in (b"/../asset.bin", b"/%2e%2e/asset.bin", b"/nested/%2E%2E/asset.bin", b"//asset.bin",
                     b"/nested%2findex.html", b"/%5csecret", b"/con", b"/NUL.txt", b"/com1.bin", b"/asset.bin.", b"/%FF"):
            with self.subTest(path=path):
                self.assertEqual(self.get(path).status, 400)
        for path in (b"/%252e%252e/asset.bin", b"/file-link", b"/directory-link/secret.bin", b"/named-pipe"):
            self.assertEqual(self.get(path).status, 404)
        self.assertEqual(self.get(method=b"POST").status, 405)

    def test_snapshot_survives_original_truncation_deletion_and_new_files(self):
        before = self.get()
        compressed = self.get(fields=[(b"Accept-Encoding", b"gzip")])
        original = self.tree.root / "asset.bin"
        added = self.tree.root / "new-after-start.bin"
        try:
            original.write_bytes(b"TRUNCATED ORIGINAL")
            original.unlink()
            added.write_bytes(b"not in the prepared catalog")
            after = self.get()
            self.assertEqual((after.body, after.headers[b"etag"], after.headers[b"last-modified"]),
                             (ASSET, before.headers[b"etag"], before.headers[b"last-modified"]))
            after_gzip = self.get(fields=[(b"Accept-Encoding", b"gzip")])
            self.assertEqual((after_gzip.body, after_gzip.headers[b"etag"]), (compressed.body, compressed.headers[b"etag"]))
            self.assertEqual(self.get(b"/new-after-start.bin").status, 404)
            peer = self.peer()
            peer.request(1, b"/asset.bin")
            self.assertEqual(peer.response(1), ASSET)
        finally:
            original.write_bytes(ASSET)
            os.utime(original, (self.tree.old_time, self.tree.old_time))
            added.unlink(missing_ok=True)

    def test_h2_file_metadata_flow_control_and_urgency(self):
        peer = self.peer(settings_values=[(4, 0)], auto_window=False)
        peer.request(1, b"/priority-a.bin", headers=[(b"priority", b"u=7")])
        peer.request(3, b"/asset.bin", headers=[(b"priority", b"u=0")])
        peer.request(5, b"/asset.bin", method=b"HEAD")
        peer.ping_barrier()
        peer.until(lambda: bool(peer.headers[1] and peer.headers[3]) and 5 in peer.ended)
        self.assertFalse(peer.data_order, "file bytes crossed a zero stream window")
        self.assertEqual(dict(peer.headers[5][0].headers)[b"content-length"], str(len(ASSET)).encode())
        self.assertEqual(bytes(peer.bodies[5]), b"")
        peer.send(window(0, 1024 * 1024))
        peer.send(settings([(4, 65536)]))
        self.assertEqual(peer.response(3), ASSET)
        self.assertEqual(peer.data_order[0][0], 3, "higher urgency file did not win simultaneous credit")
        peer.ping_barrier(b"fileflow")
        peer.until(lambda: len(peer.bodies[1]) >= 65536)
        self.assertEqual(len(peer.bodies[1]), 65536)
        self.assertNotIn(1, peer.ended)
        peer.send(window(1, len(MEDIUM_A)))
        self.assertEqual(peer.response(1), MEDIUM_A)
        self.assertFalse(peer.goaways)

    def test_h2_cancel_after_data_header_preserves_following_frames(self):
        peer = self.peer(settings_values=[(4, 16384)], auto_window=False)
        peer.request(1, b"/large.bin", headers=[(b"priority", b"u=0")])
        peer.request(3, b"/asset.bin", headers=[(b"priority", b"u=7")])
        for _ in range(128):
            header = peer.take(9)
            kind, stream = header[3], int.from_bytes(header[5:], "big") & 0x7fffffff
            peer.buffer[:0] = header
            if kind == 0 and stream == 1:
                # Cancel after seeing the frame header but before consuming its
                # file payload. The next frame still has to start at its exact
                # advertised boundary, including on TLS queue capacity one.
                peer.send(frame(3, stream=1, payload=struct.pack(">I", 8)))
                break
            peer.read()
        else:
            self.fail("large file did not produce a DATA frame")
        self.assertEqual(peer.response(3), ASSET)
        peer.ping_barrier(b"filecancel"[:8])
        peer.request(5, b"/small.bin")
        self.assertEqual(peer.response(5), SMALL)
        self.assertFalse(peer.goaways)
        self.assertNotIn(3, peer.resets)
        self.assertEqual(bytes(peer.bodies[1]), LARGE[:len(peer.bodies[1])])

    def test_h2_priority_update_reorders_files_when_credit_arrives(self):
        peer = self.peer(settings_values=[(4, 0)], auto_window=False)
        peer.request(1, b"/priority-a.bin", headers=[(b"priority", b"u=7")])
        peer.request(3, b"/priority-b.bin", headers=[(b"priority", b"u=7")])
        peer.ping_barrier()
        peer.until(lambda: bool(peer.headers[1] and peer.headers[3]))
        self.assertFalse(peer.data_order)
        peer.send(priority_update(3, b"u=0, i") + window(0, 1024 * 1024) + settings([(4, 32768)]))
        peer.until(lambda: len(peer.bodies[1]) + len(peer.bodies[3]) >= 65536)
        self.assertEqual(peer.data_order[0][0], 3)
        self.assertEqual(bytes(peer.bodies[1]), MEDIUM_A[:32768])
        self.assertEqual(bytes(peer.bodies[3]), MEDIUM_B[:32768])
        self.assertFalse(peer.ended)
        peer.send(window(3, len(MEDIUM_B)) + window(1, len(MEDIUM_A)))
        self.assertEqual(peer.response(3), MEDIUM_B)
        self.assertEqual(peer.response(1), MEDIUM_A)
        self.assertFalse(peer.goaways)

    def test_h2_ranges_compressed_variants_and_not_modified(self):
        etag = self.get().headers[b"etag"]
        peer = self.peer()
        peer.request(1, b"/asset.bin", headers=[(b"range", b"bytes=10-29")])
        peer.request(3, b"/asset.bin", headers=[(b"accept-encoding", b"br")])
        peer.request(5, b"/asset.bin", headers=[(b"if-none-match", b"W/" + etag)])
        peer.until(lambda: all(stream in peer.ended for stream in (1, 3, 5)))
        self.assertFalse(peer.goaways)
        first = dict(peer.headers[1][0].headers)
        self.assertEqual((first[b":status"], first[b"content-range"], bytes(peer.bodies[1])),
                         (b"206", f"bytes 10-29/{len(ASSET)}".encode(), ASSET[10:30]))
        compressed = dict(peer.headers[3][0].headers)
        self.assertEqual((compressed[b":status"], compressed[b"content-encoding"]), (b"200", b"br"))
        self.assertEqual(decode_brotli(bytes(peer.bodies[3]), len(ASSET)), ASSET)
        not_modified = dict(peer.headers[5][0].headers)
        self.assertEqual(not_modified[b":status"], b"304")
        self.assertNotIn(b"content-length", not_modified)
        self.assertEqual(bytes(peer.bodies[5]), b"")

    def test_large_file_slow_reader_allows_same_worker_progress(self):
        with self.server.connect(receive_buffer=16384, timeout=15) as slow:
            slow.sendall(request(b"/large.bin"))
            time.sleep(.2)
            started = time.monotonic()
            healthy = self.get(b"/small.bin")
            self.assertEqual((healthy.status, healthy.body), (200, SMALL))
            self.assertLess(time.monotonic() - started, 2.5,
                            "blocked file output stopped another connection on the same worker")
            reader = Reader(slow)
            self.assertEqual(reader.response().body, LARGE)
            reader.eof()

    def test_thousand_file_cycles_keep_native_resources_flat(self):
        cycles = int(os.environ.get("LEAN_NET_STATIC_CYCLES", "1000"))
        self.assertGreaterEqual(cycles, 1000, "acceptance requires the full 1000-cycle resource gate")
        for _ in range(16):
            self.assertEqual(self.get(b"/small.bin").body, SMALL)
        time.sleep(.1)
        before = resource_count(self.server.process.pid)
        for _ in range(cycles):
            reply = self.get(fields=[(b"Range", b"bytes=0-7")])
            self.assertEqual((reply.status, reply.body), (206, ASSET[:8]))
        deadline = time.monotonic() + 3
        while True:
            after = resource_count(self.server.process.pid)
            if after <= before + 2 or time.monotonic() >= deadline:
                break
            time.sleep(.025)
        self.assertLessEqual(after, before + 2, f"static file descriptor/HANDLE growth: {before} -> {after}")
        self.assertIsNone(self.server.process.poll())

    def test_shutdown_bounds_active_file_and_partial_requests(self):
        slow = self.server.connect(receive_buffer=4096)
        partial = self.server.connect()
        try:
            slow.sendall(request(b"/large.bin", close=False))
            partial.sendall(b"GET /asset.bin HTTP/1.1\r\nHost:")
            time.sleep(.1)
            started = time.monotonic()
            self.server.stop()
            self.assertLess(time.monotonic() - started, 7)
        finally:
            slow.close()
            partial.close()


class StaticPlain(StaticBehavior, unittest.TestCase):
    pass


class StaticTLS(StaticBehavior, unittest.TestCase):
    tls = True


class PublicStaticCLI(AssetsCase, unittest.TestCase):
    def test_curl_four_protocols_serve_the_same_binary_asset(self):
        version = subprocess.run([curl_binary(), "--version"], capture_output=True, text=True, check=True, timeout=5)
        self.assertIn("HTTP2", version.stdout, "the conformance curl must support HTTP/2")
        plain = Server(self.tree, self.certificates, public=True)
        self.addCleanup(plain.stop)
        plain.ready()
        secure = Server(self.tree, self.certificates, public=True, tls=True)
        self.addCleanup(secure.stop)
        secure.ready()
        http10 = plain.get(version=b"HTTP/1.0")
        self.assertEqual((http10.version, http10.body), (b"HTTP/1.0", ASSET))
        for option, expected in (("--http1.0", b"1"), ("--http1.1", b"1.1"), ("--http2-prior-knowledge", b"2")):
            result = subprocess.run([curl_binary(), "--silent", "--show-error", "--fail", "--noproxy", "*",
                                     option, "-H", "Accept-Encoding: identity", "--write-out", "\n%{http_version}",
                                     f"http://127.0.0.1:{plain.port}/asset.bin"], capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            body, protocol = result.stdout.rsplit(b"\n", 1)
            self.assertEqual((body, protocol), (ASSET, expected))
        result = subprocess.run([curl_binary(), "--silent", "--show-error", "--fail", "--noproxy", "*", "--http2",
                                 "--cacert", str(self.certificates.ca), "--resolve", f"{NAMES[0]}:{secure.port}:127.0.0.1",
                                 "-H", "Accept-Encoding: identity", "--write-out", "\n%{http_version}",
                                 f"https://{NAMES[0]}:{secure.port}/asset.bin"], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        body, protocol = result.stdout.rsplit(b"\n", 1)
        self.assertEqual((body, protocol), (ASSET, b"2"))

    def test_invalid_roots_and_budgets_fail_before_listening(self):
        for tls in (False, True):
            binary = PUBLIC_TLS if tls else PUBLIC
            self.assertTrue(binary.is_file(), f"missing public static executable: {binary}")
            for root, memory in ((self.tree.root / "missing", None), (self.tree.root, "1"),
                                 (self.tree.root, "0"), (self.tree.root, "1025")):
                with self.subTest(tls=tls, root=root, memory=memory):
                    port = unused_port()
                    command = [str(binary)] + ([str(self.certificates.chains[0]), str(self.certificates.keys[0])] if tls else [])
                    command += [str(port), "--static", str(root)]
                    if memory is not None:
                        command += ["--static-memory", memory]
                    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertTrue(result.stdout or result.stderr, "startup failure omitted its diagnostic")
                    with socket.socket() as probe:
                        probe.bind(("127.0.0.1", port))
            # Successful preparation on the same last-used endpoint also checks
            # the application-level endpoint lease, beyond a bare bind probe.
            healthy = Server(self.tree, self.certificates, tls=tls, public=True, port=port)
            self.addCleanup(healthy.stop)
            healthy.ready()
            healthy.stop()


if __name__ == "__main__":
    unittest.main()
