"""Independent HTTP/2 wire client using the official, pinned HPACK codec.

Frames are intentionally built here rather than by a high-level HTTP client so
tests can send malformed frames and precisely control flow-control credit.
Header blocks are always decoded in wire order, including PUSH_PROMISE, keeping
the independent HPACK dynamic table synchronized across multiplexed streams.
"""
from collections import defaultdict
from dataclasses import dataclass
import socket
import struct

try:
    import hpack
except ImportError as error:
    raise RuntimeError("install the independent wire-test dependency: python -m pip install -r test/requirements-http2.txt") from error

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
BINARY = b"\x00\xff\r\nA"


def frame(kind, flags=0, stream=0, payload=b""):
    if len(payload) > 0xFFFFFF or not 0 <= stream <= 0x7FFFFFFF:
        raise ValueError("invalid frame range")
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + struct.pack(">I", stream) + payload


def settings(values=()):
    return frame(4, payload=b"".join(struct.pack(">HI", key, value) for key, value in values))


def window(stream, increment):
    return frame(8, stream=stream, payload=struct.pack(">I", increment))


def priority_update(target, field):
    return frame(0x10, payload=struct.pack(">I", target) + field)


@dataclass(frozen=True)
class Frame:
    kind: int
    flags: int
    stream: int
    payload: bytes


@dataclass(frozen=True)
class HeaderBlock:
    kind: str
    stream: int
    parent: int
    headers: tuple
    encoded: bytes
    end_stream: bool


class H2Client:
    def __init__(self, port=None, *, sock=None, settings_values=(), auto_window=True,
                 authority=b"localhost", scheme=b"http", timeout=5, handshake=True, auto_ack=True):
        self.sock = sock if sock is not None else socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buffer = bytearray()
        self.encoder = hpack.Encoder()
        self.decoder = hpack.Decoder(max_header_list_size=1024 * 1024)
        self.authority, self.scheme = authority, scheme
        self.auto_window = auto_window
        self.auto_ack = auto_ack
        self.max_frame_size = dict(settings_values).get(5, 16384)
        self.frames = []
        self.blocks = []
        self.headers = defaultdict(list)
        self.bodies = defaultdict(bytearray)
        self.ended = set()
        self.resets = {}
        self.promises = {}
        self.server_settings = {}
        self.goaways = []
        self.assembly = None
        self.data_order = []
        if handshake:
            try:
                self.sock.sendall(PREFACE + settings(settings_values))
                seen_settings = seen_ack = False
                for _ in range(128):
                    current = self.read()
                    if current.kind == 7:
                        raise AssertionError(f"GOAWAY during handshake: {self.goaways}")
                    if current.kind == 4:
                        if current.flags & 1:
                            seen_ack = True
                        else:
                            seen_settings = True
                    if seen_settings and seen_ack:
                        break
                else:
                    raise AssertionError("settings handshake exceeded frame budget")
            except BaseException:
                self.close()
                raise

    def close(self):
        self.sock.close()

    def send(self, data):
        self.sock.sendall(data)

    def encode_request(self, path=b"/binary", *, method=b"GET", headers=()):
        return self.encoder.encode([(b":method", method), (b":scheme", self.scheme),
                                    (b":path", path), (b":authority", self.authority), *headers])

    def request(self, stream, path=b"/binary", *, method=b"GET", headers=(), end_stream=True):
        block = self.encode_request(path, method=method, headers=headers)
        self.send(frame(1, 4 | bool(end_stream), stream, block))

    def take(self, length):
        while len(self.buffer) < length:
            part = self.sock.recv(65536)
            if not part:
                raise EOFError(f"HTTP/2 EOF with {len(self.buffer)} of {length} frame bytes")
            self.buffer.extend(part)
        result = bytes(self.buffer[:length]); del self.buffer[:length]
        return result

    def _complete_headers(self):
        state = self.assembly
        encoded = b"".join(state["fragments"])
        decoded = tuple(self.decoder.decode(encoded, raw=True))
        block = HeaderBlock(state["kind"], state["target"], state["wire_stream"], decoded, encoded, state["end"])
        self.blocks.append(block)
        if block.kind == "promise":
            self.promises[block.stream] = block
        else:
            self.headers[block.stream].append(block)
            if block.end_stream:
                self.ended.add(block.stream)
        self.assembly = None

    def read(self):
        header = self.take(9)
        size = int.from_bytes(header[:3], "big")
        if size > self.max_frame_size:
            raise AssertionError(f"server frame {size} exceeds peer limit {self.max_frame_size}")
        current = Frame(header[3], header[4], int.from_bytes(header[5:], "big") & 0x7FFFFFFF, self.take(size))
        self.frames.append(current)
        if self.assembly is not None and (current.kind != 9 or current.stream != self.assembly["wire_stream"]):
            raise AssertionError("server interleaved a CONTINUATION header block")
        if current.kind in (1, 5):
            offset, end = 0, len(current.payload)
            if current.flags & 8:
                if not current.payload:
                    raise AssertionError("missing padding length")
                offset = 1; end -= current.payload[0]
            if current.kind == 1 and current.flags & 32:
                offset += 5
            if current.kind == 5:
                if end - offset < 4:
                    raise AssertionError("short PUSH_PROMISE")
                target = int.from_bytes(current.payload[offset:offset + 4], "big") & 0x7FFFFFFF
                offset += 4
            else:
                target = current.stream
            if offset > end:
                raise AssertionError("invalid header padding")
            self.assembly = {"kind": "promise" if current.kind == 5 else "headers", "target": target,
                             "wire_stream": current.stream, "fragments": [current.payload[offset:end]],
                             "end": bool(current.flags & 1) if current.kind == 1 else False}
            if current.flags & 4:
                self._complete_headers()
        elif current.kind == 9:
            if self.assembly is None:
                raise AssertionError("unprompted server CONTINUATION")
            self.assembly["fragments"].append(current.payload)
            if current.flags & 4:
                self._complete_headers()
        elif current.kind == 0:
            offset, end = 0, len(current.payload)
            if current.flags & 8:
                if not current.payload:
                    raise AssertionError("missing DATA padding byte")
                offset = 1; end -= current.payload[0]
            if offset > end:
                raise AssertionError("invalid DATA padding")
            if not self.headers[current.stream]:
                raise AssertionError("DATA preceded response HEADERS")
            self.bodies[current.stream].extend(current.payload[offset:end])
            if len(self.bodies[current.stream]) > 16 * 1024 * 1024:
                raise AssertionError("response exceeds independent client limit")
            self.data_order.append((current.stream, len(current.payload), bool(current.flags & 1)))
            if current.flags & 1:
                self.ended.add(current.stream)
            if self.auto_window and current.payload:
                self.send(window(0, len(current.payload)) + window(current.stream, len(current.payload)))
        elif current.kind == 3:
            if len(current.payload) != 4:
                raise AssertionError("bad server RST_STREAM")
            self.resets[current.stream] = int.from_bytes(current.payload, "big")
        elif current.kind == 4:
            if current.stream or len(current.payload) % 6 or (current.flags & 1 and current.payload):
                raise AssertionError("invalid server SETTINGS")
            if not current.flags & 1:
                for offset in range(0, len(current.payload), 6):
                    key, value = struct.unpack(">HI", current.payload[offset:offset + 6])
                    self.server_settings[key] = value
                    if key == 1:
                        self.encoder.header_table_size = value
                if self.auto_ack:
                    self.send(frame(4, 1))
        elif current.kind == 7:
            if current.stream or len(current.payload) < 8:
                raise AssertionError("invalid server GOAWAY")
            self.goaways.append((int.from_bytes(current.payload[:4], "big") & 0x7FFFFFFF,
                                 int.from_bytes(current.payload[4:8], "big"), current.payload[8:]))
        elif current.kind == 6 and not current.flags & 1:
            if current.stream or len(current.payload) != 8:
                raise AssertionError("invalid server PING")
            self.send(frame(6, 1, payload=current.payload))
        return current

    def until(self, predicate, limit=10000):
        for _ in range(limit):
            if predicate():
                return
            self.read()
        raise AssertionError("wire operation exceeded frame budget")

    def ping_barrier(self, token=b"barrier!"):
        if len(token) != 8:
            raise ValueError("PING token must be exactly eight bytes")
        before = len(self.frames)
        self.send(frame(6, payload=token))
        self.until(lambda: any(f.kind == 6 and f.flags & 1 and f.payload == token for f in self.frames[before:]))

    def response(self, stream):
        self.until(lambda: stream in self.ended or stream in self.resets or bool(self.goaways))
        if stream in self.resets:
            raise AssertionError(f"RST_STREAM {stream}: {self.resets[stream]}")
        if stream not in self.ended:
            raise AssertionError(f"GOAWAY before stream {stream} response: {self.goaways}")
        if not self.headers[stream]:
            raise AssertionError("response omitted HEADERS")
        status = next((value for name, value in self.headers[stream][0].headers if name == b":status"), None)
        if status != b"200":
            raise AssertionError(f"unexpected response status {status!r}")
        return bytes(self.bodies[stream])
