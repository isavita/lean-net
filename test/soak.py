#!/usr/bin/env python3
"""Exercise HTTP/1.1 and h2c connection churn while sampling RSS and FDs.

Uses only the Python standard library. Run with --help for limits and options.
"""

import argparse
import asyncio
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SERVER = ROOT / ".lake" / "build" / "bin" / "lean-net-http1"
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
EXPECTED_BODY = b"Hello from lean-net!\n"
# RFC 7541 static indexes: GET, http, /; literal :authority 127.0.0.1.
REQUEST_BLOCK = bytes.fromhex("82868441093132372e302e302e31")


def frame(kind, flags, stream, body=b""):
    return len(body).to_bytes(3, "big") + bytes((kind, flags)) + stream.to_bytes(4, "big") + body


def numeric_fds(pid):
    proc_fds = Path(f"/proc/{pid}/fd")
    if proc_fds.is_dir():
        return len(list(proc_fds.iterdir()))
    # macOS and other systems without procfs: -F f includes f<descriptor>
    # as well as nonnumeric entries such as fcwd and ftxt.
    try:
        output = subprocess.check_output(["lsof", "-nP", "-F", "f", "-p", str(pid)], text=True)
    except FileNotFoundError as exc:
        raise RuntimeError("FD sampling needs /proc or lsof") from exc
    return len({int(line[1:]) for line in output.splitlines() if re.fullmatch(r"f[0-9]+", line)})


def rss_kib(pid):
    # ps reports resident size in KiB on macOS and Linux.
    return int(subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)], text=True).strip())


async def request_http1(reader, writer, timeout):
    writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    await writer.drain()
    response = await asyncio.wait_for(reader.read(), timeout)
    head, separator, body = response.partition(b"\r\n\r\n")
    if not separator or not head.startswith(b"HTTP/1.1 200 "):
        raise AssertionError(f"invalid HTTP/1 response: {response[:160]!r}")
    fields = {}
    for line in head.split(b"\r\n")[1:]:
        name, colon, value = line.partition(b":")
        if not colon:
            raise AssertionError(f"malformed HTTP/1 response field: {line!r}")
        fields[name.lower()] = value.strip()
    if fields.get(b"content-length") != str(len(EXPECTED_BODY)).encode() or body != EXPECTED_BODY:
        raise AssertionError("HTTP/1 response framing or body mismatch")


async def request_h2(reader, writer, timeout):
    writer.write(PREFACE + frame(4, 0, 0) + frame(1, 5, 1, REQUEST_BLOCK))
    await writer.drain()
    header_block = bytearray()
    body = bytearray()
    saw_headers = False
    ended = False
    while not ended:
        header = await asyncio.wait_for(reader.readexactly(9), timeout)
        length = int.from_bytes(header[:3], "big")
        kind, flags = header[3:5]
        stream = int.from_bytes(header[5:9], "big") & 0x7fffffff
        if length > 16777215:
            raise AssertionError("invalid HTTP/2 frame size")
        payload = await asyncio.wait_for(reader.readexactly(length), timeout)
        if kind == 4 and not flags & 1:
            writer.write(frame(4, 1, 0))
            await writer.drain()
        if kind in (1, 9) and stream == 1:
            if kind == 1 and flags & 8:
                raise AssertionError("unexpected padded response headers")
            header_block.extend(payload)
            if flags & 4:
                saw_headers = True
            if kind == 1 and flags & 1:
                ended = True
        elif kind == 0 and stream == 1:
            if flags & 8:
                raise AssertionError("unexpected padded response DATA")
            body.extend(payload)
            if flags & 1:
                ended = True
        elif kind in (3, 7):
            raise AssertionError(f"HTTP/2 stream or connection error: {kind} {payload.hex()}")
    # This server's encoder emits indexed static-table :status 200 as 0x88.
    # Verify that representation and the complete application body without a
    # third-party HPACK decoder. The full HPACK suite tests other encodings.
    if not saw_headers or not header_block or header_block[0] != 0x88 or bytes(body) != EXPECTED_BODY:
        raise AssertionError("HTTP/2 status or body mismatch")


async def request_one(port, h2, semaphore, timeout):
    async with semaphore:
        reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), timeout)
        try:
            if h2:
                await request_h2(reader, writer, timeout)
            else:
                await request_http1(reader, writer, timeout)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


async def batch(port, count, start_index, concurrency, timeout):
    semaphore = asyncio.Semaphore(concurrency)
    await asyncio.gather(*(request_one(port, (start_index + i) % 2 == 1, semaphore, timeout) for i in range(count)))


async def run(args):
    if args.port:
        port = args.port
    else:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen([str(args.server), str(port)], stdout=subprocess.DEVNULL, stderr=log)
        samples = []
        async def sample(label):
            await asyncio.sleep(args.settle)
            if process.poll() is not None:
                raise RuntimeError(f"server exited early: {process.returncode}")
            rss, fds = rss_kib(process.pid), numeric_fds(process.pid)
            samples.append((label, rss, fds))
            print(f"{label}: rss_kib={rss} numeric_fds={fds}", flush=True)
        try:
            for _ in range(100):
                try:
                    _, writer = await asyncio.open_connection("127.0.0.1", port)
                    writer.close()
                    await writer.wait_closed()
                    break
                except OSError:
                    if process.poll() is not None:
                        raise RuntimeError(f"server exited during startup: {process.returncode}")
                    await asyncio.sleep(0.02)
            else:
                raise RuntimeError("server did not start")
            print(f"pid={process.pid} port={port} concurrency={args.concurrency}", flush=True)
            await sample("baseline")
            start = time.monotonic()
            await batch(port, args.warmup, 0, args.concurrency, args.timeout)
            await sample(f"warmup_{args.warmup}")
            completed = 0
            while completed < args.count:
                count = min(args.batch, args.count - completed)
                await batch(port, count, args.warmup + completed, args.concurrency, args.timeout)
                completed += count
                await sample(f"completed_{completed}")
            baseline_fds = samples[0][2]
            peak_fds = max(row[2] for row in samples)
            warm_rss = samples[1][1]
            peak_rss = max(row[1] for row in samples[2:])
            if peak_fds > baseline_fds + args.max_fd_growth:
                raise AssertionError(f"FD growth: baseline {baseline_fds}, peak {peak_fds}")
            if peak_rss > warm_rss + args.max_rss_growth_kib:
                raise AssertionError(f"RSS growth: warmup {warm_rss} KiB, peak {peak_rss} KiB")
            print(f"validated={args.warmup + args.count} elapsed_seconds={time.monotonic()-start:.2f}", flush=True)
            process.send_signal(signal.SIGINT)
            await asyncio.wait_for(asyncio.to_thread(process.wait), args.timeout)
            if process.returncode != 0:
                raise AssertionError(f"SIGINT exit status {process.returncode}")
            print("SIGINT exit=0; resource thresholds passed", flush=True)
        except BaseException:
            log.seek(0)
            tail = log.read()[-4096:]
            if tail:
                print("server stderr tail:\n" + tail.decode(errors="replace"), file=sys.stderr)
            raise
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, default=DEFAULT_SERVER, help="built lean-net-http1 executable")
    parser.add_argument("--count", type=int, default=10000, help="connections after warmup (default: 10000)")
    parser.add_argument("--warmup", type=int, default=500, help="warmup connections (default: 500)")
    parser.add_argument("--batch", type=int, default=1000, help="connections per sampled batch (default: 1000)")
    parser.add_argument("--concurrency", type=int, default=16, help="maximum concurrent clients (default: 16)")
    parser.add_argument("--timeout", type=float, default=5, help="per-operation timeout in seconds")
    parser.add_argument("--settle", type=float, default=0.15, help="seconds to settle before each sample")
    parser.add_argument("--port", type=int, default=0, help="local port; 0 selects an available port")
    parser.add_argument("--max-fd-growth", type=int, default=0, help="allowed quiescent FD growth")
    parser.add_argument("--max-rss-growth-kib", type=int, default=8192, help="allowed peak RSS increase over warmup")
    args = parser.parse_args()
    if (args.count <= 0 or args.warmup < 0 or args.batch <= 0 or args.concurrency <= 0 or
            args.timeout <= 0 or args.settle < 0 or not 0 <= args.port <= 65535 or
            args.max_fd_growth < 0 or args.max_rss_growth_kib < 0):
        parser.error("counts, concurrency, timeout, port, settle and thresholds are out of range")
    if not args.server.is_file():
        parser.error(f"server executable not found: {args.server}; run lake build first")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
