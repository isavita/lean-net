#!/usr/bin/env python3
"""Measure idle worker CPU with 32 and 1,024 pending HTTP/2 replies."""

import argparse
from pathlib import Path
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time

from http2_test_support import H2Client, frame
from test_echo import unused_port
from test_http1_reactor import Reader


def cpu_seconds(pid):
    value = subprocess.check_output(["ps", "-p", str(pid), "-o", "time="],
                                    text=True).strip()
    minutes, seconds = value.split(":")
    return int(minutes) * 60 + float(seconds)


def benchmark(binary, clients, streams):
    port = unused_port()
    peers = []
    with tempfile.TemporaryFile(mode="w+") as log:
        server = subprocess.Popen([str(binary), str(port), "bulk"], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while len(peers) < clients:
                try:
                    peers.append(H2Client(port))
                except ConnectionRefusedError:
                    if time.monotonic() > deadline or server.poll() is not None:
                        raise
                    time.sleep(0.01)
            for peer in peers:
                requests = [
                    frame(1, 5, 2 * i + 1, peer.encode_request(b"/hold"))
                    for i in range(streams)
                ]
                peer.send(b"".join(requests))
            for peer in peers:
                peer.ping_barrier()
                if peer.resets or peer.goaways or peer.ended:
                    raise RuntimeError("some deferred replies failed during benchmark setup")
            with socket.create_connection(("127.0.0.1", port), timeout=5) as status:
                status.sendall(b"GET /stats HTTP/1.1\r\nHost: localhost\r\n\r\n")
                expected = f"completed=0;started={clients * streams};".encode()
                reply = Reader(status).response().body
                if reply != expected:
                    raise RuntimeError(f"deferred workload was not admitted: {reply!r}")
            before = cpu_seconds(server.pid)
            started = time.monotonic()
            time.sleep(1.5)
            after = cpu_seconds(server.pid)
            return (after - before) / (time.monotonic() - started)
        finally:
            for peer in peers:
                peer.close()
            if server.poll() is None:
                server.send_signal(signal.SIGINT)
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
                raise
            if server.returncode:
                log.seek(0)
                raise RuntimeError(log.read())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    default = Path(__file__).resolve().parents[1] / ".lake/build/bin/lean-net-deferred-reply-fixture"
    parser.add_argument("binaries", nargs="*", type=Path, default=[default],
                        help="fixture binaries to compare")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("this benchmark uses macOS ps CPU accounting at centisecond resolution")
    for clients, streams in [(2, 16), (8, 128)]:
        samples = [[] for _ in args.binaries]
        for _ in range(3):
            for binary, values in zip(args.binaries, samples):
                values.append(benchmark(binary.resolve(), clients, streams))
        for binary, values in zip(args.binaries, samples):
            print(f"{binary.name} | {clients * streams} pending | median {statistics.median(values):.2%} "
                  f"of one core | {[round(value * 100, 2) for value in values]}", flush=True)


if __name__ == "__main__":
    main()
