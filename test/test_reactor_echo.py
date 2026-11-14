"""Exercise the real Lean echo dispatcher in direct and multi-worker modes."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
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

ROOT = Path(__file__).resolve().parents[1]
SUFFIX = ".exe" if sys.platform == "win32" else ""
BINARY = Path(os.environ.get("LEAN_NET_ECHO_BIN", ROOT / f".lake/build/bin/lean-net-echo{SUFFIX}"))


def exchange(port, identifier):
    payload = identifier.to_bytes(4, "big") + bytes(range(256)) * 257
    with socket.create_connection(("127.0.0.1", port), timeout=10) as peer:
        peer.sendall(payload)
        peer.shutdown(socket.SHUT_WR)
        received = bytearray()
        while True:
            block = peer.recv(16384)
            if not block:
                break
            received.extend(block)
        if received != payload:
            raise AssertionError(f"client {identifier}: {len(received)} bytes, expected {len(payload)}")


@contextmanager
def server(workers):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    command = [str(BINARY), str(port)]
    if workers is not None:
        command.append(str(workers))
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
    with tempfile.TemporaryFile(mode="w+") as log:
        process = subprocess.Popen(command, stdout=log, stderr=log, creationflags=flags)
        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    log.seek(0)
                    raise AssertionError(f"server startup failed: {log.read()}")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise AssertionError("server startup timed out")
                    time.sleep(0.01)
            yield port
        finally:
            if process.poll() is None:
                process.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise AssertionError("workers did not join on shutdown")
            if process.returncode:
                log.seek(0)
                raise AssertionError(f"server exit {process.returncode}: {log.read()}")


class ReactorEchoIntegration(unittest.TestCase):
    def test_concurrent_binary_half_close_and_reset_in_all_worker_modes(self):
        self.assertTrue(BINARY.is_file(), f"build the echo executable first: {BINARY}")
        for workers in (1, 4, None):
            with self.subTest(workers=workers), server(workers) as port:
                with ThreadPoolExecutor(max_workers=32) as clients:
                    results = [clients.submit(exchange, port, identifier) for identifier in range(96)]
                    for result in results:
                        result.result(timeout=30)
                linger = struct.pack("HH" if sys.platform == "win32" else "ii", 1, 0)
                for _ in range(25):
                    with socket.create_connection(("127.0.0.1", port), timeout=5) as peer:
                        peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
                        peer.sendall(b"reset after handoff")
                exchange(port, 1000)


if __name__ == "__main__":
    unittest.main()
