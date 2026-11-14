#!/usr/bin/env python3
"""Actual Lean phantom/capability aliases across a returned native batch."""
import socket
import subprocess
import sys
from pathlib import Path
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReactorWire(unittest.TestCase):
    def test_typed_claim_ready_aliases_and_retained_waker(self):
        binary = ROOT / ".lake/build/bin" / ("lean-net-reactor-native-test.exe" if sys.platform == "win32" else "lean-net-reactor-native-test")
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        process = subprocess.Popen([str(binary), "wire", str(port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    peer = socket.create_connection(("127.0.0.1", port), timeout=1)
                    break
                except OSError:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        out, err = process.communicate(timeout=2)
                        self.fail(out + err)
                    time.sleep(0.02)
            with peer:
                peer.sendall(bytes([0, 255, 13, 10, 65]))
                peer.shutdown(socket.SHUT_WR)
                received = bytearray()
                while True:
                    block = peer.recv(1024)
                    if not block:
                        break
                    received.extend(block)
                self.assertEqual(bytes(received), bytes([0, 255, 13, 10, 65]))
            out, err = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, out + err)
            self.assertIn("typed wire and retained waker tests passed", out)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=3)


if __name__ == "__main__":
    unittest.main()
