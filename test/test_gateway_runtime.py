#!/usr/bin/env python3
"""Run the owner-thread gateway pool and transaction tests on free loopback ports."""

import socket
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SUFFIX = ".exe" if sys.platform == "win32" else ""


def free_ports(count):
    reservations = []
    try:
        for _ in range(count):
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.bind(("127.0.0.1", 0))
            reservations.append(probe)
        return [probe.getsockname()[1] for probe in reservations]
    finally:
        for probe in reservations:
            probe.close()


class GatewayRuntime(unittest.TestCase):
    def run_fixture(self, name, ports):
        binary = ROOT / ".lake" / "build" / "bin" / f"lean-net-gateway-{name}-test{SUFFIX}"
        self.assertTrue(binary.is_file(), f"build {binary} first")
        result = subprocess.run([str(binary), *map(str, free_ports(ports))],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"gateway {name} tests passed", result.stdout)

    def test_pool_ownership_and_reuse(self):
        self.run_fixture("pool", 2)

    def test_engine_transactions(self):
        self.run_fixture("engine", 1)


if __name__ == "__main__":
    unittest.main()
