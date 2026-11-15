#!/usr/bin/env python3
"""Configuration-side hostname resolver validation."""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(sys.platform == "win32", "POSIX resolver fixture")
class GatewayResolverNative(unittest.TestCase):
    def test_numeric_dns_and_rejections(self):
        prefix = Path(subprocess.run(["lean", "--print-prefix"], capture_output=True,
                                     text=True, check=True).stdout.strip())
        with tempfile.TemporaryDirectory(prefix="lean-net-resolve-test-") as temporary:
            binary = Path(temporary) / "gateway-resolve"
            flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Wpedantic",
                     "-Werror", "-isystem", str(prefix / "include")]
            if os.environ.get("RN_POSIX_SANITIZERS", "1") != "0":
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            link_flags = ["-L", str(prefix / "lib/lean"),
                          "-Wl,-rpath," + str(prefix / "lib/lean"), "-lleanshared"]
            command = shlex.split(os.environ.get("CC", "cc")) + flags + [
                str(ROOT / "test/gateway_resolve_test.c")] + link_flags + ["-o", str(binary)]
            subprocess.run(command, check=True, capture_output=True, text=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("gateway resolver tests passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
