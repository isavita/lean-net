#!/usr/bin/env python3
"""Real macOS acceptor/worker distribution and bounded handoff regression."""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == "darwin", "macOS kqueue dispatch fixture")
class ReactorDispatchNative(unittest.TestCase):
    def test_threads_backpressure_lifetime_and_allocations(self):
        prefix = Path(subprocess.run(["lean", "--print-prefix"], capture_output=True, text=True, check=True).stdout.strip())
        with tempfile.TemporaryDirectory(prefix="lean-net-dispatch-test-") as temporary:
            binary = Path(temporary) / "reactor-dispatch"
            flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
                     "-isystem", str(prefix / "include"), "-pthread"]
            if os.environ.get("RN_DISPATCH_SANITIZERS", "1") != "0":
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            command = shlex.split(os.environ.get("CC", "cc")) + flags + [str(ROOT / "test/reactor_dispatch_test.c"),
                      "-L", str(prefix / "lib/lean"), "-Wl,-rpath," + str(prefix / "lib/lean"), "-lleanshared", "-o", str(binary)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("worker accepts: 50 50 50 50 50 50 50 50", result.stdout)
            self.assertIn("zero hot allocations", result.stdout)


if __name__ == "__main__":
    unittest.main()
