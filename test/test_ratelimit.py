#!/usr/bin/env python3
"""Native GCRA limiter under AddressSanitizer/UBSan and ThreadSanitizer."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(sys.platform == "win32", "POSIX sanitizers")
class NativeRateLimiter(unittest.TestCase):
    def build_and_run(self, sanitizer):
        compiler = os.environ.get("CC", "cc")
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "ratelimit"
            subprocess.run([compiler, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-pthread",
                            f"-fsanitize={sanitizer}", "-fno-omit-frame-pointer",
                            str(ROOT / "test" / "ratelimit_test.c"), "-o", str(binary)],
                           check=True, capture_output=True, text=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=300)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("rate limiter native tests passed", result.stdout)

    def test_address_and_undefined_sanitizers(self):
        self.build_and_run("address,undefined")

    def test_thread_sanitizer(self):
        self.build_and_run("thread")


if __name__ == "__main__":
    unittest.main()
