#!/usr/bin/env python3
"""Real native POSIX file FIFO/lifetime with sanitizer and syscall faults."""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(sys.platform == "win32", "POSIX sendfile fixture; Windows native fixture covers TransmitFile")
class ReactorFileNative(unittest.TestCase):
    def test_file_fifo_faults_and_lifetime(self):
        prefix = Path(subprocess.run(["lean", "--print-prefix"], capture_output=True, text=True, check=True).stdout.strip())
        with tempfile.TemporaryDirectory(prefix="lean-net-file-test-") as temporary:
            binary = Path(temporary) / "reactor-file"
            flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
                     "-isystem", str(prefix / "include"), "-pthread"]
            if os.environ.get("RN_FILE_SANITIZERS", "1") != "0":
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            command = shlex.split(os.environ.get("CC", "cc")) + flags + [str(ROOT / "test/reactor_file_test.c"),
                       "-L", str(prefix / "lib/lean"), "-Wl,-rpath," + str(prefix / "lib/lean"),
                       "-lleanshared", "-o", str(binary)]
            compiled = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("zero-allocation tests passed", result.stdout)
            if sys.platform.startswith("linux"):
                self.assertIn("SIGPIPE masks, pending signals, dispositions and one-call fault tests passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
