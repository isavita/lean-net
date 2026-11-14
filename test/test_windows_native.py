"""Real Windows IOCP lifecycle and console-wakeup tests; run on Windows CI.

Compile with the Lean distribution's own leanc, so its ByteArray allocator and
runtime are exercised rather than mocked. The production C units are included
by the fixture to inspect pending-operation lifetime without exposing handles
through the library's public API.
"""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == "win32", "requires real Windows IOCP")
class WindowsNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="lean-net-windows-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.binary = Path(cls.temporary.name) / "windows-native.exe"
        prefix = subprocess.run(["lean", "--print-prefix"], check=True,
                                capture_output=True, text=True).stdout.strip()
        command = ["leanc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra",
                   "-Wpedantic", "-Werror", "-isystem", str(Path(prefix) / "include"),
                   str(ROOT / "test/windows_native.c"), str(ROOT / "c/reactor_group.c"),
                   "-lws2_32", "-o", str(cls.binary)]
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=120)
        if compiled.returncode:
            raise RuntimeError(compiled.stdout + compiled.stderr)

    def test_iocp_lifetime_buffers_and_legacy(self):
        result = subprocess.run([str(self.binary)], capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("tests passed", result.stdout)

    def check_console(self, option):
        with subprocess.Popen([str(self.binary), option], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True,
                              creationflags=subprocess.CREATE_NEW_PROCESS_GROUP) as process:
            try:
                self.assertEqual(process.stdout.readline().strip(), "READY")
                process.send_signal(signal.CTRL_BREAK_EVENT)
                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, stdout + stderr)
                self.assertIn("tests passed", stdout)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()

    def test_console_wakes_iocp_group(self):
        self.check_console("--console")

    def test_console_wakes_legacy_poll(self):
        self.check_console("--legacy-console")


if __name__ == "__main__":
    unittest.main()
