"""Real Windows IOCP lifecycle and console-wakeup tests; run on Windows CI.

Compile with the Lean distribution's own leanc, so its ByteArray allocator and
runtime are exercised rather than mocked. The production C units are included
by the fixture to inspect pending-operation lifetime without exposing handles
through the library's public API.
"""
import os
from pathlib import Path
import signal
import shutil
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
        prefix = os.environ.get("LEAN_SYSROOT")
        if not prefix:
            lean = shutil.which("lean.exe") or shutil.which("lean")
            # lean-action may expose shell shims to Git Bash rather than a
            # Windows executable discoverable through CreateProcess/PATHEXT.
            command = ([lean, "--print-prefix"] if lean else
                       ["bash", "--noprofile", "--norc", "-c", "lean --print-prefix"])
            prefix = subprocess.run(command, check=True, capture_output=True,
                                    text=True).stdout.strip()
        leanc = Path(prefix) / "bin" / "leanc.exe"
        if not leanc.is_file():
            raise RuntimeError(f"Native leanc executable missing: {leanc}")
        # Lean's bundled clang uses a deliberately minimal -nostdinc sysroot,
        # sufficient for generated Lean C but missing the Windows SDK. Compile
        # native sources with the full MinGW SDK, then let leanc link its runtime.
        objects = []
        compiler = os.environ.get("CC") or shutil.which("gcc.exe") or shutil.which("gcc")
        if not compiler:
            raise RuntimeError("MinGW gcc executable is required for the Windows SDK headers")
        for source in ("test/windows_native.c", "c/reactor_group.c"):
            target = Path(cls.temporary.name) / (Path(source).stem + ".o")
            command = [compiler, "-std=c11", "-O1", "-g", "-Wall", "-Wextra",
                       "-Wpedantic", "-Werror", "-isystem", str(Path(prefix) / "include"),
                       "-c", str(ROOT / source), "-o", str(target)]
            compiled = subprocess.run(command, capture_output=True, text=True, timeout=120)
            if compiled.returncode:
                raise RuntimeError(compiled.stdout + compiled.stderr)
            objects.append(str(target))
        linked = subprocess.run([str(leanc), *objects, "-lws2_32", "-o", str(cls.binary)],
                                capture_output=True, text=True, timeout=120)
        if linked.returncode:
            raise RuntimeError(linked.stdout + linked.stderr)

    def test_iocp_lifetime_buffers_and_legacy(self):
        result = subprocess.run([str(self.binary)], capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("tests passed", result.stdout)

    def test_acceptor_workers_backpressure_and_both_free_orders(self):
        result = subprocess.run([str(self.binary), "--dispatch"], capture_output=True,
                                text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("tests passed", result.stdout)

    def test_read_pause_and_partial_scatter_cancellation(self):
        result = subprocess.run([str(self.binary), "--transport"], capture_output=True,
                                text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("tests passed", result.stdout)

    def test_file_regions_fifo_residency_and_lifetime(self):
        result = subprocess.run([str(self.binary), "--files"], capture_output=True,
                                text=True, timeout=90)
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
