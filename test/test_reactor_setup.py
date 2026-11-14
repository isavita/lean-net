#!/usr/bin/env python3
"""Exercise setup FFI reference counts with the actual Lean runtime."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReactorSetupNative(unittest.TestCase):
    def test_borrowed_handle_arrays(self):
        prefix = os.environ.get("LEAN_SYSROOT")
        if not prefix:
            lean = shutil.which("lean.exe") or shutil.which("lean")
            command = [lean, "--print-prefix"] if lean else ["bash", "--noprofile", "--norc", "-c", "lean --print-prefix"]
            prefix = subprocess.run(command, check=True, capture_output=True, text=True).stdout.strip()
        prefix = Path(prefix)
        with tempfile.TemporaryDirectory(prefix="lean-net-setup-test-") as temporary:
            windows = sys.platform == "win32"
            binary = Path(temporary) / ("reactor-setup.exe" if windows else "reactor-setup")
            flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
                     "-isystem", str(prefix / "include")]
            sources = ["test/reactor_setup_test.c", "c/reactor_windows.c" if windows else "c/reactor_posix.c", "c/reactor_group.c"]
            if windows:
                compiler = os.environ.get("CC") or shutil.which("gcc.exe") or shutil.which("gcc")
                if not compiler:
                    raise RuntimeError("MinGW gcc is required for Windows SDK headers")
                objects = []
                for source in sources:
                    target = Path(temporary) / (Path(source).stem + ".o")
                    subprocess.run([compiler, *flags, "-c", str(ROOT / source), "-o", str(target)],
                                   check=True, capture_output=True, text=True, timeout=120)
                    objects.append(str(target))
                command = [str(prefix / "bin/leanc.exe"), *objects, "-lws2_32", "-o", str(binary)]
            else:
                if os.environ.get("RN_SETUP_SANITIZERS", "1") != "0":
                    flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
                links = ["-L", str(prefix / "lib/lean"), "-Wl,-rpath," + str(prefix / "lib/lean"), "-lleanshared"]
                command = shlex.split(os.environ.get("CC", "cc")) + flags + [str(ROOT / source) for source in sources] + links + ["-o", str(binary)]
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("borrowed-reference tests passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
