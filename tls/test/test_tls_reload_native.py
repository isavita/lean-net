#!/usr/bin/env python3
"""Real loader threads, immutable snapshots and bounded retirement; Unix ASan."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

from tls_test_support import openssl_binary

ROOT = Path(__file__).resolve().parents[2]


class TLSReloadNative(unittest.TestCase):
    def test_loader_snapshots_failures_and_thousand_retirements(self):
        lean = shutil.which("lean.exe") or shutil.which("lean")
        command = [lean, "--print-prefix"] if lean else ["bash", "--noprofile", "--norc", "-c", "lean --print-prefix"]
        prefix = Path(subprocess.check_output(command, text=True).strip())
        includes = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "openssl"], text=True))
        with tempfile.TemporaryDirectory(prefix="lean-net-tls-reload-native-") as temporary:
            directory = Path(temporary)
            certificates = []
            for version in (1, 2):
                cert, key = directory / f"cert-{version}.pem", directory / f"key-{version}.pem"
                subprocess.run([openssl_binary(), "req", "-x509", "-newkey", "ec", "-pkeyopt",
                                "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", str(key),
                                "-out", str(cert), "-days", "1", "-subj", "/CN=alpha.test",
                                "-addext", "subjectAltName=DNS:alpha.test,DNS:beta.test"],
                               check=True, capture_output=True, timeout=20)
                certificates += [str(cert), str(key)]
            binary = directory / ("reload-native.exe" if sys.platform == "win32" else "reload-native")
            sources = [ROOT / "tls/test/tls_reload_native.c",
                       ROOT / ("c/reactor_windows.c" if sys.platform == "win32" else "c/reactor_posix.c")]
            flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
                     "-isystem", str(prefix / "include"), *includes]
            if sys.platform == "win32":
                compiler = os.environ.get("CC") or shutil.which("gcc.exe") or shutil.which("gcc")
                self.assertTrue(compiler, "MinGW SDK compiler is required")
                objects = []
                for index, source in enumerate(sources):
                    target = directory / f"source-{index}.o"
                    built = subprocess.run([compiler, *flags, "-c", str(source), "-o", str(target)],
                                           capture_output=True, text=True, timeout=90)
                    self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
                    objects.append(str(target))
                ssl_directory = Path(subprocess.check_output(["pkg-config", "--variable=libdir", "openssl"], text=True).strip())
                command = [str(prefix / "bin/leanc.exe"), *objects, str(ssl_directory / "libssl.dll.a"),
                           str(ssl_directory / "libcrypto.dll.a"), "-lws2_32", "-o", str(binary)]
            else:
                ssl_flags = shlex.split(subprocess.check_output(["pkg-config", "--libs", "openssl"], text=True))
                command = shlex.split(os.environ.get("CC", "cc")) + flags + ["-pthread", "-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer", *map(str, sources), "-L", str(prefix / "lib/lean"),
                    "-Wl,-rpath," + str(prefix / "lib/lean"), "-lleanshared", *ssl_flags, "-o", str(binary)]
            built = subprocess.run(command, capture_output=True, text=True, timeout=90)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            env = os.environ.copy()
            env["ASAN_OPTIONS"] = ("detect_leaks=0" if sys.platform == "darwin" else "detect_leaks=1") + ":halt_on_error=1"
            result = subprocess.run([str(binary), *certificates, str(directory)], capture_output=True,
                                    text=True, timeout=60, env=env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("1000 retirements, failure retention and loader lifetime passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
