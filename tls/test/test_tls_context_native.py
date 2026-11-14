#!/usr/bin/env python3
"""Borrowed certificate-table references under the real Lean allocator."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipIf(sys.platform == "win32", "Unix allocator sanitizer fixture; the same context source serves Windows")
class TLSContextNative(unittest.TestCase):
    def test_borrowed_tables_and_context_policy(self):
        prefix = Path(subprocess.check_output(["lean", "--print-prefix"], text=True).strip())
        ssl_flags = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "--libs", "openssl"], text=True))
        openssl_prefix = subprocess.check_output(["pkg-config", "--variable=prefix", "openssl"], text=True).strip()
        openssl = str(Path(openssl_prefix) / "bin/openssl")
        if not Path(openssl).is_file():
            openssl = shutil.which("openssl") or "openssl"
        with tempfile.TemporaryDirectory(prefix="lean-net-tls-context-") as temporary:
            directory = Path(temporary)
            cert, key = directory / "cert.pem", directory / "key.pem"
            subprocess.run([openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                            "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=alpha.test"],
                           check=True, capture_output=True, text=True)
            binary = directory / "context-native"
            flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-pthread",
                     "-isystem", str(prefix / "include")]
            if os.environ.get("RN_TLS_CONTEXT_SANITIZERS", "1") != "0":
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            command = shlex.split(os.environ.get("CC", "cc")) + flags + [str(ROOT / "tls/test/tls_context_native.c"),
                       str(ROOT / "c/reactor_posix.c"), "-L", str(prefix / "lib/lean"),
                       "-Wl,-rpath," + str(prefix / "lib/lean"), "-lleanshared"] + ssl_flags + ["-o", str(binary)]
            built = subprocess.run(command, capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run([str(binary), str(cert), str(key)], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("borrowed ownership and policy checks passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
