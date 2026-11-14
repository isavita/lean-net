#!/usr/bin/env python3
"""Real native TLS workers and four-cell bridge under ASan/UBSan."""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipIf(sys.platform == "win32", "Unix native allocator fixture; Windows uses the real TLS reactor suite")
class TLSWorkerNative(unittest.TestCase):
    def test_queues_wire_fences_and_join_lifetime(self):
        prefix = Path(subprocess.check_output(["lean", "--print-prefix"], text=True).strip())
        ssl_flags = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "--libs", "openssl"], text=True))
        ssl_prefix = subprocess.check_output(["pkg-config", "--variable=prefix", "openssl"], text=True).strip()
        with tempfile.TemporaryDirectory(prefix="lean-net-tls-worker-") as temporary:
            directory = Path(temporary)
            cert, key = directory / "cert.pem", directory / "key.pem"
            subprocess.run([str(Path(ssl_prefix) / "bin/openssl"), "req", "-x509", "-newkey", "ec",
                            "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", str(key),
                            "-out", str(cert), "-days", "1", "-subj", "/CN=alpha.test"],
                           check=True, capture_output=True, text=True)
            binary = directory / "worker-native"
            flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-pthread",
                     "-isystem", str(prefix / "include")]
            if os.environ.get("RN_TLS_WORKER_SANITIZERS", "1") != "0":
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            command = shlex.split(os.environ.get("CC", "cc")) + flags + [str(ROOT / "tls/test/tls_worker_native.c"),
                       "-L", str(prefix / "lib/lean"), "-Wl,-rpath," + str(prefix / "lib/lean"), "-lleanshared"] + ssl_flags + ["-o", str(binary)]
            compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([str(binary), str(cert), str(key)], capture_output=True, text=True, timeout=35)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("queue, wire fences and lifecycle tests passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
