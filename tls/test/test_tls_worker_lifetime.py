#!/usr/bin/env python3
"""Escaped public TLS-worker callbacks cannot call a freed native handle."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tls_test_support import openssl_binary

ROOT = Path(__file__).resolve().parents[2]
SUFFIX = ".exe" if sys.platform == "win32" else ""
BINARY = Path(os.environ.get("LEAN_NET_TLS_WORKER_LIFETIME_BIN",
                            ROOT / f"tls/.lake/build/bin/lean-net-tls-worker-lifetime-test{SUFFIX}"))


class TLSWorkerLifetime(unittest.TestCase):
    def test_escaped_callbacks_reject_closed_native_owner(self):
        self.assertTrue(BINARY.is_file(), f"missing worker lifetime executable: {BINARY}")
        with tempfile.TemporaryDirectory(prefix="lean-net-tls-worker-lifetime-") as temporary:
            directory = Path(temporary)
            cert, key = directory / "cert.pem", directory / "key.pem"
            subprocess.run([openssl_binary(), "req", "-x509", "-newkey", "ec", "-pkeyopt",
                            "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", str(key),
                            "-out", str(cert), "-days", "1", "-subj", "/CN=alpha.test"],
                           check=True, capture_output=True, timeout=20)
            result = subprocess.run([str(BINARY), str(cert), str(key)], capture_output=True,
                                    text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("callbacks reject closed native owners", result.stdout)


if __name__ == "__main__":
    unittest.main()
