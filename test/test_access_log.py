#!/usr/bin/env python3
"""Real isolated log helper: bounded SPSC, output/rotation and shutdown."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AccessLogNative(unittest.TestCase):
    def test_bounded_helper_and_resources(self):
        compiler = os.environ.get("CC", "gcc" if sys.platform == "win32" else "cc")
        with tempfile.TemporaryDirectory(prefix="lean-net-access-") as temporary:
            directory = Path(temporary)
            suffix = ".exe" if sys.platform == "win32" else ""
            helper = directory / ("log-helper" + suffix)
            fixture = directory / ("log-fixture" + suffix)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-O1", "-g"]
            if sys.platform != "win32":
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-pthread"]
            if sys.platform == "linux":
                flags += ["-lrt"]
            built = subprocess.run([compiler, *flags, "-DOB_NO_LEAN_FFI", "-DOB_TESTING",
                str(ROOT / "c/access_log.c"), str(ROOT / "c/access_log_helper.c"),
                "-o", str(helper)], capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            built = subprocess.run([compiler, *flags, str(ROOT / "test/access_log_native.c"),
                "-o", str(fixture)], capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            env = os.environ.copy()
            env["ASAN_OPTIONS"] = ("detect_leaks=0" if sys.platform == "darwin" else "detect_leaks=1") + ":halt_on_error=1"
            result = subprocess.run([str(fixture), str(helper), str(directory)], env=env,
                capture_output=True, text=True, timeout=60, start_new_session=sys.platform != "win32")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["hot_allocations"], 0)
            self.assertGreater(report["dropped"], 0)
            self.assertLessEqual(report["handles_after"], report["handles_before"])
            self.assertLessEqual(report["stop_ms"], 250)
            files = list(directory.glob("access.jsonl*"))
            self.assertLessEqual(len(files), 3)
            records = []
            for path in files:
                self.assertLessEqual(path.stat().st_size, 4096)
                raw = path.read_bytes()
                self.assertNotIn(b"private_query", raw)
                self.assertNotIn(b"private_password", raw)
                records += [json.loads(line) for line in raw.splitlines()]
            self.assertTrue(records)
            self.assertTrue(any(record["target_truncated"] for record in records))
            self.assertTrue(any(record["target_redacted"] for record in records))
            self.assertTrue(any(record["method"] == 'GET"\nÿ' for record in records))
            appended = (directory / "append.jsonl").read_text().splitlines()
            self.assertEqual(json.loads(appended[0]), {"prior": True})
            self.assertEqual(len(appended), 2)
            self.assertEqual((directory / "oversized.jsonl.1").read_bytes(), b"z" * 4097)
            self.assertEqual((directory / "oversized.jsonl").stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
