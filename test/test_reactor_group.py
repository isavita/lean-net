#!/usr/bin/env python3
"""Native reactor-group signal/lifetime tests (POSIX).

Run `python3 test/test_reactor_group.py -v`. AddressSanitizer and UBSan are on by
default; set RN_GROUP_SANITIZERS=0 only for a toolchain lacking their runtimes.
The native tests stub only rn_wake, so they need no Lean runtime linking.
"""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(sys.platform == "win32", "POSIX signal tests; Windows console backend needs its native runner")
class ReactorGroupNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        prefix = subprocess.run(["lean", "--print-prefix"], capture_output=True, text=True, check=True).stdout.strip()
        cls.temporary = tempfile.TemporaryDirectory(prefix="lean-net-group-test-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.compiler = shlex.split(os.environ.get("CC", "cc"))
        cls.flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-pthread", "-isystem", str(Path(prefix) / "include")]
        if os.environ.get("RN_GROUP_SANITIZERS", "1") != "0":
            cls.flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]

    def compile_and_run(self, name, sources, arguments=()):
        binary = Path(self.temporary.name) / name
        subprocess.run(self.compiler + self.flags + [str(ROOT / path) for path in sources] + ["-o", str(binary)], check=True, capture_output=True, text=True)
        result = subprocess.run([str(binary), *arguments], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("passed", result.stdout)

    def test_signal_restore_and_concurrent_free(self):
        self.compile_and_run("group-signal", ["c/reactor_group.c", "test/reactor_group_test.c"])

    def test_failed_restoration_never_retains_reactors(self):
        self.compile_and_run("group-restore-failure", ["test/reactor_group_restore_test.c"])

    def test_failed_install_rollback_poisoning(self):
        self.compile_and_run("group-install-rollback", ["test/reactor_group_restore_test.c"], ("partial-install",))

    def test_interrupted_install_restores_all_prior_handlers(self):
        self.compile_and_run("group-install-interrupted", ["test/reactor_group_restore_test.c"], ("partial-restored",))

    def test_process_gauges_track_owned_descriptors(self):
        self.compile_and_run("group-process-metrics", ["c/reactor_group.c", "test/reactor_group_metrics_test.c"])

    @unittest.skipUnless(sys.platform == "darwin", "macOS libproc failure contract")
    def test_descriptor_scan_surfaces_errors_without_retry(self):
        self.compile_and_run("group-process-metrics-faults", ["test/reactor_group_metrics_fault_test.c"])


if __name__ == "__main__":
    unittest.main()
