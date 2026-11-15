#!/usr/bin/env python3
"""Bounded startup cgroup parsing tests; never modify host cgroups or affinity."""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(sys.platform == "win32", "POSIX startup reader; Windows CPU policy is separate")
class ReactorCPU(unittest.TestCase):
    def compile_and_run(self, source):
        with tempfile.TemporaryDirectory(prefix="lean-net-cpu-") as directory:
            binary = Path(directory) / "cpu-quota"
            command = shlex.split(os.environ.get("CC", "cc")) + [
                "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                str(ROOT / source), "-o", str(binary)]
            compiled = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("fixtures passed", result.stdout)

    def test_cgroup_hierarchy_fractional_quotas_and_read_failures(self):
        self.compile_and_run("test/reactor_cpu_test.c")

    def test_dynamic_affinity_high_cpu_ids_and_failure_cleanup(self):
        self.compile_and_run("test/reactor_affinity_test.c")


if __name__ == "__main__":
    unittest.main()
