#!/usr/bin/env python3
"""Regression for stale typed handles after pooled descriptor reuse."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import unittest

from test_echo import connect, unused_port

BINARY = Path(__file__).resolve().parents[1] / ".lake/build/bin/lean-net-pool-lifetime-test"


def accepted_fd(pid, port):
    if shutil.which("lsof"):
        result = subprocess.run(["lsof", "-nP", "-a", "-p", str(pid), "-iTCP", "-Ffn"],
                                capture_output=True, text=True, check=True)
        fd = None
        for line in result.stdout.splitlines():
            if re.fullmatch(r"f\d+", line):
                fd = int(line[1:])
            elif line.startswith("n") and f":{port}->" in line and fd is not None:
                return fd
        raise AssertionError(f"accepted socket missing from lsof: {result.stdout}")
    proc = Path(f"/proc/{pid}/fd")
    if proc.is_dir():
        inodes = set()
        for table in ("/proc/net/tcp", "/proc/net/tcp6"):
            for line in Path(table).read_text().splitlines()[1:]:
                columns = line.split()
                if int(columns[1].split(":")[1], 16) == port and columns[3] == "01":
                    inodes.add(columns[9])
        for fd in proc.iterdir():
            try:
                target = os.readlink(fd)
            except FileNotFoundError:
                continue
            if target.startswith("socket:[") and target[8:-1] in inodes:
                return int(fd.name)
        raise AssertionError("accepted socket missing from /proc")
    raise unittest.SkipTest("fd reuse verification requires lsof or /proc")


class PoolLifetimeAcceptance(unittest.TestCase):
    def test_stale_handle_cannot_operate_on_reused_fd(self):
        if not BINARY.is_file():
            self.fail("run lake build lean-net-pool-lifetime-test")
        port = unused_port()
        with tempfile.TemporaryFile(mode="w+") as log:
            server = subprocess.Popen([str(BINARY), str(port)], stdout=log, stderr=log)
            self.addCleanup(lambda: server.kill() if server.poll() is None else None)
            deadline = time.monotonic() + 3
            while True:
                if server.poll() is not None:
                    log.seek(0)
                    self.fail(f"fixture exited early: {log.read()}")
                try:
                    first = connect(port)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        self.fail("fixture did not listen")
                    time.sleep(0.02)
            with first:
                self.assertEqual(first.recv(1), b"1")
                old_fd = accepted_fd(server.pid, port)
                first.sendall(b"g")
                self.assertEqual(first.recv(1), b"")
            with connect(port) as second:
                self.assertEqual(second.recv(1), b"2")
                new_fd = accepted_fd(server.pid, port)
                self.assertEqual(new_fd, old_fd, "test did not observe descriptor reuse")
                second.sendall(b"g")
                self.assertEqual(second.recv(1), b"K", "stale handle affected the new connection")
                self.assertEqual(second.recv(1), b"")
            try:
                code = server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.fail("fixture failed to exit")
            log.seek(0)
            self.assertEqual(code, 0, log.read())


if __name__ == "__main__":
    unittest.main()
