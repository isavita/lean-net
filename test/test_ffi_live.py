"""Exercise native poll and offset-send behavior against a real TCP peer."""

import os
import select
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXECUTABLE = ROOT / ".lake/build/bin/lean-net-ffi-live"


def line_with_timeout(proc):
    ready, _, _ = select.select([proc.stdout], [], [], 5)
    if not ready:
        raise TimeoutError("timed out waiting for FFI fixture")
    return proc.stdout.readline().strip()


def main():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    proc = subprocess.Popen(
        [str(EXECUTABLE), str(port)], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, cwd=ROOT,
    )
    try:
        assert line_with_timeout(proc) == "READY"
        with socket.create_connection(("127.0.0.1", port), timeout=5) as peer:
            peer.settimeout(5)
            assert line_with_timeout(proc) == "NEED_DATA"
            received = b""
            while len(received) < 2:
                data = peer.recv(2 - len(received))
                if not data:
                    raise AssertionError("peer closed before the entire slice arrived")
                received += data
            assert received == b"bc"
            peer.sendall(b"X")
            assert line_with_timeout(proc) == "WAIT_SIGINT"
            # Let the fixture enter its unbounded poll before waking it.
            time.sleep(0.1)
            os.kill(proc.pid, signal.SIGINT)
            out, err = proc.communicate(timeout=5)
            assert proc.returncode == 0, f"exit {proc.returncode}: {out} {err}"
        print("live FFI poll, nonblocking and offset-send tests passed")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


if __name__ == "__main__":
    sys.exit(main())
