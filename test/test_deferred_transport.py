#!/usr/bin/env python3
"""Controller completion metadata outlives physical asynchronous socket death."""
from contextlib import closing
import os
from pathlib import Path
import unittest

from test_observability import Running, request, Reader, ROOT, SUFFIX


class DeferredCompletion(unittest.TestCase):
    def run_case(self, *, partial):
        fixture = Path(os.environ.get("LEAN_NET_DEFERRED_TRANSPORT_BIN",
            ROOT / f".lake/build/bin/lean-net-deferred-transport-fixture{SUFFIX}"))
        # Running already owns process-group shutdown, helper joining and log QA.
        import test_observability
        previous = test_observability.FIXTURE
        test_observability.FIXTURE = fixture
        try:
            server = Running(self)
        finally:
            test_observability.FIXTURE = previous
        with closing(server.connect()) as sock:
            if partial:
                sock.sendall(request(b"/upload", b"POST", headers=[
                    (b"Content-Length", b"10"), (b"Expect", b"100-continue")]))
                self.assertEqual(Reader(sock).response().status, 100)
                self.assertEqual(sock.recv(1), b"")
            else:
                sock.sendall(request(b"/finished"))
                reader = Reader(sock)
                response = reader.response()
                self.assertEqual((response.status, response.body), (200, b"finished"))
                reader.eof()
        _, records = server.wait(success=0 if partial else 1,
            errors=1 if partial else 0, started=1, logs=1,
            body_bytes=0 if partial else 8)
        self.assertEqual(records[0]["outcome"], "error" if partial else "completed")
        self.assertEqual(records[0]["target"], "/upload" if partial else "/finished")
        self.assertEqual(server.http(b"/healthy").body, b"finished")
        server.wait(success=1 if partial else 2, errors=1 if partial else 0, started=2, logs=2)
        server.stop()
        self.assertIn("delivered satisfied WN after physical CLOSED", server.text())

    def test_completed_response_keeps_its_satisfied_write(self):
        self.run_case(partial=False)

    def test_incomplete_request_is_aborted_after_informational_write(self):
        self.run_case(partial=True)


if __name__ == "__main__":
    unittest.main()
