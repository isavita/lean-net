#!/usr/bin/env python3
"""HTTP/1 admission and output survive bounded native-controller shutdown."""
import signal
import socket
import sys
import time
import unittest

from test_echo import connect
from test_http1_reactor import Reader, ServerCase


class HTTP1Drain(ServerCase, unittest.TestCase):
    def signal_stop(self):
        started = time.monotonic()
        self.server.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
        return started

    def test_current_continue_body_finishes_after_stop(self):
        with connect(self.port) as sock:
            sock.sendall(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 7\r\n"
                         b"Expect: 100-continue\r\n\r\n")
            reader = Reader(sock)
            self.assertEqual(reader.response().status, 100)
            started = self.signal_stop()
            time.sleep(.08)
            sock.sendall(b"\x00done\xff!")
            response = reader.response()
            self.assertEqual((response.status, response.body), (200, b"\x00done\xff!"))
            self.assertEqual(response.headers[b"connection"].lower(), b"close")
            reader.eof()
            self.assertEqual(self.server.wait(timeout=3), 0)
            self.assertLess(time.monotonic() - started, 3)

    def test_queued_large_response_drains_before_close(self):
        with connect(self.port) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            sock.sendall(b"GET /large HTTP/1.1\r\nHost: x\r\n\r\n")
            reader = Reader(sock)
            head = reader.until(b"\r\n\r\n")
            self.assertIn(b"Content-Length: 2097152\r\n", head)
            started = self.signal_stop()
            self.assertEqual(reader.take(2 * 1024 * 1024), b"A" * (2 * 1024 * 1024))
            reader.eof()
            self.assertEqual(self.server.wait(timeout=3), 0)
            self.assertLess(time.monotonic() - started, 3)

    def test_incomplete_current_body_uses_the_drain_deadline(self):
        with connect(self.port) as sock:
            sock.sendall(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n"
                         b"Expect: 100-continue\r\n\r\n")
            self.assertEqual(Reader(sock).response().status, 100)
            started = self.signal_stop()
            self.assertEqual(self.server.wait(timeout=3.5), 0)
            elapsed = time.monotonic() - started
            self.assertGreaterEqual(elapsed, 1.5)
            self.assertLess(elapsed, 3.5)


if __name__ == "__main__":
    unittest.main()
