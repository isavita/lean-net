import LeanNet.Reactor.Basic
open LeanNet

-- State-indexed APIs must reject role confusion and repeated close at compile time.
example (_socket : Reactor.Socket .closed) : True := by
  fail_if_success exact (show IO (Reactor.Socket .closed) from _socket.close (by decide))
  trivial

example (_socket : Reactor.Socket .listening) (_buffer : Reactor.Buffer) : True := by
  fail_if_success exact (show IO Unit from _socket.write _buffer 0 1)
  fail_if_success exact (show IO Unit from _socket.armTimer 0 1)
  trivial

example (_socket : Reactor.Socket .fresh) : True := by
  fail_if_success exact (show IO (Reactor.Socket .listening) from _socket.listen 4096)
  trivial

example (_socket : Reactor.Socket .connected) : True := by
  fail_if_success exact (show IO (Reactor.Socket .bound) from _socket.bind "127.0.0.1" 8080)
  trivial

example : True := by
  fail_if_success exact (Reactor.Socket.mk 0 0 : Reactor.Socket .connected)
  trivial

example (_wire : Reactor.Wire .tls_ready) : True := by
  fail_if_success exact (show IO (Reactor.Wire .tls_ready) from _wire.ready)
  trivial

example (_wire : Reactor.Wire .closed) : True := by
  fail_if_success exact (show IO Unit from _wire.close)
  fail_if_success exact (show IO Unit from _wire.close (by decide))
  trivial

example (_socket : Reactor.Socket .tls_handshaking) (_buffer : Reactor.Buffer) : True := by
  fail_if_success exact (show IO Unit from _socket.write _buffer 0 1)
  trivial

example (_socket : Reactor.Socket .tls_ready) (_buffer : Reactor.Buffer) : True := by
  fail_if_success exact (show IO Unit from _socket.write _buffer 0 1)
  trivial

example (_socket : Reactor.Socket .tls_handshaking) (_capability : UInt64) : True := by
  fail_if_success exact (show Reactor.Wire .tls_handshaking from Reactor.Wire.mk _socket _capability 1)
  trivial

example (_socket : Reactor.Socket .listening) : True := by
  fail_if_success exact (show IO (Reactor.Wire .tls_handshaking) from _socket.claim)
  trivial

-- Open transport phases can supply the erased proof required by close.
example (wire : Reactor.Wire .tls_handshaking) : IO Unit := wire.close (by decide)
example (wire : Reactor.Wire .tls_ready) : IO Unit := wire.close (by decide)
