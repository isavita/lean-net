import LeanNet.Reactor.Basic

/-! Optional upstream TLS provider boundary. The core gateway stays free of
OpenSSL linkage; the `tls` package supplies a verified memory-BIO client.
Every callback is invoked only on its owning reactor worker. -/

namespace LeanNet.Gateway

inductive TLSRead where
  | pending
  | data (bytes : ByteArray)
  | eof

structure TLSSession where
  id : Reactor.SocketId
  /-- True only after a verified handshake and selected HTTP/1.1 ALPN. -/
  handshake : IO Bool
  feedCipher : ByteArray → IO Unit
  /-- Remove the next bounded ciphertext slice. The caller retains it until
      `submitCipher` succeeds; an empty array means no output. -/
  drainCipher : IO ByteArray
  submitCipher : ByteArray → IO Reactor.Submission
  /-- Pause native ciphertext reads while downstream output is backpressured. -/
  setReadEnabled : Bool → IO Unit
  armTimer : UInt32 → UInt64 → IO Unit
  cancelTimer : UInt32 → IO Unit
  /-- Called after the verified handshake and all queued handshake ciphertext
      has physically completed. It revokes the handshaking Wire alias. -/
  markWireReady : IO Unit
  writePlain : ByteArray → IO Nat
  readPlain : IO TLSRead
  cleanForReuse : IO Bool
  close : IO Unit

structure TLSProvider where
  /-- Claim the socket before any plaintext write. `verifyName` is the exact
      configured DNS name or IP literal, never taken from request headers. -/
  start : Reactor.Socket .connected → ByteArray → IO TLSSession
  /-- Called after all gateway sockets and sessions are closed on this worker. -/
  close : IO Unit := pure ()

end LeanNet.Gateway
