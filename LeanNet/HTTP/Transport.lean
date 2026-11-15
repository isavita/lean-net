import LeanNet.Reactor.Basic

namespace LeanNet.HTTP.Transport

/-- A negotiated protocol selects its parser before application bytes arrive. -/
inductive Protocol where
  | detect
  | http1
  | http2

/-- Operations remain on the reactor owner. A TLS endpoint implements these
    through bounded queues; it never exposes its underlying plain socket. -/
structure Endpoint where
  id : Reactor.SocketId
  tryWrite : Reactor.Buffer → UInt32 → UInt32 → UInt64 → IO Reactor.Submission
  tryFile : FileRegion → UInt64 → IO Reactor.FileSubmission := fun _ _ =>
    throw (IO.userError "transport does not support file output")
  setReadEnabled : Bool → IO Unit
  close : IO Unit
  closeAfterWrites : IO Unit
  armTimer : UInt32 → UInt64 → IO Unit
  cancelTimer : UInt32 → IO Unit

inductive Event where
  | ready (endpoint : Endpoint) (protocol : Protocol)
  | read (id : Reactor.SocketId) (buffer : Reactor.Buffer) (offset length : UInt32)
      (release : Option (IO Unit))
  | written (id : Reactor.SocketId) (operation : UInt64) (count : Nat)
  | eof (id : Reactor.SocketId)
  | closed (id : Reactor.SocketId)
  | timer (id : Reactor.SocketId) (kind : UInt32)
  | error (id : Reactor.SocketId) (flags : UInt32) (code : Int)
  | wake

/-- The provider consumes every native event, including historical completions.
    Returned receive buffers transfer their leases to the HTTP controller. -/
structure Worker where
  event : Reactor.Event → IO (Array Event)
  poll : IO (Array Event)
  hasWork : IO Bool
  /-- Physical socket death can precede satisfied asynchronous write fences.
      Retain controller metadata until the provider's authoritative CLOSED. -/
  deferClosed : Bool := false
  /-- Bound provider teardown by the controller's shared drain deadline. -/
  shutdownBefore : UInt64 → IO Unit := fun _ => pure ()
  /-- Requested transport-close time inside the shared deadline. The controller
      reserves at most one quarter of its total drain budget. -/
  shutdownReserveMs : UInt64 := 0
  /-- Stop application admission and begin transport closure after the
      application portion of the drain budget. Existing write fences survive. -/
  beginShutdown : IO Unit := pure ()
  /-- True once all provider-owned sessions have reached authoritative closure,
      including handshakes which never published an application endpoint. -/
  shutdownComplete : IO Bool := pure true
  reservedBuffers : Nat := 0
  /-- True for TLS transports: enables Strict-Transport-Security defaults. -/
  secure : Bool := false
  /-- Additional Prometheus exposition appended to the metrics endpoint. -/
  metrics : IO ByteArray := pure ByteArray.empty

private def plainEndpoint (socket : Reactor.Socket .connected) : Endpoint := {
  id := socket.id
  tryWrite := fun buffer offset length operation => socket.tryWrite buffer offset length operation
  tryFile := fun region operation => socket.tryFile region operation
  setReadEnabled := socket.setReadEnabled
  close := do let _ ← socket.close (by decide); pure ()
  closeAfterWrites := socket.closeAfterWrites
  armTimer := socket.armTimer
  cancelTimer := socket.cancelTimer }

private def plainEvent : Reactor.Event → IO (Array Event)
  | .accepted socket => pure #[.ready (plainEndpoint socket) .detect]
  | .read socket buffer offset length => pure #[.read socket.id buffer offset length none]
  | .written id operation count => pure #[.written id operation count]
  | .eof socket => pure #[.eof socket.id]
  | .closed socket => pure #[.closed socket.id]
  | .timer socket kind => pure #[.timer socket.id kind]
  | .error id flags code => pure #[.error id flags code]
  | .wake => pure #[.wake]
  | .wireRead _ buffer _ _ => do
    buffer.release
    throw (IO.userError "cleartext provider received ciphertext")
  | .wireEOF _ | .wireTimer .. =>
    throw (IO.userError "cleartext provider received a TLS connection event")

/-- The cleartext provider keeps all buffer and write ownership in the reactor. -/
def plain : Worker := { event := plainEvent, poll := pure #[], hasWork := pure false }

/-- The bracket encloses the entire worker, so asynchronous providers stop and
    join their native threads before reactor resources leave their brackets. -/
abbrev WithWorker := Nat → Nat → Reactor.Reactor → (Worker → IO Unit) → IO Unit

def withPlainWorker : WithWorker := fun _ _ _ use => use plain

end LeanNet.HTTP.Transport
