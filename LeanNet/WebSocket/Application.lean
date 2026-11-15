import LeanNet.WebSocket.Connection

namespace LeanNet.WebSocket

structure Reply where
  opcode : Opcode
  payload : ByteArray

/-- Synchronous callbacks on the owning reactor worker. They must return
    promptly; a returned message is subject to bounded output backpressure. -/
structure Callbacks where
  onMessage : Opcode → ByteArray → IO (Option Reply)
  onPing : ByteArray → IO Unit := fun _ => pure ()
  onPong : ByteArray → IO Unit := fun _ => pure ()
  onClosed : Connection.CloseInfo → IO Unit := fun _ => pure ()
  onProtocolError : Error → IO Unit := fun _ => pure ()

end LeanNet.WebSocket
