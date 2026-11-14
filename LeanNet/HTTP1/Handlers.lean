import LeanNet.Bytes
import LeanNet.HTTP1.Machine
import LeanNet.HTTP1.Router

namespace LeanNet.HTTP1

structure RawResult where
  output : Array ByteSlice := #[]
  closeAfterWrites : Bool := false

/-- Event-driven raw-byte handoff on the same reactor-owned connection. Input
    views stay on this worker; retained views keep their native pool cell alive. -/
structure RawPipe where
  onBytes : ByteSlice → IO RawResult
  onEOF : IO RawResult := pure { closeAfterWrites := true }
  onClose : IO Unit := pure ()

inductive HeaderResult where
  | accept (framing : Option BodyFraming := none)
  | reject (reply : Reply)
  | upgrade (reply : Reply) (pipe : RawPipe)

/-- Created once per worker. Callbacks run synchronously on that worker and
    must not block. The library does not share their mutable state across loops. -/
structure Handlers where
  onRequest : Request → IO Reply
  onHeaders : RequestHead → BodyFraming → IO HeaderResult := fun _ _ => pure (.accept none)

def Handlers.ofRouter (router : Router) : Handlers :=
  { onRequest := fun request => return { response := ← router request } }

def Handlers.default : Handlers := .ofRouter defaultRouter

end LeanNet.HTTP1
