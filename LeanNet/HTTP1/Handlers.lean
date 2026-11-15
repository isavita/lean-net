import LeanNet.Bytes
import LeanNet.HTTP1.Machine
import LeanNet.HTTP1.Router
import LeanNet.HTTP2.Push
import LeanNet.WebSocket.Application
import LeanNet.WebSocket.Handshake

namespace LeanNet.HTTP1

structure RawResult where
  output : Array ByteSlice := #[]
  /-- Bytes consumed from the supplied input view. `none` consumes it all. -/
  consumed : Option Nat := none
  /-- Physical completion ticket for this output group. -/
  ticket : Option Nat := none
  readEnabled : Option Bool := none
  closeStarted : Bool := false
  abortNow : Bool := false
  closeAfterWrites : Bool := false

/-- Event-driven raw-byte handoff on the same reactor-owned connection. Input
    views stay on this worker; retained views keep their native pool cell alive. -/
structure RawPipe where
  onBytes : ByteSlice → IO RawResult
  onWritten : Nat → IO RawResult := fun _ => pure {}
  onTimeout : IO RawResult := pure { abortNow := true }
  onShutdown : IO RawResult := pure { closeAfterWrites := true }
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
  /-- Called only for HTTP/2 when server push is enabled and the peer allows it. -/
  onPush : Request → IO (Array HTTP2.Push) := fun _ => pure #[]
  /-- RFC8441 application selection. Return none for an unsupported tunnel.
      A policy is mandatory when accepting, including missing-Origin behavior. -/
  onWebSocket : HTTP2.RequestHead → IO (Option (WebSocket.Handshake.Policy × WebSocket.Callbacks)) :=
    fun _ => pure none

def Handlers.ofRouter (router : Router) : Handlers :=
  { onRequest := fun request => return { response := ← router request } }

def Handlers.default : Handlers := .ofRouter defaultRouter

end LeanNet.HTTP1
