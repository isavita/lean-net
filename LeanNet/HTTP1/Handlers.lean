import LeanNet.Bytes
import LeanNet.HTTP.Deferred
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
  /-- Cooperative server-push polling; called on this worker while idle. -/
  onPoll : IO RawResult := pure {}
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
  /-- Bounded owner-worker maintenance, including idle periods. Timestamp uses
      IO.monoMsNow milliseconds. Must not block. -/
  onTick : Nat → IO Unit := fun _ => pure ()
  tickIntervalMs : Nat := 100
  /-- Begin cooperative drain against the same remaining native shutdown budget.
      The absolute deadline uses IO.monoMsNow milliseconds. Must not block. -/
  onDrain : Nat → IO Unit := fun _ => pure ()
  isDrained : IO Bool := pure true
  /-- Runs once after accepted exchanges drain or are cancelled. Must not block. -/
  onShutdown : IO Unit := pure ()
  onRequest : Request → IO Reply
  /-- Optional nonblocking application completion. Called on the owner worker;
      takes precedence over `onRequest`. See `HTTP.Deferred.Job`. -/
  onRequestDeferred : Option (Request → IO HTTP.Deferred.Result) := none
  /-- Opt in at headers to a bounded HTTP/2 request source, including bidi. -/
  streamRequests : RequestHead → IO Bool := fun _ => pure false
  /-- Shared early callback. H2 uses version `HTTP/2`, known Content-Length
      or `.chunked` for stream-framed unknown length (no wire chunk coding).
      H2 ignores framing overrides, sends bodyless rejections, and rejects
      raw upgrades with 501; use `onWebSocket` for RFC8441. -/
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
