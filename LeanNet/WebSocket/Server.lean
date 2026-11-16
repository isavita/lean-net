import LeanNet.WebSocket.Connection
import LeanNet.WebSocket.Handshake
import LeanNet.WebSocket.Application
import LeanNet.HTTP1.Handlers

namespace LeanNet.WebSocket.Server

open LeanNet.HTTP1

abbrev Reply := WebSocket.Reply
abbrev Callbacks := WebSocket.Callbacks

private structure Session where
  connection : Connection.State
  pending : Option Reply := none
  notified : Bool := false

private def queueReply (session : Session) (reply : Reply) :
    IO (Session × List Connection.Action) := do
  if reply.opcode == .close then
    if reply.payload.size == 1 || reply.payload.size > 125 then
      throw (IO.userError "invalid application WebSocket close payload")
    let code := if reply.payload.isEmpty then none else
      some (reply.payload[0]!.toNat * 256 + reply.payload[1]!.toNat)
    let reason := reply.payload.extract (min 2 reply.payload.size) reply.payload.size
    let step ← match session.connection.beginClose code reason with
      | .ok step => pure step
      | .error error => throw (IO.userError error.message)
    return ({ session with connection := step.state, pending := none }, step.actions)
  let accepted := if reply.opcode == .ping || reply.opcode == .pong then
      session.connection.tryControl reply.opcode reply.payload
    else session.connection.trySend reply.opcode reply.payload
  match accepted with
  | .ok (.queued step) => return ({ session with connection := step.state, pending := none }, step.actions)
  | .ok .wouldBlock => return ({ session with pending := some reply }, [])
  | .error _ =>
    match session.connection.beginClose (some 1011) with
    | .ok step => return ({ session with connection := step.state, pending := none }, step.actions)
    | .error _ =>
      let step := session.connection.abort
      return ({ session with connection := step.state, pending := none }, step.actions)

private def process (reference : IO.Ref Session) (callbacks : Callbacks)
    (step : Connection.Step) (consumed : Option Nat := none) : IO RawResult := do
  let mut session ← reference.get
  session := { session with connection := step.state }
  let mut result : RawResult := { consumed }
  let mut actions := step.actions
  -- One codec step handles at most one frame; the extra allowance covers its
  -- application response, close response and a physically queued next frame.
  for _ in [:16] do
    let action :: rest := actions | break
    actions := rest
    match action with
    | .message opcode bytes =>
      let reply : Except Unit (Option Reply) ←
        try pure (Except.ok (← callbacks.onMessage opcode bytes))
        catch _ => pure (Except.error ())
      match reply with
      | .ok (some value) =>
        let (next, more) ← queueReply session value
        session := next
        actions := actions ++ more
      | .ok none => pure ()
      | .error _ =>
        match session.connection.beginClose (some 1011) with
        | .ok next =>
          session := { session with connection := next.state }
          actions := actions ++ next.actions
        | .error _ =>
          let next := session.connection.abort
          session := { session with connection := next.state }
          actions := actions ++ next.actions
    | .ping bytes =>
      let failed ← try callbacks.onPing bytes; pure false catch _ => pure true
      if failed then
        match session.connection.beginClose (some 1011) with
        | .ok next =>
          session := { session with connection := next.state }
          actions := actions ++ next.actions
        | .error _ => pure ()
    | .pong bytes =>
      let failed ← try callbacks.onPong bytes; pure false catch _ => pure true
      if failed then
        match session.connection.beginClose (some 1011) with
        | .ok next =>
          session := { session with connection := next.state }
          actions := actions ++ next.actions
        | .error _ => pure ()
    | .write ticket bytes =>
      if result.ticket.isSome then throw (IO.userError "WebSocket emitted concurrent physical tickets")
      result := { result with ticket := some ticket, output := #[ByteSlice.full bytes] }
    | .closeReceived _ _ => pure ()
    | .closeStarted => result := { result with closeStarted := true }
    | .protocolError error =>
      try callbacks.onProtocolError error catch _ => pure ()
    | .closed info =>
      if !session.notified then
        try callbacks.onClosed info catch _ => pure ()
        session := { session with notified := true }
    | .closeTransport => result := { result with closeAfterWrites := true }
    | .abortTransport => result := { result with abortNow := true }
  if !actions.isEmpty then throw (IO.userError "WebSocket action budget exhausted")
  result := { result with readEnabled := some (session.pending.isNone && session.connection.wantsInput) }
  reference.set session
  return result

/-- Adapt the bounded RFC6455 state machine to the reactor's HTTP/1 raw
    handoff. Its output ticket is acknowledged only at a physical write fence. -/
def rawPipe (callbacks : Callbacks) (config : Connection.Config := {}) : IO RawPipe := do
  let connection ← match Connection.State.new { config with maxFramesPerStep := 1 } with
    | .ok state => pure state
    | .error error => throw (IO.userError error.message)
  let reference ← IO.mkRef ({ connection } : Session)
  return {
    onBytes := fun view => do
      let session ← reference.get
      if session.pending.isSome then return { consumed := some 0, readEnabled := some false }
      let step := session.connection.feedSlice view.bytes view.offset view.length
      process reference callbacks step (some step.consumed)
    onPoll := do
      let session ← reference.get
      if session.pending.isSome || session.connection.isClosing || session.connection.isClosed then return {}
      let reply ← callbacks.onPoll
      let some reply := reply | return {}
      let (next, actions) ← queueReply session reply
      reference.set next
      process reference callbacks { state := next.connection, actions }
    onWritten := fun ticket => do
      let session ← reference.get
      let result ← process reference callbacks (session.connection.outputWritten ticket)
      let session ← reference.get
      if let some pending := session.pending then
        if !session.connection.isClosing && !session.connection.isClosed then
          let (next, actions) ← queueReply session pending
          reference.set next
          let follow ← process reference callbacks { state := next.connection, actions }
          return { result with
            output := result.output ++ follow.output,
            ticket := result.ticket.orElse fun _ => follow.ticket,
            closeStarted := result.closeStarted || follow.closeStarted,
            abortNow := result.abortNow || follow.abortNow,
            closeAfterWrites := result.closeAfterWrites || follow.closeAfterWrites,
            readEnabled := follow.readEnabled }
      return result
    onEOF := do
      let session ← reference.get
      if session.connection.peerCloseReceived then return {}
      process reference callbacks session.connection.finish
    onTimeout := do
      let session ← reference.get
      process reference callbacks session.connection.closeTimeout
    onShutdown := do
      let session ← reference.get
      match session.connection.beginClose (some 1001) with
      | .ok step => process reference callbacks step
      | .error _ => process reference callbacks session.connection.abort
    onClose := do
      let session ← reference.get
      let _ ← process reference callbacks session.connection.abort
      pure () }

/-- Validate an HTTP/1 WebSocket handshake and create a fresh per-connection
    codec. Rejections remain normal HTTP responses. HTTP/2 heads pass through
    for the separately configured `Handlers.onWebSocket` selector. -/
def acceptHTTP1 (head : RequestHead) (policy : Handshake.Policy)
    (callbacks : Callbacks) (config : Connection.Config := {}) : IO HeaderResult := do
  -- Shared header pipelines also see HTTP/2. Its extended CONNECT handshake
  -- belongs to onWebSocket; never interpret it as an HTTP/1 GET upgrade.
  if head.version == "HTTP/2" then return .accept none
  match Handshake.acceptHTTP1 head policy with
  | .error rejection =>
    return .reject { response := { status := rejection.status, headers := rejection.headers,
                                    body := (rejection.message ++ "\n").toUTF8 } }
  | .ok accepted =>
    return .upgrade { response := accepted.response } (← rawPipe callbacks config)

/-- Useful public example: mirror each text or binary message. -/
def echo : Callbacks := {
  onMessage := fun opcode bytes => pure (some { opcode, payload := bytes }) }

end LeanNet.WebSocket.Server
