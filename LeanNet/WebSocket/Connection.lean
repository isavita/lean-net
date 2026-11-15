import LeanNet.WebSocket.Frame

namespace LeanNet.WebSocket.Connection

structure Config where
  maxFrameBytes : Nat := 1048576
  maxMessageBytes : Nat := 1048576
  maxOutputFrameBytes : Nat := 16384
  maxQueuedOutputBytes : Nat := 2 * 1024 * 1024
  maxQueuedFrames : Nat := 256
  maxFramesPerStep : Nat := 64
  maxInputBytesPerStep : Nat := 65536
  maxMessageFragments : Nat := 1024
  deriving Repr

def Config.validate (config : Config) : Except Error Unit := do
  if config.maxFrameBytes == 0 || config.maxFrameBytes > 16777216 ||
      config.maxMessageBytes == 0 || config.maxMessageBytes > 16777216 ||
      config.maxOutputFrameBytes < 125 || config.maxOutputFrameBytes > config.maxFrameBytes ||
      config.maxQueuedOutputBytes < config.maxOutputFrameBytes + 141 ||
      config.maxQueuedOutputBytes > 67108864 || config.maxQueuedFrames < 2 ||
      config.maxQueuedFrames > 65536 || config.maxFramesPerStep == 0 || config.maxFramesPerStep > 4096 ||
      config.maxInputBytesPerStep == 0 || config.maxInputBytesPerStep > 1048576 ||
      config.maxMessageFragments == 0 || config.maxMessageFragments > 65536 then
    throw ⟨1002, "invalid WebSocket resource limits"⟩

structure CloseInfo where
  code : Option Nat
  reason : ByteArray := ByteArray.empty
  clean : Bool := false
  deriving Inhabited

inductive Action where
  | message (opcode : Opcode) (bytes : ByteArray)
  | ping (bytes : ByteArray)
  | pong (bytes : ByteArray)
  /-- Exactly one ordered write is outstanding. Acknowledge physical completion
      with outputWritten; do not acknowledge merely handing bytes to a queue. -/
  | write (id : Nat) (bytes : ByteArray)
  | closeReceived (code : Option Nat) (reason : ByteArray)
  | closeStarted
  | protocolError (error : Error)
  | closed (info : CloseInfo)
  | closeTransport
  | abortTransport

private structure Utf8 where
  remaining : Nat := 0
  low : UInt8 := 128
  high : UInt8 := 191

private def utf8Feed (initial : Utf8) (bytes : ByteArray) : Option Utf8 := Id.run do
  let mut state := initial
  for byte in bytes do
    if state.remaining != 0 then
      if byte < state.low || byte > state.high then return none
      state := { remaining := state.remaining - 1 }
    else if byte <= 127 then pure ()
    else if byte >= 194 && byte <= 223 then state := { remaining := 1 }
    else if byte == 224 then state := { remaining := 2, low := 160 }
    else if (byte >= 225 && byte <= 236) || (byte >= 238 && byte <= 239) then state := { remaining := 2 }
    else if byte == 237 then state := { remaining := 2, high := 159 }
    else if byte == 240 then state := { remaining := 3, low := 144 }
    else if byte >= 241 && byte <= 243 then state := { remaining := 3 }
    else if byte == 244 then state := { remaining := 3, high := 143 }
    else return none
  return some state

/-- Registered protocol codes plus application/private-use codes. Reserved
    no-status/abnormal/TLS-failure markers are never legal on the wire. -/
def validCloseCode (code : Nat) : Bool :=
  [1000,1001,1002,1003,1007,1008,1009,1010,1011,1012,1013,1014].contains code ||
    (code >= 3000 && code <= 4999)

def closePayload (code : Option Nat) (reason : ByteArray := ByteArray.empty) : Except Error ByteArray := do
  match code with
  | none =>
    if !reason.isEmpty then throw ⟨1002, "close reason requires a status code"⟩
    return ByteArray.empty
  | some value =>
    if !validCloseCode value then throw ⟨1002, "invalid close status"⟩
    if reason.size > 123 then throw ⟨1002, "close reason exceeds control limit"⟩
    if (String.fromUTF8? reason).isNone then throw ⟨1007, "invalid close reason UTF-8"⟩
    return (ByteArray.mk #[UInt8.ofNat (value / 256), UInt8.ofNat value]).append reason

private def parseClose (payload : ByteArray) : Except Error (Option Nat × ByteArray) := do
  if payload.isEmpty then return (none, ByteArray.empty)
  if payload.size == 1 then throw ⟨1002, "one-byte close payload"⟩
  let code := payload[0]!.toNat * 256 + payload[1]!.toNat
  let reason := payload.extract 2 payload.size
  let _ ← closePayload (some code) reason
  return (some code, reason)

private structure Flight where
  id : Nat
  bytes : Nat
  close : Bool

structure State where
  private config : Config
  private parser : FrameParser
  private fragmented : Option Opcode := none
  private fragments : List ByteArray := []
  private messageBytes : Nat := 0
  private messageFragments : Nat := 0
  private utf8 : Utf8 := {}
  private output : List Frame := []
  private outputBytes : Nat := 0
  private outputFrames : Nat := 0
  private flight : Option Flight := none
  private nextOutput : Nat := 1
  private sentClose : Bool := false
  private receivedClose : Bool := false
  private closeWritten : Bool := false
  private failedAfterClose : Bool := false
  private closeCode : Option Nat := none
  private closeReason : ByteArray := ByteArray.empty
  private terminated : Bool := false

structure Step where
  state : State
  consumed : Nat := 0
  actions : List Action := []

inductive SendResult where
  | queued (step : Step)
  | wouldBlock

def State.new (config : Config := {}) : Except Error State := do
  config.validate
  return { config, parser := FrameParser.new config.maxFrameBytes true }

def State.isClosed (state : State) : Bool := state.terminated

def State.isClosing (state : State) : Bool := state.sentClose || state.receivedClose

def State.peerCloseReceived (state : State) : Bool := state.receivedClose

def State.wantsInput (state : State) : Bool := !state.terminated && !state.failedAfterClose

def State.queuedOutputBytes (state : State) : Nat := state.outputBytes

private def cost (frame : Frame) : Nat :=
  frame.payload.size + (if frame.payload.size < 126 then 2 else if frame.payload.size < 65536 then 4 else 10)

private def addFrame (state : State) (frame : Frame) : State :=
  { state with output := state.output ++ [frame], outputBytes := state.outputBytes + cost frame, outputFrames := state.outputFrames + 1 }

private def clearUnsent (state : State) : State :=
  { state with output := [], outputBytes := (state.flight.map (·.bytes)).getD 0, outputFrames := if state.flight.isSome then 1 else 0, fragments := [], fragmented := none, messageBytes := 0, messageFragments := 0, utf8 := {} }

private def drainOutput (state : State) : Step := Id.run do
  if state.terminated then return { state }
  if state.closeWritten && (state.receivedClose || state.failedAfterClose) then
    return { state := { (clearUnsent state) with terminated := true }, actions :=
      [.closed { code := state.closeCode, reason := state.closeReason, clean := state.receivedClose && !state.failedAfterClose }, .closeTransport] }
  if state.flight.isSome then return { state }
  match state.output with
  | [] => return { state }
  | frame :: remaining =>
    if state.nextOutput > 9223372036854775807 then
      return { state := { (clearUnsent state) with terminated := true }, actions := [.closed { code := some 1006 }, .abortTransport] }
    match frame.encode none state.config.maxFrameBytes with
    | .error error => return { state := { (clearUnsent state) with terminated := true }, actions := [.protocolError error, .closed { code := some 1006 }, .abortTransport] }
    | .ok bytes =>
      let id := state.nextOutput
      return { state := { state with output := remaining, nextOutput := id + 1, flight := some { id, bytes := bytes.size, close := frame.opcode == .close } }, actions := [.write id bytes] }

def State.drain (state : State) : Step := drainOutput state

private def fail (state : State) (error : Error) : Step := Id.run do
  if state.terminated then return { state }
  let mut state := (clearUnsent state)
  let mut actions := [Action.protocolError error]
  if !state.sentClose then
    let payload := (ByteArray.mk #[UInt8.ofNat (error.code / 256), UInt8.ofNat error.code])
    state := addFrame state { opcode := .close, payload }
    actions := actions ++ [.closeStarted]
  state := { state with sentClose := true, failedAfterClose := true, closeCode := some error.code, closeReason := ByteArray.empty }
  -- If a close frame was previously queued but not yet written, retain one.
  if !state.closeWritten && !(state.flight.any (·.close)) && state.output.isEmpty then
    state := addFrame state { opcode := .close, payload := ByteArray.mk #[UInt8.ofNat (error.code / 256), UInt8.ofNat error.code] }
  let next := drainOutput state
  return { next with actions := actions ++ next.actions }

private def handle (state : State) (frame : Frame) : Step := Id.run do
  if frame.opcode == .close then
    match parseClose frame.payload with
    | .error error => return fail state error
    | .ok (code, reason) =>
      if state.receivedClose then return { state }
      let mut state := { state with receivedClose := true, closeCode := code, closeReason := reason, fragments := [], fragmented := none, messageBytes := 0, messageFragments := 0, utf8 := {} }
      let mut actions := [Action.closeReceived code reason]
      if !state.sentClose then
        -- 1010 is a client-only status. Preserve the received observation but
        -- acknowledge with 1000 rather than reflecting a forbidden code.
        let reply := if code == some 1010 then
          (closePayload (some 1000)).toOption.getD ByteArray.empty else frame.payload
        state := addFrame (clearUnsent state) { opcode := .close, payload := reply }
        state := { state with sentClose := true }
        actions := actions ++ [.closeStarted]
      let next := drainOutput state
      return { next with actions := actions ++ next.actions }
  if frame.opcode == .ping then
    if state.receivedClose then return { state }
    if state.outputBytes + cost { opcode := .pong, payload := frame.payload } > state.config.maxQueuedOutputBytes - 127 ||
        state.outputFrames + 1 > state.config.maxQueuedFrames - 1 then
      return fail state ⟨1009, "control output queue is full"⟩
    let next := drainOutput (addFrame state { opcode := .pong, payload := frame.payload })
    return { next with actions := .ping frame.payload :: next.actions }
  if frame.opcode == .pong then return { state, actions := [.pong frame.payload] }
  if state.isClosing then return { state }
  let first := frame.opcode != .continuation
  if first && state.fragmented.isSome then return fail state ⟨1002, "new message before final continuation"⟩
  if !first && state.fragmented.isNone then return fail state ⟨1002, "continuation without a message"⟩
  let opcode := if first then frame.opcode else state.fragmented.getD .binary
  if state.messageFragments + 1 > state.config.maxMessageFragments then
    return fail state ⟨1009, "message exceeds fragment-count limit"⟩
  if state.messageBytes + frame.payload.size > state.config.maxMessageBytes then
    return fail state ⟨1009, "message exceeds configured limit"⟩
  let utf8 := if opcode == .text then utf8Feed state.utf8 frame.payload else some state.utf8
  let some utf8 := utf8 | return fail state ⟨1007, "invalid text UTF-8"⟩
  if frame.fin && opcode == .text && utf8.remaining != 0 then return fail state ⟨1007, "truncated text UTF-8"⟩
  if frame.fin then
    let mut body := ByteArray.emptyWithCapacity (state.messageBytes + frame.payload.size)
    for fragment in state.fragments.reverse do body := body.append fragment
    body := body.append frame.payload
    return { state := { state with fragmented := none, fragments := [], messageBytes := 0, messageFragments := 0, utf8 := {} }, actions := [.message opcode body] }
  return { state := { state with fragmented := some opcode, fragments := frame.payload :: state.fragments, messageBytes := state.messageBytes + frame.payload.size, messageFragments := state.messageFragments + 1, utf8 } }

/-- Bounded server-side input; partial UTF-8 and message fragments remain owned.
    Frame parsing is independent of transport/H2 DATA boundaries. -/
def State.feedSlice (initial : State) (input : ByteArray) (offset length : Nat) : Step := Id.run do
  if offset > input.size || length > input.size - offset then
    return fail initial ⟨1002, "invalid input slice"⟩
  if !initial.wantsInput then return { state := initial }
  let length := min length initial.config.maxInputBytesPerStep
  let mut state := initial
  let mut consumed := 0
  let mut actions := []
  for _ in [:initial.config.maxFramesPerStep] do
    if consumed == length || !state.wantsInput then break
    match state.parser.feedSlice input (offset + consumed) (length - consumed) with
    | .needMore parser used =>
      state := { state with parser }; consumed := consumed + used; break
    | .error error used =>
      consumed := consumed + used
      let next := fail state error
      return { next with consumed, actions := actions ++ next.actions }
    | .complete frame used =>
      consumed := consumed + used
      let next := handle { state with parser := FrameParser.new state.config.maxFrameBytes true } frame
      state := next.state; actions := actions ++ next.actions
  let next := drainOutput state
  return { next with consumed, actions := actions ++ next.actions }

def State.feed (state : State) (bytes : ByteArray) : Step := state.feedSlice bytes 0 bytes.size

/-- Queue a complete message, fragmenting server output without compression.
    Capacity failure leaves state unchanged; applications retry on outputWritten. -/
def State.trySend (state : State) (opcode : Opcode) (bytes : ByteArray) : Except Error SendResult := do
  if state.isClosed || state.isClosing then throw ⟨1002, "connection is closing"⟩
  if opcode != .text && opcode != .binary then throw ⟨1002, "send requires text or binary"⟩
  if bytes.size > state.config.maxMessageBytes then throw ⟨1009, "message exceeds configured limit"⟩
  if opcode == .text && (String.fromUTF8? bytes).isNone then throw ⟨1007, "invalid text UTF-8"⟩
  let count := max 1 ((bytes.size + state.config.maxOutputFrameBytes - 1) / state.config.maxOutputFrameBytes)
  if state.outputFrames + count > state.config.maxQueuedFrames - 1 then return .wouldBlock
  let mut frames := []
  let mut total := 0
  for index in [:count] do
    let start := index * state.config.maxOutputFrameBytes
    let data := bytes.extract start (min bytes.size (start + state.config.maxOutputFrameBytes))
    let frame : Frame := { fin := index + 1 == count, opcode := if index == 0 then opcode else .continuation, payload := data }
    total := total + cost frame
    frames := frame :: frames
  if total > state.config.maxQueuedOutputBytes - 127 - state.outputBytes then return .wouldBlock
  let mut state := state
  for frame in frames.reverse do state := addFrame state frame
  return .queued (drainOutput state)

/-- Initiate a Ping or unsolicited Pong without bypassing output credit.
    Payloads are control-frame-sized and never fragmented. -/
def State.tryControl (state : State) (opcode : Opcode) (payload : ByteArray := ByteArray.empty)
    : Except Error SendResult := do
  if state.isClosed || state.isClosing then throw ⟨1002, "connection is closing"⟩
  if opcode != .ping && opcode != .pong then throw ⟨1002, "control sender requires Ping or Pong"⟩
  if payload.size > 125 then throw ⟨1002, "control payload exceeds limit"⟩
  let frame : Frame := { opcode, payload }
  if state.outputFrames + 1 > state.config.maxQueuedFrames - 1 ||
      cost frame > state.config.maxQueuedOutputBytes - 127 - state.outputBytes then return .wouldBlock
  return .queued (drainOutput (addFrame state frame))

/-- Initiate close, canceling unsubmitted application messages. A frame already
    handed to the transport is retained until its physical completion ticket. -/
def State.beginClose (state : State) (code : Option Nat := some 1000)
    (reason : ByteArray := ByteArray.empty) : Except Error Step := do
  if code == some 1010 then throw ⟨1002, "server cannot initiate client-only close code1010"⟩
  let payload ← closePayload code reason
  if state.terminated || state.sentClose then return { state }
  let state := addFrame (clearUnsent state) { opcode := .close, payload }
  let next := drainOutput { state with sentClose := true, closeCode := code, closeReason := reason }
  return { next with actions := .closeStarted :: next.actions }

/-- Physical output completion; duplicate/historical acknowledgements never
    return capacity twice. Future tickets fail closed. -/
def State.outputWritten (state : State) (id : Nat) : Step :=
  if state.terminated then { state }
  else match state.flight with
  | some flight =>
    if id == flight.id then
      drainOutput { state with flight := none, outputBytes := state.outputBytes - flight.bytes, outputFrames := state.outputFrames - 1, closeWritten := state.closeWritten || flight.close }
    else if id < flight.id then { state }
    else fail state ⟨1002, "future output completion ticket"⟩
  | none =>
    if id < state.nextOutput then { state } else fail state ⟨1002, "unknown output completion ticket"⟩

/-- EOF/reset/close-timeout before the WebSocket close exchange is abnormal.
    Local1006 is an observation only and is never serialized on the wire. -/
def State.abort (state : State) : Step :=
  if state.terminated then { state }
  else { state := { (clearUnsent state) with terminated := true }, actions := [.closed { code := some 1006 }, .abortTransport] }

def State.finish (state : State) : Step := state.abort

def State.closeTimeout (state : State) : Step := state.abort

end LeanNet.WebSocket.Connection
