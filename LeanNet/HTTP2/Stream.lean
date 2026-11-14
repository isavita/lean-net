import LeanNet.HTTP2.Frame

namespace LeanNet.HTTP2

/-- Stream states are relative to the local endpoint. -/
inductive StreamState where
  | idle | reservedLocal | reservedRemote | open | halfClosedLocal | halfClosedRemote | closed
  deriving Repr, BEq, DecidableEq, Inhabited

inductive EndpointRole where
  | client | server
  deriving Repr, BEq, DecidableEq

inductive Direction where
  | inbound | outbound
  deriving Repr, BEq, DecidableEq

/-- A reserve event represents a PUSH_PROMISE on another stream. END_STREAM is
    applied after the corresponding HEADERS or DATA event. CONTINUATION and
    unknown extension frames have no independent state transition. -/
inductive StreamEvent where
  | headers (direction : Direction) (endStream : Bool)
  | data (direction : Direction) (endStream : Bool)
  | reset (direction : Direction)
  | priority (direction : Direction)
  | windowUpdate (direction : Direction)
  | reserveLocal | reserveRemote
  | extension (direction : Direction)
  deriving Repr, BEq, DecidableEq

/-- `discard` is for in-flight frames after our RST_STREAM. The caller must
    still update connection flow control and HPACK state before discarding. -/
inductive StreamDisposition where
  | process | ignore | discard
  deriving Repr, BEq, DecidableEq

def maxWindow : Nat := 2147483647
def defaultWindow : Nat := 65535

structure Stream where
  id : UInt32
  state : StreamState := .idle
  /-- Sending credit can become negative after a SETTINGS window decrease. -/
  sendWindow : Int := 65535
  recvWindow : Int := 65535
  locallyReset : Bool := false
  deriving Repr

private def connectionError (code : ErrorCode) (message : String) : ProtocolError :=
  ⟨code, .connection, message⟩
private def streamError (stream : Stream) (code : ErrorCode) (message : String) : ProtocolError :=
  ⟨code, .stream stream.id, message⟩

/-- Stream ID ordering and reuse are connection-level responsibilities. -/
def Stream.new (id : UInt32) (sendInitial : Nat := defaultWindow)
    (recvInitial : Nat := defaultWindow) : Except ProtocolError Stream := do
  if id == 0 || id.toNat > maxWindow then
    throw (connectionError .protocolError "invalid stream identifier")
  if sendInitial > maxWindow || recvInitial > maxWindow then
    throw (connectionError .flowControlError "initial stream window exceeds maximum")
  return { id, sendWindow := Int.ofNat sendInitial, recvWindow := Int.ofNat recvInitial }

private def ended (state : StreamState) (direction : Direction) : StreamState :=
  match state, direction with
  | .open, .inbound => .halfClosedRemote
  | .open, .outbound => .halfClosedLocal
  | .halfClosedLocal, .inbound | .halfClosedRemote, .outbound => .closed
  | other, _ => other

private def validClientInitiated (stream : Stream) : Bool := stream.id.toNat % 2 == 1
private def validServerInitiated (stream : Stream) : Bool := stream.id.toNat % 2 == 0

/-- Apply one stream state event. Connection-level header-block sequencing,
    stream-ID monotonicity, frame syntax, and header semantics remain the
    connection layer's responsibility. -/
def Stream.apply (stream : Stream) (role : EndpointRole) (event : StreamEvent) :
    Except ProtocolError (Stream × StreamDisposition) := do
  let state := stream.state
  match event with
  | .extension _ | .priority _ => return (stream, .ignore)
  | .reserveLocal =>
    if state == .idle && role == .server && validServerInitiated stream then
      return ({ stream with state := .reservedLocal }, .process)
    throw (connectionError .protocolError "invalid local stream reservation")
  | .reserveRemote =>
    if state == .idle && role == .client && validServerInitiated stream then
      return ({ stream with state := .reservedRemote }, .process)
    throw (connectionError .protocolError "invalid remote stream reservation")
  | .reset direction =>
    if state == .idle then throw (connectionError .protocolError "RST_STREAM on idle stream")
    if state == .closed then return (stream, .ignore)
    return ({ stream with state := .closed, locallyReset := direction == .outbound }, .process)
  | .windowUpdate direction =>
    if state == .idle then throw (connectionError .protocolError "WINDOW_UPDATE on idle stream")
    if state == .closed then return (stream, .ignore)
    if (state == .reservedRemote && direction == .inbound) ||
       (state == .reservedLocal && direction == .outbound) then
      throw (connectionError .protocolError "WINDOW_UPDATE in reserved state")
    return (stream, .process)
  | .headers direction endStream =>
    if state == .closed then
      if direction == .inbound && stream.locallyReset then return (stream, .discard)
      if direction == .inbound then throw (connectionError .streamClosed "HEADERS on closed stream")
      throw (streamError stream .streamClosed "cannot send HEADERS on closed stream")
    if state == .idle then
      if !validClientInitiated stream ||
          !((role == .server && direction == .inbound) || (role == .client && direction == .outbound)) then
        throw (connectionError .protocolError "invalid stream initiator")
      let initial := StreamState.open
      return ({ stream with state := if endStream then ended initial direction else initial }, .process)
    if state == .reservedLocal then
      if direction != .outbound then throw (connectionError .protocolError "HEADERS on locally reserved stream")
      let initial := StreamState.halfClosedRemote
      return ({ stream with state := if endStream then ended initial direction else initial }, .process)
    if state == .reservedRemote then
      if direction != .inbound then throw (connectionError .protocolError "HEADERS on remotely reserved stream")
      let initial := StreamState.halfClosedLocal
      return ({ stream with state := if endStream then ended initial direction else initial }, .process)
    if (state == .halfClosedRemote && direction == .inbound) ||
       (state == .halfClosedLocal && direction == .outbound) then
      throw (streamError stream .streamClosed "HEADERS after END_STREAM")
    return ({ stream with state := if endStream then ended state direction else state }, .process)
  | .data direction endStream =>
    if state == .closed then
      if direction == .inbound && stream.locallyReset then return (stream, .discard)
      if direction == .inbound then throw (connectionError .streamClosed "DATA on closed stream")
      throw (streamError stream .streamClosed "cannot send DATA on closed stream")
    if state == .idle || state == .reservedLocal || state == .reservedRemote then
      throw (connectionError .protocolError "DATA on idle or reserved stream")
    if (state == .halfClosedRemote && direction == .inbound) ||
       (state == .halfClosedLocal && direction == .outbound) then
      throw (streamError stream .streamClosed "DATA after END_STREAM")
    return ({ stream with state := if endStream then ended state direction else state }, .process)

/-- Independent connection-level flow-control windows. -/
structure Flow where
  sendWindow : Int := 65535
  recvWindow : Int := 65535
  deriving Repr

/-- Account the full incoming DATA payload, including its padding. The outer
    error is connection-level. On a stream-level error the updated connection
    window is still returned and MUST be retained even when resetting the stream. -/
def Flow.receiveData (flow : Flow) (stream : Stream) (size : Nat) :
    Except ProtocolError (Flow × Except ProtocolError Stream) := do
  let n := Int.ofNat size
  if size > 0 && n > flow.recvWindow then throw (connectionError .flowControlError "connection receive window exceeded")
  let flow := { flow with recvWindow := flow.recvWindow - n }
  if size > 0 && n > stream.recvWindow then
    return (flow, .error (streamError stream .flowControlError "stream receive window exceeded"))
  return (flow, .ok { stream with recvWindow := stream.recvWindow - n })

/-- Reserve outgoing DATA credit. Insufficient credit is ordinary backpressure,
    not a protocol error. An empty END_STREAM is allowed even with negative credit. -/
def Flow.sendData (flow : Flow) (stream : Stream) (size : Nat) (endStream : Bool) : Option (Flow × Stream) :=
  let n := Int.ofNat size
  if size == 0 && endStream then some (flow, stream)
  else if n > flow.sendWindow || n > stream.sendWindow then none
  else some ({ flow with sendWindow := flow.sendWindow - n }, { stream with sendWindow := stream.sendWindow - n })

private def updatedWindow (current : Int) (increment : Nat) (scope : ErrorScope) : Except ProtocolError Int := do
  if increment == 0 || increment > maxWindow then
    throw ⟨.protocolError, scope, "invalid WINDOW_UPDATE increment"⟩
  let next := current + Int.ofNat increment
  if next > Int.ofNat maxWindow then throw ⟨.flowControlError, scope, "flow-control window overflow"⟩
  return next

/-- Apply peer WINDOW_UPDATE to connection sending credit. -/
def Flow.updateSend (flow : Flow) (increment : Nat) : Except ProtocolError Flow := do
  return { flow with sendWindow := ← updatedWindow flow.sendWindow increment .connection }

/-- Apply peer WINDOW_UPDATE to stream sending credit. -/
def Stream.updateSend (stream : Stream) (increment : Nat) : Except ProtocolError Stream := do
  return { stream with sendWindow := ← updatedWindow stream.sendWindow increment (.stream stream.id) }

/-- Apply the delta from a peer SETTINGS_INITIAL_WINDOW_SIZE change. The caller
    applies this to each active stream, and retains no changes if any overflows. -/
def Stream.adjustInitialSend (stream : Stream) (delta : Int) : Except ProtocolError Stream := do
  let next := stream.sendWindow + delta
  if next > Int.ofNat maxWindow then
    throw (connectionError .flowControlError "SETTINGS initial window overflow")
  return { stream with sendWindow := next }

/-- Apply the acknowledged local initial receive-window delta. -/
def Stream.adjustInitialReceive (stream : Stream) (delta : Int) : Except ProtocolError Stream := do
  let next := stream.recvWindow + delta
  if next > Int.ofNat maxWindow then
    throw (connectionError .flowControlError "SETTINGS receive window overflow")
  return { stream with recvWindow := next }

/-- Record advertised local connection receive credit after WINDOW_UPDATE. -/
def Flow.updateReceive (flow : Flow) (increment : Nat) : Except ProtocolError Flow := do
  return { flow with recvWindow := ← updatedWindow flow.recvWindow increment .connection }

/-- Record advertised local stream receive credit after WINDOW_UPDATE. -/
def Stream.updateReceive (stream : Stream) (increment : Nat) : Except ProtocolError Stream := do
  return { stream with recvWindow := ← updatedWindow stream.recvWindow increment (.stream stream.id) }

end LeanNet.HTTP2
