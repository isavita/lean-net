import LeanNet.HTTP2.Connection
import LeanNet.HTTP2.Push
import LeanNet.HTTP1.Encoding

namespace LeanNet.HTTP2.Machine

/-- Protocol actions carry owned bytes and application requests, never sockets. -/
inductive Action where
  | write (parts : Array ByteArray)
  | writeParts (parts : Array WirePart)
  | writeObserved (output : HTTP.ObservedOutput)
  | requestStarted (streamId : UInt32) (head : HTTP1.RequestHead) (startedAt : Nat)
  | responseAborted (streamId : UInt32) (reason : HTTP.ResponseAbortReason)
  | request (event : RequestEvent)
  | drainClose

structure State where
  private connection : Connection
  private config : Connection.Config
  private started : Bool := false
  private closing : Bool := false

structure Step where
  state : State
  consumed : Nat := 0
  actions : List Action := []

inductive Input where
  | start
  | bytes (data : ByteArray) (offset length : Nat)
  | respond (stream : UInt32) (reply : HTTP1.Reply) (pushes : Array Push := #[])
  | drain
  | clock (now timeoutMs : Nat)
  | finish
  | goAway (code : ErrorCode := .noError)
  | date (value : ByteArray)

def State.new (config : Connection.Config := {}) : State :=
  { connection := Connection.newWithConfig config, config }

def State.canRespond (state : State) (id : UInt32) : Bool :=
  !state.closing && state.connection.canRespond id

def State.canPush (state : State) : Bool := !state.closing && state.connection.canPush

def State.canDrain (state : State) : Bool := !state.closing && state.connection.canDrain

def State.hasPendingOutput (state : State) : Bool := state.connection.hasPendingOutput

def State.hasPartialInput (state : State) : Bool := state.connection.hasPartialInput

def State.wantsInput (state : State) : Bool := !state.closing

def State.setTime (state : State) (now : Nat) : State :=
  { state with connection := state.connection.setTime now }

def State.setDate (state : State) (date : ByteArray) : State :=
  { state with connection := state.connection.setDate date }

private def writes (parts : Array ByteArray) : List Action :=
  let parts := parts.filter (fun bytes => !bytes.isEmpty)
  if parts.isEmpty then [] else [.write parts]

private def observedParts (previous current : Connection) (parts : Array WirePart)
    (headerStatus : Nat := 0) (resetReason : HTTP.ResponseAbortReason := .error) :
    Except ProtocolError (List Action) := do
  let mut actions : List Action := []
  let mut index := 0
  for _ in [:parts.size + 1] do
    if index == parts.size then break
    let some (.bytes bytes) := parts[index]? | throw ⟨.internalError, .connection, "unpaired observed file payload"⟩
    index := index + 1
    let mut cursor := 0
    for _ in [:bytes.size + 1] do
      if cursor == bytes.size then break
      if bytes.size - cursor < 9 then throw ⟨.internalError, .connection, "truncated observed frame header"⟩
      let length := bytes[cursor]!.toNat * 65536 + bytes[cursor + 1]!.toNat * 256 + bytes[cursor + 2]!.toNat
      let kind := bytes[cursor + 3]!
      let flags := bytes[cursor + 4]!
      let id := UInt32.ofNat ((bytes[cursor + 5]!.toNat * 16777216 + bytes[cursor + 6]!.toNat * 65536 +
        bytes[cursor + 7]!.toNat * 256 + bytes[cursor + 8]!.toNat) % 2147483648)
      let metadata := (previous.outputMetadata id).orElse (fun _ => current.outputMetadata id)
      let head := metadata.map (·.1)
      let startedAt := (metadata.map (·.2)).getD 0
      let final := (flags &&& 1) != 0
      if kind == 0 && cursor == 0 && bytes.size == 9 && index < parts.size then
        if let some (.file region) := parts[index]? then
          if region.length != length then throw ⟨.internalError, .connection, "observed file length disagrees with DATA header"⟩
          let output : HTTP.ObservedOutput := {
            requestId := id.toNat, parts := #[.bytes bytes, .file region]
            payloadRanges := if length == 0 then #[] else #[(9, length)]
            finalResponse := final, head, startedAt }
          actions := .writeObserved output :: actions
          index := index + 1
          cursor := bytes.size
          continue
      if length > bytes.size - cursor - 9 then throw ⟨.internalError, .connection, "truncated observed frame payload"⟩
      let mut finish := cursor + 9 + length
      if kind == 1 then
        let mut headersDone := (flags &&& 4) != 0
        for _ in [:bytes.size / 9 + 1] do
          if headersDone then break
          if bytes.size - finish < 9 then throw ⟨.internalError, .connection, "truncated observed header continuation"⟩
          let nextLength := bytes[finish]!.toNat * 65536 + bytes[finish + 1]!.toNat * 256 + bytes[finish + 2]!.toNat
          let nextId := UInt32.ofNat ((bytes[finish + 5]!.toNat * 16777216 + bytes[finish + 6]!.toNat * 65536 +
            bytes[finish + 7]!.toNat * 256 + bytes[finish + 8]!.toNat) % 2147483648)
          if bytes[finish + 3]! != 9 || nextId != id || nextLength > bytes.size - finish - 9 then
            throw ⟨.internalError, .connection, "invalid observed header continuation"⟩
          headersDone := (bytes[finish + 4]! &&& 4) != 0
          finish := finish + 9 + nextLength
        if !headersDone then throw ⟨.internalError, .connection, "observed header continuation budget exhausted"⟩
        let output : HTTP.ObservedOutput := {
          requestId := id.toNat, parts := #[.bytes (if cursor == 0 && finish == bytes.size then bytes else bytes.extract cursor finish)]
          finalResponse := final, status := headerStatus, head, startedAt }
        actions := .writeObserved output :: actions
      else if kind == 0 then
        let output : HTTP.ObservedOutput := {
          requestId := id.toNat, parts := #[.bytes (if cursor == 0 && finish == bytes.size then bytes else bytes.extract cursor finish)]
          payloadRanges := if length == 0 then #[] else #[(9, length)]
          finalResponse := final, head, startedAt }
        actions := .writeObserved output :: actions
      else
        actions := .write #[if cursor == 0 && finish == bytes.size then bytes else bytes.extract cursor finish] :: actions
        if kind == 3 then actions := .responseAborted id resetReason :: actions
      cursor := finish
    if cursor != bytes.size then throw ⟨.internalError, .connection, "observed output cursor exhausted"⟩
  if index != parts.size then throw ⟨.internalError, .connection, "observed part budget exhausted"⟩
  return actions.reverse

private def progress (state : State) (connection : Connection)
    (output : Array ByteArray := #[]) (requests : Array RequestEvent := #[])
    (consumed : Nat := 0) (observations : Option (List Action) := none) : Step := Id.run do
  let state := { state with connection }
  let mut requestActions := []
  for request in requests do requestActions := Action.request request :: requestActions
  let actions := observations.getD (writes output) ++ requestActions.reverse
  if connection.draining && connection.drainComplete then
    return { state := { state with closing := true }, consumed, actions := actions ++ [.drainClose] }
  return { state, consumed, actions }

private def fatal (state : State) (error : ProtocolError) (output : Array ByteArray := #[])
    (consumed : Nat := 0) : Step :=
  { state := { state with closing := true }, consumed,
    actions := writes (output.push (state.connection.goAway error)) ++ [.drainClose] }

private def outputStep (state : State) (connection : Connection) (output : Array ByteArray)
    (status : Nat := 0) (reason : HTTP.ResponseAbortReason := .error) : Step :=
  if !state.config.trackOutput then progress state connection output
  else match observedParts state.connection connection (output.map WirePart.bytes) status reason with
    | .ok actions => progress state connection output #[] 0 (some actions)
    | .error error => fatal state error

private def connectionStep (state : State) (result : Connection.Step)
    (reason : HTTP.ResponseAbortReason := .error) : Step := Id.run do
  let mut actions := writes result.output
  if state.config.trackOutput then
    match observedParts state.connection result.connection (result.output.map WirePart.bytes) 100 reason with
    | .error error => return fatal state error
    | .ok output =>
      actions := result.started.toList.map (fun event => .requestStarted event.streamId event.head event.startedAt) ++
        output ++ result.peerResets.toList.map (fun id => .responseAborted id .cancelled)
  -- feedSlice/finish already include the fatal GOAWAY, preserving prior control
  -- output. Closing here must not manufacture a duplicate GOAWAY.
  if result.error.isSome then
    return {
      state := { state with connection := result.connection, closing := true }
      consumed := result.consumed
      actions := actions ++ [.drainClose] }
  return progress state result.connection result.output result.requests result.consumed
    (if state.config.trackOutput then some actions else none)

def State.start (state : State) : Step :=
  if state.started || state.closing then { state }
  else match state.config.validate with
    | .error message => fatal state ⟨.internalError, .connection, message⟩
    | .ok () => { state := { state with started := true }, actions := writes #[state.connection.settingsFrame] }

def State.feedSlice (state : State) (bytes : ByteArray) (offset length : Nat) : Step := Id.run do
  if state.closing then return { state }
  let initial := state.start
  if initial.state.closing then return initial
  let result := connectionStep initial.state (initial.state.connection.feedSlice bytes offset length)
  return { result with actions := initial.actions ++ result.actions }

private def encodeReply (state : State) (id : UInt32) (reply : HTTP1.Reply)
    (pushes : Array Push) : Except ProtocolError (Connection × Array ByteArray × List Action) := do
  let mut connection := state.connection
  let mut output := #[]
  let mut observations := []
  if reply.informational.size > 32 then
    throw ⟨.internalError, .stream id, "too many informational HTTP/2 responses"⟩
  for (response, options) in reply.informational do
    if options.forceClose || !options.trailers.isEmpty then
      throw ⟨.internalError, .stream id, "invalid informational response options"⟩
    let previous := connection
    let (next, wire) ← connection.informational id response
    connection := next
    if state.config.trackOutput then
      observations := observations ++ (← observedParts previous connection #[.bytes wire] response.status)
    if !wire.isEmpty then output := output.push wire
  if connection.canPush then
    for index in [:min 16 pushes.size] do
      let some push := pushes[index]? | continue
      -- A rejected optional push must not terminate its associated response.
      let previous := connection
      match connection.pushPath id push.target push.headers push.response with
      | .error _ => pure ()
      | .ok (next, wire, _) =>
        connection := next
        if state.config.trackOutput then
          observations := observations ++ (← observedParts previous connection #[.bytes wire] push.response.status)
        if !wire.isEmpty then output := output.push wire
  let previous := connection
  let (next, wire) ← match reply.fileRegion with
    | none => connection.queueResponse id reply.response reply.options.trailers
    | some region => connection.queueFileResponse id reply.response region reply.options.trailers
  connection := next
  if state.config.trackOutput then
    observations := observations ++ (← observedParts previous connection #[.bytes wire] reply.response.status)
  if !wire.isEmpty then output := output.push wire
  if reply.options.forceClose then
    let (next, wire) ← connection.beginGoAway .noError
    connection := next
    if state.config.trackOutput then
      observations := observations ++ (← observedParts connection connection #[.bytes wire])
    if !wire.isEmpty then output := output.push wire
  if output.foldl (fun total part => total + part.size) 0 > state.config.maxOutputBatchBytes then
    throw ⟨.internalError, .stream id, "application headers exceed output batch budget"⟩
  return (connection, output, observations)

/-- Application errors become a local 500 response without corrupting HPACK
    state or terminating independent streams. No bytes are committed until the
    complete pure encoding step succeeds. -/
def State.respond (state : State) (id : UInt32) (reply : HTTP1.Reply)
    (pushes : Array Push := #[]) : Step := Id.run do
  if !state.canRespond id then return { state }
  match encodeReply state id reply pushes with
  | .ok (connection, output, observations) =>
    return progress state connection output #[] 0 (if state.config.trackOutput then some observations else none)
  | .error _ =>
    match state.connection.queueResponse id { status := 500 } #[] with
    | .ok (connection, wire) => return outputStep state connection #[wire] 500
    | .error error =>
      if error.scope == .connection then return fatal state error
      match state.connection.cancel id .internalError with
      | .ok (connection, wire) => return outputStep state connection #[wire]
      | .error failure => return fatal state failure

def State.fail (state : State) (error : ProtocolError) : Step :=
  if state.closing then { state } else fatal state error

def State.drain (state : State) : Step :=
  if state.closing then { state }
  else match state.connection.drainParts with
    | .ok (connection, parts) =>
      let result := progress state connection
      if parts.isEmpty then result
      else if state.config.trackOutput then
        match observedParts state.connection connection parts with
        | .ok actions => { result with actions := actions ++ result.actions }
        | .error error => fatal state error
      else if parts.any (fun part => match part with | .file _ => true | _ => false) then
        { result with actions := .writeParts parts :: result.actions }
      else
        let bytes := parts.foldl (fun out part => match part with | .bytes bytes => out.append bytes | _ => out) ByteArray.empty
        { result with actions := writes #[bytes] ++ result.actions }
    | .error error => fatal state error

def State.tick (state : State) (now timeoutMs : Nat) : Step :=
  if state.closing then { state }
  else match state.connection.expireRequests now timeoutMs with
    | .ok (connection, wire) => outputStep state connection #[wire] 0 .timeout
    | .error error => fatal state error

def State.finish (state : State) : Step :=
  if state.closing then { state } else connectionStep state state.connection.finish .cancelled

def State.goAway (state : State) (code : ErrorCode := .noError) : Step :=
  if state.closing then { state }
  else match state.connection.beginGoAway code with
    | .ok (connection, wire) => progress state connection #[wire]
    | .error error => fatal state error

/-- Sans-IO entry point: Bytes → State → Step State (List Action). -/
def step (input : Input) (state : State) : Step :=
  match input with
  | .start => state.start
  | .bytes data offset length => state.feedSlice data offset length
  | .respond stream reply pushes => state.respond stream reply pushes
  | .drain => state.drain
  | .clock now timeoutMs => state.tick now timeoutMs
  | .finish => state.finish
  | .goAway code => state.goAway code
  | .date value => { state := state.setDate value }

end LeanNet.HTTP2.Machine
