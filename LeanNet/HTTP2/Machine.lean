import LeanNet.HTTP2.Connection
import LeanNet.HTTP2.Push
import LeanNet.HTTP1.Encoding

namespace LeanNet.HTTP2.Machine

/-- Protocol actions carry owned bytes and application requests, never sockets. -/
inductive Action where
  | write (parts : Array ByteArray)
  | writeParts (parts : Array WirePart)
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

private def progress (state : State) (connection : Connection)
    (output : Array ByteArray := #[]) (requests : Array RequestEvent := #[])
    (consumed : Nat := 0) : Step := Id.run do
  let state := { state with connection }
  let mut requestActions := []
  for request in requests do requestActions := Action.request request :: requestActions
  let actions := writes output ++ requestActions.reverse
  if connection.draining && connection.drainComplete then
    return { state := { state with closing := true }, consumed, actions := actions ++ [.drainClose] }
  return { state, consumed, actions }

private def fatal (state : State) (error : ProtocolError) (output : Array ByteArray := #[])
    (consumed : Nat := 0) : Step :=
  { state := { state with closing := true }, consumed,
    actions := writes (output.push (state.connection.goAway error)) ++ [.drainClose] }

private def connectionStep (state : State) (result : Connection.Step) : Step :=
  -- feedSlice/finish already include the fatal GOAWAY, preserving prior control
  -- output. Closing here must not manufacture a duplicate GOAWAY.
  if result.error.isSome then
    { state := { state with connection := result.connection, closing := true }, consumed := result.consumed,
      actions := writes result.output ++ [.drainClose] }
  else progress state result.connection result.output result.requests result.consumed

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
    (pushes : Array Push) : Except ProtocolError (Connection × Array ByteArray) := do
  let mut connection := state.connection
  let mut output := #[]
  if reply.informational.size > 32 then
    throw ⟨.internalError, .stream id, "too many informational HTTP/2 responses"⟩
  for (response, options) in reply.informational do
    if options.forceClose || !options.trailers.isEmpty then
      throw ⟨.internalError, .stream id, "invalid informational response options"⟩
    let (next, wire) ← connection.informational id response
    connection := next
    if !wire.isEmpty then output := output.push wire
  if connection.canPush then
    for index in [:min 16 pushes.size] do
      let some push := pushes[index]? | continue
      -- A rejected optional push must not terminate its associated response.
      match connection.pushPath id push.target push.headers push.response with
      | .error _ => pure ()
      | .ok (next, wire, _) =>
        connection := next
        if !wire.isEmpty then output := output.push wire
  let (next, wire) ← match reply.fileRegion with
    | none => connection.queueResponse id reply.response reply.options.trailers
    | some region => connection.queueFileResponse id reply.response region reply.options.trailers
  connection := next
  if !wire.isEmpty then output := output.push wire
  if reply.options.forceClose then
    let (next, wire) ← connection.beginGoAway .noError
    connection := next
    if !wire.isEmpty then output := output.push wire
  if output.foldl (fun total part => total + part.size) 0 > state.config.maxOutputBatchBytes then
    throw ⟨.internalError, .stream id, "application headers exceed output batch budget"⟩
  return (connection, output)

/-- Application errors become a local 500 response without corrupting HPACK
    state or terminating independent streams. No bytes are committed until the
    complete pure encoding step succeeds. -/
def State.respond (state : State) (id : UInt32) (reply : HTTP1.Reply)
    (pushes : Array Push := #[]) : Step := Id.run do
  if !state.canRespond id then return { state }
  match encodeReply state id reply pushes with
  | .ok (connection, output) => return progress state connection output
  | .error _ =>
    match state.connection.queueResponse id { status := 500 } #[] with
    | .ok (connection, wire) => return progress state connection #[wire]
    | .error error =>
      if error.scope == .connection then return fatal state error
      match state.connection.cancel id .internalError with
      | .ok (connection, wire) => return progress state connection #[wire]
      | .error failure => return fatal state failure

def State.fail (state : State) (error : ProtocolError) : Step :=
  if state.closing then { state } else fatal state error

def State.drain (state : State) : Step :=
  if state.closing then { state }
  else match state.connection.drainParts with
    | .ok (connection, parts) =>
      let result := progress state connection
      if parts.isEmpty then result
      else if parts.any (fun part => match part with | .file _ => true | _ => false) then
        { result with actions := .writeParts parts :: result.actions }
      else
        let bytes := parts.foldl (fun out part => match part with | .bytes bytes => out.append bytes | _ => out) ByteArray.empty
        { result with actions := writes #[bytes] ++ result.actions }
    | .error error => fatal state error

def State.tick (state : State) (now timeoutMs : Nat) : Step :=
  if state.closing then { state }
  else match state.connection.expireRequests now timeoutMs with
    | .ok (connection, wire) => progress state connection #[wire]
    | .error error => fatal state error

def State.finish (state : State) : Step :=
  if state.closing then { state } else connectionStep state state.connection.finish

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
