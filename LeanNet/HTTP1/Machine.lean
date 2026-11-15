import LeanNet.HTTP1.Parser
import LeanNet.HTTP1.Encoding
import LeanNet.HTTP.ResponseOutput

namespace LeanNet.HTTP1.Machine

structure Config where
  limits : Limits := {}
  parserOptions : Parser.Options := {}
  maxInformational : Nat := 16
  maxFileResponseBytes : Nat := 1024 * 1024 * 1024
  trackOutput : Bool := false

/-- Header decisions are explicit, including the legacy HTTP/1.0 EOF-body
    extension. An override can never replace an explicit Content-Length or TE. -/
inductive HeadDecision where
  | accept (framing : Option BodyFraming := none)
  | reject (reply : Reply)
  | upgrade (reply : Reply)

inductive Action where
  | inspectHead (requestId : Nat) (head : RequestHead) (framing : BodyFraming)
  | request (requestId : Nat) (request : Request)
  | write (outputId : Nat) (parts : Array ByteArray) (waitForWrite : Bool)
  | writeObserved (outputId : Nat) (output : HTTP.ObservedOutput) (waitForWrite : Bool)
  | writeFile (outputId : Nat) (headParts : Array ByteArray) (region : FileRegion) (waitForWrite : Bool)
  | readEnabled (enabled : Bool)
  | drainClose
  | upgraded (head : RequestHead)
  | abort (reason : String)

private inductive Phase where
  | head | body | decide | application | output | upgraded | closing
  deriving BEq

private inductive AfterOutput where
  | body | application | nextRequest | close | upgrade
  deriving BEq

/-- Pure connection state. The driver owns unread input and all output leases;
    the machine never reads a clock, owns a descriptor, or schedules a task. -/
structure State where
  private mk ::
  private config : Config
  private parser : Parser
  private phase : Phase := .head
  private head : Option RequestHead := none
  private framing : BodyFraming := .none
  private requestId : Nat := 1
  private outputId : Nat := 0
  private afterOutput : AfterOutput := .nextRequest
  private ended : Bool := false
  private legacyBody : Bool := false
  private started : Bool := false
  private stopping : Bool := false
  private date : Option ByteArray := none
  private now : Nat := 0
  private requestStartedAt : Nat := 0

structure Step where
  state : State
  consumed : Nat := 0
  actions : List Action := []

def State.new (config : Config := {}) : State :=
  { config, parser := Parser.new config.limits config.parserOptions }

def State.setDate (state : State) (date : ByteArray) : State :=
  { state with date := some date }

/-- The caller supplies monotonic time; this pure machine never reads a clock. -/
def State.setTime (state : State) (now : Nat) : State := { state with now }

def State.startedAt (state : State) : Nat := state.requestStartedAt

def State.wantsInput (state : State) : Bool := state.phase == .head || state.phase == .body
def State.isIdle (state : State) : Bool := state.phase == .head && !state.started
def State.isClosing (state : State) : Bool := state.phase == .closing

private def context (state : State) : EncodeContext :=
  match state.head with
  | none => { date := state.date }
  | some head => { version := (Version.parse? head.version).getD .http11,
                   requestMethod := head.method, requestHeaders := head.headers,
                   date := state.date }

private def abort (state : State) (reason : String) : Step :=
  { state := { state with phase := .closing }, actions := [.readEnabled false, .abort reason] }

private def observation (state : State) (parts : Array WirePart)
    (ranges : Array (Nat × Nat)) (status : Nat) (finalResponse : Bool) : HTTP.ObservedOutput :=
  { requestId := state.requestId, parts, payloadRanges := ranges, status,
    finalResponse, head := state.head, startedAt := state.requestStartedAt }

private def output (state : State) (parts : Array ByteArray) (after : AfterOutput)
    (waitForWrite : Bool) (status : Nat := 0) (finalResponse : Bool := true) : Step :=
  let id := state.outputId + 1
  let action := if state.config.trackOutput then
    Action.writeObserved id (observation state (parts.map WirePart.bytes) #[] status finalResponse) waitForWrite
    else .write id parts waitForWrite
  { state := { state with phase := .output, outputId := id, afterOutput := after },
    actions := [.readEnabled false, action] }

private def outputReply (state : State) (wire : EncodedFileResponse) (after : AfterOutput)
    (waitForWrite : Bool) (status bodyBytes : Nat) : Step := Id.run do
  if !state.config.trackOutput then
    match wire.fileRegion with
    | none => return output state wire.headParts after waitForWrite
    | some region =>
      let id := state.outputId + 1
      return {
        state := { state with phase := .output, outputId := id, afterOutput := after }
        actions := [.readEnabled false, .writeFile id wire.headParts region waitForWrite] }
  let id := state.outputId + 1
  let mut parts := wire.headParts.map WirePart.bytes
  let mut ranges := #[]
  match wire.fileRegion with
  | some region =>
    let wirePrefix := wire.headParts.foldl (fun size bytes => size + bytes.size) 0
    parts := parts.push (.file region)
    if region.length > 0 then ranges := #[(wirePrefix, region.length)]
  | none =>
    if bodyBytes > 0 && state.head.all (fun head => head.method != "HEAD") &&
        status >= 200 && status != 204 && status != 205 && status != 304 then
      let bodyIndex := if wire.framing == .chunked then wire.headParts.size - 3 else wire.headParts.size - 1
      let wirePrefix := (wire.headParts.extract 0 bodyIndex).foldl (fun size bytes => size + bytes.size) 0
      ranges := #[(wirePrefix, bodyBytes)]
  return {
    state := { state with phase := .output, outputId := id, afterOutput := after }
    actions := [.readEnabled false, .writeObserved id (observation state parts ranges status true) waitForWrite] }

/-- True once graceful shutdown began; new upgrades are no longer accepted. -/
def State.isStopping (state : State) : Bool := state.stopping

private def fail (state : State) (status : Nat) : Step :=
  let response : Response := { status }
  match response.encodeFor (context state) { forceClose := true } with
  | .error reason => abort state reason
  | .ok wire => output state wire.parts .close false status

private def expectation (head : RequestHead) : Option Bool := Id.run do
  if head.version == "HTTP/1.0" then return none
  let mut seen := false
  for header in head.headers do
    if header.name.toLower == "expect" then
      seen := true
      let some value := String.fromUTF8? header.value | return some false
      for item in value.splitOn "," do
        if item.trimAscii.toString.toLower != "100-continue" then return some false
  return if seen then some true else none

private def hasBody : BodyFraming → Bool
  | .none | .contentLength 0 => false
  | _ => true

/-- Consume a bounded range and stop at the next application decision. No
    pipeline remainder is copied; `consumed` is relative to the supplied start. -/
def State.feedSlice (state : State) (bytes : ByteArray) (start length : Nat) : Step :=
  let state := if state.config.trackOutput && state.phase == .head && !state.started && length > 0 then
    { state with requestStartedAt := state.now } else state
  if !state.wantsInput then { state }
  else
    match state.parser.feedSlice bytes start length with
    | .needMore parser consumed =>
      { state := { state with parser, started := state.started || consumed > 0 }, consumed }
    | .head head framing parser consumed =>
      { state := { state with parser, head := some head, framing, phase := .decide, started := true },
        consumed, actions := [.readEnabled false, .inspectHead state.requestId head framing] }
    | .complete request consumed =>
      { state := { state with phase := .application, started := true,
                              parser := Parser.new state.config.limits state.config.parserOptions }, consumed,
        actions := [.readEnabled false, .request state.requestId request] }
    | .error message consumed => { (fail state (Parser.errorStatus message)) with consumed }

def State.feed (state : State) (bytes : ByteArray) : Step :=
  state.feedSlice bytes 0 bytes.size

/-- Call only after all driver-retained input has been offered to the machine.
    EOF during a decision/output barrier is remembered until it can be applied. -/
def State.finish (state : State) : Step :=
  let state := { state with ended := true }
  if state.wantsInput then
    match state.parser.finish with
    | .complete request _ =>
      { state := { state with phase := .application,
                              parser := Parser.new state.config.limits state.config.parserOptions },
        actions := [.readEnabled false, .request state.requestId request] }
    | .eof => { state := { state with phase := .closing }, actions := [.drainClose] }
    | .error message => fail state (Parser.errorStatus message)
    | .needMore _ => abort state "invalid parser EOF result"
  else { state }

private def encodeReply (state : State) (reply : Reply) : Except String EncodedFileResponse := do
  if reply.informational.size > state.config.maxInformational then throw "too many informational responses"
  let ctx := context state
  let mut parts := #[]
  for (response, options) in reply.informational do
    let encoded ← response.encodeFor ctx options
    if encoded.next != .informational then throw "expected informational response"
    parts := parts ++ encoded.parts
  let options := { reply.options with forceClose :=
    reply.options.forceClose || state.ended || state.legacyBody || state.stopping }
  let encoded ← match reply.fileRegion with
    | some region =>
      if region.length > state.config.maxFileResponseBytes then throw "file response exceeds configured limit"
      reply.response.encodeFileFor region ctx options
    | none => do
      let encoded ← reply.response.encodeFor ctx options
      pure { headParts := encoded.parts, framing := encoded.framing, next := encoded.next }
  match encoded.next with
  | .nextRequest _ => return { encoded with headParts := parts ++ encoded.headParts }
  | _ => throw "application reply must contain a final response"

/-- Decide before body bytes are consumed, even when they arrived with the head. -/
def State.decideHead (state : State) (requestId : Nat) (decision : HeadDecision) : Step :=
  if state.phase != .decide || requestId != state.requestId then abort state "unexpected HTTP head decision"
  else match state.head with
  | none => abort state "missing HTTP request head"
  | some head =>
    match decision with
    | .reject reply =>
      if reply.response.status < 200 then fail state 500
      else match encodeReply state { reply with options := { reply.options with forceClose := true } } with
        | .error _ => fail state 500
        | .ok wire => outputReply state wire .close false reply.response.status reply.response.body.size
    | .upgrade reply =>
      if state.stopping then fail state 503
      else if hasBody state.framing || !reply.informational.isEmpty || reply.fileRegion.isSome then fail state 400
      else match reply.response.encodeAcceptedUpgrade (context state) reply.options with
        | .error _ => fail state 400
        | .ok wire => output state wire.parts .upgrade true 101 true
    | .accept override =>
      if expectation head == some false then fail state 417
      else
        let framing := override.getD state.framing
        match state.parser.resumeBody framing with
        | .error _ => fail state 400
        | .ok parser =>
          let state : State := { state with parser, framing, phase := .body,
                                             legacyBody := framing == BodyFraming.closeDelimited }
          if state.ended then state.finish
          else if expectation head == some true && hasBody framing then
            let interim : Response := { status := 100 }
            match interim.encodeFor (context state) with
            | .error _ => fail state 500
            | .ok wire => output state wire.parts .body true 100 false
          else { state, actions := [.readEnabled true] }

/-- Supply exactly one final response for the outstanding request. Framing and
    application errors produce a bounded 500 and close this connection. -/
def State.respond (state : State) (requestId : Nat) (reply : Reply) : Step :=
  if state.phase != .application || requestId != state.requestId then abort state "unexpected HTTP response"
  else match encodeReply state reply with
    | .error _ => fail state 500
    | .ok wire =>
      match wire.next with
      | .nextRequest .keepAlive => outputReply state wire .nextRequest false reply.response.status reply.response.body.size
      | .nextRequest .close => outputReply state wire .close false reply.response.status reply.response.body.size
      | _ => fail state 500

/-- A final response is acknowledged after all its parts enter the ordered
    native write queue. Continue/upgrade barriers require actual write completion. -/
def State.outputAccepted (state : State) (outputId : Nat) : Step :=
  if outputId < state.outputId then { state }
  else if state.phase != .output || outputId != state.outputId then abort state "unexpected HTTP output acknowledgement"
  else match state.afterOutput with
    | .body =>
      let state := { state with phase := .body }
      if state.ended then state.finish else { state, actions := [.readEnabled true] }
    | .application => { state := { state with phase := .application } }
    | .close => { state := { state with phase := .closing }, actions := [.drainClose] }
    | .upgrade =>
      match state.head with
      | none => abort state "missing upgraded request head"
      | some head => { state := { state with phase := .upgraded }, actions := [.upgraded head] }
    | .nextRequest =>
      if state.ended || state.stopping then { state := { state with phase := .closing }, actions := [.drainClose] }
      else
        { state := { state with parser := Parser.new state.config.limits state.config.parserOptions,
                                phase := .head, head := none, framing := .none,
                                requestId := state.requestId + 1, legacyBody := false, started := false },
          actions := [.readEnabled true] }

/-- Stop admitting requests while finishing the current request and already
    selected response. The transport owns the absolute drain deadline. -/
def State.shutdown (state : State) : Step :=
  let state := { state with stopping := true }
  if state.isIdle || state.phase == .upgraded then
    { state := { state with phase := .closing }, actions := [.readEnabled false, .drainClose] }
  else if state.phase == .output &&
      (state.afterOutput == .nextRequest || state.afterOutput == .upgrade) then
    { state := { state with afterOutput := .close } }
  else { state }

inductive Timeout where
  | idle | request | write

def State.timeout (state : State) : Timeout → Step
  | .idle => if state.isIdle then abort state "HTTP idle timeout" else { state }
  | .request =>
    if state.started && (state.wantsInput || state.phase == .decide ||
        (state.phase == .output && state.afterOutput == .body)) then fail state 408
    else { state }
  | .write => abort state "HTTP write timeout"

inductive Input where
  | shutdown
  | bytes (data : ByteArray) (start length : Nat)
  | eof
  | headDecision (requestId : Nat) (decision : HeadDecision)
  | response (requestId : Nat) (reply : Reply)
  | outputAccepted (outputId : Nat)
  | timeout (kind : Timeout)
  | date (value : ByteArray)

/-- Sans-IO transition entry point. The action list describes work for a
    transport adapter; it performs no IO itself. -/
def step (input : Input) (state : State) : Step :=
  match input with
  | .shutdown => state.shutdown
  | .bytes bytes start length => state.feedSlice bytes start length
  | .eof => state.finish
  | .headDecision id decision => state.decideHead id decision
  | .response id reply => state.respond id reply
  | .outputAccepted id => state.outputAccepted id
  | .timeout kind => state.timeout kind
  | .date date => { state := state.setDate date }

end LeanNet.HTTP1.Machine
