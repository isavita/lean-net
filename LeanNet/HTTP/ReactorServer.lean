import Std.Data.HashMap
import LeanNet.Reactor.Basic
import LeanNet.HTTP1.Handlers
import LeanNet.HTTP2.Machine
import LeanNet.HTTP.WorkerPool
import LeanNet.HTTP.Transport
import LeanNet.HTTP.Observability
import LeanNet.HTTP.SecureHeaders
import LeanNet.HTTP.Admin

namespace LeanNet.HTTP

open HTTP1

structure ReactorServerConfig where
  server : ServerConfig := {}
  machine : Machine.Config := {}
  native : Reactor.Config := {}
  workers : Nat := 0
  outputBuffers : Nat := 128
  maxInputBytes : Nat := 2 * 1024 * 1024 + 65536
  maxOutputBytes : Nat := 16 * 1024 * 1024
  maxQueuedFileBytes : Nat := 4 * 1024 * 1024 * 1024
  workPerClient : Nat := 64
  http2 : HTTP2.Connection.Config := {}
  cleartextProtocol : Transport.Protocol := .detect
  shutdownDrainMs : Nat := 2000
  metricsPath : Option ByteArray := none
  accessLog : Option Observability.AccessConfig := none
  /-- Run on worker 0's loop after each SIGHUP (POSIX). TLS servers request a
      certificate reload here; applications can also swap routing tables or
      rate limits held in shared, thread-safe references. Must not block. -/
  onReload : IO Unit := pure ()
  /-- OWASP default response headers; HSTS is added on TLS transports only. -/
  securityHeaders : SecurityHeaders := {}
  /-- Serve `/healthz` (liveness, always 200) and `/readyz` (readiness: 503
      once draining starts) on every listener. Like the metrics path, these
      bypass application callbacks and are excluded from request metrics. -/
  healthPaths : Bool := false
  /-- Local-only (127.0.0.1) admin port with connection, request and memory
      statistics as JSON plus Prometheus metrics. -/
  adminPort : Option UInt16 := none
  /-- Pin each worker thread to one CPU of the process's allowed set. -/
  pinWorkers : Bool := false

namespace ReactorServer

private def preface : ByteArray := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toUTF8

private inductive Protocol where
  | detect (matched : Nat)
  | http1 (machine : Machine.State)
  | http2 (machine : HTTP2.Machine.State)
  | raw

private structure InputChunk where
  view : ByteSlice
  release : IO Unit := pure ()
  arrived : UInt64 := 0

private inductive OutputPart where
  | bytes (view : ByteSlice)
  | file (region : FileRegion)

private def OutputPart.length : OutputPart → Nat
  | .bytes view => view.length
  | .file region => region.length

private def OutputPart.drop (part : OutputPart) (count : Nat) : OutputPart :=
  match part with
  | .bytes view => .bytes (view.drop count)
  | .file region => .file (region.drop count)

private structure OutputObservation where
  requestId : Nat
  payloadRanges : Array (Nat × Nat)
  offset : Nat := 0
  finalResponse : Bool

private def OutputObservation.overlap (output : OutputObservation) (length : Nat) : Nat :=
  output.payloadRanges.foldl (fun size range => size +
    (min (output.offset + length) (range.1 + range.2) - max output.offset range.1)) 0

private structure Output where
  parts : List OutputPart
  id : Option Nat := none
  barrier : Bool := false
  started : UInt64
  observation : Option OutputObservation := none
  pingNonce : Option UInt64 := none

private structure FlightObservation where
  requestId : Nat
  payloadBytes : Nat

private structure Flight where
  owner : Reactor.SocketId
  operation : UInt64
  outputId : Option Nat
  barrier : Bool
  last : Bool
  started : UInt64
  length : Nat
  observation : Option FlightObservation := none
  accounted : Bool := false
  pingNonce : Option UInt64 := none

private structure OutputSlot where
  buffer : Reactor.Buffer
  generation : UInt64 := 0
  flight : Option Flight := none

private structure RequestObservation where
  protocol : Observability.Protocol
  method : ByteArray
  methodClass : Observability.Method
  target : ByteArray
  startedAt : UInt64
  status : Nat := 0
  payloadSent : UInt64 := 0
  pendingOutputs : Nat := 0
  finalQueued : Bool := false
  outcome : Option Observability.Outcome := none
  counted : Bool := true

private structure Client where
  socket : Transport.Endpoint
  protocol : Protocol := .detect 0
  inputFront : List InputChunk := []
  inputBack : List InputChunk := []
  inputBytes : Nat := 0
  outputs : List Output := []
  outputBytes : Nat := 0
  queuedFileBytes : Nat := 0
  inFlight : Nat := 0
  pipe : Option RawPipe := none
  peerEOF : Bool := false
  finishSent : Bool := false
  kick : Bool := true
  closing : Bool := false
  reading : Bool := true
  closeWhenQueued : Bool := false
  idleDeadline : Option UInt64 := none
  requestDeadline : Option UInt64 := none
  writeDeadline : Option UInt64 := none
  pingDeadline : Option UInt64 := none
  requests : Std.HashMap Nat RequestObservation := {}
  resetCounted : Bool := false
  retired : Bool := false
  retirementOutcome : Option Observability.Outcome := none

private structure WorkerState where
  clients : Std.HashMap Reactor.SocketId Client := {}
  slots : Array OutputSlot := #[]
  now : UInt64 := 0
  dateSecond : UInt64 := 0
  date : ByteArray := ByteArray.empty
  roundRobin : Nat := 0
  writeBlocked : Bool := false
  counters : Observability.Counters := {}
  publishedAt : UInt64 := 0
  wallAt : UInt64 := 0
  wallUnixMs : UInt64 := 0
  draining : Bool := false

private structure WorkerObserver where
  hub : Observability.Hub
  lane : Observability.Lane

private structure Driver where
  reactor : Reactor.Reactor
  group : Reactor.Group
  config : ReactorServerConfig
  handlers : Handlers
  transport : Transport.Worker
  clientLimit : Nat
  state : IO.Ref WorkerState
  observer : Option WorkerObserver := none
  resetErrno : Int := 0
  /-- Worker 0 serves process-level control: SIGHUP reload requests. -/
  control : Bool := false
  reloadSeen : IO.Ref UInt64

private def Driver.client? (driver : Driver) (id : Reactor.SocketId) : IO (Option Client) := do
  return (← driver.state.get).clients[id]?

private def Driver.put (driver : Driver) (id : Reactor.SocketId) (client : Client) : IO Unit :=
  driver.state.modify fun state => { state with clients := state.clients.insert id client }

/-- Release every independent owner even when an earlier cleanup fails. -/
private def cleanupActions (actions : Array (IO Unit)) : IO Unit := do
  let mut errors : Array IO.Error := #[]
  for action in actions do
    try action catch error => errors := errors.push error
  if errors.size == 1 then throw errors[0]!
  if !errors.isEmpty then
    throw (IO.userError (String.intercalate "; " (errors.toList.map toString)))

private def targetPath (target : ByteArray) : ByteArray :=
  let stop := (target.data.findIdx? (fun byte => byte == 63)).getD target.size
  target.extract 0 stop

private inductive HealthProbe where
  | liveness | readiness

private def healthTarget (driver : Driver) (target : ByteArray) : Option HealthProbe :=
  if !driver.config.healthPaths then none else
  let path := targetPath target
  if path == "/healthz".toUTF8 then some .liveness
  else if path == "/readyz".toUTF8 then some .readiness
  else none

/-- Server-owned endpoints: metrics and health probes bypass application
    callbacks and are excluded from request counters and access logs. -/
private def metricTarget (driver : Driver) (target : ByteArray) : Bool :=
  (healthTarget driver target).isSome ||
  match driver.config.metricsPath with
  | none => false
  | some path => targetPath target == path

private def Driver.startObservation (driver : Driver) (id : Reactor.SocketId)
    (requestId : Nat) (head : Option RequestHead) (startedAt : Nat) : IO Bool := do
  let some client ← driver.client? id | return false
  if client.retired then return false
  if driver.observer.isNone then return true
  if let .http2 _ := client.protocol then
    if requestId == 0 || requestId % 2 == 0 then return true
  if client.requests.contains requestId then return true
  if client.requests.size >= 4096 then return false
  let state ← driver.state.get
  let method := (head.map (·.method)).getD ""
  let target := (head.map (·.target)).getD ByteArray.empty
  let protocol := match client.protocol with
    | .http2 _ => Observability.Protocol.http2
    | _ => if head.any (fun value => value.version == "HTTP/1.0") then .http10 else .http11
  let request : RequestObservation := {
    protocol, method := method.toUTF8.extract 0 33,
    methodClass := Observability.Method.classify method, target := target.extract 0 257,
    startedAt := if startedAt == 0 then state.now else startedAt.toUInt64,
    counted := !metricTarget driver target }
  driver.put id { client with requests := client.requests.insert requestId request }
  if request.counted then driver.state.modify fun state => { state with counters := state.counters.requestStarted }
  return true

private def Driver.finishObservation (driver : Driver) (id : Reactor.SocketId) (requestId : Nat) : IO Unit := do
  let some observer := driver.observer | return
  let some client ← driver.client? id | return
  let some request := client.requests[requestId]? | return
  if request.pendingOutputs != 0 || (!request.finalQueued && request.outcome.isNone) then return
  let state ← driver.state.get
  let outcome := request.outcome.getD .completed
  let duration := (state.now - request.startedAt).toNat * 1000
  driver.put id { client with requests := client.requests.erase requestId }
  if !request.counted then return
  driver.state.modify fun state => { state with
    counters := state.counters.requestFinished request.protocol request.methodClass request.status outcome duration.toUInt64 }
  let _ ← observer.lane.emit {
    timestampUnixMs := state.wallUnixMs + (state.now - state.wallAt),
    durationUs := duration.toUInt64, bytesSent := request.payloadSent,
    status := request.status.toUInt32, protocol := request.protocol,
    method := request.method, target := request.target, outcome }
  pure ()

private def Driver.abortObservation (driver : Driver) (id : Reactor.SocketId)
    (requestId : Nat) (outcome : Observability.Outcome) : IO Unit := do
  let some client ← driver.client? id | return
  let some request := client.requests[requestId]? | return
  driver.put id { client with requests := client.requests.insert requestId { request with outcome := some outcome } }
  driver.finishObservation id requestId

/-- A transport close cancels outstanding work. Historical completions still
    reclaim leases, but cannot resurrect the removed protocol connection. -/
private def Driver.closeObservations (driver : Driver) (id : Reactor.SocketId)
    (outcome : Observability.Outcome) : IO Unit := do
  if driver.observer.isNone then return
  let some client ← driver.client? id | return
  let actions := client.requests.toArray.map fun (requestId, _) => do
    if let some current ← driver.client? id then
      if let some request := current.requests[requestId]? then
        let request := { request with pendingOutputs := 0, outcome := some (request.outcome.getD outcome) }
        driver.put id { current with requests := current.requests.insert requestId request }
        driver.finishObservation id requestId
  cleanupActions (actions.push (driver.state.modify fun state =>
    { state with counters := state.counters.connectionClosed }))

private def normalizedInput (client : Client) : Client :=
  if client.inputFront.isEmpty then
    { client with inputFront := client.inputBack.reverse, inputBack := [] }
  else client

private def releaseInput (client : Client) : IO Unit := do
  cleanupActions ((client.inputFront ++ client.inputBack).toArray.map (·.release))

private def Driver.consume (driver : Driver) (id : Reactor.SocketId) (count : Nat) : IO Unit := do
  let some current ← driver.client? id | return
  let client := normalizedInput current
  match client.inputFront with
  | [] =>
    if count != 0 then throw (IO.userError "HTTP input cursor exceeds retained bytes")
  | chunk :: rest =>
    if count > chunk.view.length then throw (IO.userError "HTTP input cursor exceeds retained slice")
    if count == chunk.view.length then
      driver.put id { client with inputFront := rest, inputBytes := client.inputBytes - count }
      chunk.release
    else
      driver.put id { client with
        inputFront := ({ chunk with view := chunk.view.drop count } :: rest)
        inputBytes := client.inputBytes - count }

private def Driver.setReading (driver : Driver) (id : Reactor.SocketId) (enabled : Bool) : IO Unit := do
  let some client ← driver.client? id | return
  if client.retired then return
  let enabled := enabled && !client.peerEOF && !client.closing
  if client.reading != enabled then
    client.socket.setReadEnabled enabled
    driver.put id { client with reading := enabled }

private def Driver.forget (driver : Driver) (id : Reactor.SocketId) : IO Unit := do
  let some client ← driver.client? id | return
  cleanupActions #[
    driver.closeObservations id (client.retirementOutcome.getD .error),
    driver.state.modify fun state => { state with clients := state.clients.erase id },
    releaseInput client,
    (do if let some pipe := client.pipe then try pipe.onClose catch _ => pure ())]

/-- Stop protocol work and return input loans immediately. An asynchronous
    provider may still deliver already-satisfied write fences before CLOSED;
    those fences retain their request metadata and reserved output slots. -/
private def Driver.retire (driver : Driver) (id : Reactor.SocketId)
    (outcome : Observability.Outcome := .error) : IO Unit := do
  let some client ← driver.client? id | return
  if client.retired then return
  driver.put id { client with
    retired := true, retirementOutcome := some outcome, closing := true, reading := false,
    protocol := .raw, pipe := none, inputFront := [], inputBack := [], inputBytes := 0,
    outputs := [], outputBytes := 0, queuedFileBytes := 0,
    idleDeadline := none, requestDeadline := none, writeDeadline := none, pingDeadline := none }
  cleanupActions #[
    releaseInput client,
    (do if let some pipe := client.pipe then try pipe.onClose catch _ => pure ())]

private def Driver.nativeGone (driver : Driver) (id : Reactor.SocketId) : IO Unit :=
  if driver.transport.deferClosed then driver.retire id else driver.forget id

private def Driver.closeNow (driver : Driver) (id : Reactor.SocketId)
    (outcome : Observability.Outcome := .error) : IO Unit := do
  let some client ← driver.client? id | return
  if client.retired then return
  if driver.transport.deferClosed then
    cleanupActions #[driver.retire id outcome, client.socket.close]
  else
    driver.put id { client with retirementOutcome := some outcome }
    cleanupActions #[driver.forget id, client.socket.close]

private def Driver.now (driver : Driver) : IO UInt64 := do return (← driver.state.get).now

private def deadline (now : UInt64) (duration : Nat) : IO UInt64 := do
  let result := now.toNat + duration
  if result > 9223372036854775807 then throw (IO.userError "HTTP timeout exceeds native clock range")
  return UInt64.ofNat result

private def Driver.cancelRequest (driver : Driver) (id : Reactor.SocketId) : IO Unit := do
  unless ← id.isLive driver.reactor do
    driver.nativeGone id
    return
  let some client ← driver.client? id | return
  if client.retired then return
  if client.requestDeadline.isSome then
    client.socket.cancelTimer 1
    driver.put id { client with requestDeadline := none }

private def Driver.syncWriteTimer (driver : Driver) (id : Reactor.SocketId) : IO Unit := do
  unless ← id.isLive driver.reactor do
    driver.nativeGone id
    return
  let state ← driver.state.get
  let some client := state.clients[id]? | return
  if client.retired then return
  -- Outputs are appended in monotonic start order. Only the queue head can
  -- precede an in-flight write; walking every queued response adds no evidence.
  let mut earliest := client.outputs.head?.map (·.started)
  for slot in state.slots do
    if let some flight := slot.flight then
      if flight.owner == id then
        earliest := some (min (earliest.getD flight.started) flight.started)
  let wanted ← match earliest with
    | none => pure none
    | some start => some <$> deadline start driver.config.server.writeTimeoutMs
  if wanted != client.writeDeadline then
    match wanted with
    | none => client.socket.cancelTimer 2
    | some value => client.socket.armTimer 2 value
    driver.put id { client with writeDeadline := wanted }
  let some client ← driver.client? id | return
  if earliest.isSome then
    if client.idleDeadline.isSome then
      client.socket.cancelTimer 0
      driver.put id { client with idleDeadline := none }
  else if !client.closing && client.idleDeadline.isNone then
    let value ← deadline state.now driver.config.server.idleTimeoutMs
    client.socket.armTimer 0 value
    driver.put id { client with idleDeadline := some value }

private def limitedReply (config : ReactorServerConfig) (reply : Reply) : Reply := Id.run do
  let mut count := 0
  let mut bytes := 0
  let mut valid : Bool := reply.informational.size <= config.machine.maxInformational
  if let some region := reply.fileRegion then
    valid := valid && region.valid && region.length <= config.server.maxFileResponseBytes && reply.response.body.isEmpty
  for (response, options) in reply.informational.push (reply.response, reply.options) do
    valid := valid && response.body.size <= config.server.maxResponseBytes
    count := count + response.headers.size + options.trailers.size
    for header in response.headers ++ options.trailers do
      bytes := bytes + header.name.toUTF8.size + header.value.size + 4
    if let some reason := options.reason then bytes := bytes + reason.toUTF8.size
    if let some (.contentLength length) := options.framing then
      valid := valid && length <= 18446744073709551615
  valid := valid && count <= config.server.maxResponseHeaders && bytes <= config.server.maxResponseHeaderBytes
  if valid then return reply
  return { response := { status := 500 }, options := { forceClose := true } }

private def Driver.appendParts (driver : Driver) (id : Reactor.SocketId)
    (parts : Array OutputPart) (outputId : Option Nat := none) (barrier : Bool := false)
    (observation : Option OutputObservation := none) (pingNonce : Option UInt64 := none) : IO Unit := do
  let some client ← driver.client? id | return
  if client.closing then return
  if parts.size > 4096 then driver.closeNow id; return
  let parts := parts.filter (fun part => part.length != 0)
  let bytes := parts.foldl (fun total part => total + match part with | .bytes view => view.length | .file _ => 0) 0
  let files := parts.foldl (fun total part => total + match part with | .file region => region.length | .bytes _ => 0) 0
  if bytes > driver.config.maxOutputBytes - client.outputBytes then driver.closeNow id; return
  if files > driver.config.maxQueuedFileBytes - client.queuedFileBytes then driver.closeNow id; return
  if parts.isEmpty then return
  let output : Output := { parts := parts.toList, id := outputId, barrier, started := ← driver.now, observation, pingNonce }
  let requests := match observation with
    | none => client.requests
    | some value => client.requests.modify value.requestId fun request =>
      { request with pendingOutputs := request.pendingOutputs + 1,
                     finalQueued := request.finalQueued || value.finalResponse }
  driver.put id { client with outputs := client.outputs ++ [output], outputBytes := client.outputBytes + bytes,
                              queuedFileBytes := client.queuedFileBytes + files, requests }
  -- Appending newer output cannot move an existing absolute deadline. Start
  -- the timer only on the transition from no pending writes to pending writes.
  if client.writeDeadline.isNone then driver.syncWriteTimer id

private def Driver.appendOutput (driver : Driver) (id : Reactor.SocketId)
    (parts : Array ByteSlice) (outputId : Option Nat := none) (barrier : Bool := false) : IO Unit :=
  driver.appendParts id (parts.map OutputPart.bytes) outputId barrier

private def Driver.appendObserved (driver : Driver) (id : Reactor.SocketId)
    (output : ObservedOutput) (outputId : Option Nat := none) (barrier : Bool := false) : IO Unit := do
  if !output.valid then throw (IO.userError "invalid protocol output observation")
  if !(← driver.startObservation id output.requestId output.head output.startedAt) then
    driver.closeNow id
    return
  let some client ← driver.client? id | return
  let observation := if client.requests.contains output.requestId then
    some { requestId := output.requestId, payloadRanges := output.payloadRanges,
           finalResponse := output.finalResponse : OutputObservation } else none
  if output.status >= 200 || output.status == 101 then
    let requests := client.requests.modify output.requestId fun request =>
      { request with
        status := output.status
        outcome := if output.status == 408 then some .timeout else request.outcome }
    driver.put id { client with requests }
  let parts := output.parts.map fun
    | .bytes bytes => OutputPart.bytes (ByteSlice.full bytes)
    | .file region => .file region
  driver.appendParts id parts outputId barrier observation

private def Driver.beginDrain (driver : Driver) (id : Reactor.SocketId) : IO Unit := do
  let some client ← driver.client? id | return
  if client.closing then return
  if !client.outputs.isEmpty then
    driver.put id { client with closeWhenQueued := true }
  else
    driver.setReading id false
    let some client ← driver.client? id | return
    driver.put id { client with closing := true }
    client.socket.closeAfterWrites

private def Driver.reply (driver : Driver) (request : Request) : IO Reply := do
  if let some probe := healthTarget driver request.target then
    if request.method != "GET" && request.method != "HEAD" then
      return { response := { status := 405, headers := #[{ name := "allow", value := "GET, HEAD".toUTF8 }] } }
    let draining := (← driver.state.get).draining || (← driver.group.stopping)
    let (status, body) := match probe with
      | .liveness => (200, "ok\n")
      | .readiness => if draining then (503, "draining\n") else (200, "ready\n")
    return { response := { status, body := body.toUTF8, headers := #[
      { name := "content-type", value := "text/plain; charset=utf-8".toUTF8 },
      { name := "cache-control", value := "no-store".toUTF8 }] } }
  if metricTarget driver request.target then
    if request.method != "GET" && request.method != "HEAD" then
      return { response := { status := 405, headers := #[{ name := "Allow", value := "GET, HEAD".toUTF8 }] } }
    let some observer := driver.observer | throw (IO.userError "metrics endpoint has no observer")
    observer.lane.publish (← driver.state.get).counters
    observer.hub.check
    let snapshot ← observer.hub.snapshot
    return { response := {
      headers := #[{ name := "Content-Type", value := Observability.metricsContentType }]
      body := snapshot.renderPrometheus ++ (← Admin.processPrometheus) ++ (← driver.transport.metrics) } }
  driver.handlers.onRequest request

private partial def Driver.applyStep (driver : Driver) (id : Reactor.SocketId) (step : Machine.Step) : IO Unit := do
  let some client ← driver.client? id | return
  if client.retired then return
  driver.put id { client with protocol := .http1 step.state, kick := true }
  for action in step.actions do
    let some client ← driver.client? id | return
    if client.retired then return
    match action with
    | .readEnabled enabled => driver.setReading id enabled
    | .write outputId parts barrier => driver.appendOutput id (parts.map ByteSlice.full) (some outputId) barrier
    | .writeObserved outputId output barrier => driver.appendObserved id output (some outputId) barrier
    | .writeFile outputId heads region barrier =>
      driver.appendParts id ((heads.map (fun bytes => OutputPart.bytes (ByteSlice.full bytes))).push (.file region))
        (some outputId) barrier
    | .abort _ => driver.closeNow id
    | .drainClose => driver.beginDrain id
    | .inspectHead requestId head framing =>
      let .http1 machine := client.protocol | return
      if !(← driver.startObservation id requestId (some head) machine.startedAt) then
        driver.closeNow id
        return
      let decision ← try
          if metricTarget driver head.target then pure (.accept none)
          else driver.handlers.onHeaders head framing
        catch _ => pure (.reject { response := { status := 500 }, options := { forceClose := true } })
      let some client ← driver.client? id | return
      if client.retired then return
      let .http1 machine := client.protocol | return
      match decision with
      | .accept framing => driver.applyStep id (machine.decideHead requestId (.accept framing))
      | .reject reply => driver.applyStep id (machine.decideHead requestId (.reject (limitedReply driver.config reply)))
      | .upgrade reply pipe =>
        driver.cancelRequest id
        let some client ← driver.client? id | return
        if client.retired then return
        driver.put id { client with pipe := some pipe }
        driver.applyStep id (machine.decideHead requestId (.upgrade (limitedReply driver.config reply)))
    | .request requestId request =>
      driver.cancelRequest id
      let some client ← driver.client? id | return
      if client.retired then return
      let reply ← try driver.reply request
        catch _ => pure { response := { status := 500 }, options := { forceClose := true } }
      let some client ← driver.client? id | return
      if client.retired then return
      let .http1 machine := client.protocol | return
      driver.applyStep id (machine.respond requestId (limitedReply driver.config reply))
    | .upgraded _ =>
      if client.pipe.isNone then driver.closeNow id
      else
        driver.put id { client with protocol := .raw, kick := true, finishSent := false }
        driver.setReading id true

private def availableSlot (slots : Array OutputSlot) : Option Nat := Id.run do
  for index in [:slots.size] do
    if let some slot := slots[index]? then
      if slot.flight.isNone then return some index
  return none

/-- Submit one bounded wire range. Bytes use a permanently reserved lease;
    files use the same operation ledger with a retained native file source. -/
private def Driver.flushOne (driver : Driver) (id : Reactor.SocketId) : IO Bool := do
  let state ← driver.state.get
  let some client := state.clients[id]? | return false
  if client.closing || state.writeBlocked then return false
  if client.inFlight >= max 1 (state.slots.size / driver.clientLimit) then return false
  let some index := availableSlot state.slots | return false
  let output :: rest := client.outputs | return false
  let part :: tail := output.parts | throw (IO.userError "empty HTTP output ticket")
  let some slot := state.slots[index]? | throw (IO.userError "HTTP output slot index is invalid")
  let length := min (match part with | .bytes _ => 4096 | .file _ => 65536) part.length
  if length == 0 then
    driver.closeNow id
    return false
  if slot.generation >= 281474976710655 then throw (IO.userError "HTTP write operation generation exhausted")
  let generation := slot.generation + 1
  let operation := generation * 65536 + UInt64.ofNat (index + 1)
  if let .bytes view := part then
    if view.offset > 4294967295 then driver.closeNow id; return false
  let submission? : Option Reactor.FileSubmission ← match part with
    | .bytes view => do
      slot.buffer.copySliceFrom view.bytes view.offset.toUInt32 length.toUInt32
      let result ← client.socket.tryWrite slot.buffer 0 length.toUInt32 operation
      pure (some (match result with | .queued => .queued | .wouldBlock => .wouldBlock))
    | .file region =>
      try some <$> client.socket.tryFile (region.take length) operation
      catch _ =>
        -- A source failure can follow a committed DATA header. Abort this
        -- connection so its incomplete frame cannot corrupt later streams.
        if ← id.isLive driver.reactor then driver.closeNow id else driver.nativeGone id
        pure none
  let some submission := submission? | return false
  match submission with
  | .interrupted => return false
  | .wouldBlock =>
    driver.state.modify fun state => { state with writeBlocked := true }
    return false
  | .queued => pure ()
  let parts := if length == part.length then tail else part.drop length :: tail
  let last := parts.isEmpty
  let flight : Flight := {
    owner := id
    operation := operation
    outputId := output.id
    barrier := output.barrier
    last := last
    started := output.started
    length := length
    pingNonce := if last then output.pingNonce else none
    observation := output.observation.map fun value =>
      { requestId := value.requestId, payloadBytes := value.overlap length } }
  driver.state.modify fun state =>
    { state with slots := state.slots.set! index { slot with generation, flight := some flight } }
  let remaining := { output with
    parts
    observation := output.observation.map fun value => { value with offset := value.offset + length } }
  driver.put id { client with
    outputs := (if last then rest else remaining :: rest)
    outputBytes := client.outputBytes - (match part with | .bytes _ => length | .file _ => 0)
    queuedFileBytes := client.queuedFileBytes - (match part with | .file _ => length | .bytes _ => 0)
    inFlight := client.inFlight + 1 }
  if last && !output.barrier then
    if let some outputId := output.id then
      let some client ← driver.client? id | return true
      if let .http1 machine := client.protocol then
        driver.applyStep id (machine.outputAccepted outputId)
  -- The lease retains output.started until its completion. Moving bytes from
  -- the queue to a lease therefore leaves the earliest deadline unchanged.
  if let some client ← driver.client? id then
    if client.closeWhenQueued && client.outputs.isEmpty then driver.beginDrain id
  return true

private def Driver.startRequest (driver : Driver) (id : Reactor.SocketId) (started : UInt64) : IO Unit := do
  let some client ← driver.client? id | return
  if client.retired then return
  if client.requestDeadline.isNone then
    let value ← deadline started driver.config.server.requestTimeoutMs
    client.socket.armTimer 1 value
    driver.put id { client with requestDeadline := some value }

-- Small control/header frames share a native 4 KiB lease. Keep larger owned
-- payloads intact so this does not introduce a second full DATA-body copy.
private def coalesceH2Output (parts : Array WirePart) : Array OutputPart := Id.run do
  let mut result := #[]
  let mut pending := ByteArray.empty
  for segment in parts do
    let part ← match segment with
      | .file region =>
        if !pending.isEmpty then result := result.push (.bytes (ByteSlice.full pending))
        pending := ByteArray.empty
        if region.length != 0 then result := result.push (.file region)
        continue
      | .bytes bytes => pure bytes
    if part.isEmpty then continue
    if part.size >= 4096 then
      if !pending.isEmpty then result := result.push (.bytes (ByteSlice.full pending))
      pending := ByteArray.empty
      result := result.push (.bytes (ByteSlice.full part))
    else if pending.size + part.size <= 4096 then
      pending := if pending.isEmpty then part else pending ++ part
    else
      result := result.push (.bytes (ByteSlice.full pending))
      pending := part
  if !pending.isEmpty then result := result.push (.bytes (ByteSlice.full pending))
  return result

private def Driver.appendH2Output (driver : Driver) (id : Reactor.SocketId) (output : Array WirePart) : IO Unit := do
  let parts := coalesceH2Output output
  for start in [:parts.size:4096] do
    driver.appendParts id (parts.extract start (min parts.size (start + 4096)))

/-- One slot in the native hashed wheel serves each connection's next probe or
    ACK deadline. Queued probes are instead bounded by the existing write timer. -/
private def Driver.syncPingTimer (driver : Driver) (id : Reactor.SocketId) : IO Unit := do
  if driver.config.http2.pingIntervalMs == 0 then return
  let some client ← driver.client? id | return
  if client.retired || client.closing then return
  unless ← id.isLive driver.reactor do
    driver.nativeGone id
    return
  let .http2 machine := client.protocol | return
  let wanted ← match machine.keepaliveDeadline with
    | none => pure none
    | some value => some <$> deadline 0 value
  if wanted == client.pingDeadline then return
  match wanted with
  | none => client.socket.cancelTimer 3
  | some value => client.socket.armTimer 3 value
  driver.put id { client with pingDeadline := wanted }

private def Driver.applyH2Step (driver : Driver) (id : Reactor.SocketId)
    (step : HTTP2.Machine.Step) : IO Unit := do
  let some client ← driver.client? id | return
  if client.retired then return
  driver.put id { client with protocol := .http2 step.state, kick := true }
  let mut actions := step.actions
  let mut output := #[]
  let mut bytes := 0
  let mut fileBytes := 0
  let mut close := false
  while !actions.isEmpty do
    let action :: rest := actions | break
    actions := rest
    let some client ← driver.client? id | return
    if client.retired then return
    let parts? := match action with
      | .write parts => some (parts.map WirePart.bytes)
      | .writeParts parts => some parts
      | _ => none
    if let some parts := parts? then
      let count := parts.foldl (fun total part => total + match part with | .bytes data => data.size | .file _ => 0) 0
      let files := parts.foldl (fun total part => total + match part with | .file region => region.length | .bytes _ => 0) 0
      if count > driver.config.maxOutputBytes - client.outputBytes - bytes then
        driver.closeNow id
        return
      if files > driver.config.maxQueuedFileBytes - client.queuedFileBytes - fileBytes then
        driver.closeNow id
        return
      bytes := bytes + count
      fileBytes := fileBytes + files
      output := output ++ parts
      continue
    match action with
    | .write _ | .writeParts _ => pure ()
    | .writePing nonce pingBytes =>
      driver.appendH2Output id output
      output := #[]
      bytes := 0
      fileBytes := 0
      driver.appendParts id #[.bytes (ByteSlice.full pingBytes)] (pingNonce := some nonce)
    | .writeObserved observed =>
      driver.appendH2Output id output
      output := #[]
      bytes := 0
      fileBytes := 0
      driver.appendObserved id observed
    | .requestStarted streamId head startedAt =>
      if !(← driver.startObservation id streamId.toNat (some head) startedAt) then driver.closeNow id
    | .responseAborted streamId reason =>
      let outcome := match reason with
        | .cancelled => Observability.Outcome.cancelled
        | .error => .error
        | .timeout => .timeout
      driver.abortObservation id streamId.toNat outcome
    | .drainClose => close := true
    | .request event =>
      let .http2 machine := client.protocol | return
      if !machine.canRespond event.streamId then continue
      let reply ← try driver.reply event.request
        catch _ => pure { response := { status := 500 } }
      let pushes ← if machine.canPush && !metricTarget driver event.request.target then
        try driver.handlers.onPush event.request catch _ => pure #[]
        else pure #[]
      let some current ← driver.client? id | return
      if current.retired then return
      let .http2 machine := current.protocol | return
      let response := machine.respond event.streamId (limitedReply driver.config reply) pushes
      driver.put id { current with protocol := .http2 response.state, kick := true }
      actions := response.actions ++ actions
  -- Preserve the generic queue's per-ticket part bound for custom large
  -- configurations without changing wire order or HTTP/1 output barriers.
  driver.appendH2Output id output
  driver.syncPingTimer id
  if close then driver.beginDrain id

private def Driver.failH2 (driver : Driver) (id : Reactor.SocketId)
    (machine : HTTP2.Machine.State) (error : HTTP2.ProtocolError) : IO Unit :=
  driver.applyH2Step id (machine.fail error)

/-- A TLS handshake accepted before admission stopped may publish READY during
    draining. Give it the same shutdown policy as the initial client snapshot. -/
private def Driver.shutdownClient (driver : Driver) (id : Reactor.SocketId) : IO Unit := do
  let some client ← driver.client? id | return
  if client.retired || client.closing then return
  match client.protocol with
  | .http1 machine => driver.applyStep id machine.shutdown
  | .http2 machine => driver.applyH2Step id machine.goAway
  | .detect _ | .raw =>
    driver.setReading id false
    driver.beginDrain id

private def Driver.feedH2 (driver : Driver) (id : Reactor.SocketId) (part : ByteSlice) : IO Bool := do
  let state ← driver.state.get
  let some client := state.clients[id]? | return false
  let .http2 machine := client.protocol | return false
  let step := ((machine.setTime state.now.toNat).setDate state.date).feedSlice part.bytes part.offset part.length
  driver.consume id step.consumed
  driver.applyH2Step id step
  if let some client ← driver.client? id then
    if let .http2 machine := client.protocol then
      if !machine.hasPartialInput then driver.cancelRequest id
  return step.consumed != 0 || !step.actions.isEmpty

private def Driver.serviceH2 (driver : Driver) (id : Reactor.SocketId) : IO Bool := do
  let state ← driver.state.get
  let some client := state.clients[id]? | return false
  let .http2 machine := client.protocol | return false
  if client.closing || client.closeWhenQueued then return false
  let tick := ((machine.setTime state.now.toNat).setDate state.date).tick
    state.now.toNat driver.config.server.requestTimeoutMs
  driver.applyH2Step id tick
  let some client ← driver.client? id | return !tick.actions.isEmpty
  let .http2 machine := client.protocol | return !tick.actions.isEmpty
  if machine.canDrain && client.outputs.isEmpty then
    let step := machine.drain
    driver.applyH2Step id step
    return !tick.actions.isEmpty || !step.actions.isEmpty
  return !tick.actions.isEmpty

private inductive Detection where
  | more (matched consumed : Nat)
  | http1 (matched consumed : Nat)
  | http2 (consumed : Nat)

private def detect (matched : Nat) (part : ByteSlice) : Detection := Id.run do
  let mut matched := matched
  for index in [:part.length] do
    if part.bytes[part.offset + index]! != preface[matched]! then return .http1 matched index
    matched := matched + 1
    if matched == preface.size then return .http2 (index + 1)
  return .more matched part.length

private def Driver.detectProtocol (driver : Driver) (id : Reactor.SocketId)
    (matched : Nat) (chunk : InputChunk) : IO Unit := do
  driver.startRequest id chunk.arrived
  match detect matched chunk.view with
  | .more matched consumed =>
    driver.consume id consumed
    if let some client ← driver.client? id then driver.put id { client with protocol := .detect matched }
  | .http1 matched consumed =>
    driver.consume id consumed
    let state ← driver.state.get
    let some current := state.clients[id]? | return
    let client := normalizedInput current
    let prefixChunk : InputChunk := { view := (ByteSlice.full preface).take matched, arrived := chunk.arrived }
    let input := if matched == 0 then client.inputFront else prefixChunk :: client.inputFront
    driver.put id { client with
      protocol := .http1 (((Machine.State.new driver.config.machine).setDate state.date).setTime chunk.arrived.toNat)
      inputFront := input
      inputBytes := client.inputBytes + matched
      kick := true }
  | .http2 consumed =>
    driver.consume id consumed
    let state ← driver.state.get
    let some client := state.clients[id]? | return
    let machine := ((HTTP2.Machine.State.new driver.config.http2).setTime state.now.toNat).setDate state.date
    driver.put id { client with protocol := .http2 machine, kick := true }
    driver.applyH2Step id machine.start
    if let some client ← driver.client? id then
      if let .http2 machine := client.protocol then
        driver.applyH2Step id (machine.feedSlice preface 0 preface.size)

private def Driver.rawResult (driver : Driver) (id : Reactor.SocketId) (result : RawResult) : IO Unit := do
  driver.appendOutput id result.output
  if result.closeAfterWrites then
    if let some client ← driver.client? id then
      driver.put id { client with closeWhenQueued := true }
      driver.setReading id false

private def Driver.finishInput (driver : Driver) (id : Reactor.SocketId) : IO Unit := do
  let some client ← driver.client? id | return
  if !client.peerEOF || client.finishSent || client.inputBytes != 0 || client.closing then return
  driver.put id { client with finishSent := true }
  match client.protocol with
  | .http1 machine => driver.applyStep id machine.finish
  | .detect matched =>
    if matched == 0 then driver.beginDrain id
    else
      let state ← driver.state.get
      driver.applyStep id (((Machine.State.new driver.config.machine).setDate state.date).feed
        (preface.extract 0 matched))
      if let some client ← driver.client? id then
        if let .http1 machine := client.protocol then driver.applyStep id machine.finish
  | .http2 machine => driver.applyH2Step id machine.finish
  | .raw =>
    match client.pipe with
    | none => driver.closeNow id
    | some pipe =>
      let result ← try pipe.onEOF catch _ => pure { closeAfterWrites := true }
      driver.rawResult id result

/-- Bounded controller work. Parser decisions may complete with zero input, so
    each transition explicitly kicks the next empty-input step as needed. -/
private def Driver.pump (driver : Driver) (id : Reactor.SocketId) : IO Unit := do
  unless ← id.isLive driver.reactor do
    driver.nativeGone id
    return
  for _ in [:driver.config.workPerClient] do
    let some current ← driver.client? id | return
    if current.closing then return
    let client := normalizedInput current
    driver.put id client
    let flushed ← driver.flushOne id
    let some client ← driver.client? id | return
    if client.closing then return
    if client.closeWhenQueued then
      if client.outputs.isEmpty then driver.beginDrain id
      if !flushed then return
      continue
    let mut advanced := flushed
    match client.inputFront.head?, client.protocol with
    | some chunk, .detect matched =>
      driver.detectProtocol id matched chunk
      advanced := true
    | some chunk, .http1 machine =>
      if machine.wantsInput then
        if machine.isIdle then driver.startRequest id chunk.arrived
        let state ← driver.state.get
        let step := ((machine.setDate state.date).setTime chunk.arrived.toNat).feedSlice chunk.view.bytes chunk.view.offset chunk.view.length
        driver.consume id step.consumed
        driver.applyStep id step
        advanced := step.consumed != 0 || !step.actions.isEmpty
    | some chunk, .http2 _ =>
      driver.startRequest id chunk.arrived
      advanced := (← driver.feedH2 id chunk.view) || advanced
    | some chunk, .raw =>
      match client.pipe with
      | none => driver.closeNow id
      | some pipe =>
        let result ← try pipe.onBytes chunk.view catch _ => pure { closeAfterWrites := true }
        driver.consume id chunk.view.length
        driver.rawResult id result
      advanced := true
    | none, .http1 machine =>
      if client.kick && machine.wantsInput then
        driver.put id { client with kick := false }
        let step := machine.feed ByteArray.empty
        driver.applyStep id step
        if step.actions.isEmpty then
          if let some client ← driver.client? id then driver.put id { client with kick := false }
        advanced := !step.actions.isEmpty
    | none, .http2 _ => advanced := (← driver.serviceH2 id) || advanced
    | none, _ => pure ()
    driver.finishInput id
    if let some client ← driver.client? id then
      if client.closeWhenQueued && client.outputs.isEmpty then driver.beginDrain id
    if !advanced then return

private def Driver.accepted (driver : Driver) (socket : Transport.Endpoint)
    (protocol : Transport.Protocol) : IO Unit := do
  let id := socket.id
  unless ← id.isLive driver.reactor do return
  let state ← driver.state.get
  if state.clients.contains id then throw (IO.userError "duplicate native HTTP accept identity")
  let value ← deadline state.now driver.config.server.idleTimeoutMs
  socket.armTimer 0 value
  let protocol := match protocol with
    | .detect => driver.config.cleartextProtocol
    | other => other
  let protocol := match protocol with
    | .detect => Protocol.detect 0
    | .http1 => .http1 (((Machine.State.new driver.config.machine).setDate state.date).setTime state.now.toNat)
    | .http2 => .http2 (((HTTP2.Machine.State.new driver.config.http2).setTime state.now.toNat).setDate state.date)
  driver.put id { socket, protocol, idleDeadline := some value }
  if driver.observer.isSome then
    driver.state.modify fun state => { state with counters := state.counters.connectionOpened }
  if let .http2 machine := protocol then driver.applyH2Step id machine.start
  if state.draining then driver.shutdownClient id

private def Driver.read (driver : Driver) (id : Reactor.SocketId)
    (buffer : Reactor.Buffer) (offset length : UInt32) (release : IO Unit) : IO Unit := do
  unless ← id.isLive driver.reactor do
    cleanupActions #[release, driver.nativeGone id]
    return
  let some client ← driver.client? id | release; return
  if client.closing || client.closeWhenQueued then release; return
  let bytes ← try buffer.view catch error => release; throw error
  let some view := ByteSlice.ofRange? bytes offset.toNat length.toNat
    | release; throw (IO.userError "native HTTP read range is invalid")
  if driver.observer.isSome then
    driver.state.modify fun state => { state with counters := state.counters.received length.toUInt64 }
  if view.length > driver.config.maxInputBytes - client.inputBytes then
    release
    driver.closeNow id
    return
  let state ← driver.state.get
  let chunk : InputChunk := { view, release, arrived := state.now }
  driver.put id { client with
    inputBack := chunk :: client.inputBack
    inputBytes := client.inputBytes + view.length
    kick := true }
  if let some client ← driver.client? id then
    if client.idleDeadline.isSome then
      let value ← deadline state.now driver.config.server.idleTimeoutMs
      client.socket.armTimer 0 value
      driver.put id { client with idleDeadline := some value }
  driver.pump id

private def Driver.closed (driver : Driver) (id : Reactor.SocketId) : IO Unit := do
  -- CLOSED can follow a user abort that already removed the client. Its write
  -- records are nevertheless the final owner of reserved output slots.
  driver.state.modify fun state => { state with
    slots := state.slots.map fun slot =>
      if slot.flight.any (fun flight => flight.owner == id) then { slot with flight := none } else slot
    writeBlocked := false }
  driver.forget id

/-- Account only completed physical operations. This runs before CLOSED in a
    mixed event batch, without granting any further protocol actions. -/
private def Driver.accountWritten (driver : Driver) (id : Reactor.SocketId)
    (operation : UInt64) (count : Nat) : IO Unit := do
  if driver.observer.isNone then return
  let low := (operation % 65536).toNat
  if low == 0 then throw (IO.userError "invalid observed write operation")
  let index := low - 1
  let state ← driver.state.get
  let some slot := state.slots[index]? | throw (IO.userError "observed write slot is invalid")
  let some flight := slot.flight | return
  if flight.owner != id || flight.operation != operation || flight.accounted then return
  if count != flight.length then throw (IO.userError "observed write length changed")
  driver.state.modify fun state => { state with
    slots := state.slots.set! index { slot with flight := some { flight with accounted := true } },
    counters := state.counters.sent count.toUInt64 }
  let some observation := flight.observation | return
  let some client ← driver.client? id | return
  let some request := client.requests[observation.requestId]? | return
  let request := { request with
    payloadSent := request.payloadSent + observation.payloadBytes.toUInt64
    pendingOutputs := request.pendingOutputs - (if flight.last then 1 else 0) }
  driver.put id { client with requests := client.requests.insert observation.requestId request }
  driver.finishObservation id observation.requestId

private def Driver.written (driver : Driver) (id : Reactor.SocketId)
    (operation : UInt64) (count : Nat) : IO Unit := do
  driver.accountWritten id operation count
  let low := (operation % 65536).toNat
  if low == 0 then throw (IO.userError "invalid HTTP write completion operation")
  let index := low - 1
  let state ← driver.state.get
  let some slot := state.slots[index]? | throw (IO.userError "HTTP write completion slot is invalid")
  let some flight := slot.flight | return
  if flight.owner != id || flight.operation != operation then return
  if count != flight.length then throw (IO.userError "HTTP write completion length changed")
  driver.state.modify fun state => { state with
    slots := state.slots.set! index { slot with flight := none }
    writeBlocked := false }
  if let some client ← driver.client? id then
    driver.put id { client with inFlight := client.inFlight - 1 }
  unless ← id.isLive driver.reactor do
    driver.nativeGone id
    return
  if (← driver.client? id).any (·.retired) then return
  if let some nonce := flight.pingNonce then
    if let some client ← driver.client? id then
      if let .http2 machine := client.protocol then
        driver.applyH2Step id (machine.pingWritten nonce (← driver.now).toNat)
  if flight.last && flight.barrier then
    if let some outputId := flight.outputId then
      if let some client ← driver.client? id then
        if let .http1 machine := client.protocol then
          driver.applyStep id (machine.outputAccepted outputId)
  driver.syncWriteTimer id

private def Driver.timer (driver : Driver) (id : Reactor.SocketId) (kind : UInt32) : IO Unit := do
  let state ← driver.state.get
  let some client := state.clients[id]? | return
  if client.retired then return
  unless ← id.isLive driver.reactor do
    driver.nativeGone id
    return
  if kind == 3 then
    if client.closing then return
    driver.put id { client with pingDeadline := none }
    if let .http2 machine := client.protocol then
      driver.applyH2Step id (machine.pingTimer state.now.toNat)
    return
  if kind == 2 then
    if client.writeDeadline.any (· <= state.now) then driver.closeNow id .timeout
  else if !client.closing then
    if kind == 0 then
      if client.idleDeadline.any (· <= state.now) then driver.closeNow id
    else if kind == 1 && client.requestDeadline.any (· <= state.now) then
      driver.put id { client with requestDeadline := none }
      match client.protocol with
      | .http1 machine => driver.applyStep id ((machine.setDate state.date).timeout .request)
      | .http2 machine => driver.failH2 id machine ⟨.enhanceYourCalm, .connection, "partial HTTP/2 input timed out"⟩
      | .detect _ => driver.closeNow id
      | .raw => pure ()

private def Driver.event (driver : Driver) : Transport.Event → IO Unit
  | .ready socket protocol => driver.accepted socket protocol
  | .read id buffer offset length release => driver.read id buffer offset length (release.getD buffer.release)
  | .written id operation count => driver.written id operation count
  | .closed id => driver.closed id
  | .eof id => do
    if let some client ← driver.client? id then
      if client.retired then return
      driver.put id { client with peerEOF := true, reading := false, kick := true }
      driver.pump id
  | .timer id kind => driver.timer id kind
  | .wake => pure ()
  | .error id flags code => do
    if (flags &&& 6) != 0 then throw (← Errno.error "HTTP native setup/close" code)
    if (flags &&& 1) != 0 then
      if !(← Reactor.isRecoverableAcceptError code) then throw (← Errno.error "HTTP accept" code)
    else if code == -(Int.ofNat (← FFI.errnoEbadf).toNat) then
      throw (← Errno.error "HTTP owned descriptor (library bug)" code)
    else if !(← Errno.isInterrupted code) then driver.nativeGone id

private def Driver.events (driver : Driver) (events : Array Transport.Event) : IO Unit := do
  if driver.observer.isSome then
    for event in events do
      match event with
      | .written id operation count => driver.accountWritten id operation count
      | .error id _ code =>
        if code == driver.resetErrno then
          if let some client ← driver.client? id then
            if !client.resetCounted then
              driver.put id { client with resetCounted := true }
              driver.state.modify fun state => { state with counters := state.counters.connectionReset }
      | _ => pure ()
  -- Account completed writes first, then retire closed identities before any
  -- remaining protocol work, including batches returned by async providers.
  for event in events do
    if let .closed id := event then driver.closed id
  for event in events do
    match event with
    | .closed _ => pure ()
    | _ => driver.event event

private def Driver.refresh (driver : Driver) : IO Unit := do
  let now ← Reactor.nowMs
  let state ← driver.state.get
  let second := now / 1000
  let changed := second != state.dateSecond || state.date.isEmpty
  let date ← if changed then currentDate else pure state.date
  let wall ← if changed && driver.observer.isSome then do
      let timestamp ← Std.Time.Timestamp.now
      pure (min 18446744073709551615 timestamp.toMillisecondsSinceUnixEpoch.val.toNat).toUInt64
    else pure state.wallUnixMs
  driver.state.modify fun state => { state with
    now
    dateSecond := second
    date
    wallUnixMs := wall
    wallAt := if changed then now else state.wallAt }
  if let some observer := driver.observer then
    let state ← driver.state.get
    if state.publishedAt == 0 || now - state.publishedAt >= 1000 then
      observer.lane.publish state.counters
      observer.hub.check
      driver.state.modify fun state => { state with publishedAt := now }

private def Driver.pumpAll (driver : Driver) : IO Unit := do
  let state ← driver.state.get
  let clients := state.clients.toArray
  if clients.isEmpty then return
  for offset in [:clients.size] do
    let index := (state.roundRobin + offset) % clients.size
    if let some (id, _) := clients[index]? then driver.pump id
  driver.state.modify fun state => { state with roundRobin := state.roundRobin + 1 }

private def Driver.hasWork (driver : Driver) : IO Bool := do
  let state ← driver.state.get
  let writable := (availableSlot state.slots).isSome && !state.writeBlocked
  for (_, client) in state.clients.toArray do
    if client.closing then continue
    if writable && !client.outputs.isEmpty &&
        client.inFlight < max 1 (state.slots.size / driver.clientLimit) then return true
    if client.closeWhenQueued then continue
    if client.peerEOF && !client.finishSent && client.inputBytes == 0 then return true
    match client.protocol with
    | .http1 machine =>
      if machine.wantsInput && (client.inputBytes != 0 || client.kick) then return true
    | .http2 machine =>
      if machine.wantsInput && client.inputBytes != 0 then return true
      if machine.canDrain && client.outputs.isEmpty then return true
    | _ => if client.inputBytes != 0 then return true
  return false

private def Driver.pollEvents (driver : Driver) (timeout : Int32) (admitting : Bool := true) : IO Unit := do
  match ← driver.reactor.poll timeout with
  | .interrupted => pure ()
  | .completions count =>
    driver.refresh
    let mut events := #[]
    for index in [:count] do
      let native ← driver.reactor.event index.toUInt32
      if !admitting then
        if let .accepted socket := native then
          if ← socket.id.isLive driver.reactor then
            let _ ← socket.close (by decide)
            pure ()
          continue
      events := events ++ (← driver.transport.event native)
    driver.events events

private def Driver.serveReloads (driver : Driver) : IO Unit := do
  if !driver.control then return
  let requested ← Reactor.reloadRequests
  if requested != (← driver.reloadSeen.get) then
    driver.reloadSeen.set requested
    try driver.config.onReload
    catch error => IO.eprintln s!"lean-net: reload hook failed: {error}"

private partial def Driver.loop (driver : Driver) : IO Unit := do
  if ← driver.group.stopping then return
  driver.serveReloads
  driver.refresh
  driver.events (← driver.transport.poll)
  driver.pumpAll
  let ready ← driver.hasWork
  let providerReady ← driver.transport.hasWork
  driver.pollEvents (if ready || providerReady then 0 else 100)
  driver.loop

/-- Stop admission, finish current HTTP/1 requests and queued output, and send
    HTTP/2 GOAWAY while accepted streams retain their flow-control traffic.
    Providers share the same absolute deadline for their close-notify work. -/
private def Driver.drain (driver : Driver) : IO Unit := do
  let cutoff ← deadline (← Reactor.nowMs) driver.config.shutdownDrainMs
  let reserve := min (driver.config.shutdownDrainMs / 4) driver.transport.shutdownReserveMs.toNat
  let applicationCutoff := cutoff - reserve.toUInt64
  driver.state.modify fun state => { state with draining := true }
  driver.transport.shutdownBefore cutoff
  for (id, _) in (← driver.state.get).clients.toArray do driver.shutdownClient id
  let mut active := true
  while active && (← Reactor.nowMs) < applicationCutoff do
    driver.refresh
    driver.events (← driver.transport.poll)
    driver.pumpAll
    active := !(← driver.state.get).clients.isEmpty
    if active then
      let ready ← driver.hasWork
      let providerReady ← driver.transport.hasWork
      driver.pollEvents (if ready || providerReady then 0 else 10) false
  if reserve != 0 then
    -- Stop HTTP work before requesting transport closure. Retain fulfilled
    -- historical write fences and their observations until provider CLOSED.
    for (id, _) in (← driver.state.get).clients.toArray do
      driver.setReading id false
      driver.retire id .shutdown
    driver.transport.beginShutdown
    let mut transportActive := true
    while transportActive && (← Reactor.nowMs) < cutoff do
      driver.refresh
      driver.events (← driver.transport.poll)
      transportActive := !(← driver.state.get).clients.isEmpty || !(← driver.transport.shutdownComplete)
      if transportActive then
        let ready ← driver.transport.hasWork
        driver.pollEvents (if ready then 0 else 10) false
  -- The original shared budget has expired. Never grant a fresh TLS timeout
  -- to blocked output; cancel what remains before joining the provider.
  cleanupActions ((← driver.state.get).clients.toArray.map fun (id, client) =>
    cleanupActions #[
      (if client.retired then do
        if ← id.isLive driver.reactor then client.socket.close
       else driver.closeNow id .shutdown),
      driver.forget id])

private def withOutputSlots (reactor : Reactor.Reactor) (count : Nat)
    (use : Array OutputSlot → IO α) : IO α := go count #[]
where
  go (remaining : Nat) (slots : Array OutputSlot) : IO α :=
    match remaining with
    | 0 => use slots
    | n + 1 => do
      let buffer ← reactor.acquire 4096
      Reactor.withBuffer buffer fun buffer => go n (slots.push { buffer })

/-- Bracket transport resources and application callbacks together on their
    owning worker. This also supports diagnostics without sharing handler state. -/
abbrev WithWorkerResources := Nat → Nat → Reactor.Reactor →
  (Transport.Worker → Handlers → IO Unit) → IO Unit

private def runWorker (resources : WithWorkerResources) (config : ReactorServerConfig)
    (hub : Option Observability.Hub)
    (workerId clientLimit : Nat) (reactor : Reactor.Reactor) (group : Reactor.Group) : IO Unit := do
  if config.pinWorkers then
    let _ ← Reactor.pinCurrentThread workerId
  resources workerId clientLimit reactor fun transport handlers => do
   let handlers := config.securityHeaders.wrap transport.secure handlers
   let pool := config.native.buffers4k.toNat + config.native.buffers16k.toNat + config.native.buffers64k.toNat
   let available := pool - transport.reservedBuffers
   let count := min config.outputBuffers (min (clientLimit * 4) (min config.native.maxWrites.toNat (available - 1)))
   if count == 0 || count > 65535 then throw (IO.userError "HTTP requires reserved output and receive buffer credits")
   if count < clientLimit then
     throw (IO.userError "HTTP output buffer credits must cover every admitted client")
   withOutputSlots reactor count fun slots => do
    let state ← IO.mkRef { slots : WorkerState }
    let observer ← match hub with
      | none => pure none
      | some hub => do
        let lane ← hub.lane workerId
        pure (some { hub, lane : WorkerObserver })
    let resetErrno := -(Errno.decode (← FFI.errnoEconnreset))
    let reloadSeen ← IO.mkRef (← Reactor.reloadRequests)
    let driver : Driver := { reactor, group, config, handlers, transport, clientLimit, state, observer,
                             resetErrno, control := workerId == 0, reloadSeen }
    try
      driver.loop
      driver.drain
    finally
      let state ← driver.state.get
      let cleanup := state.clients.toArray.map fun (id, _) => driver.forget id
      cleanupActions (cleanup.push (do
        if let some observer := driver.observer then observer.lane.publish (← driver.state.get).counters))

/-- Run the optional local admin port on its own dedicated thread for the
    lifetime of the worker pool. It reads only published snapshots. -/
private def withAdmin (config : ReactorServerConfig) (workers : Nat)
    (hub : Option Observability.Hub) (serve : IO Unit) : IO Unit := do
  let some port := config.adminPort | serve
  let stop ← IO.mkRef false
  let finished ← IO.mkRef false
  let source : Admin.Source := {
    workers, startedAtMs := ← Reactor.nowMs
    snapshot := match hub with
      | some hub => do return some (← hub.snapshot)
      | none => pure none
    -- Draining begins when the pool stops; readiness then reports 503.
    draining := do return (← finished.get) || (← Reactor.processStopping) }
  let task ← IO.asTask (Admin.serve port source stop) Task.Priority.dedicated
  try serve
  finally
    finished.set true
    stop.set true
    match ← IO.wait task with
    | .ok _ => pure ()
    | .error error => IO.eprintln s!"lean-net: admin port stopped: {error}"

/-- Construct independent callbacks and state inside each dedicated worker.
    The global client limit is partitioned, rather than multiplied by workers. -/
def serveWorkerFactory (resources : WithWorkerResources) (config : ReactorServerConfig := {})
    (host : String := "127.0.0.1") (port : UInt16 := 8080) : IO Unit := do
  if config.server.maxClients == 0 || config.server.idleTimeoutMs == 0 ||
      config.server.requestTimeoutMs == 0 || config.server.writeTimeoutMs == 0 ||
      config.outputBuffers == 0 || config.maxInputBytes == 0 || config.maxOutputBytes < 4096 ||
      config.server.maxFileResponseBytes == 0 || config.server.maxFileResponseBytes > 9223372036854775807 ||
      config.maxQueuedFileBytes < config.server.maxFileResponseBytes || config.maxQueuedFileBytes > 9223372036854775807 ||
      config.workPerClient == 0 || config.shutdownDrainMs == 0 ||
      config.shutdownDrainMs > 9223372036854775807 then throw (IO.userError "HTTP limits and timeouts must be positive")
  match config.http2.validate with
  | .error message => throw (IO.userError message)
  | .ok () => pure ()
  if let some path := config.metricsPath then
    if path.isEmpty || path.size > 256 || path[0]! != 47 ||
        path.data.any (fun byte => byte <= 32 || byte >= 127 || byte == 63 || byte == 35) then
      throw (IO.userError "metrics path must be a bounded origin path without query or fragment")
  let workers ← workerCount config.workers config.server.maxClients
  let observing := config.metricsPath.isSome || config.accessLog.isSome || config.adminPort.isSome
  let config := { config with
    workers
    machine := { config.machine with trackOutput := observing || config.machine.trackOutput }
    http2 := { config.http2 with trackOutput := observing || config.http2.trackOutput } }
  if observing then
    Observability.withHub workers config.accessLog fun hub =>
      withAdmin config workers (some hub) <|
        withWorkerPool host port workers config.server.maxClients config.native
          (runWorker resources config (some hub))
  else
    withWorkerPool host port workers config.server.maxClients config.native
      (runWorker resources config none)

/-- Attach a transport bracket while constructing callbacks on each owner. -/
def serveFactoryWithTransport (provider : Transport.WithWorker)
    (factory : Nat → IO Handlers) (config : ReactorServerConfig := {})
    (host : String := "127.0.0.1") (port : UInt16 := 8080) : IO Unit :=
  serveWorkerFactory (fun workerId maxClients reactor use =>
    provider workerId maxClients reactor fun transport => do
      let handlers ← factory workerId
      use transport handlers) config host port

/-- Cleartext HTTP uses the same controller as negotiated TLS transports. -/
def serveFactory (factory : Nat → IO Handlers) (config : ReactorServerConfig := {})
    (host : String := "127.0.0.1") (port : UInt16 := 8080) : IO Unit :=
  serveFactoryWithTransport Transport.withPlainWorker factory config host port

/-- Compatibility callbacks may close over mutable application state. Keep
    their original single-worker ownership; multicore callers use the factory. -/
def serveWithHandlers (handlers : Handlers) (config : ReactorServerConfig := {})
    (host : String := "127.0.0.1") (port : UInt16 := 8080) : IO Unit :=
  serveFactory (fun _ => pure handlers) { config with workers := 1 } host port

def serveWithConfig (router : Router) (config : ServerConfig)
    (host : String := "127.0.0.1") (port : UInt16 := 8080) : IO Unit :=
  serveWithHandlers (.ofRouter router) { server := config, workers := 1 } host port

def serve (host : String := "127.0.0.1") (port : UInt16 := 8080) : IO Unit :=
  serveFactory (fun _ => pure .default) {} host port

end ReactorServer
end LeanNet.HTTP
