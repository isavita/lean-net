import Std.Data.HashMap
import LeanNet.Reactor.Basic
import LeanNet.HTTP1.Handlers
import LeanNet.HTTP2.Machine
import LeanNet.HTTP2.Upgrade
import LeanNet.HTTP.WorkerPool
import LeanNet.HTTP.Transport
import LeanNet.HTTP.Observability
import LeanNet.HTTP.SecureHeaders
import LeanNet.HTTP.Admin
import LeanNet.HTTP.TraceContext
import LeanNet.HTTP.Admission
import LeanNet.Gateway.Engine
import LeanNet.WebSocket.Server

namespace LeanNet.HTTP

open HTTP1

structure ReactorServerConfig where
  /-- Shared connection admission, response bounds and connection deadlines. -/
  server : ServerConfig := {}
  /-- HTTP/1.0 and HTTP/1.1 parsing, body limits and streaming settings.
      HTTP/2 uses `http2`; both protocols share the application's handlers. -/
  machine : Machine.Config := {}
  native : Reactor.Config := {}
  workers : Nat := 0
  /-- Bounded owner-worker application jobs and completion deadlines. -/
  deferred : Deferred.Config := {}
  /-- Optional per-peer-IP GCRA budget checked on completed TCP accepts,
      before worker handoff and any TLS handshake. -/
  connectionRate : Option Reactor.AcceptRateConfig := none
  outputBuffers : Nat := 128
  maxInputBytes : Nat := 2 * 1024 * 1024 + 65536
  maxOutputBytes : Nat := 16 * 1024 * 1024
  maxQueuedFileBytes : Nat := 4 * 1024 * 1024 * 1024
  workPerClient : Nat := 64
  /-- HTTP/2 stream, frame, header, body and flow-control settings. -/
  http2 : HTTP2.Connection.Config := {}
  /-- Initial cleartext parser selection per connection. `.detect` accepts
      HTTP/1 or the HTTP/2 prior-knowledge preface on the same listener.
      TLS uses ALPN instead. To force cleartext HTTP/1 only, also set
      `h2cUpgrade := false`. -/
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
  /-- W3C Trace Context: accept a valid incoming `traceparent`, otherwise
      generate one and inject it into the application request. The trace-id
      is recorded in access logs. -/
  tracing : Bool := true
  /-- Accept HTTP/1.1 `Upgrade: h2c` on cleartext connections (RFC 7540
      §3.2). Never offered over TLS, where ALPN selects h2. -/
  h2cUpgrade : Bool := true
  /-- Optional head-stage admission (see `LeanNet.HTTP.Admission`). `none`
      keeps the core server's behaviour unchanged. -/
  admission : Option Admission.Factory := none
  /-- Opt-in per-worker upstream engine. Native socket capacity is reserved
      separately from inbound maxClients, so proxy connections cannot steal
      accepted-client slots. -/
  gateway : Option Gateway.Config := none
  /-- Extra Prometheus exposition appended to the metrics endpoint and the
      admin port (e.g. gate counters). -/
  extraMetrics : IO ByteArray := pure ByteArray.empty
  /-- Demo WebSocket echo route `/ws`; the exact allowed browser Origin must
      be configured explicitly. Applications can use their own policy. -/
  websocketOrigin : Option ByteArray := none

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
  remote : ByteArray := ByteArray.empty
  traceId : ByteArray := ByteArray.empty
  /-- Admission outcome labels from configuration (never request bytes). -/
  route : ByteArray := ByteArray.empty
  rejectReason : ByteArray := ByteArray.empty

/-- Admission-selected per-request handling. -/
private structure Dispatch where
  handler : Option (Request → IO Reply) := none
  rewrite : Option (Request → Request) := none
  proxy : Option Admission.ProxyPlan := none
  postBody : Option (Request → IO (Except Admission.Rejection Request)) := none

/-- At most one upstream body slice is retained per proxied response. The
    worker offers it to the downstream protocol under its output and HTTP/2
    flow-control budgets before resuming the upstream socket. -/
private structure ProxyStream where
  head : HTTP1.ClientResponse.Head
  declared : Array String := #[]
  pending : ByteArray := ByteArray.empty
  offset : Nat := 0
  finish : Option (Array HTTP1.ClientResponse.Header) := none
  upstreamPaused : Bool := false

private structure AppStream where
  body : Stream.Body
  retained : Nat
  started : UInt64
  progressed : UInt64
  pending : ByteArray := ByteArray.empty
  offset : Nat := 0
  sent : Nat := 0
  ending : Option (Array Header) := none

private structure UploadState where
  chunks : Array ByteArray := #[]
  bytes : Nat := 0
  credit : Nat := 0
  eof : Option (Array Header) := none
  cancelled : Option Deferred.CancelReason := none
  discard : Bool := false
  consumedEnd : Bool := false
  progressed : UInt64 := 0

private structure Upload where
  state : IO.Ref UploadState
  retained : Nat
  maxBytes : Nat

private def Upload.source (upload : Upload) : IncomingBody := {
  poll := fun budget => do
    let state ← upload.state.get
    if let some reason := state.cancelled then return some (.cancelled reason)
    if let some chunk := state.chunks[0]? then
      let count := min 65536 (min budget chunk.size)
      if count == 0 then return none
      let chunks := if count == chunk.size then state.chunks.extract 1 state.chunks.size
        else state.chunks.set! 0 (chunk.extract count chunk.size)
      upload.state.set { state with chunks, bytes := state.bytes - count, credit := state.credit + count }
      return some (.data (chunk.extract 0 count))
    if let some trailers := state.eof then
      upload.state.set { state with consumedEnd := true }
      return some (.finish trailers)
    return none
  cancel := fun reason => upload.state.modify fun state => { state with cancelled := some reason }
}

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
  h2Pipes : Std.HashMap UInt32 RawPipe := {}
  h2Inputs : Std.HashMap UInt32 (ByteArray × Bool) := {}
  h2Writes : Std.HashMap UInt32 (Nat × ByteArray) := {}
  h2CloseDeadlines : Std.HashMap UInt32 UInt64 := {}
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
  /-- Peer IP text, captured once at admission when observability is on. -/
  remote : ByteArray := ByteArray.empty
  /-- Accepted h2c upgrade awaiting its 101 write barrier. -/
  h2cUpgrade : Option (ByteArray × HTTP2.RequestHead × RequestHead × Nat) := none
  /-- Transport facts, resolved once per connection when admission is on. -/
  facts : Option Transport.Facts := none
  /-- Admission-selected request handlers keyed by HTTP/1 request ID or
      HTTP/2 stream ID; consumed when the request is dispatched. -/
  dispatch : Std.HashMap Nat Dispatch := {}
  proxyStreams : Std.HashMap Nat ProxyStream := {}
  appStreams : Std.HashMap Nat AppStream := {}
  uploads : Std.HashMap UInt32 Upload := {}

private structure PendingReply where
  job : Deferred.Job
  deadline : UInt64
  bytes : Nat

private structure PendingReplies where
  byClient : Std.HashMap Reactor.SocketId (Std.HashMap Nat PendingReply) := {}
  count : Nat := 0
  bytes : Nat := 0

private def PendingReplies.forClient (pending : PendingReplies) (id : Reactor.SocketId) :
    Std.HashMap Nat PendingReply :=
  pending.byClient.getD id {}

private def PendingReplies.add (pending : PendingReplies) (id : Reactor.SocketId)
    (requestId : Nat) (reply : PendingReply) : PendingReplies :=
  let entries := (pending.forClient id).insert requestId reply
  { byClient := pending.byClient.insert id entries, count := pending.count + 1,
    bytes := pending.bytes + reply.bytes }

private def PendingReplies.remove (pending : PendingReplies) (id : Reactor.SocketId)
    (requestId : Nat) : Option PendingReply × PendingReplies :=
  let entries := pending.forClient id
  match entries[requestId]? with
  | none => (none, pending)
  | some reply =>
    let entries := entries.erase requestId
    let byClient := if entries.isEmpty then pending.byClient.erase id
      else pending.byClient.insert id entries
    (some reply, { byClient, count := pending.count - 1, bytes := pending.bytes - reply.bytes })

private def PendingReplies.removeClient (pending : PendingReplies) (id : Reactor.SocketId) :
    Array PendingReply × PendingReplies :=
  match pending.byClient[id]? with
  | none => (#[], pending)
  | some entries =>
    let replies := entries.fold (fun out _ reply => out.push reply) (Array.emptyWithCapacity entries.size)
    let bytes := replies.foldl (fun total reply => total + reply.bytes) 0
    let remaining : PendingReplies := {
      byClient := pending.byClient.erase id
      count := pending.count - entries.size
      bytes := pending.bytes - bytes
    }
    (replies, remaining)

private def PendingReplies.keys (pending : PendingReplies) : Array (Reactor.SocketId × Nat) :=
  pending.byClient.fold (fun out owner entries =>
    entries.fold (fun out requestId _ => out.push (owner, requestId)) out)
    (Array.emptyWithCapacity pending.count)

private structure WorkerState where
  clients : Std.HashMap Reactor.SocketId Client := {}
  pendingReplies : PendingReplies := {}
  appStreamCount : Nat := 0
  appStreamBytes : Nat := 0
  uploadCount : Nat := 0
  uploadBytes : Nat := 0
  slots : Array OutputSlot := #[]
  now : UInt64 := 0
  nextAppTick : Nat := 0
  dateSecond : UInt64 := 0
  date : ByteArray := ByteArray.empty
  roundRobin : Nat := 0
  writeBlocked : Bool := false
  counters : Observability.Counters := {}
  publishedAt : UInt64 := 0
  wallAt : UInt64 := 0
  wallUnixMs : UInt64 := 0
  draining : Bool := false
  traces : TraceContext.Generator := default

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
  /-- This worker's admission hook, built on its own thread. -/
  admission : Option Admission.Hook := none
  gateway : Option Gateway.Engine := none

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
    counted := !metricTarget driver target, remote := client.remote }
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
    method := request.method, target := request.target, outcome,
    remote := request.remote, traceId := request.traceId, route := request.route,
    rejectReason := request.rejectReason }
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

/-- Deferred HTTP/1 work keeps transport reads armed for cancellation. Retain
its bounded pipeline tail as owned bytes rather than monopolizing native pool
cells needed by other clients or by the next reset/EOF completion. -/
private def Driver.ownInput (driver : Driver) (id : Reactor.SocketId) : IO Unit := do
  let some client ← driver.client? id | return
  let own := fun (chunk : InputChunk) =>
    { chunk with view := ByteSlice.full chunk.view.copy, release := pure () }
  let front := client.inputFront.map own
  let back := client.inputBack.map own
  driver.put id { client with inputFront := front, inputBack := back }
  releaseInput client

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

/-- Remove jobs before callbacks: cancellation exceptions cannot retain work
or cause a second cancellation during transport retirement. -/
private def Driver.cancelReplies (driver : Driver) (id : Reactor.SocketId)
    (reason : Deferred.CancelReason) (requestId : Option Nat := none) : IO Unit := do
  let selected ← driver.state.modifyGet fun state =>
    let (selected, pendingReplies) := match requestId with
      | none => state.pendingReplies.removeClient id
      | some key =>
        let (reply, remaining) := state.pendingReplies.remove id key
        (reply.toArray, remaining)
    (selected, { state with pendingReplies })
  for item in selected do try item.job.cancel reason catch _ => pure ()

private def Driver.closeUploads (driver : Driver) (id : Reactor.SocketId)
    (reason : Option Deferred.CancelReason) (streamId : Option UInt32 := none) : IO Unit := do
  let some client ← driver.client? id | return
  let selected := client.uploads.toArray.filter (fun item => streamId.all (· == item.1))
  driver.put id { client with uploads := client.uploads.filter (fun key _ => !streamId.all (· == key)) }
  driver.state.modify fun state => { state with
    uploadCount := state.uploadCount - selected.size
    uploadBytes := state.uploadBytes - selected.foldl (fun n item => n + item.2.retained) 0 }
  for (_, upload) in selected do
    upload.state.modify fun state => { state with
      chunks := #[], bytes := 0, cancelled := reason.orElse (fun _ => state.cancelled) }

private def Driver.discardUpload (driver : Driver) (id : Reactor.SocketId) (key : Nat) : IO Unit := do
  let some client ← driver.client? id | return
  let some upload := client.uploads[key.toUInt32]? | return
  upload.state.modify fun state => { state with
    chunks := #[], bytes := 0, credit := state.credit + state.bytes, discard := true }

private def Driver.openUpload (driver : Driver) (id : Reactor.SocketId) (key : UInt32)
    (ended : Bool) : IO Bool := do
  let some client ← driver.client? id | return false
  let state ← driver.state.get
  let maxBytes := max 1 (min 65536 driver.config.http2.initialWindowSize)
  let retained := maxBytes + driver.config.http2.maxHeaderListBytes + 16384
  let count := state.pendingReplies.count + state.appStreamCount + state.uploadCount
  let same := client.uploads.size + client.appStreams.size + (state.pendingReplies.forClient id).size
  let used := state.pendingReplies.bytes + state.appStreamBytes + state.uploadBytes
  if count >= driver.config.deferred.maxPending || same >= driver.config.deferred.maxPendingPerClient ||
      retained > driver.config.deferred.maxRetainedBytes - used then return false
  let source ← IO.mkRef { progressed := state.now, eof := if ended then some #[] else none : UploadState }
  driver.put id { client with uploads := client.uploads.insert key { state := source, retained, maxBytes } }
  driver.state.modify fun state => { state with uploadCount := state.uploadCount + 1, uploadBytes := state.uploadBytes + retained }
  return true

private def Driver.closeAppStreams (driver : Driver) (id : Reactor.SocketId)
    (reason : Option Deferred.CancelReason) (requestId : Option Nat := none) : IO Unit := do
  let some client ← driver.client? id | return
  let removed := client.appStreams.toArray.filter (fun item => requestId.all (· == item.1))
  let streams := client.appStreams.filter (fun key _ => !requestId.all (· == key))
  driver.put id { client with appStreams := streams }
  driver.state.modify fun state => { state with
    appStreamCount := state.appStreamCount - removed.size
    appStreamBytes := state.appStreamBytes - removed.foldl (fun n item => n + item.2.retained) 0 }
  for (key, stream) in removed do
    if reason.isNone then driver.discardUpload id key
    try stream.body.close reason catch _ => pure ()

private def Driver.forget (driver : Driver) (id : Reactor.SocketId) : IO Unit := do
  let some client ← driver.client? id | return
  cleanupActions #[
    driver.closeUploads id (some (if client.retirementOutcome == some .shutdown then .shutdown else .disconnected)),
    driver.closeAppStreams id (some (if client.retirementOutcome == some .shutdown then .shutdown else .disconnected)),
    driver.cancelReplies id (if client.retirementOutcome == some .shutdown then .shutdown else .disconnected),
    (do if let some gateway := driver.gateway then gateway.cancelDownstream id),
    driver.closeObservations id (client.retirementOutcome.getD .error),
    driver.state.modify fun state => { state with clients := state.clients.erase id },
    releaseInput client,
    (do
      if let some pipe := client.pipe then try pipe.onClose catch _ => pure ()
      for (_, pipe) in client.h2Pipes.toArray do try pipe.onClose catch _ => pure ())]

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
    h2Pipes := {}, h2Inputs := {}, h2Writes := {}, h2CloseDeadlines := {},
    proxyStreams := {},
    outputs := [], outputBytes := 0, queuedFileBytes := 0,
    idleDeadline := none, requestDeadline := none, writeDeadline := none, pingDeadline := none }
  cleanupActions #[
    driver.closeUploads id (some (if outcome == .shutdown then .shutdown else .disconnected)),
    driver.closeAppStreams id (some (if outcome == .shutdown then .shutdown else .disconnected)),
    driver.cancelReplies id (if outcome == .shutdown then .shutdown else .disconnected),
    (do if let some gateway := driver.gateway then gateway.cancelDownstream id),
    releaseInput client,
    (do
      if let some pipe := client.pipe then try pipe.onClose catch _ => pure ()
      for (_, pipe) in client.h2Pipes.toArray do try pipe.onClose catch _ => pure ())]

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

private def maxNativeDeadline : Nat := 9223372036854775807

/-- A duration validated at startup can outlive the remaining native clock range. -/
private def deadline (now : UInt64) (duration : Nat) : UInt64 :=
  UInt64.ofNat (min maxNativeDeadline (now.toNat + duration))

private def runRawCallback (callback : IO RawResult) : IO RawResult :=
  try callback catch _ => pure { abortNow := true }

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
  -- `inFlight` changes with the matching slot record on this owner thread.
  if client.inFlight > 0 then
    for slot in state.slots do
      if let some flight := slot.flight then
        if flight.owner == id then
          earliest := some (min (earliest.getD flight.started) flight.started)
  let wanted := earliest.map (fun start => deadline start driver.config.server.writeTimeoutMs)
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
    let value := deadline state.now driver.config.server.idleTimeoutMs
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
           -- An h2c 101 is a transport barrier within the original request.
           -- Its final response is emitted on HTTP/2 stream 1 after the switch.
           finalResponse := output.finalResponse &&
             !(output.status == 101 && client.h2cUpgrade.isSome) : OutputObservation } else none
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

/-- Capture immutable transport facts before post-body validation, admission
rewrite and application dispatch. Request headers cannot supply these facts. -/
private def Driver.withTransport (driver : Driver) (id : Reactor.SocketId)
    (request : Request) : IO Request := do
  let some client ← driver.client? id | return request
  let facts : Transport.Facts ← match client.facts.orElse (fun _ => client.socket.facts) with
    | some facts => pure facts
    | none => Transport.Facts.plain <$> id.peerBytes driver.reactor
  if client.facts.isNone then driver.put id { client with facts := some facts }
  return { request with
    clientCertificate := client.socket.clientCertificate
    transport := some { secure := facts.secure, peer := facts.peer, sni := facts.sni, alpn := facts.alpn } }

/-- Establish the request's trace context before application dispatch. -/
private def Driver.traced (driver : Driver) (id : Reactor.SocketId) (requestId : Nat)
    (request : Request) : IO Request := do
  let request ← driver.withTransport id request
  if !driver.config.tracing then return request
  let state ← driver.state.get
  let incoming := request.headers.filter (·.name.toLower == "traceparent")
  let remote := incoming.size == 1 && incoming[0]?.any (fun header => (TraceContext.parse header.value).isSome)
  let (context, headers, traces) := TraceContext.ensure request.headers state.traces
  driver.state.set { state with traces }
  if let some client ← driver.client? id then
    if let some observation := client.requests[requestId]? then
      let observation := { observation with traceId := context.traceId }
      driver.put id { client with requests := client.requests.insert requestId observation }
  return { request with headers, traceGenerated := !remote }

private def Driver.takeDispatch (driver : Driver) (id : Reactor.SocketId) (key : Nat) :
    IO (Option Dispatch) := do
  let some client ← driver.client? id | return none
  let some entry := client.dispatch[key]? | return none
  driver.put id { client with dispatch := client.dispatch.erase key }
  return some entry

private def Driver.reply (driver : Driver) (id : Reactor.SocketId) (requestId : Nat)
    (request : Request) (dispatch : Option Dispatch := none) : IO Reply := do
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
      body := snapshot.renderPrometheus ++ (← observer.hub.processMetrics) ++ (← driver.transport.metrics) ++
        (← driver.config.extraMetrics) } }
  let request ← driver.traced id requestId request
  let request := match dispatch.bind (·.rewrite) with | some rewrite => rewrite request | none => request
  match dispatch.bind (·.handler) with
  | some handler => handler request
  | none => driver.handlers.onRequest request

/-- Reserve the producer before committing its response head. -/
private def Driver.prepareReply (driver : Driver) (id : Reactor.SocketId) (requestId : Nat)
    (incoming : Reply) : IO Reply := do
  let fields := driver.config.securityHeaders.fields driver.transport.secure
  let secured := { incoming with response := applySecurityHeaders fields incoming.response }
  let reply := limitedReply driver.config secured
  let some body := incoming.stream | return reply
  let close := fun reason => do try body.close reason catch _ => pure ()
  if reply.stream.isNone || !reply.response.body.isEmpty || reply.fileRegion.isSome ||
      !reply.informational.isEmpty || !(body.validate).isOk then
    close (some .failed)
    return { response := { status := 500 } }
  let some client ← driver.client? id | close (some .disconnected); return { response := { status := 503 } }
  let method := match client.protocol with
    | .http1 machine => machine.requestMethod
    | .http2 machine => machine.requestMethod requestId.toUInt32
    | _ => none
  if method == some "HEAD" || [204,205,304].contains reply.response.status then
    close none
    let options := if method == some "HEAD" && ![204,205,304].contains reply.response.status then
        match body.knownLength with
        | some n => { reply.options with framing := some (.contentLength n) }
        -- Dropping the producer must not turn an unknown GET length into the
        -- buffered empty body's length. Both protocol encoders preserve this
        -- explicit absence of HEAD representation-length metadata.
        | none => { reply.options with framing := some .none }
      else reply.options
    return { reply with stream := none, options }
  let valid := reply.response.validate (method.getD "GET")
  if !valid.isOk then
    close (some .failed)
    return { response := { status := 500 } }
  let state ← driver.state.get
  let perClient := client.appStreams.size + client.uploads.size + (state.pendingReplies.forClient id).size
  let retained := body.retainedBytes + 65536
  if state.pendingReplies.count + state.appStreamCount + state.uploadCount >= driver.config.deferred.maxPending ||
      perClient >= driver.config.deferred.maxPendingPerClient ||
      retained > driver.config.deferred.maxRetainedBytes - (state.pendingReplies.bytes + state.appStreamBytes + state.uploadBytes) then
    close (some .overloaded)
    return { response := { status := 503 } }
  driver.put id { client with appStreams := client.appStreams.insert requestId {
    body, retained, started := state.now, progressed := state.now } }
  driver.state.modify fun state => { state with
    appStreamCount := state.appStreamCount + 1, appStreamBytes := state.appStreamBytes + retained }
  return reply

/-- Start bounded asynchronous application work without leaving the owner.
The protocol retains its exchange; HTTP/1 deliberately pauses its pipeline. -/
private def Driver.requestReply (driver : Driver) (id : Reactor.SocketId) (requestId : Nat)
    (request : Request) (dispatch : Option Dispatch := none) : IO (Option Reply) := do
  if metricTarget driver request.target || (dispatch.bind (·.handler)).isSome then
    return some (← driver.prepareReply id requestId (← driver.reply id requestId request dispatch))
  let some callback := driver.handlers.onRequestDeferred |
    return some (← driver.prepareReply id requestId (← driver.reply id requestId request dispatch))
  let request ← driver.traced id requestId request
  let request := match dispatch.bind (·.rewrite) with | some rewrite => rewrite request | none => request
  match ← callback request with
  | .immediate reply => return some (← driver.prepareReply id requestId reply)
  | .deferred job =>
    let state ← driver.state.get
    let config := driver.config.deferred
    let bytes := request.body.size + request.target.size + request.method.utf8ByteSize +
      request.headers.foldl (fun size field => size + field.name.utf8ByteSize + field.value.size) 0 +
      request.trailers.foldl (fun size field => size + field.name.utf8ByteSize + field.value.size) 0 +
      job.retainedBytes
    let pending := state.pendingReplies.forClient id
    let streams := ((state.clients[id]?).map (fun c => c.appStreams.size + c.uploads.size)).getD 0
    if state.pendingReplies.count + state.appStreamCount + state.uploadCount >= config.maxPending ||
        pending.size + streams >= config.maxPendingPerClient || pending.contains requestId ||
        bytes > config.maxRetainedBytes - (state.pendingReplies.bytes + state.appStreamBytes + state.uploadBytes) ||
        job.timeoutMs == 0 then
      try job.cancel .overloaded catch _ => pure ()
      return some { response := { status := 503 } }
    let expiresAt := deadline state.now (min job.timeoutMs config.maxTimeoutMs)
    driver.state.modify fun state => { state with
      pendingReplies := state.pendingReplies.add id requestId { job, deadline := expiresAt, bytes } }
    -- Release native receive credits before rearming reads. The HTTP/1
    -- parser remains paused; only its bounded, owned pipeline tail grows.
    if let some client ← driver.client? id then
      if let .http1 _ := client.protocol then driver.ownInput id
    driver.setReading id true
    return none

private def Driver.factsOf (driver : Driver) (id : Reactor.SocketId) : IO Transport.Facts := do
  let some client ← driver.client? id | return default
  if let some facts := client.facts then return facts
  let facts ← match client.socket.facts with
    | some facts => pure facts
    | none => do return Transport.Facts.plain (← id.peerBytes driver.reactor)
  driver.put id { client with facts := some facts }
  return facts

/-- Record admission labels on an in-flight observation. -/
private def Driver.labelObservation (driver : Driver) (id : Reactor.SocketId) (requestId : Nat)
    (route : Option String) (reason : String) : IO Unit := do
  if driver.observer.isNone then return
  let some client ← driver.client? id | return
  let some observation := client.requests[requestId]? | return
  let observation := { observation with route := (route.getD "").toUTF8, rejectReason := reason.toUTF8 }
  driver.put id { client with requests := client.requests.insert requestId observation }

/-- Run the configured admission hook. Exceptions become a 500 rejection. -/
private def Driver.admit (driver : Driver) (id : Reactor.SocketId) (hook : Admission.Hook)
    (head : Admission.Head) : IO Admission.Verdict := do
  let facts ← driver.factsOf id
  try hook.decide facts head
  catch _ => pure (.reject { status := 500 })

private def Driver.secureReply (driver : Driver) (reply : Reply) : Reply :=
  let secured := applySecurityHeaders
    (driver.config.securityHeaders.fields driver.transport.secure) reply.response
  { reply with response := secured }

private def Driver.secureRejection (driver : Driver)
    (rejection : Admission.Rejection) : Admission.Rejection :=
  let response : HTTP1.Response := { status := rejection.status, headers := rejection.headers }
  { rejection with headers := (applySecurityHeaders
      (driver.config.securityHeaders.fields driver.transport.secure) response).headers }

private def Driver.h2RejectionReply (driver : Driver)
    (rejection : Admission.Rejection) : Reply :=
  let reply := limitedReply driver.config (driver.secureRejection rejection).reply
  { reply with options := { reply.options with forceClose := false } }

private def admissionHead1 (driver : Driver) (head : RequestHead) (framing : BodyFraming) : Admission.Head :=
  let authority := (head.headers.find? (·.name == "host")).map (·.value) |>.getD ByteArray.empty
  let upgrade := head.headers.any (·.name == "upgrade")
  { protocol := if head.version == "HTTP/1.0" then .http10 else .http11
    method := head.method, target := head.target, authority, headers := head.headers
    contentLength := match framing with | .contentLength n => some n | _ => none
    bodyless := match framing with | .none | .contentLength 0 => true | _ => false
    kind := if metricTarget driver head.target then .internal else if upgrade then .upgrade else .request }

private def admissionHead2 (driver : Driver) (head : HTTP2.RequestHead) : Admission.Head :=
  { protocol := .http2, method := head.method, target := head.target, authority := head.authority
    scheme := some head.scheme, requestedProtocol := head.protocol,
    headers := head.headers, contentLength := head.contentLength
    kind := if head.protocol.isSome then .tunnel
      else if metricTarget driver head.target then .internal else .request }

private partial def Driver.applyStep (driver : Driver) (id : Reactor.SocketId) (step : Machine.Step) : IO Unit := do
  let some client ← driver.client? id | return
  if client.retired then return
  driver.put id { client with protocol := .http1 step.state, kick := true }
  for action in step.actions do
    let some client ← driver.client? id | return
    if client.retired then return
    match action with
    | .readEnabled enabled => driver.setReading id (enabled || !client.appStreams.isEmpty)
    | .write outputId parts barrier => driver.appendOutput id (parts.map ByteSlice.full) (some outputId) barrier
    | .writeObserved outputId output barrier => driver.appendObserved id output (some outputId) barrier
    | .streamFinished requestId =>
      if let some current ← driver.client? id then
        if let some observed := current.requests[requestId]? then
          let finished := { observed with finalQueued := true }
          driver.put id { current with requests := current.requests.insert requestId finished }
          driver.finishObservation id requestId
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
      let mut bodyLimit : Option Nat := none
      if let some hook := driver.admission then
        match ← driver.admit id hook (admissionHead1 driver head framing) with
        | .reject rejection =>
          driver.labelObservation id requestId none rejection.label
          let some client ← driver.client? id | return
          if client.retired then return
          if rejection.drop then
            driver.closeNow id
            return
          let .http1 machine := client.protocol | return
          driver.applyStep id (machine.decideHead requestId
            (.reject (limitedReply driver.config (driver.secureReply rejection.reply))))
          return
        | .accept limit handler rewrite label proxy postBody =>
          driver.labelObservation id requestId label ""
          bodyLimit := limit
          if handler.isSome || rewrite.isSome || proxy.isSome || postBody.isSome then
            if let some client ← driver.client? id then
              let selected : Dispatch := { handler, rewrite, proxy, postBody }
              driver.put id { client with dispatch := client.dispatch.insert requestId selected }
      let some client ← driver.client? id | return
      if client.retired then return
      let .http1 machine := client.protocol | return
      let h2c := if driver.config.h2cUpgrade && !driver.transport.secure && !machine.isStopping then
          HTTP2.Upgrade.candidate head framing driver.config.http2.maxRequestBodyBytes
        else none
      if let some (settings, h2head) := h2c then
        -- Preserve this observation through the 101 barrier, then transfer it
        -- to HTTP/2 stream 1 without starting or finishing a second request.
        driver.cancelRequest id
        let some client ← driver.client? id | return
        if client.retired then return
        driver.put id { client with h2cUpgrade := some (settings, h2head, head, requestId) }
        let reply : Reply := { response := { status := 101, headers := #[{ name := "upgrade", value := "h2c".toUTF8 }] } }
        driver.applyStep id (machine.decideHead requestId (.upgrade reply))
        return
      let decision ← try
          if metricTarget driver head.target then pure (.accept none)
          else driver.handlers.onHeaders head framing
        catch _ => pure (.reject { response := { status := 500 }, options := { forceClose := true } })
      let some client ← driver.client? id | return
      if client.retired then return
      let .http1 machine := client.protocol | return
      match decision with
      | .accept framing => driver.applyStep id (machine.decideHead requestId (.accept framing bodyLimit))
      | .reject reply => driver.applyStep id (machine.decideHead requestId
          (.reject (limitedReply driver.config (driver.secureReply reply))))
      | .upgrade reply pipe =>
        driver.cancelRequest id
        let some client ← driver.client? id | return
        if client.retired then return
        driver.put id { client with pipe := some pipe }
        driver.applyStep id (machine.decideHead requestId (.upgrade (limitedReply driver.config reply)))
    | .request requestId request =>
      let request ← driver.withTransport id request
      driver.cancelRequest id
      let some client ← driver.client? id | return
      if client.retired then return
      let handler ← driver.takeDispatch id requestId
      let request ← match handler.bind (·.postBody) with
        | none => pure (some request)
        | some validate => match ← (try validate request catch _ =>
            pure (.error { status := 500 })) with
          | .ok checked => pure (some checked)
          | .error rejection => do
            driver.labelObservation id requestId none rejection.label
            if let some current ← driver.client? id then
              if let .http1 machine := current.protocol then
                driver.applyStep id (machine.respond requestId
                  (limitedReply driver.config (driver.secureReply rejection.reply)))
            pure none
      let some request := request | continue
      let reply? ← match handler.bind (·.proxy) with
        | some plan =>
          match driver.gateway with
          | none => pure (some { response := { status := 503 } })
          | some gateway => do
            let request ← driver.traced id requestId request
            let request := match handler.bind (·.rewrite) with
              | some rewrite => rewrite request | none => request
            let result ← try
                some <$> gateway.start { downstream := id, requestId } plan request (← driver.now)
              catch _ => pure none
            pure <| match result with
              | some outcome? => outcome?.map (·.reply)
              | none => some { response := { status := 502 } }
        | none => do
          try driver.requestReply id requestId request handler
          catch _ => pure (some { response := { status := 500 }, options := { forceClose := true } })
      let some reply := reply? | return
      let some client ← driver.client? id | return
      if client.retired then return
      let .http1 machine := client.protocol | return
      let response := machine.respond requestId (limitedReply driver.config (driver.secureReply reply))
      if reply.stream.isSome && !response.state.responseStreamOpen requestId then
        driver.closeAppStreams id (some .failed) (some requestId)
      driver.applyStep id response
    | .upgraded _ =>
      if client.h2cUpgrade.isSome then
        -- The 101 barrier completed; `pump` switches this client to HTTP/2.
        let state ← driver.state.get
        let machine := ((HTTP2.Machine.State.new driver.config.http2).setTime state.now.toNat).setDate state.date
        driver.put id { client with protocol := .http2 machine, kick := true, finishSent := false }
        driver.setReading id true
      else if client.pipe.isNone then driver.closeNow id
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
    let value := deadline started driver.config.server.requestTimeoutMs
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
  let wanted := machine.keepaliveDeadline.map (deadline 0)
  if wanted == client.pingDeadline then return
  match wanted with
  | none => client.socket.cancelTimer 3
  | some value => client.socket.armTimer 3 value
  driver.put id { client with pingDeadline := wanted }

private def tunnelTicket (streamId : UInt32) (ticket : Nat) : Nat :=
  streamId.toNat * 18446744073709551616 + ticket

private def Driver.syncTunnelTimer (driver : Driver) (id : Reactor.SocketId) : IO Unit := do
  let some client ← driver.client? id | return
  let wanted := client.h2CloseDeadlines.toArray.foldl
    (fun (prior : Option UInt64) (_, value) => some (min (prior.getD value) value)) none
  match wanted with
  | none => client.socket.cancelTimer 4
  | some value => client.socket.armTimer 4 value

private def Driver.dropTunnel (driver : Driver) (id : Reactor.SocketId)
    (streamId : UInt32) : IO Unit := do
  let some client ← driver.client? id | return
  if let some pipe := client.h2Pipes[streamId]? then
    try pipe.onClose catch _ => pure ()
  driver.put id { client with
    h2Pipes := client.h2Pipes.erase streamId,
    h2Inputs := client.h2Inputs.erase streamId,
    h2Writes := client.h2Writes.erase streamId,
    h2CloseDeadlines := client.h2CloseDeadlines.erase streamId }
  driver.syncTunnelTimer id

/-- Translate one bounded WebSocket codec step into H2 stream actions. The
    codec's physical ticket remains live when peer flow control blocks DATA. -/
private def Driver.h2RawResult (driver : Driver) (id : Reactor.SocketId)
    (streamId : UInt32) (result : RawResult) : IO (List HTTP2.Machine.Action) := do
  let some client ← driver.client? id | return []
  let .http2 machine := client.protocol | return []
  if result.abortNow then
    let step := (machine.setTime (← driver.now).toNat).cancelTunnel streamId
    driver.put id { client with protocol := .http2 step.state }
    driver.dropTunnel id streamId
    return step.actions
  let mut actions := []
  if result.closeStarted then
    let value := deadline (← driver.now) 5000
    driver.put id { client with h2CloseDeadlines := client.h2CloseDeadlines.insert streamId value }
    driver.syncTunnelTimer id
  if !result.output.isEmpty then
    if result.output.size != 1 || result.ticket.isNone then
      throw (IO.userError "H2 WebSocket output requires one physical ticket")
    let some view := result.output[0]? | throw (IO.userError "missing H2 WebSocket output")
    let bytes := view.copy
    let ticket := result.ticket.getD 0
    let some current ← driver.client? id | return actions
    let .http2 machine := current.protocol | return actions
    match machine.trySendTunnel streamId ticket bytes with
    | .error _ =>
      let step := (machine.setTime (← driver.now).toNat).cancelTunnel streamId
      driver.put id { current with protocol := .http2 step.state }
      driver.dropTunnel id streamId
      actions := actions ++ step.actions
    | .ok none =>
      if current.h2Writes.contains streamId then throw (IO.userError "duplicate blocked H2 tunnel output")
      driver.put id { current with h2Writes := current.h2Writes.insert streamId (ticket, bytes) }
    | .ok (some step) =>
      driver.put id { current with protocol := .http2 step.state }
      actions := actions ++ step.actions
  if result.closeAfterWrites then
    let some current ← driver.client? id | return actions
    let .http2 machine := current.protocol | return actions
    if current.h2Writes.contains streamId then throw (IO.userError "WebSocket closed with blocked output")
    let step := machine.endTunnel streamId
    let peerEnded := current.h2Inputs[streamId]?.any (·.2)
    driver.put id { current with protocol := .http2 step.state, h2CloseDeadlines := current.h2CloseDeadlines.erase streamId, h2Pipes := if peerEnded then current.h2Pipes.erase streamId else current.h2Pipes, h2Inputs := if peerEnded then current.h2Inputs.erase streamId else current.h2Inputs }
    driver.syncTunnelTimer id
    actions := actions ++ step.actions
  return actions

/-- Retain at most one receive window of unconsumed RFC6455 bytes per stream.
    Other H2 streams keep progressing while this stream is backpressured. -/
private def Driver.h2FeedPipe (driver : Driver) (id : Reactor.SocketId)
    (streamId : UInt32) (data : ByteArray) (endStream : Bool) : IO (List HTTP2.Machine.Action) := do
  let some client ← driver.client? id | return []
  let some pipe := client.h2Pipes[streamId]? | return []
  let (prior, priorEnd) := client.h2Inputs[streamId]?.getD (ByteArray.empty, false)
  if priorEnd && !data.isEmpty then throw (IO.userError "H2 tunnel DATA after END_STREAM")
  let combined := prior.append data
  if combined.size > 65536 then
    let .http2 machine := client.protocol | return []
    let step := (machine.setTime (← driver.now).toNat).cancelTunnel streamId
    driver.put id { client with protocol := .http2 step.state }
    driver.dropTunnel id streamId
    return step.actions
  let ended := priorEnd || endStream
  if combined.isEmpty && !ended then return []
  let result ← if combined.isEmpty then pure ({ consumed := some 0 } : RawResult)
    else try pipe.onBytes (ByteSlice.full combined) catch _ => pure { abortNow := true, consumed := some 0 }
  let used := result.consumed.getD combined.size
  if used > combined.size then throw (IO.userError "H2 tunnel consumed beyond DATA")
  let remaining := combined.extract used combined.size
  if let some current ← driver.client? id then
    let inputs := if remaining.isEmpty && !ended then current.h2Inputs.erase streamId
      else current.h2Inputs.insert streamId (remaining, ended)
    driver.put id { current with h2Inputs := inputs }
  let mut actions := []
  if used > 0 then
    if let some current ← driver.client? id then
      if let .http2 machine := current.protocol then
        let step := machine.consumeTunnel streamId used
        driver.put id { current with protocol := .http2 step.state }
        actions := actions ++ step.actions
  actions := actions ++ (← driver.h2RawResult id streamId result)
  if remaining.isEmpty && ended && !result.abortNow then
    actions := actions ++ (← driver.h2RawResult id streamId (← runRawCallback pipe.onEOF))
    if let some current ← driver.client? id then
      if let .http2 machine := current.protocol then
        if !machine.canRespond streamId then
          driver.put id { current with h2Pipes := current.h2Pipes.erase streamId, h2Inputs := current.h2Inputs.erase streamId, h2CloseDeadlines := current.h2CloseDeadlines.erase streamId }
          driver.syncTunnelTimer id
  return actions

private def Driver.retryTunnelWrites (driver : Driver) (id : Reactor.SocketId) :
    IO (List HTTP2.Machine.Action) := do
  let some client ← driver.client? id | return []
  let mut actions := []
  for (streamId, (ticket, bytes)) in client.h2Writes.toArray do
    let some current ← driver.client? id | break
    let .http2 machine := current.protocol | break
    match machine.trySendTunnel streamId ticket bytes with
    | .error _ =>
      let step := (machine.setTime (← driver.now).toNat).cancelTunnel streamId
      driver.put id { current with protocol := .http2 step.state }
      driver.dropTunnel id streamId
      actions := actions ++ step.actions
    | .ok none => pure ()
    | .ok (some step) =>
      driver.put id { current with protocol := .http2 step.state, h2Writes := current.h2Writes.erase streamId }
      actions := actions ++ step.actions
  return actions

private def tunnelPayloadRanges (bytes : ByteArray) : IO (Array (Nat × Nat)) := do
  let mut ranges := #[]
  let mut cursor := 0
  for _ in [:bytes.size / 9 + 1] do
    if cursor == bytes.size then break
    if bytes.size - cursor < 9 || bytes[cursor + 3]! != 0 then
      throw (IO.userError "invalid emitted tunnel DATA frame")
    let count := bytes[cursor]!.toNat * 65536 + bytes[cursor + 1]!.toNat * 256 + bytes[cursor + 2]!.toNat
    if count > bytes.size - cursor - 9 then throw (IO.userError "truncated emitted tunnel DATA frame")
    ranges := ranges.push (cursor + 9, count)
    cursor := cursor + 9 + count
  if cursor != bytes.size then throw (IO.userError "tunnel DATA frame budget exhausted")
  return ranges

private def Driver.applyH2Step (driver : Driver) (id : Reactor.SocketId)
    (step : HTTP2.Machine.Step) : IO Unit := do
  let some client ← driver.client? id | return
  if client.retired then return
  driver.put id { client with protocol := .http2 step.state, kick := true }
  let mut actions := step.actions ++ (← driver.retryTunnelWrites id)
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
    | .writeTunnel streamId ticket wire =>
      driver.appendH2Output id output
      output := #[]
      bytes := 0
      fileBytes := 0
      let ranges ← tunnelPayloadRanges wire
      let observation : Option OutputObservation := if driver.observer.isSome then
        some { requestId := streamId.toNat, payloadRanges := ranges, finalResponse := false } else none
      driver.appendParts id #[.bytes (ByteSlice.full wire)]
        (some (tunnelTicket streamId ticket)) true observation
    | .tunnelData event =>
      if let some upload := client.uploads[event.streamId]? then
        let state ← upload.state.get
        let overflow := !state.discard &&
          (state.chunks.size >= 256 || event.data.size > upload.maxBytes - state.bytes)
        if overflow then
          driver.closeUploads id (some .overloaded) (some event.streamId)
          let .http2 machine := client.protocol | return
          let step := machine.cancelTunnel event.streamId
          driver.put id { client with protocol := .http2 step.state, uploads := client.uploads.erase event.streamId }
          actions := step.actions ++ actions
        else
          let chunks := if state.discard || event.data.isEmpty then state.chunks else state.chunks.push event.data
          upload.state.set { state with
            chunks
            bytes := if state.discard then 0 else state.bytes + event.data.size
            credit := state.credit + if state.discard then event.data.size else 0
            eof := if event.endStream then some event.trailers else state.eof
            progressed := ← driver.now }
      else
        actions := (← driver.h2FeedPipe id event.streamId event.data event.endStream) ++ actions
    | .tunnelReset streamId =>
      driver.dropTunnel id streamId
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
      driver.closeUploads id (some (match reason with
        | .timeout => .timeout | .cancelled => .streamReset | .error => .failed)) (some streamId)
      driver.closeAppStreams id (some (match reason with
        | .timeout => .timeout | .cancelled => .streamReset | .error => .failed)) (some streamId.toNat)
      driver.cancelReplies id (match reason with
        | .timeout => .timeout | .cancelled => .streamReset | .error => .failed) (some streamId.toNat)
      let outcome := match reason with
        | .cancelled => Observability.Outcome.cancelled
        | .error => .error
        | .timeout => .timeout
      if let some gateway := driver.gateway then
        gateway.cancelTicket { downstream := id, requestId := streamId.toNat }
      if let some current ← driver.client? id then
        driver.put id { current with
          proxyStreams := current.proxyStreams.erase streamId.toNat,
          dispatch := current.dispatch.erase streamId.toNat }
      driver.abortObservation id streamId.toNat outcome
    | .drainClose => close := true
    | .headReady streamId head _ =>
      let .http2 machine := client.protocol | return
      let verdict ← match driver.admission with
        | some hook => driver.admit id hook (admissionHead2 driver head)
        | none => pure (.accept none none none none)
      match verdict with
      | .reject rejection => driver.labelObservation id streamId.toNat none rejection.label
      | .accept _ _ _ label _ _ => driver.labelObservation id streamId.toNat label ""
      let step ← match verdict with
        | .reject rejection =>
          if rejection.drop then pure (machine.rejectHead streamId 421 #[])
          else
            let rejection := driver.secureRejection rejection
            pure (machine.rejectHead streamId rejection.status rejection.headers)
        | .accept limit _ _ _ _ postBody => do
          let framing := match head.contentLength with
            | some n => BodyFraming.contentLength n | none => .chunked
          let plainHead : RequestHead := {
            method := head.method, version := "HTTP/2", target := head.target, headers := head.headers }
          let decision ← try
              if metricTarget driver head.target then pure (.accept none)
              else driver.handlers.onHeaders plainHead framing
            catch _ => pure (.reject { response := { status := 500 } })
          match decision with
          | .accept _ =>
            -- A post-body validator must see terminal metadata before any
            -- handler or proxy is dispatched. The bounded H2 body lane does
            -- that; the streaming lane dispatches at the initial head.
            let streaming ← if head.protocol.isNone && postBody.isNone then
              try some <$> driver.handlers.streamRequests plainHead catch _ => pure none
              else pure (some false)
            match streaming with
            | none =>
              let rejection := driver.secureRejection { status := 500 }
              pure (machine.rejectHead streamId rejection.status rejection.headers)
            | some true =>
              if ← driver.openUpload id streamId (machine.requestEnded streamId) then
                pure (machine.admitStreamingHead streamId limit)
              else pure (machine.rejectHead streamId 503)
            | some false => pure (machine.admitHead streamId limit)
          | .upgrade _ pipe =>
            try pipe.onClose catch _ => pure ()
            pure (machine.rejectHead streamId 501 (driver.config.securityHeaders.fields driver.transport.secure))
          | .reject reply =>
            let reply := limitedReply driver.config (driver.secureReply reply)
            -- A refused H2 upload receives a bodyless final response and
            -- RST_STREAM(NO_ERROR), just like server admission rejection.
            let checked := if reply.response.status < 200 || reply.response.status > 599 then
                { reply.response with status := 500, headers := #[], body := ByteArray.empty }
              else reply.response
            let response := match checked.validate head.method with
              | .ok () => checked
              | .error _ => (driver.secureReply { response := { status := 500 } }).response
            let forbidden := ["content-length", "connection", "transfer-encoding",
              "keep-alive", "proxy-connection", "upgrade", "te"]
            let headers := response.headers.filter fun field => !forbidden.contains field.name.toLower
            pure (machine.rejectHead streamId response.status headers)
      if let .accept _ handler rewrite _ proxy postBody := verdict then
        if step.state.hasAdmittedStream streamId &&
            (handler.isSome || rewrite.isSome || proxy.isSome || postBody.isSome) then
          if let some current ← driver.client? id then
            let selected : Dispatch := { handler, rewrite, proxy, postBody }
            driver.put id { current with dispatch := current.dispatch.insert streamId.toNat selected }
      if let some current ← driver.client? id then
        driver.put id { current with protocol := .http2 step.state, kick := true }
      actions := step.actions ++ actions
    | .request event =>
      let .http2 machine := client.protocol | return
      if !machine.canRespond event.streamId then continue
      if let some tunnelHead := event.tunnelHead then
        let expectedScheme := if driver.transport.secure then "https".toUTF8 else "http".toUTF8
        if tunnelHead.scheme != expectedScheme then
          let response := machine.rejectTunnel event.streamId { status := 400 }
          driver.put id { client with protocol := .http2 response.state, kick := true }
          actions := response.actions ++ actions
          continue
        let selection ← try driver.handlers.onWebSocket tunnelHead catch _ => pure none
        let accepted := if tunnelHead.protocol == some "websocket".toUTF8 then
          selection.map fun (policy, callbacks) =>
            (WebSocket.Handshake.acceptHTTP2 tunnelHead tunnelHead.protocol policy, callbacks)
          else none
        match accepted with
        | some (outcome, callbacks) =>
          match outcome with
          | .ok handshake =>
            let pipe ← WebSocket.Server.rawPipe callbacks
            driver.put id { client with h2Pipes := client.h2Pipes.insert event.streamId pipe }
            let response := machine.acceptTunnel event.streamId handshake.response
            if let some current ← driver.client? id then
              driver.put id { current with protocol := .http2 response.state, kick := true }
            actions := response.actions ++ actions
          | .error rejection =>
            let response := machine.rejectTunnel event.streamId
              { status := rejection.status, headers := rejection.headers }
            driver.put id { client with protocol := .http2 response.state, kick := true }
            actions := response.actions ++ actions
        | none =>
          let response := machine.rejectTunnel event.streamId { status := 501 }
          driver.put id { client with protocol := .http2 response.state, kick := true }
          actions := response.actions ++ actions
        continue
      let request ← driver.withTransport id event.request
      let request := match client.uploads[event.streamId]? with
        | some upload => { request with incoming := some upload.source }
        | none => request
      let handler ← driver.takeDispatch id event.streamId.toNat
      let request ← match handler.bind (·.postBody) with
        | none => pure (some request)
        | some validate => match ← (try validate request catch _ =>
            pure (.error { status := 500 })) with
          | .ok checked => pure (some checked)
          | .error rejection => do
            driver.labelObservation id event.streamId.toNat none rejection.label
            if let some current ← driver.client? id then
              if let .http2 machine := current.protocol then
                let response := machine.respond event.streamId
                  (driver.h2RejectionReply rejection) #[]
                driver.put id { current with protocol := .http2 response.state, kick := true }
                actions := response.actions ++ actions
            pure none
      let some request := request | continue
      let reply? ← match handler.bind (·.proxy) with
        | some plan =>
          match driver.gateway with
          | none => pure (some { response := { status := 503 } })
          | some gateway => do
            let request ← driver.traced id event.streamId.toNat request
            let request := match handler.bind (·.rewrite) with
              | some rewrite => rewrite request | none => request
            let result ← try
                some <$> gateway.start { downstream := id, requestId := event.streamId.toNat }
                  plan request (← driver.now)
              catch _ => pure none
            pure <| match result with
              | some outcome? => outcome?.map (·.reply)
              | none => some { response := { status := 502 } }
        | none => do
          try driver.requestReply id event.streamId.toNat request handler
          catch _ => pure (some { response := { status := 500 } })
      let some reply := reply? | continue
      let pushes ← if (handler.bind (·.proxy)).isNone && machine.canPush && !metricTarget driver request.target then
        try driver.handlers.onPush request catch _ => pure #[]
        else pure #[]
      let some current ← driver.client? id | return
      if current.retired then return
      let .http2 machine := current.protocol | return
      let response := machine.respond event.streamId
        (limitedReply driver.config (driver.secureReply reply)) pushes
      driver.put id { current with protocol := .http2 response.state, kick := true }
      if reply.stream.isNone || !response.state.responseStreamOpen event.streamId then
        if reply.stream.isSome then driver.closeAppStreams id (some .failed) (some event.streamId.toNat)
        driver.discardUpload id event.streamId.toNat
      actions := response.actions ++ actions
  -- Preserve the generic queue's per-ticket part bound for custom large
  -- configurations without changing wire order or HTTP/1 output barriers.
  driver.appendH2Output id output
  driver.syncPingTimer id
  if close then driver.beginDrain id

private def Driver.failH2 (driver : Driver) (id : Reactor.SocketId)
    (machine : HTTP2.Machine.State) (error : HTTP2.ProtocolError) : IO Unit :=
  driver.applyH2Step id (machine.fail error)

private def Driver.setProxyStream (driver : Driver) (id : Reactor.SocketId)
    (requestId : Nat) (value : Option ProxyStream) : IO Unit := do
  if let some client ← driver.client? id then
    let streams := match value with
      | some stream => client.proxyStreams.insert requestId stream
      | none => client.proxyStreams.erase requestId
    driver.put id { client with proxyStreams := streams }

private def Driver.proxyReply (driver : Driver) (id : Reactor.SocketId)
    (requestId : Nat) (reply : Reply) : IO Unit := do
  let reply ← driver.prepareReply id requestId reply
  let some client ← driver.client? id | return
  let secured := applySecurityHeaders (driver.config.securityHeaders.fields driver.transport.secure)
    reply.response
  let bounded := limitedReply driver.config { reply with response := secured }
  match client.protocol with
  | .http1 machine =>
    let response := machine.respond requestId bounded
    if reply.stream.isSome && !response.state.responseStreamOpen requestId then
      driver.closeAppStreams id (some .failed) (some requestId)
    driver.applyStep id response
  | .http2 machine =>
    if requestId <= 2147483647 then
      let response := machine.respond requestId.toUInt32 bounded #[]
      if reply.stream.isNone || !response.state.responseStreamOpen requestId.toUInt32 then
        if reply.stream.isSome then driver.closeAppStreams id (some .failed) (some requestId)
        driver.discardUpload id requestId
      driver.applyH2Step id response
  | _ => pure ()

/-- Poll every job once per turn. A slow HTTP/2 stream never prevents a later
stream from completing. All response publication stays on the socket owner. -/
private def Driver.pumpReplies (driver : Driver) : IO Unit := do
  -- Publication can retire a connection and remove other jobs. Snapshot
  -- only their keys and check the index before polling each job.
  let state ← driver.state.get
  let keys := state.pendingReplies.keys
  let now := state.now
  for (owner, requestId) in keys do
    let some pending := ((← driver.state.get).pendingReplies.forClient owner)[requestId]? | continue
    let some client ← driver.client? owner | do
      driver.cancelReplies owner .disconnected
      continue
    if client.retired then
      driver.cancelReplies owner .disconnected
      continue
    let (reply, reason) ← if now >= pending.deadline then
        pure (some { response := { status := 504 } }, some Deferred.CancelReason.timeout)
      else try
        let reply ← pending.job.poll
        pure (reply, none)
      catch _ => pure (some { response := { status := 500 } }, some Deferred.CancelReason.failed)
    let some reply := reply | continue
    -- Commit removal before cancellation or publication; both can retire a
    -- connection and recursively run lifecycle cleanup.
    driver.state.modify fun state => { state with
      pendingReplies := (state.pendingReplies.remove owner requestId).2 }
    if let some reason := reason then try pending.job.cancel reason catch _ => pure ()
    driver.proxyReply owner requestId reply

private def Driver.abortProxyStream (driver : Driver) (id : Reactor.SocketId)
    (requestId : Nat) : IO Unit := do
  let some client ← driver.client? id | return
  driver.setProxyStream id requestId none
  match client.protocol with
  | .http1 machine => driver.applyStep id (machine.abortStream requestId)
  | .http2 machine =>
    if requestId <= 2147483647 then
      driver.applyH2Step id ((machine.setTime (← driver.now).toNat).abortResponseStream requestId.toUInt32)
  | _ => pure ()

private def Driver.pumpUploads (driver : Driver) : IO Unit := do
  for (id, snapshot) in (← driver.state.get).clients.toArray do
    for (key, upload) in snapshot.uploads.toArray do
      let source ← upload.state.get
      let now ← driver.now
      let reason := source.cancelled.orElse fun _ =>
        if source.eof.isNone && now.toNat - source.progressed.toNat >= driver.config.server.requestTimeoutMs then some .timeout else none
      if let some reason := reason then
        driver.closeUploads id (some reason) (some key)
        driver.closeAppStreams id (some reason) (some key.toNat)
        driver.cancelReplies id reason (some key.toNat)
        if let some client ← driver.client? id then
          if let .http2 machine := client.protocol then driver.applyH2Step id (machine.cancelTunnel key)
        continue
      if source.credit > 0 then
        upload.state.set { source with credit := 0 }
        if let some client ← driver.client? id then
          if let .http2 machine := client.protocol then
            driver.applyH2Step id (machine.consumeTunnel key source.credit)
      let source ← upload.state.get
      if (source.discard || source.consumedEnd) && source.eof.isSome && source.bytes == 0 then
        driver.closeUploads id none (some key)

private def Driver.setAppStream (driver : Driver) (id : Reactor.SocketId) (key : Nat)
    (stream : AppStream) : IO Unit := do
  if let some client ← driver.client? id then
    if client.appStreams.contains key then
      driver.put id { client with appStreams := client.appStreams.insert key stream }

private def Driver.abortAppStream (driver : Driver) (id : Reactor.SocketId) (key : Nat)
    (reason : Deferred.CancelReason) : IO Unit := do
  driver.closeAppStreams id (some reason) (some key)
  driver.abortProxyStream id key

/-- At most one producer event and one DATA write per stream per worker turn.
No producer runs ahead of bounded output or HTTP/2 stream flow control. -/
private def Driver.pumpAppStreams (driver : Driver) : IO Unit := do
  for (id, snapshot) in (← driver.state.get).clients.toArray do
    if snapshot.retired || snapshot.closing then continue
    for (key, _) in snapshot.appStreams.toArray do
      let some client ← driver.client? id | continue
      let some stream := client.appStreams[key]? | continue
      let now ← driver.now
      if now.toNat - stream.started.toNat >= stream.body.lifetimeMs ||
          now.toNat - stream.progressed.toNat >= stream.body.idleTimeoutMs then
        driver.abortAppStream id key .timeout
        continue
      let available := driver.config.maxOutputBytes - min client.outputBytes driver.config.maxOutputBytes
      let ceiling := min driver.config.maxOutputBytes 262144
      if client.outputBytes >= ceiling || available < 256 then continue
      let budget := min 65536 (available - 256)
      let budget := match client.protocol with
        | .http1 machine => if machine.canStreamChunk key then budget else 0
        | .http2 machine => min budget (machine.streamSendBudget key.toUInt32)
        | _ => 0
      if let .http1 machine := client.protocol then
        if !machine.canStreamChunk key then continue
      if stream.pending.size == stream.offset && stream.ending.isNone then
        let event ← try bodyPoll stream.body budget catch _ => do
          driver.abortAppStream id key .failed
          pure none
        if let some event := event then
          match event with
          | .data bytes =>
            if bytes.isEmpty || bytes.size > budget ||
                stream.body.knownLength.any (fun length => stream.sent + bytes.size > length) then
              driver.abortAppStream id key .failed
              continue
            driver.setAppStream id key { stream with pending := bytes, offset := 0, progressed := now }
          | .finish trailers =>
            if trailers.size > driver.config.server.maxResponseHeaders ||
                trailers.foldl (fun n h => n + h.name.utf8ByteSize + h.value.size + 4) 0 > driver.config.server.maxResponseHeaderBytes ||
                trailers.any (fun h => !stream.body.declaredTrailers.any (·.toLower == h.name.toLower) ||
                  h.value.data.any (fun b => (b < 32 && b != 9) || b == 127)) ||
                stream.body.knownLength.any (· != stream.sent) then
              driver.abortAppStream id key .failed
              continue
            driver.setAppStream id key { stream with ending := some trailers }
      let some client ← driver.client? id | continue
      let some stream := client.appStreams[key]? | continue
      if stream.pending.size > stream.offset then
        let bytes := stream.pending.extract stream.offset stream.pending.size
        match client.protocol with
        | .http1 machine =>
          if !machine.canStreamChunk key then continue
          driver.setAppStream id key { stream with
            pending := ByteArray.empty
            offset := 0
            sent := stream.sent + bytes.size
            progressed := now }
          driver.applyStep id (machine.streamChunk key bytes)
        | .http2 machine =>
          match machine.tryStreamData key.toUInt32 bytes with
          | .error _ => driver.abortAppStream id key .failed
          | .ok none => pure ()
          | .ok (some (count, step)) =>
            let offset := stream.offset + count
            driver.setAppStream id key { stream with
              pending := if offset == stream.pending.size then ByteArray.empty else stream.pending
              offset := if offset == stream.pending.size then 0 else offset
              sent := stream.sent + count, progressed := now }
            driver.applyH2Step id step
        | _ => driver.abortAppStream id key .failed
      else if let some trailers := stream.ending then
        match client.protocol with
        | .http1 machine =>
          if !machine.canEndStream key then continue
          driver.closeAppStreams id none (some key)
          driver.applyStep id (machine.endStream key trailers)
        | .http2 machine =>
          match machine.endResponseStream key.toUInt32 trailers with
          | .error _ => driver.abortAppStream id key .failed
          | .ok step =>
            driver.closeAppStreams id none (some key)
            driver.applyH2Step id step
        | _ => driver.abortAppStream id key .failed
where
  bodyPoll (body : Stream.Body) (budget : Nat) : IO (Option Stream.Event) := body.poll budget

private def Driver.proxyOutcomes (driver : Driver) (outcomes : Array Gateway.Outcome) : IO Unit := do
  for outcome in outcomes do
    let id := outcome.ticket.downstream
    let requestId := outcome.ticket.requestId
    let some client ← driver.client? id | continue
    if client.retired || client.closing then continue
    match outcome.stream with
    | none =>
      if client.proxyStreams.contains requestId then
        driver.abortProxyStream id requestId
      else driver.proxyReply id requestId outcome.reply
    | some (.start head) =>
      if client.proxyStreams.contains requestId then
        driver.abortProxyStream id requestId
        continue
      let .ok decoded := Gateway.decodeReply head ByteArray.empty
        | do
          if let some gateway := driver.gateway then gateway.cancelTicket outcome.ticket
          driver.proxyReply id requestId { response := { status := 502 } }
          continue
      let secured := applySecurityHeaders (driver.config.securityHeaders.fields driver.transport.secure)
        decoded.response
      let reply := limitedReply driver.config { decoded with response := secured }
      let .ok declared := Gateway.declaredTrailers head
        | do
          if let some gateway := driver.gateway then gateway.cancelTicket outcome.ticket
          driver.proxyReply id requestId { response := { status := 502 } }
          continue
      let length : Option Nat := match head.framing with
        | .contentLength value => some value
        | _ => none
      if reply.response.status != head.status.toNat ||
          length.any (· > driver.config.machine.maxStreamResponseBytes) then
        if let some gateway := driver.gateway then gateway.cancelTicket outcome.ticket
        driver.proxyReply id requestId { response := { status := 502 } }
        continue
      match client.protocol with
      | .http1 machine =>
        let declared := if length.isNone && machine.streamSupportsTrailers then declared else #[]
        driver.setProxyStream id requestId (some { head, declared })
        driver.applyStep id (machine.beginStream requestId reply.response length declared)
      | .http2 machine =>
        if requestId > 2147483647 then continue
        match machine.beginResponseStream requestId.toUInt32 reply.response with
        | .ok step =>
          driver.setProxyStream id requestId (some { head, declared })
          driver.applyH2Step id step
        | .error _ =>
          if let some gateway := driver.gateway then gateway.cancelTicket outcome.ticket
          driver.proxyReply id requestId { response := { status := 502 } }
      | _ =>
        if let some gateway := driver.gateway then gateway.cancelTicket outcome.ticket
    | some (.data bytes) =>
      let some stream := client.proxyStreams[requestId]? | do
        if let some gateway := driver.gateway then gateway.cancelTicket outcome.ticket
        continue
      if stream.offset < stream.pending.size || bytes.isEmpty || bytes.size > 65536 then
        if let some gateway := driver.gateway then gateway.cancelTicket outcome.ticket
        driver.abortProxyStream id requestId
      else
        driver.setProxyStream id requestId (some {
          stream with pending := bytes, offset := 0, upstreamPaused := true })
    | some (.finish trailers) =>
      if let some stream := client.proxyStreams[requestId]? then
        driver.setProxyStream id requestId (some { stream with finish := some trailers })
    | some .abort => driver.abortProxyStream id requestId

/-- Offer at most one bounded body piece per stream per pass. A blocked HTTP/2
    flow window or an HTTP/1 output acknowledgement leaves the slice owned by
    this client. The upstream stays read-paused until that slice is accepted. -/
private def Driver.pumpProxyStreams (driver : Driver) : IO Unit := do
  let clients := (← driver.state.get).clients.toArray
  for (id, snapshot) in clients do
    if snapshot.retired || snapshot.closing then continue
    for (requestId, _) in snapshot.proxyStreams.toArray do
      let some client ← driver.client? id | continue
      let some stream := client.proxyStreams[requestId]? | continue
      if client.retired || client.closing then continue
      let ceiling := min driver.config.maxOutputBytes 262144
      let available := driver.config.maxOutputBytes - min client.outputBytes driver.config.maxOutputBytes
      let pending := stream.pending.size - min stream.offset stream.pending.size
      if pending > 0 then
        if client.outputBytes >= ceiling || available <= 128 then continue
        let count := min pending (min 16384 (available - 128))
        if count == 0 then continue
        let bytes := stream.pending.extract stream.offset (stream.offset + count)
        match client.protocol with
        | .http1 machine =>
          if !machine.canStreamChunk requestId then continue
          let nextOffset := stream.offset + count
          let next := if nextOffset == stream.pending.size then
            { stream with pending := ByteArray.empty, offset := 0 }
            else { stream with offset := nextOffset }
          driver.setProxyStream id requestId (some next)
          driver.applyStep id (machine.streamChunk requestId bytes)
        | .http2 machine =>
          if requestId > 2147483647 then continue
          match machine.tryStreamData requestId.toUInt32 bytes with
          | .error _ => driver.abortProxyStream id requestId
          | .ok none => pure ()
          | .ok (some (consumed, step)) =>
            let nextOffset := stream.offset + consumed
            let next := if nextOffset == stream.pending.size then
              { stream with pending := ByteArray.empty, offset := 0 }
              else { stream with offset := nextOffset }
            driver.setProxyStream id requestId (some next)
            driver.applyH2Step id step
        | _ => driver.abortProxyStream id requestId
        continue
      if let some trailers := stream.finish then
        match client.protocol with
        | .http1 machine =>
          if !machine.canStreamChunk requestId then continue
          let .ok decoded := Gateway.decodeReply stream.head ByteArray.empty trailers
            | do driver.abortProxyStream id requestId; continue
          let downstreamTrailers := decoded.options.trailers.filter
            (fun field => stream.declared.contains field.name.toLower)
          driver.setProxyStream id requestId none
          driver.applyStep id (machine.endStream requestId downstreamTrailers)
        | .http2 machine =>
          if requestId > 2147483647 then continue
          let .ok decoded := Gateway.decodeReply stream.head ByteArray.empty trailers
            | do driver.abortProxyStream id requestId; continue
          match machine.endResponseStream requestId.toUInt32 decoded.options.trailers with
          | .ok step =>
            driver.setProxyStream id requestId none
            driver.applyH2Step id step
          | .error _ => driver.abortProxyStream id requestId
        | _ => driver.abortProxyStream id requestId
        continue
      if stream.upstreamPaused && client.outputBytes < ceiling then
        let ready := match client.protocol with
          | .http1 machine => machine.canStreamChunk requestId
          | .http2 _ => true
          | _ => false
        if ready then
          if let some gateway := driver.gateway then
            driver.setProxyStream id requestId (some { stream with upstreamPaused := false })
            driver.proxyOutcomes (← gateway.resume { downstream := id, requestId } (← driver.now))

private def Driver.rawResult (driver : Driver) (id : Reactor.SocketId) (result : RawResult) : IO Unit := do
  if result.abortNow then driver.closeNow id; return
  if result.ticket.isSome && result.output.isEmpty then
    throw (IO.userError "raw output ticket has no bytes")
  driver.appendOutput id result.output result.ticket result.ticket.isSome
  if let some enabled := result.readEnabled then driver.setReading id enabled
  if result.closeStarted then
    if let some client ← driver.client? id then
      client.socket.armTimer 4 (deadline (← driver.now) 5000)
  if result.closeAfterWrites then
    if let some client ← driver.client? id then
      driver.put id { client with closeWhenQueued := true }
      driver.setReading id false

/-- A TLS handshake accepted before admission stopped may publish READY during
    draining. Give it the same shutdown policy as the initial client snapshot. -/
private def Driver.shutdownClient (driver : Driver) (id : Reactor.SocketId) : IO Unit := do
  let some client ← driver.client? id | return
  if client.retired || client.closing then return
  match client.protocol with
  | .http1 machine => driver.applyStep id machine.shutdown
  | .http2 machine =>
    driver.applyH2Step id machine.goAway
    for (streamId, pipe) in client.h2Pipes.toArray do
      let more ← driver.h2RawResult id streamId (← runRawCallback pipe.onShutdown)
      if let some current ← driver.client? id then
        if let .http2 next := current.protocol then
          driver.applyH2Step id { state := next, actions := more }
  | .raw =>
    if let some pipe := client.pipe then driver.rawResult id (← runRawCallback pipe.onShutdown)
    else driver.beginDrain id
  | .detect _ =>
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
    if matched >= 16 then
      -- "PRI * HTTP/2.0\r\n" is never a valid HTTP/1 request: this peer speaks
      -- HTTP/2 with a corrupt preface. Let the HTTP/2 machine reject it with
      -- GOAWAY(PROTOCOL_ERROR) (RFC 9113 §3.4) instead of an HTTP/1 error.
      let machine := ((HTTP2.Machine.State.new driver.config.http2).setTime state.now.toNat).setDate state.date
      driver.put id { current with protocol := .http2 machine, kick := true }
      driver.applyH2Step id machine.start
      if let some client ← driver.client? id then
        if let .http2 machine := client.protocol then
          driver.applyH2Step id (machine.feedSlice preface 0 matched)
      return
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
  if let some client ← driver.client? id then
    if let (some (settings, h2head, head, requestId), .http2 machine) := (client.h2cUpgrade, client.protocol) then
      let mut requests := client.requests
      if let some request := requests[requestId]? then
        if request.pendingOutputs != 0 then
          throw (IO.userError "h2c observation crossed an incomplete 101 write barrier")
        requests := requests.erase requestId
        if requests.contains 1 then
          throw (IO.userError "h2c stream observation collides with an unfinished request")
        requests := requests.insert 1 { request with protocol := .http2 }
      -- The head was admitted at the HTTP/1 stage; its handler now serves stream 1.
      let dispatch := match client.dispatch[requestId]? with
        | some handler => (client.dispatch.erase requestId).insert 1 handler
        | none => client.dispatch
      driver.put id { client with h2cUpgrade := none, requests, dispatch }
      driver.applyH2Step id (machine.upgrade settings h2head head)
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
        let consumed := result.consumed.getD chunk.view.length
        if consumed > chunk.view.length then throw (IO.userError "raw pipe consumed beyond input view")
        driver.consume id consumed
        driver.rawResult id result
        advanced := consumed != 0 || !result.output.isEmpty || result.closeAfterWrites
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
  let value := deadline state.now driver.config.server.idleTimeoutMs
  socket.armTimer 0 value
  let protocol := match protocol with
    | .detect => driver.config.cleartextProtocol
    | other => other
  let protocol := match protocol with
    | .detect => Protocol.detect 0
    | .http1 => .http1 (((Machine.State.new driver.config.machine).setDate state.date).setTime state.now.toNat)
    | .http2 => .http2 (((HTTP2.Machine.State.new driver.config.http2).setTime state.now.toNat).setDate state.date)
  let remote ← if driver.observer.isSome then id.peerAddress driver.reactor else pure ByteArray.empty
  driver.put id { socket, protocol, idleDeadline := some value, remote }
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
  let paused := match client.protocol with
    | .http1 _ => !client.appStreams.isEmpty || state.pendingReplies.byClient.contains id
    | _ => false
  let chunk ← if paused then do
      let owned := view.copy
      release
      pure { view := ByteSlice.full owned, arrived := state.now : InputChunk }
    else pure { view, release, arrived := state.now }
  driver.put id { client with
    inputBack := chunk :: client.inputBack
    inputBytes := client.inputBytes + view.length
    kick := true }
  if let some client ← driver.client? id then
    if client.idleDeadline.isSome then
      let value := deadline state.now driver.config.server.idleTimeoutMs
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
        else if let .http2 _ := client.protocol then
          let streamId := UInt32.ofNat (outputId / 18446744073709551616)
          let ticket := outputId % 18446744073709551616
          if let some pipe := client.h2Pipes[streamId]? then
            let more ← driver.h2RawResult id streamId (← runRawCallback (pipe.onWritten ticket))
            let more := more ++ (← driver.h2FeedPipe id streamId ByteArray.empty false)
            if let some current ← driver.client? id then
              if let .http2 machine := current.protocol then
                driver.applyH2Step id { state := machine, actions := more }
        else if let some pipe := client.pipe then
          driver.rawResult id (← runRawCallback (pipe.onWritten outputId))
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
  if kind == 4 then
    if !client.closing then
      if let some pipe := client.pipe then driver.rawResult id (← runRawCallback pipe.onTimeout)
      else
        for (streamId, due) in client.h2CloseDeadlines.toArray do
          if due <= state.now then
            if let some current ← driver.client? id then
              if let some pipe := current.h2Pipes[streamId]? then
                let more ← driver.h2RawResult id streamId (← runRawCallback pipe.onTimeout)
                if let some latest ← driver.client? id then
                  if let .http2 machine := latest.protocol then
                    driver.applyH2Step id { state := machine, actions := more }
        driver.syncTunnelTimer id
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
    let mut inbound := #[]
    for index in [:count] do
      let native ← driver.reactor.event index.toUInt32
      -- Drain every upstream completion before dispatching any downstream
      -- request from this batch. An idle socket with unsolicited bytes is
      -- discarded before a new request can check it out.
      let consumed ← match driver.gateway with
        | none => pure false
        | some gateway => do
          let (consumed, outcomes) ← gateway.onNative native (← driver.now)
          driver.proxyOutcomes outcomes
          pure consumed
      if consumed then continue
      inbound := inbound.push native
    for native in inbound do
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

private def Driver.pumpPipes (driver : Driver) : IO Unit := do
  for (id, snapshot) in (← driver.state.get).clients.toArray do
    if snapshot.retired || snapshot.closing then continue
    if let some pipe := snapshot.pipe then
      let result ← runRawCallback pipe.onPoll
      driver.rawResult id result
    for (key, pipe) in snapshot.h2Pipes.toArray do
      let result ← runRawCallback pipe.onPoll
      let actions ← driver.h2RawResult id key result
      if !actions.isEmpty then
        if let some client ← driver.client? id then
          if let .http2 machine := client.protocol then driver.applyH2Step id { state := machine, actions }

private def Driver.tickApplication (driver : Driver) : IO Unit := do
  let state ← driver.state.get
  if state.now.toNat < state.nextAppTick then return
  driver.state.modify fun current => { current with nextAppTick := state.now.toNat + driver.handlers.tickIntervalMs }
  driver.handlers.onTick (← IO.monoMsNow)

private partial def Driver.loop (driver : Driver) : IO Unit := do
  if ← driver.group.stopping then return
  driver.serveReloads
  driver.refresh
  driver.tickApplication
  driver.events (← driver.transport.poll)
  if let some gateway := driver.gateway then
    driver.proxyOutcomes (← gateway.pump (← driver.now))
  driver.pumpReplies
  driver.pumpAppStreams
  driver.pumpPipes
  driver.pumpUploads
  driver.pumpAll
  driver.pumpProxyStreams
  let ready ← driver.hasWork
  let providerReady ← driver.transport.hasWork
  let state ← driver.state.get
  let pending := state.pendingReplies.count > 0 || state.appStreamCount > 0
  driver.pollEvents (if ready || providerReady then 0 else if pending then driver.config.deferred.pollIntervalMs.toUInt32.toInt32 else (min 100 driver.handlers.tickIntervalMs).toUInt32.toInt32)
  driver.loop

/-- Stop admission, finish current HTTP/1 requests and queued output, and send
    HTTP/2 GOAWAY while accepted streams retain their flow-control traffic.
    Providers share the same absolute deadline for their close-notify work. -/
private def Driver.drain (driver : Driver) : IO Unit := do
  let cutoff := deadline (← Reactor.nowMs) driver.config.shutdownDrainMs
  let reserve := min (driver.config.shutdownDrainMs / 4) driver.transport.shutdownReserveMs.toNat
  let applicationCutoff := cutoff - reserve.toUInt64
  driver.state.modify fun state => { state with draining := true }
  -- Public application deadlines use Lean's monotonic clock. Its epoch can
  -- differ from CLOCK_MONOTONIC/GetTickCount64 used by native socket timers.
  let remaining := (cutoff - min cutoff (← Reactor.nowMs)).toNat
  driver.handlers.onDrain ((← IO.monoMsNow) + remaining)
  driver.transport.shutdownBefore cutoff
  for (id, _) in (← driver.state.get).clients.toArray do driver.shutdownClient id
  let mut active := true
  while active && (← Reactor.nowMs) < applicationCutoff do
    driver.refresh
    driver.tickApplication
    driver.events (← driver.transport.poll)
    if let some gateway := driver.gateway then
      driver.proxyOutcomes (← gateway.pump (← driver.now))
    driver.pumpReplies
    driver.pumpAppStreams
    driver.pumpPipes
    driver.pumpUploads
    driver.pumpAll
    driver.pumpProxyStreams
    active := !(← driver.state.get).clients.isEmpty || !(← driver.handlers.isDrained)
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
      driver.tickApplication
      driver.events (← driver.transport.poll)
      transportActive := !(← driver.state.get).clients.isEmpty || !(← driver.transport.shutdownComplete) || !(← driver.handlers.isDrained)
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
   if handlers.tickIntervalMs == 0 || handlers.tickIntervalMs > 60000 then
     throw (IO.userError "application tick interval must be between 1 and 60000ms")
   let pool := config.native.buffers4k.toNat + config.native.buffers16k.toNat + config.native.buffers64k.toNat
   let available := pool - transport.reservedBuffers
   let count := min config.outputBuffers (min (clientLimit * 4) (min config.native.maxWrites.toNat (available - 1)))
   if count == 0 || count > 65535 then throw (IO.userError "HTTP requires reserved output and receive buffer credits")
   if count < clientLimit then
     throw (IO.userError "HTTP output buffer credits must cover every admitted client")
   withOutputSlots reactor count fun slots => do
    let state ← IO.mkRef { slots, traces := ← TraceContext.Generator.seeded : WorkerState }
    let observer ← match hub with
      | none => pure none
      | some hub => do
        let lane ← hub.lane workerId
        pure (some { hub, lane : WorkerObserver })
    let resetErrno := -(Errno.decode (← FFI.errnoEconnreset))
    let reloadSeen ← IO.mkRef (← Reactor.reloadRequests)
    let admission ← match config.admission with
      | some factory => some <$> factory workerId
      | none => pure none
    let gateway ← config.gateway.mapM (fun options => Gateway.Engine.new reactor options)
    let driver : Driver := { admission, gateway, reactor, group, config, handlers, transport, clientLimit, state, observer,
                             resetErrno, control := workerId == 0, reloadSeen }
    try
      driver.loop
      driver.drain
    finally
      let state ← driver.state.get
      let cleanup := state.clients.toArray.map fun (id, _) => driver.forget id
      let cleanup := cleanup.push (do
        if let some observer := driver.observer then observer.lane.publish (← driver.state.get).counters)
      let cleanup := cleanup.push (do if let some engine := gateway then engine.close)
      let cleanup := cleanup.push handlers.onShutdown
      cleanupActions cleanup

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
    processMetrics := match hub with
      | some hub => hub.processMetrics
      | none => pure ByteArray.empty
    -- Draining begins when the pool stops; readiness then reports 503.
    draining := do return (← finished.get) || (← Reactor.processStopping)
    extraMetrics := config.extraMetrics }
  Admin.withServer port source stop fun run => do
    let task ← IO.asTask run Task.Priority.dedicated
    try serve
    finally
      finished.set true
      stop.set true
      match ← IO.wait task with
      | .ok _ => pure ()
      | .error error => throw error

/-- Construct independent callbacks and state inside each dedicated worker.
    The global client limit is partitioned, rather than multiplied by workers. -/
def serveWorkerFactory (resources : WithWorkerResources) (config : ReactorServerConfig := {})
    (host : String := "127.0.0.1") (port : UInt16 := 8080) : IO Unit := do
  if config.server.maxClients == 0 || config.server.idleTimeoutMs == 0 ||
      config.server.requestTimeoutMs == 0 || config.server.writeTimeoutMs == 0 ||
      config.outputBuffers == 0 || config.maxInputBytes == 0 || config.maxOutputBytes < 4096 ||
      config.server.maxFileResponseBytes == 0 || config.server.maxFileResponseBytes > 9223372036854775807 ||
      config.maxQueuedFileBytes < config.server.maxFileResponseBytes || config.maxQueuedFileBytes > 9223372036854775807 ||
      config.workPerClient == 0 || config.shutdownDrainMs == 0 then
    throw (IO.userError "HTTP limits and timeouts must be positive")
  let remainingClock := maxNativeDeadline - (← Reactor.nowMs).toNat
  let timeouts := #[
    ("idleTimeoutMs", config.server.idleTimeoutMs),
    ("requestTimeoutMs", config.server.requestTimeoutMs),
    ("writeTimeoutMs", config.server.writeTimeoutMs),
    ("shutdownDrainMs", config.shutdownDrainMs),
    ("deferred.maxTimeoutMs", config.deferred.maxTimeoutMs),
    ("http2.pingIntervalMs", config.http2.pingIntervalMs),
    ("http2.pingTimeoutMs", config.http2.pingTimeoutMs)]
  for (name, duration) in timeouts do
    if duration > remainingClock then
      throw (IO.userError s!"HTTP {name} exceeds native clock range")
  match config.deferred.validate with
  | .error message => throw (IO.userError message)
  | .ok () => pure ()
  match config.http2.validate with
  | .error message => throw (IO.userError message)
  | .ok () => pure ()
  if let some path := config.metricsPath then
    if path.isEmpty || path.size > 256 || path[0]! != 47 ||
        path.data.any (fun byte => byte <= 32 || byte >= 127 || byte == 63 || byte == 35) then
      throw (IO.userError "metrics path must be a bounded origin path without query or fragment")
  let workers ← workerCount config.workers config.server.maxClients
  -- Both shared onHeaders middleware and admission run before H2 bodies.
  let config := { config with http2 := { config.http2 with headGate := true } }
  let observing := config.metricsPath.isSome || config.accessLog.isSome || config.adminPort.isSome
  let config := { config with
    workers
    machine := { config.machine with trackOutput := observing || config.machine.trackOutput }
    http2 := { config.http2 with trackOutput := observing || config.http2.trackOutput } }
  if observing then
    Observability.withHub (sampleProcessMetrics :=
        if config.metricsPath.isSome || config.adminPort.isSome then some Admin.processPrometheus else none)
      workers config.accessLog fun hub =>
      withAdmin config workers (some hub) <|
        withWorkerPool host port workers config.server.maxClients config.native
          (runWorker resources config (some hub))
          ((config.gateway.map (·.pool.maxTotal)).getD 0) config.connectionRate
  else
    withWorkerPool host port workers config.server.maxClients config.native
      (runWorker resources config none)
      ((config.gateway.map (·.pool.maxTotal)).getD 0) config.connectionRate

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
