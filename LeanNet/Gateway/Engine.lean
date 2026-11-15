import Std.Data.HashMap
import LeanNet.Gateway.Pool
import LeanNet.Gateway.Wire
import LeanNet.Gateway.Resolve
import LeanNet.Gateway.Transport

/-! Owner-thread HTTP/1.1 reverse-proxy transaction engine. It shares the
server's reactor and never waits for a connect, read, write or backend reply.
Only a complete, unambiguous response may return a socket to the pool. -/

namespace LeanNet.Gateway

open LeanNet
open LeanNet.HTTP
open LeanNet.HTTP1

structure Config where
  pool : Pool.Config := { maxTotal := 64, maxPerTarget := 16 }
  response : ClientResponse.Limits := {}
  responseTimeoutMs : UInt64 := 30000
  maxQueuedWrites : Nat := 4
  resolveTimeoutMs : UInt64 := 5000
  resolveCacheMs : UInt64 := 60000
  tlsProviderFactory : Option (Reactor.Reactor → IO TLSProvider) := none

structure Ticket where
  downstream : Reactor.SocketId
  requestId : Nat
  deriving BEq

/-- One bounded step of an upstream response. A stream starts only after its
head passes the gateway's downstream-header validation. After `.start`, any
failure becomes `.abort`; a replacement HTTP status would be ambiguous. -/
inductive StreamEvent where
  | start (head : ClientResponse.Head)
  | data (bytes : ByteArray)
  | finish (trailers : Array ClientResponse.Header)
  | abort

structure Outcome where
  ticket : Ticket
  reply : Reply
  stream : Option StreamEvent := none

private structure Job where
  ticket : Ticket
  lease : Option Pool.Lease := none
  tls : Option TLSSession := none
  tlsVerified : Bool := false
  tlsReady : Bool := false
  pendingCipher : Option ByteArray := none
  parser : ClientResponse.Parser
  wire : Array ByteArray
  part : Nat := 0
  offset : Nat := 0
  pendingWrites : Nat := 0
  head : Option ClientResponse.Head := none
  body : Array ByteArray := #[]
  bodyBytes : Nat := 0
  trailers : Array ClientResponse.Header := #[]
  streaming : Bool := false
  paused : Bool := false
  /-- POSIX may have already emitted up to one poll's 64 KiB read budget
  before read interest is disabled. Coalesce only that bounded remainder. -/
  pendingInput : Option ByteArray := none
  pendingCipherInput : Option ByteArray := none
  /-- EOF can share a completion batch with data held behind downstream credit. -/
  pendingEOF : Bool := false

private abbrev ResolveTask := Task (Except IO.Error (Except Resolve.Error ByteArray))

private structure PendingResolve where
  ticket : Ticket
  target : Admission.UpstreamTarget
  wire : Array ByteArray
  parser : ClientResponse.Parser
  since : UInt64

private structure State where
  jobs : Std.HashMap Reactor.SocketId Job := {}
  retired : Array Reactor.SocketId := #[]
  nextReapMs : UInt64 := 0
  nextTarget : Nat := 0
  resolved : Std.HashMap String (ByteArray × UInt64) := {}
  resolving : Std.HashMap String ResolveTask := {}
  pendingResolve : Array PendingResolve := #[]

structure Engine where
  private mk ::
  reactor : Reactor.Reactor
  pool : Pool.Pool
  config : Config
  tlsProvider : Option TLSProvider
  private state : IO.Ref State

private def errorReply (status : Nat) : Reply :=
  { response := { status } }

def Engine.new (reactor : Reactor.Reactor) (config : Config := {}) : IO Engine := do
  if config.responseTimeoutMs == 0 || config.resolveTimeoutMs == 0 ||
      config.resolveCacheMs == 0 || config.maxQueuedWrites == 0 ||
      config.responseTimeoutMs.toNat > 9223372036854775807 then
    throw (IO.userError "invalid gateway response timeout or write credits")
  let tlsProvider ← config.tlsProviderFactory.mapM (· reactor)
  let poolConfig := { config.pool with allowTls := tlsProvider.isSome }
  let .ok pool ← Pool.new reactor poolConfig
    | do
      if let some provider := tlsProvider then provider.close
      throw (IO.userError "invalid gateway pool configuration")
  return ⟨reactor, pool, config, tlsProvider, ← IO.mkRef {}⟩

private def Engine.retire (engine : Engine) (id : Reactor.SocketId) : IO Unit :=
  engine.state.modify fun state =>
    { state with retired := if state.retired.contains id then state.retired else state.retired.push id }

private def Engine.removeJob (engine : Engine) (id : Reactor.SocketId) : IO Unit :=
  engine.state.modify fun state => { state with jobs := state.jobs.erase id }

private def Engine.job? (engine : Engine) (id : Reactor.SocketId) : IO (Option Job) :=
  return (← engine.state.get).jobs[id]?

private def Engine.putJob (engine : Engine) (id : Reactor.SocketId) (job : Job) : IO Unit :=
  engine.state.modify fun state => { state with jobs := state.jobs.insert id job }

private def Engine.abort (engine : Engine) (id : Reactor.SocketId) (status : Nat) : IO (Option Outcome) := do
  let some job ← engine.job? id | return none
  engine.removeJob id
  if let some lease := job.lease then
    let _ ← engine.pool.discard lease
  else
    let _ ← engine.pool.onError id
  engine.retire id
  let stream := if job.streaming then some StreamEvent.abort else none
  return some { ticket := job.ticket, reply := errorReply status, stream }

private def Job.hasUnqueued (job : Job) : Bool := job.part < job.wire.size

private def Job.bodyCapable (job : Job) (head : ClientResponse.Head) : Bool :=
  job.parser.requestMethod != "HEAD".toUTF8 && head.status.toNat >= 200 &&
    head.status != 204 && head.status != 205 && head.status != 304 &&
    head.framing != .none

private def Engine.pumpCipher (engine : Engine) (initial : Job) : IO Job := do
  let some session := initial.tls | return initial
  let mut job := initial
  while job.pendingWrites < engine.config.maxQueuedWrites do
    let cipher ← match job.pendingCipher with
      | some bytes => pure bytes
      | none => session.drainCipher
    if cipher.isEmpty then break
    match ← session.submitCipher cipher with
    | .wouldBlock =>
      job := { job with pendingCipher := some cipher }
      break
    | .queued =>
      job := { job with pendingCipher := none, pendingWrites := job.pendingWrites + 1 }
  return job

private def Engine.pumpTLSPlain (engine : Engine) (initial : Job) : IO Job := do
  let some session := initial.tls | return initial
  if !initial.tlsReady then return initial
  let mut job ← engine.pumpCipher initial
  while job.hasUnqueued && job.pendingWrites < engine.config.maxQueuedWrites &&
      job.pendingCipher.isNone do
    let part := job.wire[job.part]!
    if job.offset >= part.size then
      job := { job with part := job.part + 1, offset := 0 }
      continue
    let length := min 16384 (part.size - job.offset)
    let plain := part.extract job.offset (job.offset + length)
    let written ← session.writePlain plain
    if written > length then throw (IO.userError "upstream TLS over-consumed plaintext")
    if written > 0 then
      let offset := job.offset + written
      job := if offset == part.size then { job with part := job.part + 1, offset := 0 }
        else { job with offset }
    job ← engine.pumpCipher job
    if written == 0 then break
  return job

private def Engine.progressTLS (engine : Engine) (id : Reactor.SocketId) : IO Unit := do
  let some original ← engine.job? id | return
  let some session := original.tls | return
  let mut job := original
  if !job.tlsVerified then
    if ← session.handshake then job := { job with tlsVerified := true }
  job ← engine.pumpCipher job
  if job.tlsVerified && !job.tlsReady && job.pendingWrites == 0 && job.pendingCipher.isNone then
    -- `pumpCipher` has drained OpenSSL's output BIO. The wire transition
    -- fences the handshake before any application plaintext is encrypted.
    session.markWireReady
    job := { job with tlsReady := true }
  if job.tlsReady then job ← engine.pumpTLSPlain job
  engine.putJob id job

/-- Queue at most a few native buffer slices, preserving backpressure. The
request body stays in its own ByteArray; only each 64 KiB I/O slice is copied
into a reactor buffer. -/
private def Engine.pumpWrites (engine : Engine) (id : Reactor.SocketId) : IO Unit := do
  let some original ← engine.job? id | return
  let some lease := original.lease | return
  if original.tls.isSome then
    engine.progressTLS id
    return
  let mut job := original
  while job.hasUnqueued && job.pendingWrites < engine.config.maxQueuedWrites do
    let part := job.wire[job.part]!
    if job.offset >= part.size then
      job := { job with part := job.part + 1, offset := 0 }
      continue
    let length := min 65536 (part.size - job.offset)
    let some buffer ← engine.reactor.tryAcquire length.toUInt32 | break
    let submission ← try
        buffer.copySliceFrom part job.offset.toUInt32 length.toUInt32
        lease.socket.tryWrite buffer 0 length.toUInt32
      finally buffer.release
    match submission with
    | .wouldBlock => break
    | .queued =>
      let offset := job.offset + length
      job := if offset == part.size then
        { job with part := job.part + 1, offset := 0, pendingWrites := job.pendingWrites + 1 }
      else { job with offset, pendingWrites := job.pendingWrites + 1 }
  engine.putJob id job

private def Engine.activate (engine : Engine) (id : Reactor.SocketId)
    (lease : Pool.Lease) (nowMs : UInt64) : IO Unit := do
  let some job ← engine.job? id | return
  if nowMs.toNat + engine.config.responseTimeoutMs.toNat > 9223372036854775807 then
    throw (IO.userError "gateway response deadline overflow")
  match lease.target.security with
  | .plain =>
    lease.socket.armTimer 6 (nowMs + engine.config.responseTimeoutMs)
    engine.putJob id { job with lease := some lease }
    engine.pumpWrites id
  | .tls verifyName _ =>
    let some provider := engine.tlsProvider
      | throw (IO.userError "upstream TLS provider is unavailable")
    let session ← provider.start lease.socket verifyName
    match ← engine.pool.attachTLS lease session with
    | .error _ =>
      session.close
      throw (IO.userError "upstream TLS pool attachment failed")
    | .ok () => pure ()
    session.armTimer 6 (nowMs + engine.config.responseTimeoutMs)
    engine.putJob id { job with lease := some lease, tls := some session }
    engine.progressTLS id

private def Engine.activateSecureReady (engine : Engine) (id : Reactor.SocketId)
    (lease : Pool.Lease) (session : TLSSession) (nowMs : UInt64) : IO Unit := do
  let some job ← engine.job? id | return
  if nowMs.toNat + engine.config.responseTimeoutMs.toNat > 9223372036854775807 then
    throw (IO.userError "gateway response deadline overflow")
  session.armTimer 6 (nowMs + engine.config.responseTimeoutMs)
  let readyJob := { job with lease := some lease, tls := some session, tlsVerified := true, tlsReady := true }
  engine.putJob id readyJob
  engine.pumpWrites id

private def Engine.checkout (engine : Engine) (ticket : Ticket)
    (target : Admission.UpstreamTarget) (address : ByteArray)
    (parser : ClientResponse.Parser) (wire : Array ByteArray)
    (nowMs : UInt64) : IO (Option Outcome) := do
  let security := if target.tls then Pool.Security.tls target.verifyName.toUTF8 0
    else Pool.Security.plain
  let key : Pool.Target := { address, port := target.port, security }
  let acquired ← try engine.pool.acquire key nowMs catch _ => pure (.error .invalidTarget)
  match acquired with
  | .error .unsupportedTransport => return some { ticket, reply := errorReply 503 }
  | .error _ => return some { ticket, reply := errorReply 502 }
  | .ok .atCapacity => return some { ticket, reply := errorReply 503 }
  | .ok (.connecting id) =>
    engine.putJob id { ticket, parser, wire }
    return none
  | .ok (.ready lease) =>
    let id := lease.id
    engine.putJob id { ticket, parser, wire }
    try engine.activate id lease nowMs
    catch _ => return ← engine.abort id 502
    return none
  | .ok (.secureReady lease session) =>
    let id := lease.id
    engine.putJob id { ticket, parser, wire, lease := some lease, tls := some session }
    try engine.activateSecureReady id lease session nowMs
    catch _ => return ← engine.abort id 502
    return none

/-- Begin one route-bound upstream transaction. DNS lookups run in a task
outside the reactor loop and share a bounded cache across requests. -/
def Engine.start (engine : Engine) (ticket : Ticket) (plan : Admission.ProxyPlan)
    (request : Request) (nowMs : UInt64) : IO (Option Outcome) := do
  let .ok wire := plan.serialize request
    | return some { ticket, reply := errorReply 502 }
  let .ok parser := ClientResponse.Parser.new request.method.toUTF8 engine.config.response
    | return some { ticket, reply := errorReply 502 }
  if plan.targets.isEmpty then return some { ticket, reply := errorReply 503 }
  let state ← engine.state.get
  engine.state.modify fun state => { state with nextTarget := state.nextTarget + 1 }
  let target := plan.targets[state.nextTarget % plan.targets.size]!
  if let some address := Gate.parseAddress target.host then
    return ← engine.checkout ticket target address parser wire nowMs
  if let some (address, expires) := state.resolved[target.host]? then
    if expires > nowMs then
      return ← engine.checkout ticket target address parser wire nowMs
  if state.jobs.size + state.pendingResolve.size >= engine.config.pool.maxTotal then
    return some { ticket, reply := errorReply 503 }
  if !state.resolving.contains target.host then
    if state.resolving.size >= engine.config.pool.maxTotal then
      return some { ticket, reply := errorReply 503 }
    let task ← IO.asTask (Resolve.resolve target.host) Task.Priority.dedicated
    engine.state.modify fun state =>
      { state with resolving := state.resolving.insert target.host task }
  engine.state.modify fun state =>
    { state with pendingResolve := state.pendingResolve.push { ticket, target, wire, parser, since := nowMs } }
  return none

private def Job.materialize (job : Job) : ByteArray :=
  job.body.foldl (init := ByteArray.emptyWithCapacity job.bodyBytes) ByteArray.append

private def Engine.complete (engine : Engine) (id : Reactor.SocketId) (job : Job)
    (unread : Nat) (nowMs : UInt64) : IO Outcome := do
  engine.removeJob id
  let some head := job.head | do
    if let some lease := job.lease then
      let _ ← engine.pool.discard lease
    engine.retire id
    return { ticket := job.ticket, reply := errorReply 502 }
  let reply := decodeReply head job.materialize job.trailers
  let replyValid := match reply with | .ok _ => true | .error _ => false
  if let some lease := job.lease then
    try
      if let some session := job.tls then session.cancelTimer 6
      else lease.socket.cancelTimer 6
    catch _ => pure ()
    if !replyValid || job.hasUnqueued || job.pendingWrites != 0 then
      let _ ← engine.pool.discard lease
    else
      let _ ← engine.pool.finishResponse lease head true true unread nowMs
  if !(← engine.pool.owns id) then engine.retire id
  return { ticket := job.ticket, reply := match reply with
    | .ok value => value | .error _ => errorReply 502 }

private def Engine.finishStream (engine : Engine) (id : Reactor.SocketId) (job : Job)
    (unread : Nat) (nowMs : UInt64) : IO (Array Outcome) := do
  let some head := job.head | return (← engine.abort id 502).toArray
  let .ok _ := decodeReply head ByteArray.empty job.trailers
    | return (← engine.abort id 502).toArray
  engine.removeJob id
  if let some lease := job.lease then
    try
      if let some session := job.tls then session.cancelTimer 6
      else lease.socket.cancelTimer 6
    catch _ => pure ()
    if job.hasUnqueued || job.pendingWrites != 0 then
      let _ ← engine.pool.discard lease
    else
      let _ ← engine.pool.finishResponse lease head true true unread nowMs
  if !(← engine.pool.owns id) then engine.retire id
  return #[{ ticket := job.ticket, reply := errorReply 200, stream := some (.finish job.trailers) }]

private def Engine.setResponseReading (engine : Engine) (id : Reactor.SocketId)
    (enabled : Bool) : IO Unit := do
  let some job ← engine.job? id | return
  if let some session := job.tls then
    session.setReadEnabled enabled
  else if let some lease := job.lease then
    lease.socket.setReadEnabled enabled

private def Engine.feedPlain (engine : Engine) (id : Reactor.SocketId) (bytes : ByteArray)
    (offset length : Nat) (nowMs : UInt64) : IO (Array Outcome) := do
  let some job ← engine.job? id | do
    let _ ← engine.pool.onUnexpectedRead id
    return #[]
  if offset > bytes.size || length > bytes.size - offset || length > 65536 then
    return (← engine.abort id 502).toArray
  if job.paused then
    let pending := job.pendingInput.getD ByteArray.empty
    if length > 65536 - min pending.size 65536 then
      return (← engine.abort id 502).toArray
    engine.putJob id { job with pendingInput := some (pending.append (bytes.extract offset (offset + length))) }
    return #[]
  let .ok step := job.parser.feedSlice bytes offset length
    | return (← engine.abort id 502).toArray
  let mut job := { job with parser := step.parser }
  let mut complete := false
  let mut body := ByteArray.empty
  for event in step.events do
    match event with
    | .informational _ => pure ()
    | .head head => job := { job with head := some head }
    | .body view =>
      body := body.append view.copy
    | .trailers fields => job := { job with trailers := fields }
    | .complete => complete := true
    | .tunnel _ => return (← engine.abort id 502).toArray
  if complete && !job.streaming then
    job := { job with body := if body.isEmpty then job.body else job.body.push body, bodyBytes := job.bodyBytes + body.size }
    return #[← engine.complete id job (length - step.consumed) nowMs]
  let mut outcomes : Array Outcome := #[]
  if !job.streaming then
    if let some head := job.head then
      if job.bodyCapable head then
        let .ok _ := decodeReply head ByteArray.empty
          | return (← engine.abort id 502).toArray
        job := { job with streaming := true, body := #[], bodyBytes := 0 }
        outcomes := outcomes.push { ticket := job.ticket, reply := errorReply 200, stream := some (.start head) }
      else
        job := { job with body := if body.isEmpty then job.body else job.body.push body, bodyBytes := job.bodyBytes + body.size }
        engine.putJob id job
        return #[]
  if job.streaming && !body.isEmpty then
    outcomes := outcomes.push { ticket := job.ticket, reply := errorReply 200, stream := some (.data body) }
  engine.putJob id job
  if complete then
    return outcomes ++ (← engine.finishStream id job (length - step.consumed) nowMs)
  if job.streaming && !body.isEmpty then
    engine.putJob id { job with paused := true }
    try engine.setResponseReading id false
    catch _ => return outcomes ++ (← engine.abort id 502).toArray
  return outcomes

private def Engine.read (engine : Engine) (id : Reactor.SocketId) (buffer : Reactor.Buffer)
    (offset length : UInt32) (nowMs : UInt64) : IO (Array Outcome) := do
  let bytes ← try buffer.view finally buffer.release
  engine.feedPlain id bytes offset.toNat length.toNat nowMs

private def Engine.eof (engine : Engine) (id : Reactor.SocketId) (nowMs : UInt64) : IO (Array Outcome) := do
  let some job ← engine.job? id | do
    let _ ← engine.pool.onError id
    engine.retire id
    return #[]
  if job.paused then
    engine.putJob id { job with pendingEOF := true }
    return #[]
  let .ok step := job.parser.eof | return (← engine.abort id 502).toArray
  if step.events.any (fun event => match event with | .complete => true | _ => false) then
    if job.streaming then return ← engine.finishStream id job 0 nowMs
    return #[← engine.complete id job 0 nowMs]
  return (← engine.abort id 502).toArray

private def Engine.readTLSPlain (engine : Engine) (id : Reactor.SocketId)
    (nowMs : UInt64) : IO (Array Outcome) := do
  let some job ← engine.job? id | return #[]
  let some session := job.tls | return #[]
  if !job.tlsReady || job.paused then return #[]
  let mut outcomes := #[]
  for _ in [:256] do
    match ← session.readPlain with
    | .pending => break
    | .eof =>
      outcomes := outcomes ++ (← engine.eof id nowMs)
      break
    | .data bytes =>
      outcomes := outcomes ++ (← engine.feedPlain id bytes 0 bytes.size nowMs)
      let some current ← engine.job? id | break
      if current.paused then break
  return outcomes

/-- Process an event only if this engine owns its connection. Unrecognized
events must go to the inbound transport provider. -/
def Engine.onNative (engine : Engine) (event : Reactor.Event) (nowMs : UInt64) :
    IO (Bool × Array Outcome) := do
  let id? : Option Reactor.SocketId := match event with
    | .connected socket | .read socket .. | .eof socket | .timer socket .. | .closed socket => some socket.id
    | .written id .. | .error id .. | .connectTimer id .. |
      .wireRead id .. | .wireEOF id | .wireTimer id .. => some id
    | _ => none
  let some id := id? | return (false, #[])
  let known := (← engine.pool.owns id) || (← engine.state.get).retired.contains id
  if !known then return (false, #[])
  let mut outcomes := #[]
  match event with
  | .connected socket =>
    if let some lease ← engine.pool.onConnected socket then
      try engine.activate id lease nowMs
      catch _ => outcomes := (← engine.abort id 502).toArray
  | .read _ buffer offset length =>
    if (← engine.job? id).bind (·.tls) |>.isSome then
      buffer.release
      outcomes := (← engine.abort id 502).toArray
    else
      outcomes ← engine.read id buffer offset length nowMs
  | .wireRead _ buffer offset length =>
    let bytes ← try buffer.view finally buffer.release
    if let some job ← engine.job? id then
      if let some session := job.tls then
        let start := offset.toNat
        let stop := start + length.toNat
        if stop > bytes.size || length.toNat > 65536 then
          outcomes := (← engine.abort id 502).toArray
        else if job.paused then
          let pending := job.pendingCipherInput.getD ByteArray.empty
          if length.toNat > 65536 - min pending.size 65536 then
            outcomes := (← engine.abort id 502).toArray
          else
            engine.putJob id { job with pendingCipherInput := some (pending.append (bytes.extract start stop)) }
        else
          try
            session.feedCipher (bytes.extract start stop)
            engine.progressTLS id
            outcomes ← engine.readTLSPlain id nowMs
          catch _ => outcomes := (← engine.abort id 502).toArray
      else outcomes := (← engine.abort id 502).toArray
    else
      let _ ← engine.pool.onUnexpectedRead id
  | .written _ _ _ =>
    if let some job ← engine.job? id then
      if job.pendingWrites > 0 then
        engine.putJob id { job with pendingWrites := job.pendingWrites - 1 }
        try
          engine.pumpWrites id
          if job.tls.isSome then outcomes ← engine.readTLSPlain id nowMs
        catch _ => outcomes := (← engine.abort id 502).toArray
  | .eof _ =>
    if (← engine.job? id).bind (·.tls) |>.isSome then
      outcomes := (← engine.abort id 502).toArray
    else outcomes ← engine.eof id nowMs
  | .wireEOF _ =>
    if let some job ← engine.job? id then
      if job.tls.isSome then
        try
          outcomes ← engine.readTLSPlain id nowMs
          if let some current ← engine.job? id then
            if current.paused then
              engine.putJob id { current with pendingEOF := true }
            else outcomes := outcomes ++ (← engine.abort id 502).toArray
        catch _ => outcomes := (← engine.abort id 502).toArray
      else outcomes := (← engine.abort id 502).toArray
    else
      let _ ← engine.pool.onError id
      engine.retire id
  | .timer _ kind =>
    if kind == 6 then outcomes := (← engine.abort id 504).toArray
  | .wireTimer _ kind =>
    if kind == 6 then outcomes := (← engine.abort id 504).toArray
  | .connectTimer _ kind =>
    if ← engine.pool.onConnectTimer id kind then
      outcomes := (← engine.abort id 504).toArray
  | .error _ _ _ =>
    if (← engine.job? id).isSome then
      outcomes := (← engine.abort id 502).toArray
    else
      let _ ← engine.pool.onError id
      engine.retire id
  | .closed _ =>
    if (← engine.job? id).isSome then outcomes := (← engine.abort id 502).toArray
    let _ ← engine.pool.onClosed id
    engine.state.modify fun state => { state with retired := state.retired.filter (· != id) }
  | _ => pure ()
  return (true, outcomes)

/-- Retry pending writes when native buffers become available; periodically
expire idle connections and timed-out connects without a new checkout. -/
def Engine.pump (engine : Engine) (nowMs : UInt64) : IO (Array Outcome) := do
  -- Idle sockets must expire even when no new checkout puts the pool under
  -- capacity pressure. Limit the O(pool size) pass to one short interval;
  -- active leases remain owned by their response jobs.
  let state ← engine.state.get
  if nowMs >= state.nextReapMs then
    let interval := max 1 (min 1000 (min engine.config.pool.idleTimeoutMs.toNat
      engine.config.pool.connectTimeoutMs.toNat))
    let nextReapMs := if nowMs.toNat + interval > 18446744073709551615 then nowMs
      else nowMs + interval.toUInt64
    engine.state.modify fun state => { state with nextReapMs }
    engine.pool.reap nowMs
  let mut outcomes := #[]
  let pending := (← engine.state.get).pendingResolve
  engine.state.modify fun state => { state with pendingResolve := #[] }
  for request in pending do
    if nowMs >= request.since && nowMs - request.since >= engine.config.resolveTimeoutMs then
      outcomes := outcomes.push { ticket := request.ticket, reply := errorReply 504 }
      continue
    let state ← engine.state.get
    if let some (address, expiry) := state.resolved[request.target.host]? then
      if expiry > nowMs then
        if let some outcome ← engine.checkout request.ticket request.target address
            request.parser request.wire nowMs then
          outcomes := outcomes.push outcome
        continue
    let some task := state.resolving[request.target.host]? | do
      outcomes := outcomes.push { ticket := request.ticket, reply := errorReply 502 }
      continue
    if !(← IO.hasFinished task) then
      engine.state.modify fun state =>
        { state with pendingResolve := state.pendingResolve.push request }
      continue
    let resolved ← IO.wait task
    engine.state.modify fun state => { state with resolving := state.resolving.erase request.target.host }
    match resolved with
    | .ok (.ok address) =>
      let expiry := if nowMs.toNat + engine.config.resolveCacheMs.toNat > 9223372036854775807
        then nowMs else nowMs + engine.config.resolveCacheMs
      engine.state.modify fun state =>
        { state with resolved := state.resolved.insert request.target.host (address, expiry) }
      if let some outcome ← engine.checkout request.ticket request.target address
          request.parser request.wire nowMs then
        outcomes := outcomes.push outcome
    | _ => outcomes := outcomes.push { ticket := request.ticket, reply := errorReply 502 }
  -- A downstream may cancel its last waiter while getaddrinfo is in flight.
  -- Reap those completed tasks even when no request remains to consume them.
  for (host, task) in (← engine.state.get).resolving.toArray do
    if !(← engine.state.get).pendingResolve.any (·.target.host == host) &&
        (← IO.hasFinished task) then
      let _ ← IO.wait task
      engine.state.modify fun state => { state with resolving := state.resolving.erase host }
  engine.state.modify fun state =>
    { state with resolved := if state.resolved.size < 1024 then state.resolved
      else state.resolved.filter (fun _ (_, expires) => expires > nowMs) }
  for (id, job) in (← engine.state.get).jobs.toArray do
    if !(← engine.pool.owns id) then
      outcomes := outcomes ++ (← engine.abort id 504).toArray
    else if job.lease.isSome then
      try engine.pumpWrites id catch _ =>
        outcomes := outcomes ++ (← engine.abort id 502).toArray
  return outcomes

/-- Resume exactly one paused upstream after its downstream chunk has entered
the bounded output queue. A late native read may have been copied into one
pending slice; TLS may also have decrypted plaintext waiting in OpenSSL. Both
are drained before native read interest is re-enabled. -/
def Engine.resume (engine : Engine) (ticket : Ticket) (nowMs : UInt64) : IO (Array Outcome) := do
  let some (id, job) := (← engine.state.get).jobs.toArray.find? (fun (_, value) => value.ticket == ticket)
    | return #[]
  if !job.paused then return #[]
  engine.putJob id { job with paused := false, pendingInput := none, pendingCipherInput := none }
  let mut outcomes := #[]
  if let some bytes := job.pendingInput then
    outcomes := outcomes ++ (← engine.feedPlain id bytes 0 bytes.size nowMs)
  if let some bytes := job.pendingCipherInput then
    if let some current ← engine.job? id then
      if !current.paused then
        if let some session := current.tls then
          try
            session.feedCipher bytes
            engine.progressTLS id
            outcomes := outcomes ++ (← engine.readTLSPlain id nowMs)
          catch _ => outcomes := outcomes ++ (← engine.abort id 502).toArray
  if let some current ← engine.job? id then
    if !current.paused && current.tls.isSome then
      try outcomes := outcomes ++ (← engine.readTLSPlain id nowMs)
      catch _ => outcomes := outcomes ++ (← engine.abort id 502).toArray
  if let some current ← engine.job? id then
    if !current.paused && current.pendingEOF then
      if current.tls.isSome then
        -- A native EOF is only a transport close. `readTLSPlain` completes a
        -- close-delimited response solely after authenticated close_notify.
        try outcomes := outcomes ++ (← engine.readTLSPlain id nowMs)
        catch _ => outcomes := outcomes ++ (← engine.abort id 502).toArray
        if let some stillActive ← engine.job? id then
          if !stillActive.paused then
            outcomes := outcomes ++ (← engine.abort id 502).toArray
      else outcomes := outcomes ++ (← engine.eof id nowMs)
  if let some current ← engine.job? id then
    if !current.paused then
      try engine.setResponseReading id true
      catch _ => outcomes := outcomes ++ (← engine.abort id 502).toArray
  return outcomes

def Engine.isPaused (engine : Engine) (ticket : Ticket) : IO Bool := do
  return (← engine.state.get).jobs.toArray.any (fun (_, job) => job.ticket == ticket && job.paused)

/-- Cancel one HTTP/2 stream without affecting sibling streams sharing the
same downstream connection. DNS waiters are identified by the same ticket. -/
def Engine.cancelTicket (engine : Engine) (ticket : Ticket) : IO Unit := do
  engine.state.modify fun state =>
    { state with pendingResolve := state.pendingResolve.filter (·.ticket != ticket) }
  for (id, job) in (← engine.state.get).jobs.toArray do
    if job.ticket == ticket then
      let _ ← engine.abort id 502

def Engine.cancelDownstream (engine : Engine) (downstream : Reactor.SocketId) : IO Unit := do
  engine.state.modify fun state =>
    { state with pendingResolve := state.pendingResolve.filter (·.ticket.downstream != downstream) }
  for (id, job) in (← engine.state.get).jobs.toArray do
    if job.ticket.downstream == downstream then
      let _ ← engine.abort id 502

def Engine.close (engine : Engine) : IO Unit := do
  engine.state.set {}
  try engine.pool.close finally
    if let some provider := engine.tlsProvider then provider.close

end LeanNet.Gateway
