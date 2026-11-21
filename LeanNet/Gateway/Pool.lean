import LeanNet.Reactor.Basic
import LeanNet.HTTP1.ClientResponse
import LeanNet.Gateway.Transport
import Std.Data.HashMap

/-! Owner-thread pool for outbound HTTP/1.1 reactor sockets. One instance belongs
to one reactor worker. Pending connects and busy sockets count against both
capacity limits. A lease is returned to idle only after a complete, reusable
response with no unread bytes. Generation-bearing `SocketId`s and a separate
lease sequence reject late completions and stale releases. -/

namespace LeanNet.Gateway.Pool

open LeanNet

/-- A TLS identity is part of the target key. A configured provider must
attach its claimed session before any TLS connection may be reused. -/
inductive Security where
  | plain
  | tls (verifyName : ByteArray) (profile : UInt64)
  deriving BEq, Hashable

/-- Resolved network address. DNS and backend selection happen off the reactor
loop; a pool never shares a socket across an address, port or TLS identity. -/
structure Target where
  address : ByteArray
  port : UInt16
  security : Security := .plain
  deriving BEq, Hashable

structure Config where
  maxTotal : Nat := 1024
  maxPerTarget : Nat := 64
  idleTimeoutMs : UInt64 := 30000
  connectTimeoutMs : UInt64 := 5000
  /-- A provider must claim and attach every TLS connection before I/O. -/
  allowTls : Bool := false
  deriving Inhabited

inductive Error where
  | invalidConfig
  | invalidTarget
  | unsupportedTransport
  | closed
  | staleLease
  deriving BEq, Repr

/-- A checked-out, currently connected socket. The sequence prevents a late
release from returning a later transaction on the same socket to idle. -/
structure Lease where
  private mk ::
  private connection : Reactor.Socket .connected
  private sequence : Nat
  target : Target

def Lease.socket (lease : Lease) : Reactor.Socket .connected := lease.connection
def Lease.id (lease : Lease) : Reactor.SocketId := lease.connection.id

inductive Acquire where
  | ready (lease : Lease)
  | secureReady (lease : Lease) (session : TLSSession)
  | connecting (id : Reactor.SocketId)
  | atCapacity

/-- Evidence that read interest was re-enabled on socket `id` when it went
idle. A streamed response may have disabled reads for downstream backpressure;
an idle socket must still observe upstream EOF or stray bytes, and its next
lease must receive a response. Only `armReads` and `armSecureReads` construct
it, so every idle entry was armed (see `LeanNetSpec.UpstreamLifecycle`). -/
structure ReadArmed (id : Reactor.SocketId) : Type where
  private mk ::

private def armReads (socket : Reactor.Socket .connected) : IO (ReadArmed socket.id) := do
  socket.setReadEnabled true
  return ⟨⟩

private def armSecureReads (session : TLSSession) : IO (ReadArmed session.id) := do
  session.setReadEnabled true
  return ⟨⟩

private inductive Phase where
  | connecting (socket : Reactor.Connecting) (since : UInt64)
  | busy (socket : Reactor.Socket .connected) (sequence : Nat)
  | secureBusy (socket : Reactor.Socket .connected) (session : TLSSession) (sequence : Nat)
  | idle (socket : Reactor.Socket .connected) (since : UInt64) (armed : ReadArmed socket.id)
  | secureIdle (socket : Reactor.Socket .connected) (session : TLSSession) (since : UInt64)
      (armed : ReadArmed session.id)

private structure Entry where
  target : Target
  phase : Phase

private structure State where
  entries : Std.HashMap Reactor.SocketId Entry := {}
  counts : Std.HashMap Target Nat := {}
  idle : Std.HashMap Target (Array Reactor.SocketId) := {}
  nextSequence : Nat := 0

structure Pool where
  private mk ::
  private reactor : Reactor.Reactor
  private config : Config
  private state : IO.Ref State
  private alive : IO.Ref Bool

/-- Reserved only on pending upstream sockets; native timer kinds are 0..7. -/
def connectTimerKind : UInt32 := 5

private def validTarget (target : Target) : Bool :=
  (target.address.size == 4 || target.address.size == 16) && target.port != 0

def new (reactor : Reactor.Reactor) (config : Config := {}) : IO (Except Error Pool) := do
  if config.maxTotal == 0 || config.maxPerTarget == 0 ||
      config.maxPerTarget > config.maxTotal || config.connectTimeoutMs == 0 then
    return .error .invalidConfig
  return .ok ⟨reactor, config, ← IO.mkRef {}, ← IO.mkRef true⟩

private def elapsed (now since timeout : UInt64) : Bool :=
  now >= since && now - since >= timeout

private def dropIdleId (state : State) (target : Target) (id : Reactor.SocketId) : State := Id.run do
  let ids := (state.idle.getD target #[]).filter (· != id)
  return { state with idle := if ids.isEmpty then state.idle.erase target else state.idle.insert target ids }

private def remove (state : State) (id : Reactor.SocketId) : State := Id.run do
  let some entry := state.entries[id]? | return state
  let count := state.counts.getD entry.target 0
  let counts := if count <= 1 then state.counts.erase entry.target
    else state.counts.insert entry.target (count - 1)
  let state := { state with entries := state.entries.erase id, counts }
  return match entry.phase with
    | .idle .. | .secureIdle .. => dropIdleId state entry.target id
    | _ => state

private def closeEntry (entry : Entry) : IO Unit := do
  try
    match entry.phase with
    | .connecting socket _ => socket.close
    | .busy socket _ | .idle socket _ _ =>
      let _ ← socket.close (by decide)
    | .secureBusy _ session _ | .secureIdle _ session _ _ => session.close
  catch _ => pure ()

/-- Prune idle timeouts and pending connect timeouts. Call from the worker's
timer as well as on capacity pressure; this owns and closes expired sockets. -/
def Pool.reap (pool : Pool) (nowMs : UInt64) : IO Unit := do
  unless ← pool.alive.get do return
  let mut state ← pool.state.get
  for (id, entry) in state.entries.toList do
    let expired := match entry.phase with
      | .idle _ since _ | .secureIdle _ _ since _ => elapsed nowMs since pool.config.idleTimeoutMs
      | .connecting _ since => elapsed nowMs since pool.config.connectTimeoutMs
      | .busy .. | .secureBusy .. => false
    if expired then
      state := remove state id
      closeEntry entry
  pool.state.set state

/-- Get an idle connection or start a new nonblocking connect. A synchronous
connect failure throws `IO.Error` and leaves no pending pool entry. -/
def Pool.acquire (pool : Pool) (target : Target) (nowMs : UInt64) : IO (Except Error Acquire) := do
  if !(← pool.alive.get) then return .error .closed
  if !validTarget target then return .error .invalidTarget
  if target.security != .plain && !pool.config.allowTls then return .error .unsupportedTransport
  let mut state ← pool.state.get
  let mut idleIds := state.idle.getD target #[]
  while !idleIds.isEmpty do
    let some id := idleIds[idleIds.size - 1]? | break
    idleIds := idleIds.pop
    state := { state with idle := if idleIds.isEmpty then state.idle.erase target
      else state.idle.insert target idleIds }
    let some entry := state.entries[id]? | continue
    match entry.phase with
    | .idle socket since _ =>
      -- The index is only a hint; the authoritative entry must still match.
      if entry.target != target then continue
      if target.security != .plain then
        state := remove state id
        closeEntry entry
        continue
      if elapsed nowMs since pool.config.idleTimeoutMs || !(← id.isLive pool.reactor) then
        state := remove state id
        closeEntry entry
        continue
      let sequence := state.nextSequence + 1
      let entries := state.entries.insert id { entry with phase := .busy socket sequence }
      state := { state with entries, nextSequence := sequence }
      pool.state.set state
      return .ok (.ready ⟨socket, sequence, target⟩)
    | .secureIdle socket session since _ =>
      if entry.target != target || target.security == .plain ||
          elapsed nowMs since pool.config.idleTimeoutMs || !(← id.isLive pool.reactor) then
        state := remove state id
        closeEntry entry
        continue
      let clean ← try session.cleanForReuse catch _ => pure false
      if !clean then
        state := remove state id
        closeEntry entry
        continue
      let sequence := state.nextSequence + 1
      let entries := state.entries.insert id { entry with phase := .secureBusy socket session sequence }
      state := { state with entries, nextSequence := sequence }
      pool.state.set state
      return .ok (.secureReady ⟨socket, sequence, target⟩ session)
    | _ => continue
  pool.state.set state
  if state.entries.size >= pool.config.maxTotal || state.counts.getD target 0 >= pool.config.maxPerTarget then
    pool.reap nowMs
    state ← pool.state.get
    if state.entries.size >= pool.config.maxTotal || state.counts.getD target 0 >= pool.config.maxPerTarget then
      return .ok .atCapacity
  let fresh ← pool.reactor.socket
  let connecting ← fresh.startConnect target.address target.port
  if nowMs.toNat + pool.config.connectTimeoutMs.toNat > 18446744073709551615 then
    connecting.close
    return .error .invalidTarget
  try connecting.armTimer connectTimerKind (nowMs + pool.config.connectTimeoutMs)
  catch e =>
    try connecting.close catch _ => pure ()
    throw e
  let id := connecting.id
  let entries := state.entries.insert id { target, phase := .connecting connecting nowMs }
  let counts := state.counts.insert target (state.counts.getD target 0 + 1)
  state := { state with entries, counts }
  pool.state.set state
  return .ok (.connecting id)

/-- Consume a successful reactor `.connected` event. Unknown or stale events
are left for the other reactor owner; this pool never closes foreign sockets. -/
def Pool.onConnected (pool : Pool) (socket : Reactor.Socket .connected) : IO (Option Lease) := do
  unless ← pool.alive.get do return none
  let id := socket.id
  let state ← pool.state.get
  let some entry := state.entries[id]? | return none
  match entry.phase with
  | .connecting connecting _ =>
    try connecting.cancelTimer connectTimerKind
    catch _ =>
      pool.state.set (remove state id)
      closeEntry entry
      return none
    let sequence := state.nextSequence + 1
    let entries := state.entries.insert id { entry with phase := .busy socket sequence }
    pool.state.set { state with entries, nextSequence := sequence }
    return some ⟨socket, sequence, entry.target⟩
  | _ => return none

/-- A stale lease cannot mutate or close a later checkout. -/
private def Pool.matchLease (pool : Pool) (lease : Lease) : IO (Except Error Entry) := do
  if !(← pool.alive.get) then return .error .closed
  let state ← pool.state.get
  let some entry := state.entries[lease.id]? | return .error .staleLease
  if entry.target != lease.target then return .error .staleLease
  match entry.phase with
  | .busy _ sequence =>
    if sequence == lease.sequence then return .ok entry
    return .error .staleLease
  | .secureBusy _ _ sequence =>
    if sequence == lease.sequence then return .ok entry
    return .error .staleLease
  | _ => return .error .staleLease

/-- Transfer a claimed TLS transport into the pool's busy record. The engine
must call this immediately after `TLSProvider.start` and close `session` itself
if attachment fails. From here on, discard/timeout/close invokes session.close
instead of the now-invalid raw socket alias. -/
def Pool.attachTLS (pool : Pool) (lease : Lease) (session : TLSSession) : IO (Except Error Unit) := do
  let .ok entry ← pool.matchLease lease | return .error .staleLease
  if lease.target.security == .plain then return .error .unsupportedTransport
  if session.id != lease.id then return .error .staleLease
  match entry.phase with
  | .busy .. =>
    let state ← pool.state.get
    let entries := state.entries.insert lease.id
      { entry with phase := .secureBusy lease.socket session lease.sequence }
    pool.state.set { state with entries }
    return .ok ()
  | _ => return .error .staleLease

/-- Abort a checked-out connection after parse error, upstream EOF, write
error, timeout, or a response that cannot be safely reused. -/
def Pool.discard (pool : Pool) (lease : Lease) : IO (Except Error Unit) := do
  let .ok entry ← pool.matchLease lease | return .error .staleLease
  pool.state.modify (remove · lease.id)
  closeEntry entry
  return .ok ()

/-- Return a socket to idle only after the final response event, all request
writes complete, no unconsumed bytes, and a reusable response head. Claimed
TLS sockets remain paired with their verified session and pass a final
OpenSSL buffered-data check before secure reuse. -/
def Pool.finishResponse (pool : Pool) (lease : Lease) (head : HTTP1.ClientResponse.Head)
    (complete outboundWritesComplete : Bool) (unreadBytes : Nat) (nowMs : UInt64) : IO (Except Error Unit) := do
  let .ok entry ← pool.matchLease lease | return .error .staleLease
  if !complete || !outboundWritesComplete || !head.reusable || unreadBytes != 0 ||
      pool.config.idleTimeoutMs == 0 ||
      !(← lease.id.isLive pool.reactor) then
    return ← pool.discard lease
  let state ← pool.state.get
  let ids := state.idle.getD entry.target #[]
  match entry.phase with
  | .busy socket _ =>
    if lease.target.security != .plain then return ← pool.discard lease
    -- A streamed response can finish from input held while downstream
    -- backpressure disabled reads; `.idle` requires re-armed reads.
    let armed? ← try some <$> armReads socket catch _ => pure none
    let some armed := armed? | return ← pool.discard lease
    pool.state.set { state with
      entries := state.entries.insert lease.id ({ entry with phase := .idle socket nowMs armed }),
      idle := state.idle.insert entry.target (ids.push lease.id) }
    return .ok ()
  | .secureBusy socket session _ =>
    if lease.target.security == .plain then return ← pool.discard lease
    let clean ← try session.cleanForReuse catch _ => pure false
    if !clean then return ← pool.discard lease
    let armed? ← try some <$> armSecureReads session catch _ => pure none
    let some armed := armed? | return ← pool.discard lease
    pool.state.set { state with
      entries := state.entries.insert lease.id
        ({ entry with phase := .secureIdle socket session nowMs armed }),
      idle := state.idle.insert entry.target (ids.push lease.id) }
    return .ok ()
  | _ => return .error .staleLease

/-- A read while idle is protocol contamination. Busy reads belong to the
client parser; an unknown ID belongs to another owner. -/
def Pool.onUnexpectedRead (pool : Pool) (id : Reactor.SocketId) : IO Bool := do
  unless ← pool.alive.get do return false
  let state ← pool.state.get
  let some entry := state.entries[id]? | return false
  match entry.phase with
  | .idle .. | .secureIdle .. | .connecting .. =>
    pool.state.set (remove state id)
    closeEntry entry
    return true
  | .busy .. | .secureBusy .. => return false

/-- An error or EOF disqualifies the socket immediately. A later `.closed`
event is harmless because the generation-bearing ID has been removed. -/
def Pool.onError (pool : Pool) (id : Reactor.SocketId) : IO Bool := do
  unless ← pool.alive.get do return false
  let state ← pool.state.get
  let some entry := state.entries[id]? | return false
  pool.state.set (remove state id)
  closeEntry entry
  return true

/-- Handle only this pool's pending-connect timer. Other timer kinds belong to
the application. Late connected events for the canceled generation are ignored. -/
def Pool.onConnectTimer (pool : Pool) (id : Reactor.SocketId) (kind : UInt32) : IO Bool := do
  if kind != connectTimerKind || !(← pool.alive.get) then return false
  let state ← pool.state.get
  let some entry := state.entries[id]? | return false
  match entry.phase with
  | .connecting .. => pool.onError id
  | _ => return false

def Pool.onClosed (pool : Pool) (id : Reactor.SocketId) : IO Bool := do
  unless ← pool.alive.get do return false
  let state ← pool.state.get
  let some entry := state.entries[id]? | return false
  pool.state.set (remove state id)
  closeEntry entry
  return true

def Pool.owns (pool : Pool) (id : Reactor.SocketId) : IO Bool := do
  unless ← pool.alive.get do return false
  return (← pool.state.get).entries.contains id

def Pool.size (pool : Pool) : IO Nat := return (← pool.state.get).entries.size

/-- Close every owned socket before the reactor's bracket ends. -/
def Pool.close (pool : Pool) : IO Unit := do
  unless ← pool.alive.get do return
  pool.alive.set false
  let state ← pool.state.get
  pool.state.set {}
  for (_, entry) in state.entries.toList do closeEntry entry

def withPool (reactor : Reactor.Reactor) (config : Config) (use : Pool → IO α) : IO α := do
  let .ok pool ← new reactor config | throw (IO.userError "invalid upstream pool configuration")
  try use pool finally pool.close

end LeanNet.Gateway.Pool
