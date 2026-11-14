import LeanNet.Socket.State
import LeanNet.FFI.Errno
import LeanNet.FFI.Reactor

namespace LeanNet.Reactor

structure Config where
  maxConnections : UInt32 := 4096
  maxEvents : UInt32 := 1024
  maxWrites : UInt32 := 8192
  buffers4k : UInt32 := 4096
  buffers16k : UInt32 := 256
  buffers64k : UInt32 := 64
  timerTickMs : UInt32 := 10

/-- One thread owns this reactor and every connection and buffer lease it creates. -/
structure Reactor where
  private mk ::
  private handle : UInt64
  private alive : IO.Ref Bool

/-- Native generation tokens prevent stale aliases from reaching a reused socket. -/
structure Socket (state : SocketState) where
  private mk ::
  private reactor : Reactor
  private token : UInt64

/-- A non-actionable, reactor-scoped identity for completion accounting. -/
structure SocketId where
  private mk ::
  private owner : UInt64
  private token : UInt64
  deriving BEq, Hashable

def Socket.id (socket : Socket state) : SocketId := ⟨socket.reactor.handle, socket.token⟩

/-- A reactor-owned receive buffer. Retained ByteArray views prevent reuse. -/
structure Buffer where
  private mk ::
  private reactor : Reactor
  private token : UInt64

/-- Claimed transport access. Native mode checks reject plaintext socket aliases;
    the expected phase also rejects an old handshaking Wire after ready. -/
structure Wire (state : SocketState) where
  private mk ::
  private socket : Socket state
  private capability : UInt64
  private phase : UInt8

/-- Retained native notification endpoint; it never borrows a reactor pointer. -/
structure Waker where
  private mk ::
  private handle : UInt64
  private alive : IO.Ref Bool

private def ensureAlive (reactor : Reactor) : IO Unit := do
  unless (← reactor.alive.get) do throw (IO.userError "reactor is closed")

private def checked (operation : String) (raw : UInt64) : IO UInt64 := do
  let value := LeanNet.Errno.decode raw
  if value < 0 then throw (← LeanNet.Errno.error operation value)
  return raw

private def checkedZero (operation : String) (raw : UInt64) : IO Unit := do
  let value ← checked operation raw
  unless value == 0 do throw (IO.userError s!"{operation}: invalid native success result")

/-- A historical completion identity does not grant socket access. Query before
    taking protocol actions: CLOSED may still be queued for a later poll. -/
def SocketId.isLive (id : SocketId) (reactor : Reactor) : IO Bool := do
  if id.owner != reactor.handle then throw (IO.userError "socket identity belongs to another reactor")
  if !(← reactor.alive.get) then return false
  let value ← checked "reactor connection liveness" (← FFI.Reactor.connectionLive reactor.handle id.token)
  if value > 1 then throw (IO.userError "invalid reactor connection liveness result")
  return value == 1

/-- Peer failures reported by an accept operation do not invalidate the listener.
    Resource exhaustion, configuration failures and invalid owned descriptors
    remain fatal. Apply only after checking setup/close error flags. -/
def isRecoverableAcceptError (code : Int) : IO Bool := do
  if ← LeanNet.Errno.isInterrupted code then return true
  if ← LeanNet.Errno.isWouldBlock code then return true
  let codes ← [LeanNet.FFI.errnoEconnaborted, LeanNet.FFI.errnoEconnreset,
    LeanNet.FFI.errnoEnetdown, LeanNet.FFI.errnoEnetunreach, LeanNet.FFI.errnoEhostunreach,
    LeanNet.FFI.errnoEnonet, LeanNet.FFI.errnoEproto, LeanNet.FFI.errnoEnoprotoopt,
    LeanNet.FFI.errnoEhostdown, LeanNet.FFI.errnoEopnotsupp, LeanNet.FFI.errnoEpipe,
    LeanNet.FFI.errnoEnotconn, LeanNet.FFI.errnoEtimedout, LeanNet.FFI.errnoEconnrefused,
    LeanNet.FFI.errnoEnetreset].mapM id
  return codes.any (fun value => value != 0 && code == -(Int.ofNat value.toNat))

private def destroy (reactor : Reactor) : IO Unit := do
  ensureAlive reactor
  reactor.alive.set false
  checkedZero "reactor free" (← FFI.Reactor.free reactor.handle)

/-- Bracket the reactor, including every still-open connection and pooled buffer. -/
def withReactor (config : Config) (use : Reactor → IO α) : IO α := do
  let handle ← checked "reactor create" (← FFI.Reactor.create config.maxConnections config.maxEvents
    config.maxWrites config.buffers4k config.buffers16k config.buffers64k config.timerTickMs)
  if handle == 0 then throw (IO.userError "reactor create: null native handle")
  let reactor : Reactor := ⟨handle, ← IO.mkRef true⟩
  try use reactor finally destroy reactor

/-- Configure before starting any member's listener or loop. Each worker owns
    its adopted connections. Stop and join every member before freeing any of
    them; reactor brackets must enclose the complete worker lifetime. -/
def Reactor.setAcceptTargets (acceptor : Reactor) (workers : Array Reactor)
    (queueCapacity : UInt32 := 4096) : IO Unit := do
  ensureAlive acceptor
  let mut handles := #[]
  for worker in workers do
    ensureAlive worker
    handles := handles.push worker.handle
  checkedZero "reactor accept targets"
    (← FFI.Reactor.setAcceptTargets acceptor.handle handles queueCapacity)

def Reactor.socket (reactor : Reactor) : IO (Socket .fresh) := do
  ensureAlive reactor
  let token ← checked "reactor socket" (← FFI.Reactor.socketNew reactor.handle)
  if token == 0 then throw (IO.userError "reactor socket: null token")
  return ⟨reactor, token⟩

def Socket.bind (socket : Socket .fresh) (host : String) (port : UInt16)
    (reusePort : Bool := false) : IO (Socket .bound) := do
  ensureAlive socket.reactor
  if host.toUTF8.toList.contains 0 then throw (IO.userError "bind host contains NUL")
  checkedZero "reactor bind" (← FFI.Reactor.bind socket.reactor.handle socket.token host port (if reusePort then 1 else 0))
  return ⟨socket.reactor, socket.token⟩

def Socket.listen (socket : Socket .bound) (backlog : UInt32 := 4096) : IO (Socket .listening) := do
  ensureAlive socket.reactor
  checkedZero "reactor start listening" (← FFI.Reactor.startListening socket.reactor.handle socket.token backlog)
  return ⟨socket.reactor, socket.token⟩

def Reactor.listen (reactor : Reactor) (host : String) (port : UInt16)
    (reusePort : Bool := false) : IO (Socket .listening) := do
  ensureAlive reactor
  if host.toUTF8.toList.contains 0 then throw (IO.userError "listen host contains NUL")
  let token ← checked "reactor listen" (← FFI.Reactor.listen reactor.handle host port (if reusePort then 1 else 0))
  if token == 0 then throw (IO.userError "reactor listen: null socket token")
  return ⟨reactor, token⟩

/-- Closing an already-closed phantom state cannot be expressed by a caller. -/
def Socket.close (socket : Socket state) (_open : state ≠ .closed) : IO (Socket .closed) := do
  ensureAlive socket.reactor
  checkedZero "reactor close" (← FFI.Reactor.close socket.reactor.handle socket.token)
  return ⟨socket.reactor, socket.token⟩

def Buffer.view (buffer : Buffer) : IO ByteArray := do
  ensureAlive buffer.reactor
  let (result, bytes) ← FFI.Reactor.buffer buffer.reactor.handle buffer.token
  checkedZero "reactor buffer view" result
  return bytes

def Buffer.release (buffer : Buffer) : IO Unit := do
  ensureAlive buffer.reactor
  checkedZero "reactor buffer release" (← FFI.Reactor.release buffer.reactor.handle buffer.token)

def withBuffer (buffer : Buffer) (use : Buffer → IO α) : IO α :=
  try use buffer finally buffer.release

inductive Submission where
  | queued
  | wouldBlock

def Wire.id (wire : Wire state) : SocketId := ⟨wire.socket.reactor.handle, wire.socket.token⟩

private def ensureWire (wire : Wire state) : IO Unit := do
  ensureAlive wire.socket.reactor
  let mode ← checked "transport mode" (← FFI.Reactor.transportMode wire.socket.reactor.handle wire.socket.token wire.capability)
  if mode != wire.phase.toUInt64 then throw (IO.userError "transport phase alias is stale")

/-- Claim before any plaintext write. A returned native read batch can still
    contain old connected aliases; their operations now fail the native guard. -/
def Socket.claim (socket : Socket .connected) : IO (Wire .tls_handshaking) := do
  ensureAlive socket.reactor
  let capability ← checked "transport claim" (← FFI.Reactor.transportClaim socket.reactor.handle socket.token)
  if capability == 0 then throw (IO.userError "transport claim returned a null capability")
  return ⟨⟨socket.reactor, socket.token⟩, capability, 1⟩

/-- Complete only after the TLS engine's handshake and outgoing wire fence. -/
def Wire.ready (wire : Wire .tls_handshaking) : IO (Wire .tls_ready) := do
  ensureWire wire
  checkedZero "transport ready" (← FFI.Reactor.transportReady wire.socket.reactor.handle wire.socket.token wire.capability)
  return ⟨⟨wire.socket.reactor, wire.socket.token⟩, wire.capability, 2⟩

def Wire.isLive (wire : Wire state) : IO Bool := do
  unless ← wire.id.isLive wire.socket.reactor do return false
  ensureWire wire
  return true

def Wire.tryWrite (wire : Wire state) (buffer : Buffer) (offset length : UInt32)
    (operation : UInt64 := 0) : IO Submission := do
  ensureWire wire
  ensureAlive buffer.reactor
  if wire.socket.reactor.handle != buffer.reactor.handle then throw (IO.userError "transport buffer belongs to another reactor")
  let raw ← FFI.Reactor.transportWrite wire.socket.reactor.handle wire.socket.token wire.capability buffer.token offset length operation
  let result := LeanNet.Errno.decode raw
  if result < 0 && (← LeanNet.Errno.isWouldBlock result) then return .wouldBlock
  checkedZero "transport write" raw
  return .queued

def Wire.write (wire : Wire state) (buffer : Buffer) (offset length : UInt32)
    (operation : UInt64 := 0) : IO Unit := do
  match ← wire.tryWrite buffer offset length operation with
  | .queued => pure ()
  | .wouldBlock => throw (IO.userError "transport cipher write exhausted reserved credits")

def Wire.setReadEnabled (wire : Wire state) (enabled : Bool) : IO Unit := do
  ensureWire wire
  checkedZero "transport read interest" (← FFI.Reactor.transportReadEnabled wire.socket.reactor.handle wire.socket.token wire.capability (if enabled then 1 else 0))

def Wire.armTimer (wire : Wire state) (kind : UInt32) (deadlineMs : UInt64) : IO Unit := do
  ensureWire wire
  checkedZero "transport arm timer" (← FFI.Reactor.transportArmTimer wire.socket.reactor.handle wire.socket.token wire.capability kind deadlineMs)

def Wire.cancelTimer (wire : Wire state) (kind : UInt32) : IO Unit := do
  ensureWire wire
  checkedZero "transport cancel timer" (← FFI.Reactor.transportCancelTimer wire.socket.reactor.handle wire.socket.token wire.capability kind)

def Wire.closeAfterWrites (wire : Wire state) : IO Unit := do
  ensureWire wire
  checkedZero "transport drain close" (← FFI.Reactor.transportDrain wire.socket.reactor.handle wire.socket.token wire.capability)

def Wire.close (wire : Wire state) : IO Unit := do
  ensureWire wire
  checkedZero "transport abort" (← FFI.Reactor.transportAbort wire.socket.reactor.handle wire.socket.token wire.capability)

/-- Acquire on the loop; native consumers retain their own reference. -/
def Reactor.waker (reactor : Reactor) : IO Waker := do
  ensureAlive reactor
  let handle ← checked "waker acquire" (← FFI.Reactor.wakerAcquire reactor.handle)
  if handle == 0 then throw (IO.userError "waker acquire returned a null handle")
  return ⟨handle, ← IO.mkRef true⟩

def Waker.wake (waker : Waker) : IO Unit := do
  unless ← waker.alive.get do throw (IO.userError "waker is released")
  checkedZero "waker notify" (← FFI.Reactor.wakerWake waker.handle)

def Waker.release (waker : Waker) : IO Unit := do
  unless ← waker.alive.get do throw (IO.userError "waker is released")
  waker.alive.set false
  checkedZero "waker release" (← FFI.Reactor.wakerRelease waker.handle)

def Reactor.withWaker (reactor : Reactor) (use : Waker → IO α) : IO α := do
  let waker ← reactor.waker
  try use waker finally waker.release


/-- Queue an owned slice. Backpressure preserves the caller's buffer lease. -/
def Socket.tryWrite (socket : Socket .connected) (buffer : Buffer)
    (offset length : UInt32) (operation : UInt64 := 0) : IO Submission := do
  ensureAlive socket.reactor
  ensureAlive buffer.reactor
  if socket.reactor.handle != buffer.reactor.handle then
    throw (IO.userError "write buffer belongs to another reactor")
  let raw ← FFI.Reactor.write socket.reactor.handle socket.token buffer.token offset length operation
  let result := LeanNet.Errno.decode raw
  if result < 0 && (← LeanNet.Errno.isWouldBlock result) then return .wouldBlock
  checkedZero "reactor queue write" raw
  return .queued

/-- Convenience for protocols that reserve one native write credit per read. -/
def Socket.write (socket : Socket .connected) (buffer : Buffer)
    (offset length : UInt32) (operation : UInt64 := 0) : IO Unit := do
  match ← socket.tryWrite buffer offset length operation with
  | .queued => pure ()
  | .wouldBlock => throw (IO.userError "reactor queue write exhausted reserved credits")

/-- Drain all already-queued writes before closing a peer that half-closed. -/
def Socket.closeAfterWrites (socket : Socket .connected) : IO Unit := do
  ensureAlive socket.reactor
  checkedZero "reactor drain close" (← FFI.Reactor.closeAfterWrites socket.reactor.handle socket.token)

/-- Pause future reads. Already-returned events and one outstanding IOCP read
    can still complete; the dispatcher remains responsible for their leases. -/
def Socket.setReadEnabled (socket : Socket .connected) (enabled : Bool) : IO Unit := do
  ensureAlive socket.reactor
  checkedZero "reactor read interest"
    (← FFI.Reactor.readEnabled socket.reactor.handle socket.token (if enabled then 1 else 0))

def Reactor.acquire (reactor : Reactor) (minimum : UInt32) : IO Buffer := do
  ensureAlive reactor
  let token ← checked "reactor acquire buffer" (← FFI.Reactor.acquire reactor.handle minimum)
  if token == 0 then throw (IO.userError "reactor acquire: null buffer token")
  return ⟨reactor, token⟩

/-- Pool exhaustion is ordinary backpressure; invalid requests remain errors. -/
def Reactor.tryAcquire (reactor : Reactor) (minimum : UInt32) : IO (Option Buffer) := do
  ensureAlive reactor
  let raw ← FFI.Reactor.acquire reactor.handle minimum
  let result := LeanNet.Errno.decode raw
  if result < 0 && (← LeanNet.Errno.isWouldBlock result) then return none
  let token ← checked "reactor acquire buffer" raw
  if token == 0 then throw (IO.userError "reactor acquire: null buffer token")
  return some ⟨reactor, token⟩

def Buffer.copyFrom (buffer : Buffer) (bytes : ByteArray) : IO Unit := do
  ensureAlive buffer.reactor
  checkedZero "reactor copy buffer" (← FFI.Reactor.copy buffer.reactor.handle buffer.token bytes)

/-- Replace buffer contents with a bounded source range without allocating an
    intermediate ByteArray. Queued writes and retained views prevent mutation. -/
def Buffer.copySliceFrom (buffer : Buffer) (bytes : ByteArray) (offset length : UInt32) : IO Unit := do
  ensureAlive buffer.reactor
  checkedZero "reactor copy buffer slice"
    (← FFI.Reactor.copySlice buffer.reactor.handle buffer.token bytes offset length)

def Socket.armTimer (socket : Socket .connected)
    (kind : UInt32) (deadlineMs : UInt64) : IO Unit := do
  ensureAlive socket.reactor
  checkedZero "reactor arm timer" (← FFI.Reactor.armTimer socket.reactor.handle socket.token kind deadlineMs)

def Socket.cancelTimer (socket : Socket .connected) (kind : UInt32) : IO Unit := do
  ensureAlive socket.reactor
  checkedZero "reactor cancel timer" (← FFI.Reactor.cancelTimer socket.reactor.handle socket.token kind)

inductive Event where
  | accepted (socket : Socket .connected)
  | read (socket : Socket .connected) (buffer : Buffer) (offset length : UInt32)
  | written (socket : SocketId) (operation : UInt64) (count : Nat)
  | eof (socket : Socket .connected)
  | timer (socket : Socket .connected) (kind : UInt32)
  | closed (socket : Socket .closed)
  | error (socket : SocketId) (flags : UInt32) (code : Int)
  | wake
  | wireRead (socket : SocketId) (buffer : Buffer) (offset length : UInt32)
  | wireEOF (socket : SocketId)
  | wireTimer (socket : SocketId) (kind : UInt32)

inductive PollResult where
  | interrupted
  | completions (count : Nat)

def Reactor.poll (reactor : Reactor) (timeoutMs : Int32 := -1) : IO PollResult := do
  ensureAlive reactor
  let raw ← FFI.Reactor.step reactor.handle timeoutMs
  let result := LeanNet.Errno.decode raw
  if result < 0 then
    if ← LeanNet.Errno.isInterrupted result then return .interrupted
    throw (← LeanNet.Errno.error "reactor step" result)
  return .completions result.toNat

/-- Events remain valid only until the next poll. Leases explicitly outlive it. -/
def Reactor.event (reactor : Reactor) (index : UInt32) : IO Event := do
  ensureAlive reactor
  let event ← FFI.Reactor.event reactor.handle index
  let result := LeanNet.Errno.decode event.result
  if event.kind == 7 then return .error ⟨reactor.handle, event.connection⟩ event.flags result
  if result < 0 then throw (← LeanNet.Errno.error "reactor event" result)
  match event.kind.toNat with
  | 1 => return .accepted ⟨reactor, event.connection⟩
  | 2 =>
    if (event.flags &&& 8) != 0 then
      return .wireRead ⟨reactor.handle, event.connection⟩ ⟨reactor, event.buffer⟩ event.offset event.length
    return .read ⟨reactor, event.connection⟩ ⟨reactor, event.buffer⟩ event.offset event.length
  | 3 => return .written ⟨reactor.handle, event.connection⟩ event.operation result.toNat
  | 4 =>
    if (event.flags &&& 8) != 0 then return .wireEOF ⟨reactor.handle, event.connection⟩
    return .eof ⟨reactor, event.connection⟩
  | 5 =>
    if (event.flags &&& 8) != 0 then return .wireTimer ⟨reactor.handle, event.connection⟩ event.operation.toUInt32
    return .timer ⟨reactor, event.connection⟩ event.operation.toUInt32
  | 6 => return .closed ⟨reactor, event.connection⟩
  | 8 => return .wake
  | _ => throw (IO.userError "reactor returned an invalid completion kind")

/-- Setup-time reactor collection; each later worker owns one member. -/
def withReactors (count : Nat) (config : Config) (use : Array Reactor → IO α) : IO α :=
  go count #[]
where
  go (remaining : Nat) (reactors : Array Reactor) : IO α :=
    match remaining with
    | 0 => use reactors
    | n + 1 => withReactor config fun reactor => go n (reactors.push reactor)

structure Group where
  private mk ::
  private handle : UInt64
  private alive : IO.Ref Bool

private def ensureGroup (group : Group) : IO Unit := do
  unless (← group.alive.get) do throw (IO.userError "reactor group is closed")

def Group.stop (group : Group) : IO Unit := do
  ensureGroup group
  checkedZero "reactor group stop" (← FFI.Reactor.groupStop group.handle)

def Group.stopping (group : Group) : IO Bool := do
  ensureGroup group
  let value ← checked "reactor group stopping" (← FFI.Reactor.groupStopping group.handle)
  if value > 1 then throw (IO.userError "invalid reactor group stop result")
  return value == 1

/-- Workers must be joined before returning from this bracket. -/
def withGroup (reactors : Array Reactor) (use : Group → IO α) : IO α := do
  let mut handles := #[]
  for reactor in reactors do
    ensureAlive reactor
    handles := handles.push reactor.handle
  let handle ← checked "reactor group create" (← FFI.Reactor.groupNew handles)
  if handle == 0 then throw (IO.userError "reactor group returned a null handle")
  let group : Group := ⟨handle, ← IO.mkRef true⟩
  try
    checkedZero "reactor group install" (← FFI.Reactor.groupInstall handle)
    let result ← use group
    checkedZero "reactor group wake" (← FFI.Reactor.groupWakeError handle)
    return result
  finally
    group.alive.set false
    checkedZero "reactor group free" (← FFI.Reactor.groupFree handle)

/-- One process owns an endpoint while its per-core listeners share SO_REUSEPORT. -/
def withEndpoint (port : UInt16) (use : IO α) : IO α := do
  let handle ← checked "reactor endpoint claim" (← FFI.Reactor.endpointAcquire port)
  if handle == 0 then throw (IO.userError "reactor endpoint claim: null handle")
  try use finally checkedZero "reactor endpoint release" (← FFI.Reactor.endpointRelease handle)

def cpuCount : IO Nat := do
  let value ← checked "reactor cpu count" (← FFI.Reactor.cpuCount)
  if value == 0 then throw (IO.userError "reactor cpu count returned zero")
  return value.toNat

def nowMs : IO UInt64 := FFI.Reactor.now

end LeanNet.Reactor
