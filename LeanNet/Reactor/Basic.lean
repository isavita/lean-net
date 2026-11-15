import LeanNet.Socket.State
import LeanNet.FFI.Errno
import LeanNet.FFI.Reactor
import LeanNet.FileRegion
import LeanNet.FileSource

namespace LeanNet.Reactor

structure Config where
  maxConnections : UInt32 := 4096
  maxEvents : UInt32 := 1024
  maxWrites : UInt32 := 8192
  buffers4k : UInt32 := 4096
  buffers16k : UInt32 := 256
  buffers64k : UInt32 := 64
  timerTickMs : UInt32 := 10

/-- Optional per-peer-IP budget for completed inbound TCP accepts. This is
    checked by the native listener before a TLS worker sees the socket. -/
structure AcceptRateConfig where
  tokens : Nat
  periodMs : Nat := 1000
  burst : Nat
  keyedSlots : Nat := 65536
  deriving Inhabited

/-- One thread owns this reactor and every connection and buffer lease it creates. -/
structure Reactor where
  private mk ::
  private handle : UInt64
  private alive : IO.Ref Bool

/-- Setup-scoped shared table. Every listener reactor borrows it until all
    owner loops and reactor brackets have completed. -/
structure AcceptLimiter where
  private mk ::
  private handle : UInt64
  private lanes : Nat

@[extern "lean_net_rl_new"]
private opaque acceptLimiterNew (rules : @& ByteArray) (workers slots : UInt32)
    (random : @& ByteArray) (nowMs : UInt64) : IO UInt64
@[extern "lean_net_rl_free"]
private opaque acceptLimiterFree (handle : UInt64) : IO UInt64

/-- Native generation tokens prevent stale aliases from reaching a reused socket. -/
structure Socket (state : SocketState) where
  private mk ::
  private reactor : Reactor
  private token : UInt64

/-- Pending outbound connect. It has no plaintext or TLS write capability. -/
structure Connecting where
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

def Connecting.id (connecting : Connecting) : SocketId :=
  ⟨connecting.reactor.handle, connecting.token⟩

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

/-- Numeric peer IP address of a live connection (IPv4-mapped IPv6 rendered
    as IPv4), or an empty array when unavailable. Never throws for a peer that
    has already gone away. -/
def SocketId.peerAddress (id : SocketId) (reactor : Reactor) : IO ByteArray := do
  if id.owner != reactor.handle || !(← reactor.alive.get) then return ByteArray.empty
  FFI.Reactor.peerAddress reactor.handle id.token

/-- Binary peer IP: 4 bytes (IPv4, including IPv4-mapped IPv6) or 16 bytes
    (IPv6); empty when unavailable. -/
def SocketId.peerBytes (id : SocketId) (reactor : Reactor) : IO ByteArray := do
  if id.owner != reactor.handle || !(← reactor.alive.get) then return ByteArray.empty
  FFI.Reactor.peerRaw reactor.handle id.token

/-- A historical completion identity does not grant socket access. Query before
    taking protocol actions: CLOSED may still be queued for a later poll. -/
def SocketId.isLive (id : SocketId) (reactor : Reactor) : IO Bool := do
  if id.owner != reactor.handle then throw (IO.userError "socket identity belongs to another reactor")
  if !(← reactor.alive.get) then return false
  let value ← checked "reactor connection liveness" (← FFI.Reactor.connectionLive reactor.handle id.token)
  if value > 1 then throw (IO.userError "invalid reactor connection liveness result")
  return value == 1

/-- Descriptor or kernel memory exhaustion while accepting. The native
    reactor has already paused its listener and resumes after a short backoff;
    pending clients stay in the kernel backlog instead of crashing the loop. -/
def isAcceptExhaustion (code : Int) : IO Bool := do
  let codes ← [LeanNet.FFI.errnoEmfile, LeanNet.FFI.errnoEnfile,
    LeanNet.FFI.errnoEnobufs, LeanNet.FFI.errnoEnomem].mapM id
  return codes.any (fun value => value != 0 && code == -(Int.ofNat value.toNat))

/-- Peer failures and descriptor/memory exhaustion reported by an accept
    operation do not invalidate the listener. Configuration failures and invalid
    owned descriptors remain fatal. Apply only after checking setup/close flags. -/
def isRecoverableAcceptError (code : Int) : IO Bool := do
  if ← isAcceptExhaustion code then return true
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

private def le32 (value : Nat) : ByteArray :=
  ByteArray.mk #[value.toUInt8, (value >>> 8).toUInt8,
    (value >>> 16).toUInt8, (value >>> 24).toUInt8]

/-- Allocate one fixed-size, lock-free keyed GCRA table shared by all accept
    lanes. Table saturation denies new peers rather than resetting a budget. -/
def withAcceptLimiter (config : AcceptRateConfig) (lanes : Nat)
    (use : AcceptLimiter → IO α) : IO α := do
  if config.tokens == 0 || config.tokens > 4294967295 ||
      config.periodMs == 0 || config.periodMs > 4294967295 ||
      config.burst == 0 || config.burst > 4294967295 ||
      config.keyedSlots < 4 || config.keyedSlots > 16777216 ||
      config.keyedSlots &&& (config.keyedSlots - 1) != 0 ||
      lanes == 0 || lanes > 256 then
    throw (IO.userError "invalid accept rate configuration")
  let rule := le32 config.tokens ++ le32 config.periodMs ++ le32 config.burst ++
    le32 2 ++ le32 1
  let handle ← checked "accept rate limiter setup"
    (← acceptLimiterNew rule lanes.toUInt32 config.keyedSlots.toUInt32
      (← IO.getRandomBytes 16) (← FFI.Reactor.now))
  if handle == 0 then throw (IO.userError "accept rate limiter setup returned null")
  try use ⟨handle, lanes⟩ finally
    checkedZero "accept rate limiter free" (← acceptLimiterFree handle)

/-- Install before any listener or event loop starts. The limiter must outlive
    this reactor; `withAcceptLimiter` should bracket the whole worker pool. -/
def AcceptLimiter.attach (limiter : AcceptLimiter) (reactor : Reactor) (lane : Nat) : IO Unit := do
  if lane >= limiter.lanes then throw (IO.userError "invalid accept limiter lane")
  ensureAlive reactor
  checkedZero "reactor accept rate limiter"
    (← FFI.Reactor.setAcceptLimiter reactor.handle limiter.handle lane.toUInt32)

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

/-- The address is a 4-byte IPv4 or 16-byte IPv6 network-order IP. Resolve
    hostnames outside the reactor thread. Initiation failure retires the fresh
    slot; asynchronous failure arrives as `.error` then `.closed`. -/
def Socket.startConnect (socket : Socket .fresh) (address : ByteArray)
    (port : UInt16) : IO Connecting := do
  ensureAlive socket.reactor
  if (address.size != 4 && address.size != 16) || port == 0 then
    let _ ← socket.close (by decide)
    throw (IO.userError "outbound address must be a 4- or 16-byte IP and port nonzero")
  let raw ← FFI.Reactor.connect socket.reactor.handle socket.token address port
  let result := LeanNet.Errno.decode raw
  if result < 0 then
    let _ ← socket.close (by decide)
    throw (← LeanNet.Errno.error "reactor connect" result)
  checkedZero "reactor connect" raw
  return ⟨socket.reactor, socket.token⟩

/-- Cancel pending connect; later native completions cannot reuse its token. -/
def Connecting.close (connecting : Connecting) : IO Unit := do
  ensureAlive connecting.reactor
  checkedZero "reactor cancel connect"
    (← FFI.Reactor.close connecting.reactor.handle connecting.token)

def Connecting.armTimer (connecting : Connecting) (kind : UInt32)
    (deadlineMs : UInt64) : IO Unit := do
  ensureAlive connecting.reactor
  checkedZero "reactor connect timer"
    (← FFI.Reactor.armTimer connecting.reactor.handle connecting.token kind deadlineMs)

def Connecting.cancelTimer (connecting : Connecting) (kind : UInt32) : IO Unit := do
  ensureAlive connecting.reactor
  checkedZero "reactor cancel connect timer"
    (← FFI.Reactor.cancelTimer connecting.reactor.handle connecting.token kind)

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

inductive FileSubmission where
  | queued
  | wouldBlock
  | interrupted

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

def Wire.close (wire : Wire state) (_open : state ≠ .closed) : IO Unit := do
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

/-- Allocate the file registration table before this worker's first poll. -/
def Reactor.setupFiles (reactor : Reactor) (capacity : UInt32) : IO Unit := do
  ensureAlive reactor
  checkedZero "reactor file table" (← FFI.Reactor.fileTable reactor.handle capacity)

/-- The native table retains its source until registration release or reactor
    destruction. Protocol machines receive only the borrowed range identity. -/
def Reactor.importFile (reactor : Reactor) (source : File.Source) : IO FileRegion := do
  ensureAlive reactor
  source.ensureAlive
  let owner ← checked "reactor file namespace" (← FFI.Reactor.fileOwner reactor.handle)
  if owner == 0 then throw (IO.userError "reactor file namespace is invalid")
  let token ← checked "reactor file import" (← FFI.Reactor.fileImport reactor.handle source.handle)
  if token == 0 then throw (IO.userError "reactor file import returned no token")
  return { owner, token, length := source.size }

def Reactor.releaseFile (reactor : Reactor) (region : FileRegion) : IO Unit := do
  ensureAlive reactor
  let owner ← checked "reactor file namespace" (← FFI.Reactor.fileOwner reactor.handle)
  if region.owner != owner then throw (IO.userError "file belongs to another reactor")
  checkedZero "reactor file release" (← FFI.Reactor.fileRelease reactor.handle region.token)

/-- Queue file bytes through the same native FIFO as pooled byte writes. The
    native mode check also rejects old plaintext aliases to TLS sockets. -/
def Socket.tryFile (socket : Socket .connected) (region : FileRegion)
    (operation : UInt64 := 0) : IO FileSubmission := do
  ensureAlive socket.reactor
  if !region.valid || region.length > 4294967295 then
    throw (IO.userError "invalid or foreign file range")
  let raw ← FFI.Reactor.fileWrite socket.reactor.handle socket.token region.owner region.token
    region.offset region.length.toUInt32 operation
  let result := Errno.decode raw
  if result < 0 && (← Errno.isInterrupted result) then return .interrupted
  if result < 0 && (← Errno.isWouldBlock result) then return .wouldBlock
  checkedZero "reactor queue file" raw
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
  | connected (socket : Socket .connected)
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
  | connectTimer (socket : SocketId) (kind : UInt32)

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
    if (event.flags &&& 16) != 0 then return .connectTimer ⟨reactor.handle, event.connection⟩ event.operation.toUInt32
    if (event.flags &&& 8) != 0 then return .wireTimer ⟨reactor.handle, event.connection⟩ event.operation.toUInt32
    return .timer ⟨reactor, event.connection⟩ event.operation.toUInt32
  | 6 => return .closed ⟨reactor, event.connection⟩
  | 8 => return .wake
  | 9 => return .connected ⟨reactor, event.connection⟩
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

/-- Process-wide count of SIGHUP deliveries observed by installed groups.
    Control code compares it with the last value it served. Always zero on
    Windows, which has no hang-up signal. -/
def reloadRequests : IO UInt64 := do
  let value ← checked "reactor reload requests" (← FFI.Reactor.groupReloadRequests)
  return value

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

/-- Pin the calling worker thread to the `index`-th CPU (modulo) of the
    process's allowed CPU set. Returns the CPU, or `none` where the platform
    offers no binding (macOS on Apple silicon). Call from the worker itself. -/
def pinCurrentThread (index : Nat) : IO (Option Nat) := do
  let raw := LeanNet.Errno.decode (← FFI.Reactor.pinCurrentThread index.toUInt32)
  if raw >= 0 then return some raw.toNat
  if raw == -(Int.ofNat (← LeanNet.FFI.errnoEopnotsupp).toNat) then return none
  throw (← LeanNet.Errno.error "reactor pin worker" raw)

/-- Resident set size of this process in bytes, if the platform reports it. -/
def processResidentBytes : IO (Option Nat) := do
  let raw := LeanNet.Errno.decode (← FFI.Reactor.processResidentBytes)
  return if raw >= 0 then some raw.toNat else none

/-- Open descriptors (POSIX) or kernel handles (Windows), if reported. -/
def processOpenFds : IO (Option Nat) := do
  let raw := LeanNet.Errno.decode (← FFI.Reactor.processOpenFds)
  return if raw >= 0 then some raw.toNat else none

/-- True once the process's installed worker group has been asked to stop. -/
def processStopping : IO Bool := do return (← FFI.Reactor.processStopping) == 1

def nowMs : IO UInt64 := FFI.Reactor.now

end LeanNet.Reactor
