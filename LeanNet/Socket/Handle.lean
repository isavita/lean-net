import LeanNet.FFI.Errno
import LeanNet.Socket.State

namespace LeanNet

inductive ReadOutcome where
  | data (bytes : ByteArray)
  | eof
  | interrupted
  | wouldBlock
  | wantWrite

inductive WriteOutcome where
  | written (count : Nat)
  | interrupted
  | wouldBlock
  | wantRead
  deriving Repr

inductive TransportProtocol where
  | detect | http1 | http2
  deriving BEq

inductive TransportProgress where
  | complete (protocol : TransportProtocol)
  | interrupted | wantRead | wantWrite

/-- Optional transport hooks own protocol state but never the socket descriptor.
    Hooks are called only on the single-threaded socket event loop. -/
structure ConnectionTransport where
  handshake : IO TransportProgress
  recv : USize → IO ReadOutcome
  send : ByteArray → Nat → Nat → IO WriteOutcome
  buffered : IO Bool
  shutdown : IO TransportProgress
  close : IO Unit

/-- A socket's role is tracked statically. Its constructor is not public. -/
structure Socket (state : SocketState) where
  private mk ::
  private fd : Int64
  private identity : Nat
  private alive : IO.Ref Bool
  private transport : IO.Ref (Option ConnectionTransport)

private initialize nextSocketIdentity : IO.Ref Nat ← IO.mkRef 0

private def newSocket (fd : Int64) : IO (Socket state) := do
  let identity ← nextSocketIdentity.get
  nextSocketIdentity.set (identity + 1)
  return ⟨fd, identity, ← IO.mkRef true, ← IO.mkRef none⟩

private def ensureOpen (socket : Socket state) : IO Unit := do
  unless (← socket.alive.get) do
    throw (IO.userError "socket is closed (library bug)")

abbrev Listener := Socket .listening
abbrev Connection := Socket .connected

private def checkResult (operation : String) (value : UInt64) : IO Int := do
  let result := Errno.decode value
  if result < 0 then throw (← Errno.error operation result)
  return result

private def closeSocket (socket : Socket state) (_open : state ≠ .closed) : IO Unit := do
  ensureOpen socket
  -- Mark dead before calling close; even a failing close must never be retried.
  socket.alive.set false
  let transport ← socket.transport.get
  socket.transport.set none
  try
    if let some transport := transport then transport.close
  finally
    let result ← FFI.rawClose socket.fd
    let _ ← checkResult "close" result
    pure ()

/-- The closed state cannot supply the proof required for another close. -/
def Socket.close (socket : Socket state) (isOpen : state ≠ .closed) : IO (Socket .closed) := do
  closeSocket socket isOpen
  return ⟨socket.fd, socket.identity, socket.alive, socket.transport⟩

/-- Closes the listener when the callback exits, including when it throws.
    Callbacks must not retain the handle beyond the scope of this bracket. -/
def withListener (host : String) (port : UInt16) (use : Listener → IO α) : IO α := do
  let result ← checkResult "listen" (← FFI.rawTcpListen host port)
  let listener : Listener ← newSocket (Int64.ofInt result)
  try use listener finally closeSocket listener (by decide)

/-- Own an accepted connection for the duration of the callback.
    The caller must pass each connection to this bracket once and must not use
    or retain it after the callback exits; Lean does not enforce affine ownership. -/
def withConnection (connection : Connection) (use : Connection → IO α) : IO α := do
  ensureOpen connection
  try use connection finally closeSocket connection (by decide)

namespace Listener

def accept (listener : Listener) : IO Connection := do
  ensureOpen listener
  let result ← checkResult "accept" (← FFI.rawTcpAccept listener.fd)
  newSocket (Int64.ofInt result)

/-- An interruptible accept returns `none` on an interrupt. -/
def acceptInterruptible (listener : Listener) : IO (Option Connection) := do
  ensureOpen listener
  let result := Errno.decode (← FFI.interruptibleAccept listener.fd)
  if result < 0 then
    if ← Errno.isInterrupted result then return none
    if ← Errno.isWouldBlock result then return none
    throw (← Errno.error "accept" result)
  return some (← newSocket (Int64.ofInt result))

end Listener

namespace Connection

/-- Attach one transport using a descriptor borrowed only for setup. The hook
    must not close, duplicate, or retain ownership of the descriptor. Its close
    callback releases transport state; the socket bracket closes the descriptor. -/
def installTransport (connection : Connection) (setup : Int64 → IO ConnectionTransport) : IO Unit := do
  ensureOpen connection
  if (← connection.transport.get).isSome then throw (IO.userError "transport already installed")
  let hooks ← setup connection.fd
  connection.transport.set (some hooks)

def handshake (connection : Connection) : IO TransportProgress := do
  ensureOpen connection
  match ← connection.transport.get with
  | some hooks => hooks.handshake
  | none => return .complete .detect

def buffered (connection : Connection) : IO Bool := do
  ensureOpen connection
  match ← connection.transport.get with
  | some hooks => hooks.buffered
  | none => return false

def shutdownTransport (connection : Connection) : IO TransportProgress := do
  ensureOpen connection
  match ← connection.transport.get with
  | some hooks => hooks.shutdown
  | none => return .complete .detect

private def classifyRead (result : UInt64 × ByteArray) : IO ReadOutcome := do
  let count := Errno.decode result.1
  if count < 0 then
    if ← Errno.isInterrupted count then return .interrupted
    if ← Errno.isWouldBlock count then return .wouldBlock
    throw (← Errno.error "recv" count)
  if count == 0 then return .eof
  if count.toNat != result.2.size then
    throw (IO.userError "recv: invalid byte count from socket shim")
  return .data result.2

/-- Read at most `maxLen` bytes. Zero is rejected rather than mistaken for EOF. -/
def recv (connection : Connection) (maxLen : USize) : IO ReadOutcome := do
  ensureOpen connection
  if maxLen == 0 then throw (IO.userError "recv: maxLen must be positive")
  match ← connection.transport.get with
  | some hooks => hooks.recv maxLen
  | none => classifyRead (← FFI.rawTcpRecv connection.fd maxLen)

def recvInterruptible (connection : Connection) (maxLen : USize) : IO ReadOutcome := do
  ensureOpen connection
  if (← connection.transport.get).isSome then
    throw (IO.userError "interruptible raw recv is unavailable on transported sockets")
  if maxLen == 0 then throw (IO.userError "recv: maxLen must be positive")
  classifyRead (← FFI.interruptibleRecv connection.fd maxLen)

private def classifyWrite (value : UInt64) : IO WriteOutcome := do
  let count := Errno.decode value
  if count < 0 then
    if ← Errno.isInterrupted count then return .interrupted
    if ← Errno.isWouldBlock count then return .wouldBlock
    throw (← Errno.error "send" count)
  return .written count.toNat

def send (connection : Connection) (bytes : ByteArray) : IO WriteOutcome := do
  ensureOpen connection
  match ← connection.transport.get with
  | some hooks => hooks.send bytes 0 bytes.size
  | none => classifyWrite (← FFI.rawTcpSend connection.fd bytes bytes.size.toUSize)

def sendInterruptible (connection : Connection) (bytes : ByteArray) : IO WriteOutcome := do
  ensureOpen connection
  if (← connection.transport.get).isSome then
    throw (IO.userError "interruptible raw send is unavailable on transported sockets")
  classifyWrite (← FFI.interruptibleSend connection.fd bytes bytes.size.toUSize)

/-- Blocking read policy: retry interruptions, and surface unexpected would-block. -/
partial def recv! (connection : Connection) (maxLen : USize) : IO ReadOutcome := do
  match ← connection.recv maxLen with
  | .interrupted => connection.recv! maxLen
  | result => return result

/-- Write every byte, handling partial writes and retrying EINTR. -/
partial def send! (connection : Connection) (bytes : ByteArray) : IO Unit := do
  ensureOpen connection
  if bytes.size == 0 then return
  match ← connection.send bytes with
  | .interrupted => connection.send! bytes
  | .wouldBlock | .wantRead => throw (IO.userError "send: socket would block")
  | .written n =>
    if n == 0 || n > bytes.size then throw (IO.userError "send: invalid progress")
    connection.send! (bytes.extract n bytes.size)

end Connection

/-- Installs scoped SIGINT handling. Use only in single-threaded server loops. -/
def withInterruptHandler (use : IO α) : IO α := do
  let _ ← checkResult "install signal handler" (← FFI.interruptBegin)
  try use finally
    let _ ← checkResult "restore signal handler" (← FFI.interruptEnd)
    pure ()

def interruptRequested : IO Bool := do
  let n ← checkResult "check signal" (← FFI.interruptRequested)
  if n == 0 then return false
  if n == 1 then return true
  throw (IO.userError "check signal: invalid result")


/-- Managed collection of accepted sockets. Connections must only be closed via
    this pool and must not be retained beyond its bracket. -/
structure ConnectionPool where
  private mk ::
  private active : IO.Ref (Array Connection)
  private alive : IO.Ref Bool

private def ensurePoolOpen (pool : ConnectionPool) : IO Unit := do
  unless (← pool.alive.get) do
    throw (IO.userError "connection pool is closed (library bug)")

inductive AcceptOutcome where
  | accepted (connection : Connection)
  | interrupted
  | wouldBlock
  | retry

private def matchesErrno (result : Int) (codes : List (IO UInt64)) : IO Bool := do
  let codes ← codes.mapM id
  return codes.any (fun code => code != 0 && result == -(Int.ofNat code.toNat))

private def acceptTransient (result : Int) : IO Bool :=
  matchesErrno result [FFI.errnoEconnaborted, FFI.errnoEconnreset, FFI.errnoEnetdown,
    FFI.errnoEnetunreach, FFI.errnoEhostunreach, FFI.errnoEnonet, FFI.errnoEproto,
    FFI.errnoEnoprotoopt, FFI.errnoEhostdown, FFI.errnoEopnotsupp]

private def verifiedPeerFailure (result : Int) : IO Bool :=
  matchesErrno result [FFI.errnoEconnaborted, FFI.errnoEconnreset, FFI.errnoEpipe,
    FFI.errnoEtimedout, FFI.errnoEnetreset, FFI.errnoEnetdown, FFI.errnoEnetunreach,
    FFI.errnoEhostunreach, FFI.errnoEconnrefused, FFI.errnoEnotconn]

private def setSocketNonblocking (socket : Socket state) : IO Unit := do
  ensureOpen socket
  let _ ← checkResult "set nonblocking" (← FFI.setNonblocking socket.fd 1)
  pure ()

def Listener.setNonblocking (listener : Listener) : IO Unit := setSocketNonblocking listener

def Connection.setNonblocking (connection : Connection) : IO Unit := setSocketNonblocking connection

def ConnectionPool.close (pool : ConnectionPool) (connection : Connection) : IO Unit := do
  ensurePoolOpen pool
  let active ← pool.active.get
  if !(active.any (fun c => c.identity == connection.identity && c.fd == connection.fd)) then
    throw (IO.userError "close: connection is not owned by pool (library bug)")
  -- Remove before close: close is never retried, even if the syscall fails.
  pool.active.set (active.filter (fun c => c.identity != connection.identity))
  closeSocket connection (by decide)

def ConnectionPool.accept (pool : ConnectionPool) (listener : Listener) : IO AcceptOutcome := do
  ensurePoolOpen pool
  ensureOpen listener
  let (raw, stage) ← FFI.acceptStaged listener.fd
  let result := Errno.decode raw
  if result < 0 then
    if stage == 1 then
      if ← Errno.isInterrupted result then return .interrupted
      if ← Errno.isWouldBlock result then return .wouldBlock
      if ← acceptTransient result then return .retry
      throw (← Errno.error "accept" result)
    if stage == 2 then throw (← Errno.error "accepted socket setup" result)
    if stage == 3 then throw (← Errno.error "close" result)
    if stage == 4 then
      if ← verifiedPeerFailure result then return .retry
      throw (IO.userError "accept: invalid verified peer failure")
    throw (IO.userError "accept: invalid failure stage")
  if stage != 0 then throw (IO.userError "accept: invalid success stage")
  let conn : Connection ← newSocket (Int64.ofInt result)
  pool.active.modify (fun active => active.push conn)
  -- On failure the pool remains responsible for closing this descriptor.
  setSocketNonblocking conn
  return .accepted conn

private def closePool (pool : ConnectionPool) : IO Unit := do
  ensurePoolOpen pool
  pool.alive.set false
  let active ← pool.active.get
  pool.active.set #[]
  let mut firstError : Option IO.Error := none
  for connection in active do
    try closeSocket connection (by decide)
    catch error =>
      if firstError.isNone then firstError := some error
  if let some error := firstError then throw error

/-- Bracket all pool-owned sockets, even across exceptions or signal shutdown.
    The callback is single-threaded and must not retain handles past its scope. -/
def withConnectionPool (use : ConnectionPool → IO α) : IO α := do
  let pool : ConnectionPool := ⟨← IO.mkRef #[], ← IO.mkRef true⟩
  try use pool finally closePool pool

/-- Nonblocking send from an offset, with no copying of the unsent tail. -/
def Connection.sendAt (connection : Connection) (buffer : ByteArray)
    (offset length : Nat) : IO WriteOutcome := do
  ensureOpen connection
  if offset > buffer.size || length > buffer.size - offset then
    throw (IO.userError "send: range outside byte array")
  match ← connection.transport.get with
  | some hooks => hooks.send buffer offset length
  | none => Connection.classifyWrite (← FFI.sendOffset connection.fd buffer offset.toUSize length.toUSize)

inductive PollRequest where
  | listener (socket : Listener)
  | read (socket : Connection)
  | write (socket : Connection)
  | readWrite (socket : Connection)

structure PollReady where
  readable : Bool
  writable : Bool
  hangup : Bool
  error : Bool
  invalid : Bool

inductive PollOutcome where
  | interrupted
  | ready (events : Array PollReady)

private def pollFd : PollRequest → Int64
  | .listener socket => socket.fd
  | .read socket => socket.fd
  | .write socket | .readWrite socket => socket.fd

private def pollMask : PollRequest → UInt8
  | .listener _ | .read _ => 1
  | .write _ => 2
  | .readWrite _ => 3

/-- Polls a set of typed sockets. Each returned readiness record corresponds to
    the request at the same index. SIGINT or EINTR is reported to the caller. -/
def poll (requests : Array PollRequest) (timeoutMs : Int32 := -1) : IO PollOutcome := do
  let mut wire := ByteArray.empty
  for request in requests do
    match request with
    | .listener socket => ensureOpen socket
    | .read socket | .write socket | .readWrite socket => ensureOpen socket
    let fd := (pollFd request).toInt
    if fd < 0 || fd > 2147483647 then throw (IO.userError "poll: invalid descriptor")
    let n := fd.toNat
    wire := wire.push (UInt8.ofNat (n % 256))
    wire := wire.push (UInt8.ofNat ((n / 256) % 256))
    wire := wire.push (UInt8.ofNat ((n / 65536) % 256))
    wire := wire.push (UInt8.ofNat ((n / 16777216) % 256))
    wire := wire.push (pollMask request)
  let (raw, masks) ← FFI.poll wire timeoutMs
  let count := Errno.decode raw
  if count < 0 then
    if ← Errno.isInterrupted count then return .interrupted
    throw (← Errno.error "poll" count)
  if masks.size != requests.size then throw (IO.userError "poll: invalid result length")
  let mut ready := #[]
  let mut seen := 0
  for mask in masks do
    let n := mask.toNat
    if n >= 32 then throw (IO.userError "poll: invalid event mask")
    if n != 0 then seen := seen + 1
    ready := ready.push ⟨n % 2 == 1, (n / 2) % 2 == 1, (n / 4) % 2 == 1,
      (n / 8) % 2 == 1, (n / 16) % 2 == 1⟩
  if count.toNat != seen then throw (IO.userError "poll: inconsistent ready count")
  return .ready ready

end LeanNet
