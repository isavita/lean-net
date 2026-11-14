import LeanNet.Socket.Handle
import LeanNetTLS.FFI.Raw

namespace LeanNetTLS

private structure Entry where
  handle : UInt64
  alive : IO.Ref Bool

/-- A context owns the OpenSSL configuration and all sessions created from it.
    Its constructor and native handle are private. -/
structure Context where
  private mk ::
  private handle : UInt64
  private alive : IO.Ref Bool
  private sessions : IO.Ref (Array Entry)

/-- A TLS session borrows its socket descriptor; closing it never closes the socket. -/
structure Session where
  private mk ::
  private context : Context
  private entry : Entry
  private pendingWrite : IO.Ref (Option ByteArray)

private def checkContext (context : Context) : IO Unit := do
  unless (← context.alive.get) do throw (IO.userError "TLS context is closed")

private def checkSession (session : Session) : IO Unit := do
  checkContext session.context
  unless (← session.entry.alive.get) do throw (IO.userError "TLS session is closed")

private def resultError (operation : String) (value : Int) (message : String) : IO IO.Error := do
  let protocol := (← LeanNet.FFI.errnoEproto).toNat
  if protocol != 0 && value == -(Int.ofNat protocol) then
    return .resourceVanished (UInt32.ofNat protocol) s!"{operation}: {message}"
  let base ← LeanNet.Errno.error "recv" value
  match base with
  | .resourceVanished code details => return .resourceVanished code s!"{operation}: {details}: {message}"
  | _ => return IO.userError s!"{operation}: {base}: {message}"

private def checkFree (operation : String) (value : UInt64) : IO Unit := do
  let n := LeanNet.Errno.decode value
  if n != 0 then throw (← LeanNet.Errno.error operation n)

/-- Free a session once. Its borrowed socket remains owned by the caller. -/
def Session.close (session : Session) : IO Unit := do
  checkSession session
  session.entry.alive.set false
  session.context.sessions.modify (fun entries => entries.filter (fun entry => entry.handle != session.entry.handle))
  checkFree "TLS session free" (← FFI.sessionFree session.entry.handle)

private def closeContext (context : Context) : IO Unit := do
  checkContext context
  context.alive.set false
  let entries ← context.sessions.get
  context.sessions.set #[]
  let mut firstError : Option IO.Error := none
  for entry in entries do
    if ← entry.alive.get then
      entry.alive.set false
      try checkFree "TLS session free" (← FFI.sessionFree entry.handle)
      catch error => if firstError.isNone then firstError := some error
  try checkFree "TLS context free" (← FFI.contextFree context.handle)
  catch error => if firstError.isNone then firstError := some error
  if let some error := firstError then throw error

/-- Bracket an OpenSSL server context and any sessions still owned by it. -/
def Context.withContext (certificate privateKey : String) (use : Context → IO α) : IO α := do
  if certificate.toUTF8.toList.contains 0 || privateKey.toUTF8.toList.contains 0 then
    throw (IO.userError "TLS file paths cannot contain NUL")
  let (raw, message) ← FFI.contextNew certificate privateKey
  let value := LeanNet.Errno.decode raw
  if value <= 0 then throw (IO.userError s!"TLS context: {message} (error {value})")
  let context : Context := ⟨raw, ← IO.mkRef true, ← IO.mkRef #[]⟩
  try use context finally closeContext context

/-- Create a session around a nonblocking borrowed descriptor. Each session
    must be closed before the socket closes; the context bracket is a fallback. -/
def Context.openSession (context : Context) (fd : Int64) : IO Session := do
  checkContext context
  let ((raw, stage), message) ← FFI.sessionNew context.handle fd
  let value := LeanNet.Errno.decode raw
  if value <= 0 then
    if stage == 2 && value < 0 then
      let error ← LeanNet.Errno.error "recv" value
      match error with
      | .resourceVanished code details => throw (.resourceVanished code s!"TLS session: {message}: {details}")
      | _ => throw (IO.userError "TLS session: invalid verified peer failure")
    if stage != 1 then throw (IO.userError "TLS session: invalid failure stage")
    throw (IO.userError s!"TLS session: {message} (error {value})")
  if stage != 0 then throw (IO.userError "TLS session: invalid success stage")
  let entry : Entry := ⟨raw, ← IO.mkRef true⟩
  context.sessions.modify (fun entries => entries.push entry)
  return ⟨context, entry, ← IO.mkRef none⟩

/-- Bracket one session. -/
def Context.withSession (context : Context) (fd : Int64) (use : Session → IO α) : IO α := do
  let session ← context.openSession fd
  try use session finally session.close

private def negotiated (session : Session) : IO LeanNet.TransportProtocol := do
  let ((raw, status), (protocol, message)) ← FFI.alpn session.entry.handle
  let n := LeanNet.Errno.decode raw
  if n < 0 then throw (← resultError "TLS ALPN" n message)
  if status != 0 || n.toNat != protocol.size then throw (IO.userError "invalid TLS ALPN result")
  if protocol.isEmpty || protocol == "http/1.1".toUTF8 then return .http1
  if protocol == "h2".toUTF8 then return .http2
  throw (IO.userError "TLS negotiated an unsupported ALPN protocol")

private def progress (session : Session) (operation : String)
    (result : (UInt64 × UInt8) × String) (isHandshake : Bool) : IO LeanNet.TransportProgress := do
  let ((raw, status), message) := result
  let n := LeanNet.Errno.decode raw
  if n < 0 then
    if ← LeanNet.Errno.isInterrupted n then return .interrupted
    throw (← resultError operation n message)
  if n != 0 then throw (IO.userError s!"{operation}: invalid result")
  if status == 1 then return .wantRead
  if status == 2 then return .wantWrite
  if status == 3 && isHandshake then throw (.resourceVanished 0 "TLS peer closed during handshake")
  if status == 3 then return .complete .detect
  if status != 0 then throw (IO.userError s!"{operation}: invalid status")
  if isHandshake then return .complete (← negotiated session)
  return .complete .detect

/-- Perform one nonblocking server handshake step. -/
def Session.handshake (session : Session) : IO LeanNet.TransportProgress := do
  checkSession session
  progress session "TLS handshake" (← FFI.handshake session.entry.handle) true

/-- Read plaintext; wouldBlock means WANT_READ, wantWrite means WANT_WRITE. -/
def Session.recv (session : Session) (size : USize) : IO LeanNet.ReadOutcome := do
  checkSession session
  if size == 0 then throw (IO.userError "TLS read size must be positive")
  let ((raw, status), (bytes, message)) ← FFI.read session.entry.handle size
  let n := LeanNet.Errno.decode raw
  if n < 0 then
    if ← LeanNet.Errno.isInterrupted n then return .interrupted
    throw (← resultError "TLS read" n message)
  if status != 0 && (n != 0 || !bytes.isEmpty) then throw (IO.userError "invalid TLS read status payload")
  if status == 1 then return .wouldBlock
  if status == 2 then return .wantWrite
  if status == 3 then return .eof
  if status != 0 || n <= 0 || n.toNat != bytes.size then throw (IO.userError "invalid TLS read result")
  return .data bytes

/-- Send a plaintext slice. After WANT or EINTR, repeat the same bytes and
    length until completion; moving the underlying ByteArray is permitted. -/
def Session.send (session : Session) (bytes : ByteArray) (offset length : Nat) : IO LeanNet.WriteOutcome := do
  checkSession session
  if offset > bytes.size || length > bytes.size - offset then throw (IO.userError "invalid TLS write range")
  if length == 0 then return .written 0
  let slice := bytes.extract offset (offset + length)
  if let some previous ← session.pendingWrite.get then
    if previous != slice then throw (IO.userError "TLS write retry changed pending bytes")
  let ((raw, status), message) ← FFI.write session.entry.handle bytes offset.toUSize length.toUSize
  let n := LeanNet.Errno.decode raw
  if n < 0 then
    if ← LeanNet.Errno.isInterrupted n then
      session.pendingWrite.set (some slice)
      return .interrupted
    throw (← resultError "TLS write" n message)
  if status != 0 && n != 0 then throw (IO.userError "invalid TLS write status payload")
  if status == 1 || status == 2 then
    session.pendingWrite.set (some slice)
    if status == 1 then return .wantRead else return .wouldBlock
  if status == 3 then throw (.resourceVanished 0 "TLS peer closed during write")
  if status != 0 || n <= 0 || n.toNat > length then throw (IO.userError "invalid TLS write result")
  session.pendingWrite.set none
  return .written n.toNat

/-- Whether OpenSSL already has plaintext available without socket readiness. -/
def Session.buffered (session : Session) : IO Bool := do
  checkSession session
  let n := LeanNet.Errno.decode (← FFI.pending session.entry.handle)
  if n < 0 then throw (← LeanNet.Errno.error "TLS pending" n)
  return n > 0

/-- Perform one close_notify step. WANT_READ after sending close_notify means
    the peer's close_notify has not arrived yet; freeing is a separate action. -/
def Session.shutdown (session : Session) : IO LeanNet.TransportProgress := do
  checkSession session
  progress session "TLS shutdown" (← FFI.shutdown session.entry.handle) false

/-- Adapt a session to the shared single-threaded connection transport hooks. -/
def Context.transport (context : Context) (fd : Int64) : IO LeanNet.ConnectionTransport := do
  let session ← context.openSession fd
  return { handshake := session.handshake, recv := session.recv, send := session.send,
           buffered := session.buffered, shutdown := session.shutdown, close := session.close }

end LeanNetTLS
