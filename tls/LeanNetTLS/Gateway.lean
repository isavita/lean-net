import LeanNet.FFI.Errno
import LeanNetTLS.FFI.Gateway

/-! Optional upstream HTTPS engine for `LeanNet.Gateway`. Each context and
    session belongs to one reactor worker. OpenSSL uses bounded memory BIOs;
    the caller owns the reactor `Wire`, feeds its read events here, drains
    encrypted output into reactor writes, and calls `Wire.ready` only after
    `handshake` returns `.ready`. No plaintext socket alias is exposed here. -/

namespace LeanNetTLS.Gateway

structure Context where
  private mk ::
  private handle : UInt64
  private alive : IO.Ref Bool

structure Session where
  private mk ::
  private handle : UInt64
  private context : Context
  private alive : IO.Ref Bool

inductive Handshake where
  | pending
  | ready
  deriving BEq, Repr

inductive Read where
  | pending
  | eof
  | data (bytes : ByteArray)

inductive Shutdown where
  | pending
  | complete
  deriving BEq, Repr

private def checkHandle (action : String) (raw : UInt64) (message : String) : IO UInt64 := do
  if LeanNet.Errno.decode raw < 0 || raw == 0 then
    throw (IO.userError s!"{action}: {message}")
  return raw

private def checkCode (action : String) (raw : UInt64) (message : String) : IO Nat := do
  let value := LeanNet.Errno.decode raw
  if value < 0 then throw (IO.userError s!"{action}: {message}")
  return value.toNat

private def ensureContext (context : Context) : IO Unit := do
  unless ← context.alive.get do throw (IO.userError "upstream TLS context is closed")

private def ensureSession (session : Session) : IO Unit := do
  unless ← session.alive.get do throw (IO.userError "upstream TLS session is closed")
  ensureContext session.context

/-- `caFile = none` uses OpenSSL's configured default trust roots. A supplied
    PEM file is an isolated trust root set. Setup fails if roots cannot load. -/
def Context.open (caFile : Option String := none) : IO Context := do
  let (raw, message) ← FFI.Gateway.contextNew (caFile.getD "")
  let handle ← checkHandle "upstream TLS trust context" raw message
  return ⟨handle, ← IO.mkRef true⟩

def Context.close (context : Context) : IO Unit := do
  ensureContext context
  context.alive.set false
  let raw ← FFI.Gateway.contextFree context.handle
  if LeanNet.Errno.decode raw != 0 then
    throw (IO.userError "upstream TLS context release failed")

def withContext (caFile : Option String) (use : Context → IO α) : IO α := do
  let context ← Context.open caFile
  try use context finally context.close

/-- `verifyName` must be the configured backend identity. DNS names are sent
    in SNI and checked against dNSName SAN/CN; IPv4 and IPv6 literals use
    iPAddress SAN without SNI. -/
def Context.openSession (context : Context) (verifyName : String) : IO Session := do
  ensureContext context
  let (raw, message) ← FFI.Gateway.sessionNew context.handle verifyName
  let handle ← checkHandle "upstream TLS session" raw message
  return ⟨handle, context, ← IO.mkRef true⟩

def Session.close (session : Session) : IO Unit := do
  unless ← session.alive.get do return
  session.alive.set false
  let raw ← FFI.Gateway.sessionFree session.handle
  if LeanNet.Errno.decode raw != 0 then
    throw (IO.userError "upstream TLS session release failed")

def Context.withSession (context : Context) (verifyName : String)
    (use : Session → IO α) : IO α := do
  let session ← context.openSession verifyName
  try use session finally session.close

/-- Run one nonblocking handshake step. Drain and enqueue `cipherOutput`
    after each step; then wait for a reactor wire read or write completion. -/
def Session.handshake (session : Session) : IO Handshake := do
  ensureSession session
  let (raw, message) ← FFI.Gateway.handshake session.handle
  let code ← checkCode "upstream TLS handshake" raw message
  match code with
  | 0 => return .pending
  | 1 => return .ready
  | _ => throw (IO.userError "upstream TLS returned invalid handshake state")

/-- Copy one ciphertext read from the reactor. The native engine caps a feed
    at 64 KiB and its buffered ciphertext at 256 KiB. -/
def Session.feedCipher (session : Session) (cipher : ByteArray) : IO Unit := do
  ensureSession session
  let (raw, message) ← FFI.Gateway.feed session.handle cipher
  let count ← checkCode "upstream TLS feed" raw message
  if count != cipher.size then throw (IO.userError "upstream TLS feed was partial")

/-- Retrieve up to 64 KiB of ciphertext to queue on the claimed reactor wire.
    The caller owns returned bytes and must retain them on write backpressure. -/
def Session.drainCipher (session : Session) : IO ByteArray := do
  ensureSession session
  let (raw, (bytes, message)) ← FFI.Gateway.drain session.handle
  let count ← checkCode "upstream TLS drain" raw message
  if count != bytes.size then throw (IO.userError "upstream TLS drain length mismatch")
  return bytes

/-- Read decrypted application data after the verified handshake. `.eof`
    means a real TLS close_notify; an unclean EOF is an error. -/
def Session.readPlain (session : Session) (maximum : UInt32 := 16384) : IO Read := do
  ensureSession session
  let (raw, (bytes, message)) ← FFI.Gateway.read session.handle maximum
  let value := LeanNet.Errno.decode raw
  if value == -2 then return .pending
  if value < 0 then throw (IO.userError s!"upstream TLS read: {message}")
  if value == 0 then return .eof
  if value.toNat != bytes.size then throw (IO.userError "upstream TLS read length mismatch")
  return .data bytes

/-- Encrypt at most one 16 KiB plaintext slice. A return of zero means
    OpenSSL needs another feed/drain step before retrying the identical slice. -/
def Session.writePlain (session : Session) (plain : ByteArray) : IO Nat := do
  ensureSession session
  let (raw, message) ← FFI.Gateway.write session.handle plain
  let value := LeanNet.Errno.decode raw
  if value == -2 then return 0
  if value < 0 then throw (IO.userError s!"upstream TLS write: {message}")
  if value.toNat > plain.size then throw (IO.userError "upstream TLS write over-consumed")
  return value.toNat

/-- Require no pending decrypted, encrypted or inbound ciphertext before a
    complete HTTP/1.1 response may return to an upstream connection pool. -/
def Session.cleanForReuse (session : Session) : IO Bool := do
  ensureSession session
  let raw ← FFI.Gateway.clean session.handle
  if raw > 1 then throw (IO.userError "upstream TLS returned invalid reuse state")
  return raw == 1

/-- Ciphertext still waiting in the OpenSSL output BIO. -/
def Session.pendingCipherBytes (session : Session) : IO Nat := do
  ensureSession session
  let raw ← FFI.Gateway.cipherPending session.handle
  let count ← checkCode "upstream TLS pending ciphertext" raw "invalid TLS session"
  return count

/-- Generate close_notify before draining ciphertext and closing the wire. -/
def Session.beginShutdown (session : Session) : IO Shutdown := do
  ensureSession session
  let (raw, message) ← FFI.Gateway.shutdown session.handle
  let code ← checkCode "upstream TLS shutdown" raw message
  match code with
  | 0 => return .pending
  | 1 => return .complete
  | _ => throw (IO.userError "upstream TLS returned invalid shutdown state")

end LeanNetTLS.Gateway
