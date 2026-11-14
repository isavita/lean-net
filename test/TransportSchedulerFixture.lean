import LeanNet.HTTP1.Server
import LeanNet.FFI.Raw

open LeanNet LeanNet.HTTP1

private def rawRead (fd : Int64) (size : Nat) : IO ReadOutcome := do
  let (raw, bytes) ← FFI.rawTcpRecv fd size.toUSize
  let n := Errno.decode raw
  if n < 0 then
    if ← Errno.isInterrupted n then return .interrupted
    if ← Errno.isWouldBlock n then return .wouldBlock
    throw (← Errno.error "fixture recv" n)
  if n == 0 then return .eof
  if n.toNat != bytes.size then throw (IO.userError "fixture recv size")
  return .data bytes

private def rawWrite (fd : Int64) (bytes : ByteArray) : IO WriteOutcome := do
  let raw ← FFI.rawTcpSend fd bytes bytes.size.toUSize
  let n := Errno.decode raw
  if n < 0 then
    if ← Errno.isInterrupted n then return .interrupted
    if ← Errno.isWouldBlock n then return .wouldBlock
    throw (← Errno.error "fixture send" n)
  return .written n.toNat

private def makeTransport (mode : String) (fd : Int64) : IO ConnectionTransport := do
  let readStage ← IO.mkRef (0 : Nat)
  let readBuffer ← IO.mkRef ByteArray.empty
  let writeStage ← IO.mkRef (0 : Nat)
  let firstAttempt ← IO.mkRef ByteArray.empty
  let expected := if mode == "retry" then
    "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".toUTF8
  else
    ("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toUTF8.append (ByteArray.mk #[0,0,0,4,0,0,0,0,0,0]))
  let receive : USize → IO ReadOutcome := fun size => do
    if mode == "mutate" then return ← rawRead fd size.toNat
    let stage ← readStage.get
    if mode == "retry" && stage == 0 then
      readStage.set 1
      IO.eprintln "MOCK_READ_WANT_WRITE"
      return .wantWrite
    let collecting := if mode == "retry" then stage == 1 else stage == 0
    if collecting then
      let buffered ← readBuffer.get
      match ← rawRead fd (expected.size - buffered.size) with
      | .data bytes =>
        let buffered := buffered.append bytes
        readBuffer.set buffered
        if buffered.size < expected.size then return .wouldBlock
        if buffered != expected then throw (IO.userError "fixture initial bytes differ")
        readStage.set (if mode == "retry" then 2 else 1)
        return .data buffered
      | other => return other
    if mode != "retry" && stage == 1 then
      -- Ensure the request deadline expires before the scheduler handles WANT_WRITE.
      IO.sleep 900
      readStage.set 2
      IO.eprintln "MOCK_CLOSING_READ_WANT_WRITE"
      return .wantWrite
    if mode != "retry" && stage == 2 then
      match ← rawRead fd 1 with
      | .data bytes =>
        unless bytes == "!".toUTF8 do throw (IO.userError "fixture closing read marker")
        readStage.set 3
        IO.eprintln "MOCK_CLOSING_READ_RETRIED"
        -- The scheduler must discard these bytes after closeAfter is set.
        return .data "discard me".toUTF8
      | other => return other
    return ← rawRead fd 16384
  let send : ByteArray → Nat → Nat → IO WriteOutcome := fun bytes offset length => do
    let slice := bytes.extract offset (offset + length)
    if mode == "retry" || mode == "mutate" then
      match ← writeStage.get with
      | 0 =>
        if mode == "retry" || (slice.size >= 4 && slice[3]! == 1) then
          firstAttempt.set slice
          writeStage.set 1
          IO.eprintln "MOCK_WRITE_WANT_READ"
          return .wantRead
      | 1 =>
        unless (← firstAttempt.get) == slice do throw (IO.userError "retry bytes changed")
        IO.eprintln "MOCK_RETRY_IDENTICAL"
        match ← rawRead fd 1 with
        | .data marker => unless marker == "!".toUTF8 do throw (IO.userError "fixture write marker")
        | .wouldBlock => return .wantRead
        | _ => throw (IO.userError "fixture missing write marker")
        writeStage.set 2
      | _ => pure ()
    rawWrite fd slice
  return { handshake := pure (.complete (if mode == "retry" then .http1 else .http2)),
           recv := receive, send, buffered := pure false,
           shutdown := pure (.complete .detect), close := pure () }

def main (args : List String) : IO UInt32 := do
  let mode := args[0]?.getD "retry"
  let some port := args[1]?.bind String.toNat? | throw (IO.userError "missing port")
  let config : ServerConfig := { idleTimeoutMs := 3000, requestTimeoutMs := 600, writeTimeoutMs := 3000 }
  let install (connection : Connection) : IO Unit := connection.installTransport (makeTransport mode)
  serveWithTransport defaultRouter config (some install) "127.0.0.1" (UInt16.ofNat port)
  return 0
