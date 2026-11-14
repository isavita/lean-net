import LeanNet.FFI.Errno
import LeanNet.Socket.Handle

open LeanNet

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do throw (IO.userError message)

private def entry (fd : Nat) (interest : UInt8) : ByteArray :=
  ByteArray.mk #[UInt8.ofNat fd, UInt8.ofNat (fd / 256), UInt8.ofNat (fd / 65536),
    UInt8.ofNat (fd / 16777216), interest]

private def announce (message : String) : IO Unit := do
  IO.println message
  (← IO.getStdout).flush

private def waitFor (fd : Nat) (interest required : UInt8) : IO Unit := do
  let (count, events) ← FFI.poll (entry fd interest) 5000
  check (Errno.decode count == 1 && events.size == 1 && (events[0]! &&& required) == required)
    s!"unexpected poll readiness: {Errno.decode count}"

private partial def sendSlice (fd : Int64) (data : ByteArray) (offset : Nat) : IO Unit := do
  if offset == 3 then return
  let n := Errno.decode (← FFI.sendOffset fd data offset.toUSize (3 - offset).toUSize)
  if ← Errno.isInterrupted n then sendSlice fd data offset
  else if ← Errno.isWouldBlock n then
    throw (IO.userError "unexpected would-block on small test write")
  else
    check (n > 0 && n.toNat <= 3 - offset) "invalid send progress"
    sendSlice fd data (offset + n.toNat)

private def run (port : UInt16) : IO Unit := withInterruptHandler do
  let listenResult := Errno.decode (← FFI.rawTcpListen "127.0.0.1" port)
  check (listenResult >= 0) "listen failed"
  let listener := Int64.ofInt listenResult
  try
    check (Errno.decode (← FFI.setNonblocking listener 1) == 0) "nonblocking listener failed"
    let (acceptedRaw, acceptedStage) ← FFI.acceptStaged listener
    let accepted := Errno.decode acceptedRaw
    check (acceptedStage == 1 && (← Errno.isWouldBlock accepted))
      "accept should report would-block at syscall stage"
    let (zero, noEvents) ← FFI.poll (entry listenResult.toNat 1) 0
    check (Errno.decode zero == 0 && noEvents.size == 1 && noEvents[0]! == 0)
      "idle listener unexpectedly ready"
    announce "READY"
    waitFor listenResult.toNat 1 1
    let (connRaw, connStage) ← FFI.acceptStaged listener
    let connResult := Errno.decode connRaw
    check (connResult >= 0 && connStage == 0) "accept after readiness failed"
    let conn := Int64.ofInt connResult
    try
      check (Errno.decode (← FFI.setNonblocking conn 1) == 0) "nonblocking connection failed"
      let (recvResult, recvBytes) ← FFI.rawTcpRecv conn 32
      check ((← Errno.isWouldBlock (Errno.decode recvResult)) && recvBytes.isEmpty)
        "empty receive should report would-block"
      waitFor connResult.toNat 2 2
      sendSlice conn "abcd".toUTF8 1
      announce "NEED_DATA"
      waitFor connResult.toNat 1 1
      let (readCount, received) ← FFI.rawTcpRecv conn 32
      check (Errno.decode readCount == 1 && received == "X".toUTF8) "invalid receive"
      announce "WAIT_SIGINT"
      let (interrupted, payload) ← FFI.poll ByteArray.empty (-1)
      check ((← Errno.isInterrupted (Errno.decode interrupted)) && payload.isEmpty)
        "SIGINT did not interrupt poll"
    finally
      check (Errno.decode (← FFI.rawClose conn) == 0) "connection close failed"
  finally
    check (Errno.decode (← FFI.rawClose listener) == 0) "listener close failed"

def main (args : List String) : IO Unit := do
  let some port := args.head?.bind String.toNat? | throw (IO.userError "expected port")
  check (port > 0 && port <= 65535) "invalid port"
  run (UInt16.ofNat port)
