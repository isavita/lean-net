import LeanNet.Socket.Handle

open LeanNet

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do throw (IO.userError message)

private def rejectPoll (label : String) (entries : ByteArray) (timeout : Int32 := 0) : IO Unit := do
  let (code, result) ← FFI.poll entries timeout
  check (Errno.decode code < 0 && result.isEmpty) s!"{label}: invalid poll input accepted"

def main : IO Unit := do
  withInterruptHandler do
    let (code, ready) ← FFI.poll ByteArray.empty 0
    check (Errno.decode code == 0 && ready.isEmpty) "empty zero-timeout poll"
    rejectPoll "incomplete poll record" (ByteArray.mk #[0, 0, 0, 0])
    rejectPoll "unknown poll mask" (ByteArray.mk #[0, 0, 0, 0, 4])
    rejectPoll "out-of-range descriptor" (ByteArray.mk #[255, 255, 255, 255, 1])
    rejectPoll "invalid timeout" ByteArray.empty (-2)
    let data := "abc".toUTF8
    check (Errno.decode (← FFI.sendOffset 0 data 4 0) < 0) "out-of-bounds offset"
    check (Errno.decode (← FFI.sendOffset 0 data 2 2) < 0) "out-of-bounds length"
    check (Errno.decode (← FFI.sendOffset 0 data 3 0) == 0) "empty tail slice"
    check (Errno.decode (← FFI.sendOffset (-1) data 0 1) < 0) "invalid descriptor"
    check (Errno.decode (← FFI.setNonblocking (-1) 1) < 0) "invalid nonblocking descriptor"
  IO.println "event FFI validation tests passed"
