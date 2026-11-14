import LeanNetTLS.Session

open LeanNet

private def rejected (operation : IO α) : IO Bool := do
  try
    let _ ← operation
    return false
  catch _ => return true

def main (args : List String) : IO UInt32 := do
  let cert ← match args[0]? with | some value => pure value | none => throw (IO.userError "missing cert")
  let key ← match args[1]? with | some value => pure value | none => throw (IO.userError "missing key")
  let some port := args[2]?.bind String.toNat? | throw (IO.userError "missing port")
  LeanNetTLS.Context.withContext cert key fun context =>
    withInterruptHandler <| withListener "127.0.0.1" (UInt16.ofNat port) fun listener => do
      let connection ← listener.accept
      withConnection connection fun connection => do
        match ← connection.sendInterruptible "READY".toUTF8 with
        | .written 5 => pure ()
        | _ => throw (IO.userError "pre-transport readiness write failed")
        connection.setNonblocking
        connection.installTransport context.transport
        let recvRejected ← rejected (connection.recvInterruptible 1)
        let sendRejected ← rejected (connection.sendInterruptible "PLAINTEXT-LEAK".toUTF8)
        unless recvRejected && sendRejected do
          throw (IO.userError "interruptible raw I/O bypassed installed TLS")
  return 0
