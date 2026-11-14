import LeanNet.Socket.Handle

open LeanNet

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do throw (IO.userError message)

private partial def nextConnection (pool : ConnectionPool) (listener : Listener) : IO Connection := do
  match ← poll #[.listener listener] 3000 with
  | .interrupted => throw (IO.userError "accept poll interrupted")
  | .ready events =>
    check (events.size == 1 && events.any (fun e => e.readable)) "listener not readable"
    match ← pool.accept listener with
    | .accepted connection => return connection
    | .wouldBlock | .retry => nextConnection pool listener
    | .interrupted => throw (IO.userError "accept interrupted")

private def sendByte (connection : Connection) (byte : UInt8) : IO Unit := do
  match ← connection.sendAt (ByteArray.mk #[byte]) 0 1 with
  | .written n => check (n == 1) "short synchronization write"
  | _ => throw (IO.userError "synchronization write blocked")

private def receiveByte (connection : Connection) : IO UInt8 := do
  match ← poll #[.read connection] 3000 with
  | .interrupted => throw (IO.userError "read poll interrupted")
  | .ready events => check (events.size == 1 && events.any (fun e => e.readable)) "connection not readable"
  match ← connection.recv 1 with
  | .data bytes =>
    check (bytes.size == 1) "invalid synchronization read"
    return bytes[0]!
  | _ => throw (IO.userError "synchronization read failed")

private def rejected (label : String) (operation : IO α) : IO Unit := do
  let failed ← try
    let _ ← operation
    pure false
  catch _ => pure true
  check failed s!"{label}: stale socket was accepted"

def main (args : List String) : IO UInt32 := do
  let some port := args.head?.bind String.toNat? | throw (IO.userError "usage: test PORT")
  withInterruptHandler <| withListener "127.0.0.1" (UInt16.ofNat port) fun listener => do
    listener.setNonblocking
    withConnectionPool fun pool => do
      let first ← nextConnection pool listener
      sendByte first 49
      check ((← receiveByte first) == 103) "first synchronization"
      pool.close first
      let second ← nextConnection pool listener
      sendByte second 50
      check ((← receiveByte second) == 103) "second synchronization"
      rejected "recv" (first.recv 1)
      rejected "send" (first.send "bad".toUTF8)
      rejected "sendAt" (first.sendAt "bad".toUTF8 0 3)
      rejected "poll" (poll #[.read first] 0)
      rejected "re-close" (pool.close first)
      sendByte second 75
      pool.close second
  return 0
