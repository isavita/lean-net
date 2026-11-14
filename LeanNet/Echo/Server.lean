import LeanNet.Socket.Handle

namespace LeanNet.Echo

private partial def writeAll (connection : Connection) (bytes : ByteArray) : IO Unit := do
  if bytes.size == 0 || (← interruptRequested) then return
  match ← connection.sendInterruptible bytes with
  | .interrupted | .wouldBlock => writeAll connection bytes
  | .wantRead => throw (IO.userError "unexpected transport on blocking echo")
  | .written n =>
    if n == 0 || n > bytes.size then throw (IO.userError "send: invalid progress")
    writeAll connection (bytes.extract n bytes.size)

private partial def serveConnection (connection : Connection) : IO Unit := do
  if ← interruptRequested then return
  match ← connection.recvInterruptible 16384 with
  | .eof => pure ()
  | .interrupted | .wouldBlock => serveConnection connection
  | .wantWrite => throw (IO.userError "unexpected transport on blocking echo")
  | .data bytes =>
    writeAll connection bytes
    serveConnection connection

private partial def acceptLoop (listener : Listener) : IO Unit := do
  if ← interruptRequested then return
  match ← listener.acceptInterruptible with
  | none => acceptLoop listener
  | some connection =>
    -- A peer reset affects only its own session; the bracket still closes it.
    withConnection connection fun conn => do
      try
        serveConnection conn
      catch error =>
        match error with
        | .resourceVanished .. =>
          unless (← interruptRequested) do
            IO.eprintln s!"connection: {error}"
        | _ => throw error
    acceptLoop listener

/-- Run the single-threaded TCP echo server until SIGINT. -/
def serve (host : String := "127.0.0.1") (port : UInt16 := 8080) : IO Unit :=
  withInterruptHandler <| withListener host port acceptLoop

end LeanNet.Echo
