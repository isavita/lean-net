import LeanNet.Reactor.Basic

namespace LeanNet.Echo.ReactorServer

private def dispatch (event : Reactor.Event) : IO Unit := do
  match event with
  | .read socket buffer offset length =>
    Reactor.withBuffer buffer fun buffer => socket.write buffer offset length
  | .wireRead _ buffer _ _ =>
    buffer.release
    throw (IO.userError "echo unexpectedly received claimed ciphertext")
  | .wireEOF _ | .wireTimer .. => throw (IO.userError "echo unexpectedly received claimed transport event")
  | .eof socket => socket.closeAfterWrites
  | .timer socket _ => let _ ← socket.close (by decide); pure ()
  | .error _ flags code =>
    -- The reactor already disposed of failed peer sockets. Configuration and
    -- close failures are infrastructure faults and cannot be ignored.
    if (flags &&& 6) != 0 then throw (← LeanNet.Errno.error "reactor socket setup/close" code)
    if (flags &&& 1) != 0 && !(← Reactor.isRecoverableAcceptError code) then
      throw (← LeanNet.Errno.error "reactor accept" code)
    if code == -(Int.ofNat (← LeanNet.FFI.errnoEbadf).toNat) then
      throw (← LeanNet.Errno.error "reactor owned descriptor (library bug)" code)
  | .connected socket => do
    let _ ← socket.close (by decide)
    throw (IO.userError "echo server received an outbound connection")
  | .connectTimer .. => throw (IO.userError "echo server received a connect timer")
  | .accepted _ | .written .. | .closed _ | .wake => pure ()

private partial def loop (reactor : Reactor.Reactor) (group : Reactor.Group) : IO Unit := do
  if ← group.stopping then return
  match ← reactor.poll 100 with
  | .interrupted => pure ()
  | .completions count =>
    for index in [:count] do dispatch (← reactor.event index.toUInt32)
  loop reactor group

private def runWorkers (reactors : Array Reactor.Reactor) (group : Reactor.Group) : IO Unit := do
  let tasks ← IO.mkRef (#[] : Array (Task (Except IO.Error Unit)))
  try
    for reactor in reactors do
      let task ← IO.asTask (do
        try loop reactor group
        catch error =>
          group.stop
          throw error) Task.Priority.dedicated
      tasks.modify (·.push task)
    let mut firstError : Option IO.Error := none
    for task in (← tasks.get) do
      match ← IO.wait task with
      | .ok _ => pure ()
      | .error error =>
        if firstError.isNone then firstError := some error
    if let some error := firstError then throw error
  finally
    -- Startup failure and exceptions still stop and join every started worker
    -- before native signal registration or borrowed reactors are destroyed.
    try group.stop
    finally
      for task in (← tasks.get) do
        let result ← IO.wait task
        match result with
        | .ok _ => pure ()
        | .error _ => pure () -- The original worker/startup error is propagated.

/-- One dedicated loop per configured core, with no per-request task scheduling.
    A worker count of zero chooses the host's active logical core count. -/
def serve (host : String := "127.0.0.1") (port : UInt16 := 8080)
    (workers : Nat := 0) (config : Reactor.Config := {}) : IO Unit := do
  let buffers := config.buffers4k.toNat + config.buffers16k.toNat + config.buffers64k.toNat
  if config.maxWrites.toNat < buffers then
    throw (IO.userError "echo requires one write credit per pooled buffer")
  let count ← if workers == 0 then Reactor.cpuCount else pure workers
  if count == 0 || count > 256 then throw (IO.userError "worker count must be between 1 and 256")
  Reactor.withEndpoint port <| Reactor.withReactors count config fun reactors => do
    if (System.Platform.isWindows || System.Platform.isOSX) && count > 1 then
      -- A platform acceptor transfers untouched sockets; each worker registers
      -- its own readiness/completion backend before starting connection I/O.
      let acceptConfig : Reactor.Config := {
        maxConnections := 4, maxEvents := 64, maxWrites := 1,
        buffers4k := 1, buffers16k := 0, buffers64k := 0,
        timerTickMs := config.timerTickMs }
      Reactor.withReactor acceptConfig fun acceptor => do
        acceptor.setAcceptTargets reactors config.maxConnections
        let _ ← acceptor.listen host port
        let members := reactors.push acceptor
        Reactor.withGroup members fun group => runWorkers members group
    else
      for reactor in reactors do
        let fresh ← reactor.socket
        let bound ← fresh.bind host port (count > 1)
        let _ ← bound.listen 4096
      Reactor.withGroup reactors fun group => runWorkers reactors group

end LeanNet.Echo.ReactorServer
