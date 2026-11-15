import LeanNet.Reactor.Basic

namespace LeanNet.HTTP

private def acceptorEvent (event : Reactor.Event) : IO Unit := do
  match event with
  | .wake | .closed _ => pure ()
  | .read _ buffer _ _ | .wireRead _ buffer _ _ =>
    buffer.release
    throw (IO.userError "HTTP acceptor unexpectedly received connection data")
  | .error _ flags code =>
    if (flags &&& 6) != 0 then
      throw (← LeanNet.Errno.error "HTTP acceptor socket setup/close" code)
    if code == -(Int.ofNat (← LeanNet.FFI.errnoEbadf).toNat) then
      throw (← LeanNet.Errno.error "HTTP acceptor owned descriptor (library bug)" code)
    if (flags &&& 1) != 0 && (← Reactor.isRecoverableAcceptError code) then return
    throw (← LeanNet.Errno.error "HTTP acceptor" code)
  | .accepted _ | .connected _ | .written .. | .eof _ | .timer .. |
    .wireEOF _ | .wireTimer .. | .connectTimer .. =>
    throw (IO.userError "HTTP acceptor unexpectedly owns a protocol connection")

private partial def acceptorLoop (reactor : Reactor.Reactor) (group : Reactor.Group) : IO Unit := do
  if ← group.stopping then return
  match ← reactor.poll 100 with
  | .interrupted => pure ()
  | .completions count =>
    for index in [:count] do acceptorEvent (← reactor.event index.toUInt32)
  acceptorLoop reactor group

/-- A returning callback also stops its peers; an unexpected early return
    cannot leave the control thread waiting forever on another worker. -/
private def supervised (group : Reactor.Group) (action : IO Unit) : IO Unit := do
  try
    action
    unless ← group.stopping do group.stop
  catch error =>
    try group.stop
    catch stopError =>
      throw (IO.userError s!"{error}; stopping HTTP workers failed: {stopError}")
    throw error

private def remember (first : IO.Ref (Option IO.Error)) (error : IO.Error) : IO Unit :=
  first.modify fun previous => if previous.isNone then some error else previous

private def runMembers (reactors : Array Reactor.Reactor) (partitions : Array Nat)
    (acceptor : Option Reactor.Reactor) (group : Reactor.Group)
    (run : Nat → Nat → Reactor.Reactor → Reactor.Group → IO Unit) : IO Unit := do
  let tasks ← IO.mkRef (#[] : Array (Task (Except IO.Error Unit)))
  let first ← IO.mkRef (none : Option IO.Error)
  try
    for h : workerId in [:reactors.size] do
      if ← group.stopping then break
      let reactor := reactors[workerId]
      let limit := partitions[workerId]!
      -- The callback creates its handler/connection state on this dedicated
      -- thread. No controller-created handler instance is cloned per worker.
      let task ← IO.asTask (do
        supervised group (do run workerId limit reactor group)) Task.Priority.dedicated
      tasks.modify (·.push task)
    if let some source := acceptor then
      unless ← group.stopping do
        let task ← IO.asTask (supervised group (acceptorLoop source group)) Task.Priority.dedicated
        tasks.modify (·.push task)
    for task in (← tasks.get) do
      match ← IO.wait task with
      | .ok _ => pure ()
      | .error error => remember first error
  catch error => remember first error
  finally
    -- Even wake/registration failures must not bypass the join barrier: every
    -- reactor and every channel outlives all tasks that can still access it.
    try group.stop
    catch error => remember first error
    for task in (← tasks.get) do
      match ← IO.wait task with
      | .ok _ => pure ()
      | .error error => remember first error
  if let some error := ← first.get then throw error

private def withPartitionReactors (partitions : Array Nat) (native : Reactor.Config)
    (listenerSlots outboundSlots : Nat) (use : Array Reactor.Reactor → IO Unit) : IO Unit :=
  go 0 partitions.size #[]
where
  go (index remaining : Nat) (reactors : Array Reactor.Reactor) : IO Unit :=
    match remaining with
    | 0 => use reactors
    | n + 1 => do
      let capacity := partitions[index]! + listenerSlots + outboundSlots
      -- Match the supported native connection bounds before UInt32 conversion.
      if capacity == 0 || capacity > 1000000 then
        throw (IO.userError "HTTP worker native connection capacity must be between 1 and 1000000")
      let config := { native with maxConnections := UInt32.ofNat capacity }
      Reactor.withReactor config fun reactor => go (index + 1) n (reactors.push reactor)

/-- Bracket one protocol loop per worker, partitioning the global admission
    limit exactly. Zero workers chooses the active CPU count, bounded by the
    client limit and 256. Explicit counts must fit both bounds.

    The callback runs inside each dedicated thread and receives its worker ID,
    client limit, private reactor, and shared stop group. It should create its
    own handler state there, then run until the group stops. All started tasks
    are stopped and joined before signal, reactor, or endpoint brackets close. -/
def workerCount (workers maxClients : Nat) : IO Nat := do
  if maxClients == 0 then throw (IO.userError "HTTP maxClients must be positive")
  if workers > 256 then throw (IO.userError "HTTP worker count must not exceed 256")
  if workers > maxClients then throw (IO.userError "HTTP worker count exceeds maxClients")
  let count ← if workers == 0 then pure (min 256 (min maxClients (← Reactor.cpuCount))) else pure workers
  if count == 0 then throw (IO.userError "HTTP worker count must be positive")
  return count

/-- Create the resolved worker set; the callback constructs its private state
    on each dedicated owner and every task joins before resources close. -/
def withWorkerPool (host : String) (port : UInt16) (workers maxClients : Nat)
    (native : Reactor.Config)
    (run : Nat → Nat → Reactor.Reactor → Reactor.Group → IO Unit)
    (outboundSlotsPerWorker : Nat := 0)
    (acceptRate : Option Reactor.AcceptRateConfig := none) : IO Unit := do
  let count ← workerCount workers maxClients
  let partitions := (Array.range count).map fun index =>
    maxClients / count + if index < maxClients % count then 1 else 0
  let handoff := count > 1 && (System.Platform.isWindows || System.Platform.isOSX)
  let start := fun (limiter : Option Reactor.AcceptLimiter) =>
   Reactor.withEndpoint port <| withPartitionReactors partitions native
      (if handoff then 0 else 1) outboundSlotsPerWorker fun reactors => do
    if handoff then
      let sourceConfig : Reactor.Config := {
        maxConnections := 4, maxEvents := 64, maxWrites := 1,
        buffers4k := 1, buffers16k := 0, buffers64k := 0,
        timerTickMs := native.timerTickMs }
      Reactor.withReactor sourceConfig fun acceptor => do
        if let some limiter := limiter then limiter.attach acceptor 0
        acceptor.setAcceptTargets reactors 1
        let _ ← acceptor.listen host port
        Reactor.withGroup (reactors.push acceptor) fun group =>
          runMembers reactors partitions (some acceptor) group run
    else
      for h : index in [:reactors.size] do
        let reactor := reactors[index]
        if let some limiter := limiter then limiter.attach reactor index
        let fresh ← reactor.socket
        let bound ← fresh.bind host port (count > 1)
        let _ ← bound.listen 4096
      Reactor.withGroup reactors fun group => runMembers reactors partitions none group run
  if let some rate := acceptRate then
    Reactor.withAcceptLimiter rate (if handoff then 1 else count) fun limiter =>
      start (some limiter)
  else start none

end LeanNet.HTTP
