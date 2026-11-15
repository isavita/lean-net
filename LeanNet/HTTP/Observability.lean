import LeanNet.FFI.Observability
import LeanNet.FFI.Errno
import LeanNet.HTTP.Observability.Metrics

namespace LeanNet.HTTP.Observability

structure AccessConfig where
  path : System.FilePath
  helperBinary : System.FilePath
  queueCapacity : Nat := 1024
  /-- Regular files rotate at record boundaries. Oversized existing active or
      managed archive files fail startup with EFBIG, preserving their bytes.
      Device/FIFO sinks never rotate; unrelated paths remain untouched. -/
  maxFileBytes : Nat := 16 * 1024 * 1024
  fileCount : Nat := 4
  startupTimeoutMs : Nat := 2000
  shutdownTimeoutMs : Nat := 2000
  pollIntervalMs : Nat := 10

structure AccessRecord where
  timestampUnixMs : UInt64
  durationUs : UInt64
  bytesSent : UInt64
  status : UInt32
  protocol : Protocol
  method : ByteArray
  target : ByteArray
  outcome : Outcome := .completed
  /-- Textual peer IP address; empty when unknown. -/
  remote : ByteArray := ByteArray.empty
  /-- 16-byte W3C trace-id; empty when the request carried none. -/
  traceId : ByteArray := ByteArray.empty

inductive EmitResult where
  | queued | dropped | disabled
  deriving BEq, Repr

structure Hub where
  private mk ::
  private handle : UInt64
  private workers : Nat
  private alive : IO.Ref Bool
  private access : Option AccessConfig
  private processCache : IO.Ref ByteArray
  private samplerFailure : IO.Ref (Option IO.Error)
structure Lane where
  private mk ::
  private hub : Hub
  workerId : UInt32

private def checked (label : String) (raw : UInt64) : IO UInt64 := do
  let code := Errno.decode raw
  if code < 0 then throw (← Errno.error label code)
  return raw
private def zero (label : String) (raw : UInt64) : IO Unit := do
  unless (← checked label raw) == 0 do throw (IO.userError s!"{label}: invalid native result")
private def Hub.ensureAlive (hub : Hub) : IO Unit := do
  unless ← hub.alive.get do throw (IO.userError "observability hub is closed")
private def captureFailure (original : IO.Ref (Option IO.Error)) (action : IO α) : IO α := do
  try action
  catch error =>
    original.set (some error)
    throw error

def Hub.lane (hub : Hub) (worker : Nat) : IO Lane := do
  hub.ensureAlive
  if worker >= hub.workers then throw (IO.userError "observability worker exceeds its configured bound")
  return ⟨hub, worker.toUInt32⟩
def Lane.emit (lane : Lane) (record : AccessRecord) : IO EmitResult := do
  lane.hub.ensureAlive
  let result ← checked "access log enqueue" (← FFI.Observability.emit lane.hub.handle lane.workerId
    record.timestampUnixMs record.durationUs record.bytesSent record.status
    record.protocol.index.toUInt32 record.outcome.index.toUInt32 record.method record.target
    (record.remote.extract 0 63) (if record.traceId.size == 16 then record.traceId else ByteArray.empty))
  match result with
  | 0 => return .queued
  | 1 => return .dropped
  | 2 => return .disabled
  | _ => throw (IO.userError "access log enqueue returned an invalid result")
def Lane.publish (lane : Lane) (counters : Counters) : IO Unit := do
  lane.hub.ensureAlive
  zero "observability snapshot publication" (← FFI.Observability.publish lane.hub.handle lane.workerId counters.fields)
def Hub.snapshot (hub : Hub) : IO Snapshot := do
  hub.ensureAlive
  for _ in [:3] do
    let (result, fields) ← FFI.Observability.snapshot hub.handle
    let code := Errno.decode result
    if code < 0 && (← Errno.isWouldBlock code) then continue
    zero "observability snapshot" result
    let some snapshot := Snapshot.ofFields? fields | throw (IO.userError "invalid observability snapshot schema")
    return snapshot
  throw (IO.userError "observability snapshot publication is contended")
def Hub.check (hub : Hub) : IO Unit := do
  hub.ensureAlive
  if let some error ← hub.samplerFailure.get then throw error
  for _ in [:3] do
    let raw ← FFI.Observability.check hub.handle
    let code := Errno.decode raw
    if code < 0 && (← Errno.isInterrupted code) then
      let persistent ← FFI.Observability.lastError hub.handle
      if Errno.decode persistent < 0 then let _ ← checked "access log writer stopped" persistent
      continue
    zero "access log writer" raw
    return
  throw (IO.userError "access log health check repeatedly interrupted")

/-- Process gauges are published by a dedicated task, never collected on a
    network worker. Like counter snapshots, these can lag by one second. -/
def Hub.processMetrics (hub : Hub) : IO ByteArray := do
  hub.ensureAlive
  if let some error ← hub.samplerFailure.get then throw error
  hub.processCache.get

private def Hub.withSampler (hub : Hub) (sample : Option (IO ByteArray))
    (use : IO α) : IO α := do
  let some sample := sample | use
  hub.processCache.set (← sample)
  let stop ← IO.mkRef false
  let task ← IO.asTask (do
    try
      let mut ticks := 0
      repeat
        if ← stop.get then break
        IO.sleep 100
        ticks := ticks + 1
        if ticks >= 10 then
          if ← stop.get then break
          hub.processCache.set (← sample)
          ticks := 0
    catch error =>
      hub.samplerFailure.set (some error)
      throw error) Task.Priority.dedicated
  let original ← IO.mkRef (none : Option IO.Error)
  try captureFailure original use
  finally
    stop.set true
    match ← IO.wait task with
    | .ok _ => pure ()
    | .error error =>
      if let some first ← original.get then
        throw (IO.userError s!"{first}; process metrics sampler: {error}")
      throw error

private def Hub.close (hub : Hub) : IO Unit := do
  hub.ensureAlive
  hub.alive.set false
  let timeout := (hub.access.map (·.shutdownTimeoutMs)).getD 2000
  let original ← IO.mkRef (none : Option IO.Error)
  try
    captureFailure original (do
      zero "access log stop" (← FFI.Observability.stop hub.handle timeout.toUInt64)
      let cutoff := (← IO.monoMsNow) + timeout + 200
      repeat
        if (← IO.monoMsNow) >= cutoff then throw (IO.userError "access log join deadline exceeded")
        let raw ← FFI.Observability.join hub.handle
        let code := Errno.decode raw
        if code < 0 && (← Errno.isInterrupted code) then
          let persistent ← FFI.Observability.lastError hub.handle
          if Errno.decode persistent < 0 then let _ ← checked "access log writer stopped" persistent
          continue
        let result ← checked "access log bounded join" raw
        if result == 1 then break
        if result != 0 then throw (IO.userError "access log join returned an invalid result")
        IO.sleep 1
    )
  finally
    try
      repeat
        let raw ← FFI.Observability.free hub.handle
        let code := Errno.decode raw
        if code < 0 && (← Errno.isInterrupted code) then continue
        zero "observability resource cleanup" raw
        break
    catch cleanup =>
      if let some error ← original.get then throw (IO.userError s!"{error}; cleanup: {cleanup}")
      throw cleanup

/-- Bracket outside all worker lifetimes. Workers exclusively own their Lane;
    stop/join runs only after every producer has stopped. Metrics-only hubs do
    not spawn a helper or allocate log queues. -/
def withHub (workers : Nat) (access : Option AccessConfig := none) (use : Hub → IO α)
    (sampleProcessMetrics : Option (IO ByteArray) := none) : IO α := do
  if workers == 0 || workers > 256 then throw (IO.userError "observability supports between 1 and 256 workers")
  if let some config := access then
    if config.path.toString.isEmpty || config.helperBinary.toString.isEmpty ||
        config.queueCapacity == 0 || config.queueCapacity > 65536 ||
        config.queueCapacity &&& (config.queueCapacity - 1) != 0 ||
        config.maxFileBytes < 4096 || config.maxFileBytes > 1073741824 ||
        config.fileCount == 0 || config.fileCount > 16 || config.pollIntervalMs == 0 ||
        config.pollIntervalMs > 1000 || config.startupTimeoutMs == 0 ||
        config.startupTimeoutMs > 60000 || config.shutdownTimeoutMs == 0 || config.shutdownTimeoutMs > 60000 then
      throw (IO.userError "invalid bounded access log configuration")
  let handle ← checked "observability startup" (← FFI.Observability.create workers.toUInt32
    ((access.map (·.queueCapacity.toUInt32)).getD 0)
    ((access.map (·.path.toString)).getD "") ((access.map (·.helperBinary.toString)).getD "")
    ((access.map (·.maxFileBytes.toUInt64)).getD 0) ((access.map (·.fileCount.toUInt32)).getD 0)
    ((access.map (·.pollIntervalMs.toUInt32)).getD 0))
  if handle == 0 then throw (IO.userError "observability startup returned no hub")
  let hub : Hub := ⟨handle, workers, ← IO.mkRef true, access,
    ← IO.mkRef ByteArray.empty, ← IO.mkRef none⟩
  let original ← IO.mkRef (none : Option IO.Error)
  try
    captureFailure original (do
      let cutoff := (← IO.monoMsNow) + (access.map (·.startupTimeoutMs)).getD 2000
      repeat
        if (← IO.monoMsNow) >= cutoff then throw (IO.userError "access log startup deadline exceeded")
        let raw ← FFI.Observability.ready handle
        let code := Errno.decode raw
        if code < 0 && (← Errno.isInterrupted code) then
          let persistent ← FFI.Observability.lastError handle
          if Errno.decode persistent < 0 then let _ ← checked "access log startup failed" persistent
          continue
        let result ← checked "access log startup handshake" raw
        if result == 1 then break
        if result != 0 then throw (IO.userError "access log handshake returned an invalid result")
        IO.sleep 1
      hub.withSampler sampleProcessMetrics (use hub)
    )
  finally
    try hub.close
    catch cleanup =>
      if let some error ← original.get then throw (IO.userError s!"{error}; shutdown: {cleanup}")
      throw cleanup

end LeanNet.HTTP.Observability
