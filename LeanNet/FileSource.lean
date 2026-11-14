import LeanNet.FFI.Static
import LeanNet.FFI.Errno

namespace LeanNet.File

private def checked (label : String) (raw : UInt64) : IO UInt64 := do
  let value := Errno.decode raw
  if value < 0 then throw (← Errno.error label value)
  return raw

private def checkedZero (label : String) (raw : UInt64) : IO Unit := do
  unless (← checked label raw) == 0 do throw (IO.userError s!"{label}: unexpected native result")

/-- Immutable, resident packed bytes. Reactor registrations retain independent
    native references, and must outlive their queued file operations. -/
structure Source where
  private mk ::
  handle : UInt64
  size : Nat
  private alive : IO.Ref Bool

def Source.ensureAlive (source : Source) : IO Unit := do
  unless ← source.alive.get do throw (IO.userError "file source is closed")

def Source.close (source : Source) : IO Unit := do
  source.ensureAlive
  source.alive.set false
  checkedZero "file source release" (← FFI.Static.sourceRelease source.handle)

structure BuilderConfig where
  maxFileBytes : Nat := 8 * 1024 * 1024
  maxPackBytes : Nat := 8 * 1024 * 1024
  maxEntries : Nat := 4096
  minCompressBytes : Nat := 128
  gzipLevel : Nat := 6
  brotliQuality : Nat := 5
  stepBytes : Nat := 65536
  startupTimeoutMs : Nat := 120000

structure Builder where
  private mk ::
  private handle : UInt64
  private config : BuilderConfig
  private alive : IO.Ref Bool
  private finished : IO.Ref Bool
  private cutoff : Nat

private def Builder.ensureOpen (builder : Builder) : IO Unit := do
  unless ← builder.alive.get do throw (IO.userError "static builder is closed")
  if ← builder.finished.get then throw (IO.userError "static builder was published")
  if (← IO.monoMsNow) >= builder.cutoff then throw (IO.userError "static catalog startup deadline exceeded")

private def Builder.prepare (builder : Builder) : IO Unit := do
  repeat
    builder.ensureOpen
    let raw ← FFI.Static.prepare builder.handle
    let code := Errno.decode raw
    if code < 0 && (← Errno.isInterrupted code) then continue
    checkedZero "static catalog preparation" raw
    break

private def Builder.complete (builder : Builder) : IO UInt32 := do
  repeat
    builder.ensureOpen
    let raw ← FFI.Static.step builder.handle builder.config.stepBytes.toUInt32
    let result := Errno.decode raw
    if result < 0 then
      if ← Errno.isInterrupted result then continue
      throw (← Errno.error "static catalog build" result)
    if raw > 4294967295 then throw (IO.userError "static entry identifier exceeds its native range")
    if raw != 0 then return raw.toUInt32
  throw (IO.userError "static builder did not complete")

def Builder.addPath (builder : Builder) (path : ByteArray) (compression : UInt32 := 3) : IO UInt32 := do
  builder.ensureOpen
  checkedZero "static catalog path" (← FFI.Static.beginPath builder.handle path compression)
  builder.complete

def Builder.addBytes (builder : Builder) (bytes : ByteArray) (compression : UInt32 := 3) : IO UInt32 := do
  builder.ensureOpen
  checkedZero "static catalog bytes" (← FFI.Static.beginBytes builder.handle bytes compression)
  builder.complete

def Builder.checkDirectory (builder : Builder) (path : ByteArray) : IO Unit := do
  repeat
    builder.ensureOpen
    let raw ← FFI.Static.checkDirectory builder.handle path
    let code := Errno.decode raw
    if code < 0 && (← Errno.isInterrupted code) then continue
    checkedZero "static anchored directory" raw
    break

/-- Enumerate relative to the retained root, with a bound covering every entry,
    including links and unsupported files. Interrupted enumeration is discarded
    by C and explicitly restarted here. -/
def Builder.readDirectory (builder : Builder) (path : ByteArray)
    (limit : Nat := 1000000) : IO (Array (ByteArray × UInt32)) := do
  let bound := min limit builder.config.maxEntries
  repeat
    builder.ensureOpen
    let (raw, entries) ← FFI.Static.readDirectory builder.handle path bound.toUInt32
    let code := Errno.decode raw
    if code < 0 && (← Errno.isInterrupted code) then continue
    checkedZero "static anchored directory enumeration" raw
    if entries.size > bound then throw (IO.userError "static directory entry count exceeded")
    for (_, kind) in entries do
      if kind < 1 || kind > 4 then throw (IO.userError "static directory entry type is invalid")
    return entries
  throw (IO.userError "static directory enumeration did not complete")

def Builder.field (builder : Builder) (entry index : UInt32) : IO UInt32 := do
  builder.ensureOpen
  let value ← checked "static catalog metadata" (← FFI.Static.field builder.handle entry index)
  if value > 4294967295 then throw (IO.userError "static metadata exceeds its native range")
  return value.toUInt32

/-- Publish once all paths and generated representations have been prepared.
    Windows working-set adjustment is an explicit startup policy. -/
def Builder.publish (builder : Builder) (residentBudget : Nat)
    (adjustWorkingSet : Bool := false) : IO Source := do
  builder.ensureOpen
  if residentBudget > 9223372036854775807 then throw (IO.userError "resident budget exceeds native range")
  if adjustWorkingSet then
    checkedZero "static resident working-set budget" (← FFI.Static.prepareResidency residentBudget.toUInt64)
  repeat
    builder.ensureOpen
    let raw ← FFI.Static.finish builder.handle residentBudget.toUInt64
    let value := Errno.decode raw
    if value < 0 then
      if ← Errno.isInterrupted value then continue
      throw (← Errno.error "static catalog resident publication (check locked-memory budget)" value)
    if raw == 0 then throw (IO.userError "static catalog publication returned no source")
    builder.finished.set true
    try
      let size ← checked "file source size" (← FFI.Static.sourceSize raw)
      return ⟨raw, size.toNat, ← IO.mkRef true⟩
    catch error =>
      checkedZero "file source failed-publication cleanup" (← FFI.Static.sourceRelease raw)
      throw error
  throw (IO.userError "static catalog publication did not complete")

def withBuilder (root : System.FilePath) (config : BuilderConfig := {})
    (use : Builder → IO α) : IO α := do
  if config.maxFileBytes == 0 || config.maxFileBytes > config.maxPackBytes ||
      config.maxPackBytes > 9223372036854775807 || config.maxEntries == 0 ||
      config.maxEntries > 1000000 || config.minCompressBytes > config.maxFileBytes ||
      config.gzipLevel > 9 || config.brotliQuality > 11 || config.stepBytes == 0 ||
      config.stepBytes > 65536 || config.startupTimeoutMs == 0 ||
      config.startupTimeoutMs > 9223372036854775807 then
    throw (IO.userError "invalid static catalog resource limits")
  let handle ← checked "static catalog create" (← FFI.Static.create root.toString
    config.maxFileBytes.toUInt64 config.maxPackBytes.toUInt64 config.maxEntries.toUInt32
    config.minCompressBytes.toUInt64 config.gzipLevel.toUInt32 config.brotliQuality.toUInt32)
  if handle == 0 then throw (IO.userError "static catalog create returned no builder")
  let cutoff := (← IO.monoMsNow) + config.startupTimeoutMs
  let builder : Builder := ⟨handle, config, ← IO.mkRef true, ← IO.mkRef false, cutoff⟩
  try
    builder.prepare
    use builder
  finally
    builder.alive.set false
    repeat
      let raw ← FFI.Static.free handle
      let code := Errno.decode raw
      if code < 0 && (← Errno.isInterrupted code) then continue
      checkedZero "static catalog release" raw
      break

end LeanNet.File
