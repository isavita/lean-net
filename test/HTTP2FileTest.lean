import LeanNet.HTTP2.Machine

open LeanNet LeanNet.HTTP2

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do throw (IO.userError message)
private def ok (value : Except ProtocolError α) : IO α := do
  match value with
  | .ok result => return result
  | .error error => throw (IO.userError (reprStr error))
private def hp (value : Except String α) : IO α := do
  match value with
  | .ok result => return result
  | .error error => throw (IO.userError error)
private def rejected (value : Except ProtocolError α) : IO Unit :=
  match value with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError "invalid file operation accepted")
private def b32 (n : Nat) : ByteArray := ByteArray.mk #[UInt8.ofNat (n / 16777216), UInt8.ofNat (n / 65536), UInt8.ofNat (n / 256), UInt8.ofNat n]
private def frame (kind flags : UInt8) (id : UInt32) (payload : ByteArray) : IO ByteArray :=
  ok ((Frame.mk kind flags id payload).encode 16777215)
private def head (method : String := "GET") (extra : Array HPACK.Header := #[]) : Array HPACK.Header := #[
  { name := ":method".toUTF8, value := method.toUTF8 }, { name := ":scheme".toUTF8, value := "http".toUTF8 }, { name := ":path".toUTF8, value := "/file".toUTF8 }, { name := ":authority".toUTF8, value := "files.test".toUTF8 }] ++ extra
private def preface : ByteArray := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toUTF8
private def connect (config : Connection.Config := {}) (zeroWindow : Bool := false) : IO Connection := do
  let settings := if zeroWindow then ByteArray.mk #[0,4,0,0,0,0] else ByteArray.empty
  let (connection, _, _) ← ok ((Connection.newWithConfig config).feed (preface.append (← frame 4 0 0 settings)))
  return connection
private def send (connection : Connection) (kind flags : UInt8) (id : UInt32) (payload : ByteArray) : IO Connection := do
  let bytes ← frame kind flags id payload
  let step := connection.feedSlice bytes 0 bytes.size
  check (step.error.isNone && step.consumed == bytes.size) "control/frame processing failed"
  return step.connection
private def request (connection : Connection) (id : UInt32) (method : String := "GET")
    (extra : Array HPACK.Header := #[]) : IO Connection := do
  let (_, block) ← hp (HPACK.encode HPACK.Context.new (head method extra))
  let connection ← send connection 1 5 id block
  check (connection.canRespond id) "request not ready"
  return connection
private def frames (bytes : ByteArray) : IO (Array Frame) := do
  let mut cursor := 0
  let mut result := #[]
  for _ in [:bytes.size + 1] do
    if cursor == bytes.size then break
    match (FrameParser.new 16777215).feedSlice bytes cursor (bytes.size - cursor) with
    | .complete frame used => result := result.push frame; cursor := cursor + used
    | .needMore _ _ => throw (IO.userError "truncated framed output")
    | .error error _ => throw (IO.userError (reprStr error))
  return result
private def source : ByteArray := ByteArray.mk ((Array.range 100100).map UInt8.ofNat)
private def region (length : Nat := 40000) : FileRegion := { owner := 7, token := 11, offset := 17, length }
/-- Independent test-only file resolver: protocol code never sees these bytes. -/
private def materialize (parts : Array WirePart) : IO ByteArray := do
  let mut result := ByteArray.empty
  for part in parts do
    match part with
    | .bytes bytes => result := result.append bytes
    | .file file =>
      check (file.owner == 7 && file.token == 11 && file.valid && file.offset.toNat + file.length <= source.size) "file range escaped immutable source"
      result := result.append (source.extract file.offset.toNat (file.offset.toNat + file.length))
  return result
private def fileCount (parts : Array WirePart) : Nat := parts.foldl (fun n part =>
  match part with | .file _ => n + 1 | _ => n) 0

private def flowAndFraming : IO Unit := do
  let connection ← request (← connect { maxDataPerDrain := 32768 } true) 1
  let (queued, headers) ← ok (connection.queueFileResponse 1 {} (region 40000))
  let headers ← frames headers
  let (_, fields) ← hp (HPACK.decode HPACK.Context.new headers[0]!.payload)
  check (fields.any (fun field => field.name == "content-length".toUTF8 && field.value == "40000".toUTF8)) "file Content-Length missing"
  check (queued.hasPendingOutput && !queued.canDrain) "zero stream window did not block file DATA"
  rejected queued.drain
  let c ← send queued 8 0 1 (b32 5)
  let (c, first) ← ok c.drainParts
  check (first.size == 2 && fileCount first == 1) "DATA header/file region pair"
  match (first[0]? : Option WirePart), (first[1]? : Option WirePart) with
  | some (WirePart.bytes header), some (WirePart.file file) =>
    check (header.size == 9 && file == (region 40000).take 5) "DATA header copied source bytes or advanced wrong offset"
  | _, _ => throw (IO.userError "file payload preceded its DATA header")
  let firstFrames ← frames (← materialize first)
  check (firstFrames.size == 1 && firstFrames[0]!.payload == source.extract 17 22 && firstFrames[0]!.flags == 0) "partial-credit file payload"
  let c ← send c 8 0 1 (b32 39995)
  let (c, middle) ← ok c.drainParts
  check (middle.foldl (fun total part => total + match part with | .file file => file.length | _ => 0) 0 == 32768) "file drain exceeded its payload budget"
  let (c, last) ← ok c.drainParts
  let allFrames ← frames ((← materialize first).append ((← materialize middle).append (← materialize last)))
  let bytes := allFrames.foldl (fun out frame => out.append frame.payload) ByteArray.empty
  check (bytes == source.extract 17 40017 && (allFrames[allFrames.size - 1]!).flags == 1 &&
    !c.hasPendingOutput) "file slice offsets, final END_STREAM or completion"
  check (!queued.canRespond 1 && queued.hasPendingOutput) "retained queued state mutated"
  let c ← send queued 8 0 1 (b32 5)
  let (_, repeatParts) ← ok c.drainParts
  check ((← materialize repeatParts) == (← materialize first)) "retained file cursor was mutated"

private def limitsAndCompatibility : IO Unit := do
  let c ← request (← connect) 1
  let c ← request c 3
  let huge := region (1024 * 1024 * 1024)
  let (queued, _) ← ok (c.queueFileResponse 1 {} huge)
  check queued.hasPendingOutput "logical 1GiB file charged against 8MiB resident body limit"
  rejected queued.drain
  rejected (queued.respond 3 { body := "x".toUTF8 })
  check (queued.canRespond 3) "legacy file rejection mutated another stream"
  let (canceled, _) ← ok (queued.cancel 1)
  let (canceled, _) ← ok (canceled.queueResponse 3 { body := "healthy".toUTF8 })
  let (_, bytes) ← ok canceled.drain
  check ((← frames bytes)[0]!.payload == "healthy".toUTF8) "legacy BA drain after file cancellation"
  rejected (c.queueFileResponse 1 {} (region (1024 * 1024 * 1024 + 1)))
  rejected (c.queueFileResponse 1 {} { (region 1) with owner := 0 })
  rejected (c.queueFileResponse 1 { body := "mixed".toUTF8 } (region 1))
  for status in #[103,204,205,304] do rejected (c.queueFileResponse 1 { status } (region 0))
  let config : Connection.Config := { maxResponseBodyBytes := 4, maxQueuedResponseBytes := 4, maxFileResponseBytes := 8, maxQueuedFileBytes := 16 }
  let c ← request (← connect config) 1
  let c ← request c 3
  let c ← request c 5
  let c ← request c 7
  let (c, _) ← ok (c.queueFileResponse 1 {} (region 8))
  let (c, _) ← ok (c.queueFileResponse 3 {} (region 8))
  rejected (c.queueFileResponse 5 {} (region 1))
  let (c, _) ← ok (c.queueResponse 5 { body := "abcd".toUTF8 })
  rejected (c.queueResponse 7 { body := "e".toUTF8 })
  check c.canDrain "file and resident debt did not remain independent"
  let head ← request (← connect) 1 "HEAD"
  let (head, output) ← ok (head.queueFileResponse 1 {} huge)
  let output ← frames output
  let (_, fields) ← hp (HPACK.decode HPACK.Context.new output[0]!.payload)
  check (!head.hasPendingOutput && output[0]!.flags == 5 &&
    fields.any (fun field => field.name == "content-length".toUTF8 && field.value == "1073741824".toUTF8)) "HEAD lost file length or queued a source operation"

private def orderingAndCancellation : IO Unit := do
  let low : Array HPACK.Header := #[{ name := "priority".toUTF8, value := "u=7".toUTF8 }]
  let high : Array HPACK.Header := #[{ name := "priority".toUTF8, value := "u=0".toUTF8 }]
  let c ← request (← connect) 1 "GET" low
  let c ← request c 3 "GET" high
  let (c, _) ← ok (c.queueFileResponse 1 {} (region 20))
  let (c, _) ← ok (c.queueResponse 3 { body := "high".toUTF8 })
  let (_, parts) ← ok c.drainParts
  let output ← frames (← materialize parts)
  check (output.size == 2 && output[0]!.streamId == 3 && output[0]!.payload == "high".toUTF8 &&
    output[1]!.streamId == 1 && output[1]!.payload == source.extract 17 37) "file DATA bypassed priority or byte/file order"
  let c ← request (← connect { maxDataPerDrain := 32768 }) 1
  let c ← request c 3
  let (c, _) ← ok (c.queueFileResponse 1 {} (region 100000))
  let (c, committed) ← ok c.drainParts
  let (c, _) ← ok (c.cancel 1)
  let (c, _) ← ok (c.queueResponse 3 { body := "next".toUTF8 })
  let (_, bytes) ← ok c.drain
  check ((← frames bytes)[0]!.streamId == 3 && (← frames (← materialize committed)).all
    (fun frame => frame.kind == 0 && frame.streamId == 1)) "RST changed already committed frame payloads or killed another stream"
  let c ← request (← connect) 1
  let (c, initial) ← ok (c.queueFileResponse 1 {} (region 10) #[{ name := "X-End", value := "yes".toUTF8 }])
  let initial ← frames initial
  let (decoder, _) ← hp (HPACK.decode HPACK.Context.new initial[0]!.payload)
  let (c, parts) ← ok c.drainParts
  let output ← frames (← materialize parts)
  check (output.size == 2 && output[0]!.kind == 0 && output[0]!.flags == 0 &&
    output[1]!.kind == 1 && output[1]!.flags == 5 && !c.hasPendingOutput) "file trailers or END_STREAM order"
  let (_, trailing) ← hp (HPACK.decode decoder output[1]!.payload)
  check (trailing.any (fun field => field.name == "x-end".toUTF8 && field.value == "yes".toUTF8)) "file trailer HPACK state"

private def machine : IO Unit := do
  let input := preface.append (← frame 4 0 0 ByteArray.empty)
  let boot := (Machine.State.new).feedSlice input 0 input.size
  let (_, block) ← hp (HPACK.encode HPACK.Context.new (head))
  let input ← frame 1 5 1 block
  let parsed := boot.state.feedSlice input 0 input.size
  let replied := parsed.state.respond 1 { response := {}, fileRegion := some (region 20) }
  check (replied.actions.any (fun | .write _ => true | _ => false) &&
    !replied.actions.any (fun | .writeParts _ => true | _ => false)) "file response eagerly emitted DATA"
  let drained := replied.state.drain
  let [parts] := drained.actions.filterMap (fun | .writeParts parts => some parts | _ => none)
    | throw (IO.userError "machine omitted file-aware action")
  check (fileCount parts == 1 && !drained.state.hasPendingOutput) "machine file drain action"
  let invalid := parsed.state.respond 1 { response := { body := "mixed".toUTF8 }, fileRegion := some (region 20) }
  check (!invalid.actions.any (fun | .writeParts _ => true | _ => false) && !invalid.state.hasPendingOutput) "invalid mixed file failed to fall back atomically"

def main : IO Unit := do
  flowAndFraming
  limitsAndCompatibility
  orderingAndCancellation
  machine
  IO.println "HTTP/2 file metadata, framing, flow and priority tests passed"
