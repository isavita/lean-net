import LeanNet.HTTP2.Frame

open LeanNet.HTTP2

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do throw (IO.userError message)

private def bytes (values : Array UInt8) : ByteArray := ByteArray.mk values

private def wire (kind flags : UInt8) (stream : UInt32) (payload : ByteArray) : ByteArray :=
  let n := payload.size
  let id := stream.toNat
  (bytes #[UInt8.ofNat (n / 65536), UInt8.ofNat (n / 256), UInt8.ofNat n,
    kind, flags, UInt8.ofNat (id / 16777216), UInt8.ofNat (id / 65536),
    UInt8.ofNat (id / 256), UInt8.ofNat id]).append payload

private def payload (size : Nat) : ByteArray := Id.run do
  let mut result := ByteArray.emptyWithCapacity size
  for i in [:size] do result := result.push (UInt8.ofNat (i * 37 + i / 256))
  return result

private def complete (result : FrameSliceResult) (expected : Frame) (used : Nat) : IO Unit := do
  match result with
  | .complete frame consumed => check (frame == expected && consumed == used) "slice frame or consumed count changed"
  | .error error _ => throw (IO.userError s!"unexpected frame error: {repr error}")
  | .needMore _ _ => throw (IO.userError "missing frame completion")

private def rejected (result : FrameSliceResult) (code : ErrorCode) (scope : ErrorScope)
    (used : Nat) : IO Unit := do
  match result with
  | .error error consumed => check (error.code == code && error.scope == scope && consumed == used) "frame error scope or cursor changed"
  | _ => throw (IO.userError "expected a frame error")

private def splitAt (expected : Frame) (split : Nat) : IO Unit := do
  let encoded := wire expected.kind expected.flags expected.streamId expected.payload
  let source := ((bytes #[77, 88, 99]).append encoded).append (bytes #[33, 44])
  match (FrameParser.new 16777215).feedSlice source 3 split with
  | .needMore parser consumed =>
    check (consumed == split && split < encoded.size) "split input was not consumed exactly"
    check (split == 0 || !parser.finish.isOk) "partial frame was accepted at EOF"
    complete (parser.feedSlice source (3 + split) (encoded.size - split)) expected (encoded.size - split)
  | result =>
    check (split == encoded.size) "frame completed before its full range"
    complete result expected encoded.size

private def everySplit (expected : Frame) : IO Unit := do
  let size := expected.payload.size + 9
  for split in [:size + 1] do splitAt expected split

private def bytewise (expected : Frame) : IO Unit := do
  let encoded := wire expected.kind expected.flags expected.streamId expected.payload
  let source := (bytes #[19, 20]).append encoded
  let mut parser := FrameParser.new 16777215
  for index in [:encoded.size] do
    match parser.feedSlice source (2 + index) 1 with
    | .needMore next used =>
      check (used == 1 && index + 1 < encoded.size) "bytewise cursor or completion boundary"
      parser := next
    | result =>
      check (index + 1 == encoded.size) "bytewise frame completed early"
      complete result expected 1

private def completeErrorBoundary (encoded : ByteArray) (code : ErrorCode) (scope : ErrorScope) : IO Unit := do
  let suffix := wire 201 255 7 (bytes #[0, 255, 9])
  let source := ((bytes #[71, 72]).append encoded).append suffix
  for split in [:encoded.size] do
    match (FrameParser.new).feedSlice source 2 split with
    | .needMore parser used =>
      check (used == split) "invalid frame stopped before its complete payload"
      rejected (parser.feedSlice source (2 + split) (source.size - 2 - split)) code scope (encoded.size - split)
    | _ => throw (IO.userError "invalid frame terminated before its full length")
  rejected ((FrameParser.new).feedSlice source 2 (source.size - 2)) code scope encoded.size
  complete ((FrameParser.new).feedSlice source (2 + encoded.size) suffix.size)
    ⟨201, 255, 7, bytes #[0, 255, 9]⟩ suffix.size

def main : IO Unit := do
  let small : Array Frame := #[⟨0, 1, 1, bytes #[0, 255, 13, 10]⟩,
    ⟨4, 0, 0, ByteArray.empty⟩, ⟨6, 1, 0, payload 8⟩,
    ⟨16, 253, 0, (bytes #[0, 0, 0, 1]).append "u=0, i".toUTF8⟩,
    ⟨17, 255, 3, bytes #[255]⟩]
  for frame in small do
    everySplit frame
    bytewise frame
  for size in #[0, 1, 4095, 4096, 4097, 8192, 16384, 65536] do
    let frame : Frame := ⟨201, 255, 7, payload size⟩
    let full := size + 9
    for split in #[0, 1, 8, 9, 10, 4095, 4096, 4104, full - 1, full] do
      if split <= full then splitAt frame split
    if size == 4097 || size == 16384 then bytewise frame

  let frames : Array Frame := #[⟨201, 0, 1, payload 4097⟩, ⟨4, 1, 0, ByteArray.empty⟩,
    ⟨16, 0, 0, bytes #[128, 0, 0, 2]⟩]
  let mut source := bytes #[8, 7, 6]
  for frame in frames do source := source.append (wire frame.kind frame.flags frame.streamId frame.payload)
  source := source.append (bytes #[4, 3])
  let mut cursor := 3
  for frame in frames do
    let used := frame.payload.size + 9
    complete ((FrameParser.new).feedSlice source cursor (source.size - cursor)) frame used
    cursor := cursor + used
  check (cursor == source.size - 2) "coalesced frame cursor consumed its suffix"

  -- Header reserved bits are discarded; priority payload reserved bits remain
  -- owned opaque bytes for the extension decoder to interpret.
  let reserved := wire 201 251 2147483649 (bytes #[0, 255])
  complete ((FrameParser.new).feedSlice reserved 0 reserved.size) ⟨201, 251, 1, bytes #[0, 255]⟩ reserved.size
  for target in #[1, 2, 2147483649] do
    let data := bytes #[UInt8.ofNat (target / 16777216), UInt8.ofNat (target / 65536), UInt8.ofNat (target / 256), UInt8.ofNat target]
    let encoded := wire 16 255 0 data
    complete ((FrameParser.new).feedSlice encoded 0 encoded.size) ⟨16, 255, 0, data⟩ encoded.size
  completeErrorBoundary (wire 16 0 1 (bytes #[0, 0, 0, 1])) .protocolError .connection
  for size in [:4] do completeErrorBoundary (wire 16 0 0 (payload size)) .frameSizeError .connection
  for data in #[bytes #[0, 0, 0, 0], bytes #[128, 0, 0, 0]] do
    completeErrorBoundary (wire 16 0 0 data) .protocolError .connection
  for value in #[0, 1] do
    let setting := bytes #[0, 9, 0, 0, 0, UInt8.ofNat value]
    everySplit ⟨4, 0, 0, setting⟩
  for setting in #[bytes #[0, 9, 0, 0, 0, 2], bytes #[0, 9, 255, 255, 255, 255]] do
    completeErrorBoundary (wire 4 0 0 setting) .protocolError .connection
  completeErrorBoundary (wire 2 0 1 (bytes #[0, 1, 2])) .frameSizeError (.stream 1)
  completeErrorBoundary (wire 2 0 1 (bytes #[0, 0, 0, 1, 0])) .protocolError (.stream 1)
  completeErrorBoundary (wire 8 0 3 (bytes #[0, 0, 0, 0])) .protocolError (.stream 3)

  -- HEADERS self-dependency must reach the connection so it can decode the
  -- complete HPACK block before resetting only that stream.
  let dependent := bytes #[0, 0, 0, 1, 0, 130, 134, 132]
  everySplit ⟨1, 36, 1, dependent⟩

  let oversized := wire 201 0 1 (payload 10)
  rejected ((FrameParser.new 5).feedSlice oversized 0 oversized.size) .frameSizeError .connection 9
  match (FrameParser.new 5).feedSlice oversized 0 8 with
  | .needMore parser used =>
    check (used == 8) "oversize header fragment cursor"
    rejected (parser.feedSlice oversized 8 (oversized.size - 8)) .frameSizeError .connection 1
  | _ => throw (IO.userError "oversize header was rejected before nine bytes")
  for (offset, length) in #[(oversized.size + 1, 0), (oversized.size, 1), (1, oversized.size)] do
    rejected ((FrameParser.new).feedSlice oversized offset length) .internalError .connection 0
  match (FrameParser.new).feedSlice oversized oversized.size 0 with
  | .needMore parser used => check (used == 0 && parser.finish.isOk) "empty input created a partial frame"
  | _ => throw (IO.userError "empty range did not need more input")

  -- Retaining and independently resuming the same parser preserves both
  -- branches across the active block's 4096-byte ownership boundary.
  let common := payload 4097
  let a := (wire 201 0 1 (common.append (payload 5000))).extract 0 (9 + common.size)
  let start ← match (FrameParser.new).feedSlice a 0 a.size with
    | .needMore parser used => check (used == a.size) "persistent prefix cursor"; pure parser
    | _ => throw (IO.userError "persistent prefix completed early")
  let tailA := payload 5000
  let tailB := ByteArray.mk (Array.replicate 5000 (255 : UInt8))
  complete (start.feedSlice tailA 0 tailA.size) ⟨201, 0, 1, common.append tailA⟩ tailA.size
  complete (start.feedSlice tailB 0 tailB.size) ⟨201, 0, 1, common.append tailB⟩ tailB.size
  IO.println "HTTP/2 bulk frame slice, extension and ownership tests passed"
