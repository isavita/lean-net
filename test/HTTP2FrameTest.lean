import LeanNet.HTTP2.Frame

open LeanNet.HTTP2

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do throw (IO.userError message)

private def raw (xs : List UInt8) : ByteArray := ByteArray.mk xs.toArray

private def encoded (frame : Frame) : IO ByteArray := do
  match frame.encode with
  | .ok bytes => return bytes
  | .error err => throw (IO.userError s!"unexpected encode error: {repr err}")

private def expectFrame (result : FrameParseResult) (frame : Frame) (remaining : ByteArray) : IO Unit := do
  match result with
  | .complete parsed rest => check (parsed == frame && rest == remaining) "frame or remainder mismatch"
  | .error error _ => throw (IO.userError s!"unexpected frame error: {repr error}")
  | .needMore _ => throw (IO.userError "expected a complete frame")

private def expectError (bytes : ByteArray) (code : ErrorCode) (scope : ErrorScope)
    (remaining : ByteArray := ByteArray.empty) : IO Unit := do
  match (FrameParser.new).feed bytes with
  | .error error rest =>
    check (error.code == code && error.scope == scope && rest == remaining) "wrong frame error or remainder"
  | .needMore _ => throw (IO.userError "expected frame error, got needMore")
  | .complete _ _ => throw (IO.userError "expected frame error, got frame")

private def allSplits (frame : Frame) : IO Unit := do
  let wire ← encoded frame
  let remainder := raw [7, 8, 9]
  let both := wire.append remainder
  for split in [0:both.size + 1] do
    let first := both.extract 0 split
    let last := both.extract split both.size
    let result := match (FrameParser.new).feed first with
      | .needMore parser => parser.feed last
      | .complete value rest => .complete value (rest.append last)
      | .error error rest => .error error (rest.append last)
    expectFrame result frame remainder

private def run : IO Unit := do
  let data : Frame := ⟨0, 1, 1, raw [0, 255, 13, 10]⟩
  let emptySettings : Frame := ⟨4, 0, 0, ByteArray.empty⟩
  let ping : Frame := ⟨6, 1, 0, raw [0, 1, 2, 3, 4, 5, 6, 7]⟩
  let extension : Frame := ⟨201, 255, 3, raw [42, 0, 255]⟩
  for frame in #[data, emptySettings, ping, extension] do allSplits frame
  for size in #[0, 1, 4095, 4096, 4097, 16384] do
    let mut payload := ByteArray.empty
    for i in [0:size] do payload := payload.push (UInt8.ofNat (i % 256))
    let frame : Frame := ⟨201, 255, 7, payload⟩
    let wire ← encoded frame
    expectFrame ((FrameParser.new).feed wire) frame ByteArray.empty
    let split := min wire.size 4101
    match (FrameParser.new).feed (wire.extract 0 split) with
    | .needMore next => expectFrame (next.feed (wire.extract split wire.size)) frame ByteArray.empty
    | .complete value rest => check (value == frame && rest.isEmpty && split == wire.size) "boundary parse"
    | .error error _ => throw (IO.userError s!"boundary parse: {repr error}")
  let wire ← encoded data
  let mut parser := FrameParser.new
  for i in [0:wire.size] do
    match parser.feed (wire.extract i (i + 1)) with
    | .needMore next => parser := next
    | result@(.complete _ _) =>
      check (i + 1 == wire.size) "completed before final byte"
      expectFrame result data ByteArray.empty
    | .error error _ => throw (IO.userError s!"bytewise parse: {repr error}")
  let reserved := raw [0, 0, 0, 0, 0, 128, 0, 0, 1]
  expectFrame ((FrameParser.new).feed reserved) ⟨0, 0, 1, ByteArray.empty⟩ ByteArray.empty
  expectError (raw [0, 0, 0, 0, 0, 0, 0, 0, 0]) .protocolError .connection
  expectError (raw [0, 0, 1, 2, 0, 0, 0, 0, 1, 0, 9, 8]) .frameSizeError (.stream 1) (raw [9, 8])
  expectError (raw [0, 0, 3, 3, 0, 0, 0, 0, 1, 0, 0, 0]) .frameSizeError .connection
  expectError (raw [0, 0, 1, 4, 1, 0, 0, 0, 0, 0]) .frameSizeError .connection
  expectError (raw [0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 2]) .protocolError .connection
  expectError (raw [0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 4, 128, 0, 0, 0]) .flowControlError .connection
  expectError (raw [0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 5, 0, 0, 63, 255]) .protocolError .connection
  expectError (raw [0, 0, 7, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]) .frameSizeError .connection
  expectError (raw [0, 0, 4, 8, 0, 0, 0, 0, 1, 128, 0, 0, 0]) .protocolError (.stream 1)
  expectError (raw [0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0]) .protocolError .connection
  expectError (raw [0, 0, 2, 0, 8, 0, 0, 0, 1, 2, 0]) .protocolError .connection
  expectError (raw [0, 0, 5, 2, 0, 0, 0, 0, 1, 0, 0, 0, 1, 4]) .protocolError (.stream 1)
  expectError (raw [0, 0, 4, 5, 0, 0, 0, 0, 1, 0, 0, 0, 0]) .protocolError .connection
  match (FrameParser.new 5).feed (raw [0, 0, 6, 6, 0, 0, 0, 0, 0, 1, 2]) with
  | .error error rest => check (error.code == .frameSizeError && rest == raw [1, 2]) "frame size limit"
  | _ => throw (IO.userError "oversized frame not rejected at header")
  match (FrameParser.new).feed (raw [0, 0, 2, 0, 0, 0, 0, 0, 1, 0]) with
  | .needMore next =>
    match next.finish with
    | .error _ => pure ()
    | .ok _ => throw (IO.userError "truncated frame accepted")
  | _ => throw (IO.userError "truncated frame did not wait")
  match (Frame.mk 0 8 1 (raw [1, 7])).encode with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError "nonzero outgoing padding accepted")
  IO.println "HTTP/2 frame tests passed"

def main : IO Unit := run
