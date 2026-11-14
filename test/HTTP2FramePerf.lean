import LeanNet.HTTP2.Frame

open LeanNet.HTTP2

private def body (size step : Nat) : IO Unit := do
  let payload := ByteArray.mk (Array.replicate size (173 : UInt8))
  let encoded ← match (Frame.mk 201 0 1 payload).encode 16777215 with
    | .ok value => pure value
    | .error error => throw (IO.userError error.message)
  let mut parser := FrameParser.new 16777215
  let mut cursor := 0
  let mut done := false
  let start ← IO.monoMsNow
  while cursor < encoded.size do
    let amount := min step (encoded.size - cursor)
    match parser.feedSlice encoded cursor amount with
    | .needMore next consumed =>
      unless consumed == amount do throw (IO.userError "partial slice cursor")
      parser := next
    | .complete frame consumed =>
      unless consumed == amount && cursor + consumed == encoded.size && frame.payload == payload do
        throw (IO.userError "frame completion changed")
      done := true
    | .error error _ => throw (IO.userError error.message)
    cursor := cursor + amount
  unless done do throw (IO.userError "missing completed frame")
  IO.println s!"slice-body bytes={size} step={step} ms={(← IO.monoMsNow) - start}"

private def coalesced (count : Nat) : IO Unit := do
  let frame := ByteArray.mk #[0, 0, 0, 201, 0, 0, 0, 0, 1]
  let mut encoded := ByteArray.emptyWithCapacity (count * 9)
  for _ in [:count] do encoded := encoded.append frame
  let mut cursor := 0
  let mut parsed := 0
  let start ← IO.monoMsNow
  while cursor < encoded.size do
    match (FrameParser.new).feedSlice encoded cursor (encoded.size - cursor) with
    | .complete _ consumed => cursor := cursor + consumed; parsed := parsed + 1
    | _ => throw (IO.userError "coalesced frame failed")
  unless parsed == count do throw (IO.userError "coalesced frame count changed")
  IO.println s!"slice-coalesced frames={count} ms={(← IO.monoMsNow) - start}"

def main : IO Unit := do
  body 1048576 8192
  body 2097152 8192
  body 4194304 8192
  body 262144 1
  coalesced 4096
  coalesced 8192
