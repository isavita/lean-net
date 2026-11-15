import LeanNet.HTTP2.Machine

open LeanNet.HTTP2

private def check (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

private def fail (message : String) : IO α := throw (IO.userError message)

private def ok (label : String) (result : Except ProtocolError α) : IO α :=
  match result with
  | .ok value => pure value
  | .error error => fail s!"{label}: {repr error}"

private def wire (frame : Frame) : IO ByteArray := ok "frame encoding" (frame.encode 16777215)

private def frames (data : ByteArray) : IO (Array Frame) := do
  let mut data := data
  let mut out := #[]
  for _ in [:data.size + 1] do
    if data.isEmpty then break
    match (FrameParser.new 16777215).feed data with
    | .complete frame rest => out := out.push frame; data := rest
    | _ => fail "invalid outbound HTTP/2 frame"
  return out

private def b32 (n : Nat) : ByteArray :=
  ByteArray.mk #[UInt8.ofNat (n / 16777216), UInt8.ofNat (n / 65536), UInt8.ofNat (n / 256), UInt8.ofNat n]

private def preface : ByteArray := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toUTF8

private def requestHeaders (method : ByteArray := "GET".toUTF8) : Array HPACK.Header := #[
  { name := ":method".toUTF8, value := method },
  { name := ":scheme".toUTF8, value := "http".toUTF8 },
  { name := ":authority".toUTF8, value := "localhost".toUTF8 },
  { name := ":path".toUTF8, value := "/".toUTF8 }]

private def openRequest (method : ByteArray := "GET".toUTF8)
    (zeroStreamWindow : Bool := false) : IO Connection := do
  let settings ← if zeroStreamWindow then
    wire ⟨4, 0, 0, ByteArray.mk #[0, 4, 0, 0, 0, 0]⟩
    else wire ⟨4, 0, 0, ByteArray.empty⟩
  let (encoder, block) ← match HPACK.encode HPACK.Context.new (requestHeaders method) with
    | .ok result => pure result
    | .error message => fail s!"request HPACK encode: {message}"
  let _ := encoder
  let input := ((preface.append settings).append (← wire ⟨1, 5, 1, block⟩))
  let (connection, output, requests) ← ok "request setup" (Connection.new.feed input)
  let ack ← frames output
  check (ack.size == 1 && ack[0]!.kind == 4 && requests.size == 1)
    "request setup did not finish"
  return connection

private def onlyFrame (data : ByteArray) : IO Frame := do
  let parsed ← frames data
  let some frame := parsed[0]? | fail "missing output frame"
  check (parsed.size == 1) "unexpected extra output frames"
  return frame

def main : IO Unit := do
  let c ← openRequest
  let head : LeanNet.HTTP1.Response := {
    status := 200, headers := #[{ name := "x-upstream", value := "safe".toUTF8 }]
  }
  let (c, headWire) ← ok "begin stream" (c.beginResponseStream 1 head)
  let responseHead ← onlyFrame headWire
  check (responseHead.kind == 1 && responseHead.flags == 4 && !c.canRespond 1)
    "stream HEADERS did not hold the response open"
  let (_, decoded) ← match HPACK.decode HPACK.Context.new responseHead.payload with
    | .ok result => pure result
    | .error message => fail s!"response HPACK decode: {message}"
  check (decoded.any (fun field => field.name == ":status".toUTF8 && field.value == "200".toUTF8))
    "stream status missing"
  check (!decoded.any (·.name == "content-length".toUTF8))
    "unknown streamed length was advertised"
  match c.queueResponse 1 { status := 200 } with
  | .error _ => pure ()
  | .ok _ => fail "duplicate complete response replaced streamed response"

  let body := ByteArray.mk (Array.replicate 65536 (65 : UInt8))
  let some (c, firstWire, consumed) ← ok "stream first DATA" (c.tryStreamData 1 body) |
    fail "initial DATA unexpectedly backpressured"
  let firstData ← onlyFrame firstWire
  check (firstData.kind == 0 && firstData.flags == 0 && consumed == 16384 &&
    firstData.payload.size == consumed) "DATA was not limited to one frame"
  let (c, endWire) ← ok "finish stream" (c.endResponseStream 1)
  let finalData ← onlyFrame endWire
  check (finalData.kind == 0 && finalData.flags == 1 && finalData.payload.isEmpty &&
    !c.canRespond 1) "terminal empty DATA did not close stream"
  match c.endResponseStream 1 with
  | .error _ => pure ()
  | .ok _ => fail "duplicate END_STREAM accepted"

  let c ← openRequest (zeroStreamWindow := true)
  let (c, zeroHeadWire) ← ok "zero-window stream head" (c.beginResponseStream 1 { status := 200 })
  let zeroHead ← onlyFrame zeroHeadWire
  let (decoder, _) ← match HPACK.decode HPACK.Context.new zeroHead.payload with
    | .ok result => pure result
    | .error message => fail s!"streaming HEADERS decode: {message}"
  match ← ok "zero-window DATA" (c.tryStreamData 1 "hello".toUTF8) with
  | none => pure ()
  | some _ => fail "DATA bypassed zero stream window"
  let (c, _, _) ← ok "window update" (c.feed (← wire ⟨8, 0, 1, b32 3⟩))
  let some (c, firstWire, consumed) ← ok "partial-window DATA" (c.tryStreamData 1 "hello".toUTF8) |
    fail "partial credit was not used"
  let firstData ← onlyFrame firstWire
  check (consumed == 3 && firstData.payload == "hel".toUTF8 && firstData.flags == 0)
    "partial credit consumed the wrong prefix"
  match ← ok "exhausted-window DATA" (c.tryStreamData 1 "lo".toUTF8) with
  | none => pure ()
  | some _ => fail "exhausted window accepted DATA"
  let (c, _, _) ← ok "second window update" (c.feed (← wire ⟨8, 0, 1, b32 2⟩))
  let some (c, secondWire, consumed) ← ok "remaining DATA" (c.tryStreamData 1 "lo".toUTF8) |
    fail "remaining DATA was not resumed"
  let secondData ← onlyFrame secondWire
  check (consumed == 2 && secondData.payload == "lo".toUTF8) "remaining DATA changed"
  let (c, trailerWire) ← ok "finish with trailers" (c.endResponseStream 1
    #[{ name := "x-check", value := "yes".toUTF8 }])
  let trailerFrame ← onlyFrame trailerWire
  check (trailerFrame.kind == 1 && trailerFrame.flags == 5 && !c.canRespond 1)
    "trailing HEADERS did not end stream"
  let (_, trailerFields) ← match HPACK.decode decoder trailerFrame.payload with
    | .ok result => pure result
    | .error message => fail s!"streaming trailer decode: {message}"
  check (trailerFields.any (fun field => field.name == "x-check".toUTF8 && field.value == "yes".toUTF8))
    "trailing HEADERS lost upstream trailer"

  let c ← openRequest "HEAD".toUTF8
  let (c, headWire) ← ok "HEAD stream" (c.beginResponseStream 1 { status := 200 })
  let headFrame ← onlyFrame headWire
  check (headFrame.kind == 1 && headFrame.flags == 5 && !c.canRespond 1)
    "HEAD streaming response was not bodyless"
  match c.tryStreamData 1 "x".toUTF8 with
  | .error _ => pure ()
  | _ => fail "HEAD response accepted DATA"

  let c ← openRequest
  let (c, _) ← ok "trailer rejection stream" (c.beginResponseStream 1 { status := 200 })
  match c.endResponseStream 1 #[{ name := "Content-Length", value := "3".toUTF8 }] with
  | .error _ => pure ()
  | .ok _ => fail "forbidden trailer committed"

  let config : Connection.Config := { maxResponseBodyBytes := 4, maxQueuedResponseBytes := 4 }
  let settings ← wire ⟨4, 0, 0, ByteArray.empty⟩
  let (_, block) ← match HPACK.encode HPACK.Context.new requestHeaders with
    | .ok result => pure result
    | .error message => fail s!"request HPACK encode: {message}"
  let (limited, _, _) ← ok "limited request setup"
    ((Connection.newWithConfig config).feed ((preface.append settings).append (← wire ⟨1, 5, 1, block⟩)))
  let (limited, _) ← ok "limited stream head" (limited.beginResponseStream 1 { status := 200 })
  match limited.tryStreamData 1 "hello".toUTF8 with
  | .error _ => pure ()
  | .ok _ => fail "streaming response exceeded configured body limit"

  let input := ((preface.append settings).append (← wire ⟨1, 5, 1, block⟩))
  let initial := Machine.State.new { trackOutput := true }
  let received := initial.feedSlice input 0 input.size
  check (received.state.canRespond 1) "machine did not expose complete request"
  let begun ← ok "machine begin stream" (received.state.beginResponseStream 1 { status := 200 })
  check (begun.actions.any (fun action => match action with
    | .writeObserved output => output.status == 200
    | _ => false)) "machine did not observe streaming HEADERS"
  let some (used, dataStep) ← ok "machine stream DATA" (begun.state.tryStreamData 1 "abc".toUTF8) |
    fail "machine DATA unexpectedly backpressured"
  check (used == 3 && dataStep.actions.any (fun action => match action with
    | .writeObserved output => output.payloadRanges == #[(9, 3)]
    | _ => false)) "machine did not observe streamed DATA payload"
  let ended ← ok "machine end stream" (dataStep.state.endResponseStream 1)
  check (!ended.state.canRespond 1 && ended.actions.any (fun action => match action with
    | .writeObserved output => output.finalResponse
    | _ => false)) "machine did not observe streaming END_STREAM"

  IO.println "gateway HTTP/2 streaming tests passed"
