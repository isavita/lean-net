import LeanNet.HTTP2.Connection

open LeanNet.HTTP2

set_option maxRecDepth 4096

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do throw (IO.userError message)
private def ok (label : String) (result : Except ProtocolError α) : IO α := do
  match result with
  | .ok value => return value
  | .error error => throw (IO.userError s!"{label}: {repr error}")
private def hpackOk (result : Except String α) : IO α := do
  match result with
  | .ok value => return value
  | .error error => throw (IO.userError s!"HPACK: {error}")
private def wire (f : Frame) : IO ByteArray := ok "encode frame" (f.encode 16777215)
private def frames (data : ByteArray) : IO (Array Frame) := do
  let mut data := data
  let mut out := #[]
  for _ in [0:data.size + 1] do
    if data.isEmpty then break
    match (FrameParser.new 16777215).feed data with
    | .complete frame rest => out := out.push frame; data := rest
    | .error error _ => throw (IO.userError s!"bad output frame: {repr error}")
    | .needMore _ => throw (IO.userError "truncated output frame")
  return out
private def read32 (p : ByteArray) : Nat :=
  (p[0]!).toNat * 16777216 + (p[1]!).toNat * 65536 + (p[2]!).toNat * 256 + (p[3]!).toNat
private def b32 (n : Nat) : ByteArray := ByteArray.mk #[UInt8.ofNat (n / 16777216), UInt8.ofNat (n / 65536), UInt8.ofNat (n / 256), UInt8.ofNat n]
private def preface : ByteArray := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toUTF8
private def baseHeaders : Array HPACK.Header := #[
  { name := ":method".toUTF8, value := "GET".toUTF8 },
  { name := ":scheme".toUTF8, value := "http".toUTF8 },
  { name := ":authority".toUTF8, value := "localhost".toUTF8 },
  { name := ":path".toUTF8, value := "/".toUTF8 }]
private def settings0 : Frame := ⟨4, 0, 0, ByteArray.empty⟩
private def connect : IO Connection := do
  let input := preface.append (← wire settings0)
  let (connection, output, events) ← ok "handshake" (Connection.new.feed input)
  let result ← frames output
  check (events.isEmpty && result.size == 1 && result[0]!.kind == 4 && result[0]!.flags == 1) "SETTINGS acknowledgement"
  return connection
private def feed (c : Connection) (frame : Frame) : IO (Connection × ByteArray × Array RequestEvent) := do
  ok "feed frame" (c.feed (← wire frame))
private def expectError (label : String) (result : Except ProtocolError α) (code : ErrorCode) : IO Unit := do
  match result with
  | .ok _ => throw (IO.userError s!"{label}: expected error")
  | .error error => check (error.scope == .connection && error.code == code) s!"{label}: wrong error {repr error}"

def main : IO Unit := do
  let initial ← frames Connection.initialSettings
  check (initial.size == 1 && initial[0]!.kind == 4 && initial[0]!.flags == 0) "initial SETTINGS"
  let (_, requestBlock) ← hpackOk (HPACK.encode HPACK.Context.new baseHeaders)
  let headers ← wire ⟨1, 5, 1, requestBlock⟩
  let input := (preface.append (← wire settings0)).append headers
  for split in [0:input.size + 1] do
    let (first, output1, requests1) ← ok "split first" (Connection.new.feed (input.extract 0 split))
    let (_, output2, requests2) ← ok "split second" (first.feed (input.extract split input.size))
    let requests := requests1 ++ requests2
    check (requests.size == 1) s!"split {split}: request count"
    let some event := requests[0]? | throw (IO.userError "missing request")
    check (event.streamId == 1 && event.request.method == "GET" && event.request.target == "/".toUTF8) "request conversion"
    let out ← frames (output1.append output2)
    check (out.size == 1 && out[0]!.kind == 4 && out[0]!.flags == 1) "split SETTINGS output"
  let invalid := ByteArray.mk #[0]
  expectError "bad preface" (Connection.new.feed invalid) .protocolError
  let earlyPing := preface.append (← wire ⟨6, 0, 0, ByteArray.mk #[0,0,0,0,0,0,0,0]⟩)
  expectError "first frame not SETTINGS" (Connection.new.feed earlyPing) .protocolError
  let c ← connect
  let (c, _, request) ← feed c ⟨1, 5, 1, requestBlock⟩
  check (request.size == 1) "complete request"
  let (c, responseWire) ← ok "respond" (c.respond 1 { body := "hello".toUTF8 })
  let output ← frames responseWire
  check (output.size == 2 && output[0]!.kind == 1 && output[1]!.kind == 0 && output[1]!.flags == 1 && output[1]!.payload == "hello".toUTF8) "response frames"
  check (!c.hasPendingOutput) "completed response left pending"

  let (secretConn, _, _) ← feed (← connect) ⟨1, 5, 1, requestBlock⟩
  let (_, secretWire) ← ok "sensitive response" (secretConn.respond 1 {
    headers := #[{ name := "Set-Cookie", value := "session=secret".toUTF8 }] })
  let secretFrames ← frames secretWire
  let (_, secretFields) ← hpackOk (HPACK.decode HPACK.Context.new secretFrames[0]!.payload)
  check (secretFields.any (fun h => h.name == "set-cookie".toUTF8 && h.sensitive)) "cookie was not marked never-indexed"

  let (negativeConn, _, _) ← feed (← connect) ⟨1, 5, 1, requestBlock⟩
  let (negativeConn, initialNegativeWire) ← ok "queue response before settings reduction"
    (negativeConn.respond 1 { body := ByteArray.mk (Array.replicate 70000 (65 : UInt8)) })
  let (negativeConn, settingAck, _) ← feed negativeConn ⟨4, 0, 0, ByteArray.mk #[0,4,0,0,0,0]⟩
  check (!negativeConn.canDrain && (← frames settingAck).size == 1) "negative SETTINGS window must stop DATA"
  let sent := (← frames initialNegativeWire).foldl (fun n frame => n + if frame.kind == 0 then frame.payload.size else 0) 0
  let (negativeConn, _, _) ← feed negativeConn ⟨8, 0, 0, b32 1⟩
  let (_, resumedWire, _) ← feed negativeConn ⟨8, 0, 1, b32 (sent + 1)⟩
  let resumed ← frames resumedWire
  check (resumed.size == 1 && resumed[0]!.kind == 0 && resumed[0]!.payload.size == 1) "negative SETTINGS window did not recover correctly"

  let canceledInput := (← wire ⟨1, 5, 1, requestBlock⟩).append (← wire ⟨3, 0, 1, b32 8⟩)
  let (canceled, _, canceledEvents) ← ok "same-read cancellation" ((← connect).feed canceledInput)
  check (canceledEvents.isEmpty && !canceled.canRespond 1) "canceled request must not be dispatched"

  let post := baseHeaders.set! 0 { name := ":method".toUTF8, value := "POST".toUTF8 }
  let expectHeaders := post.push { name := "expect".toUTF8, value := "100-continue".toUTF8 }
  let (_, expectBlock) ← hpackOk (HPACK.encode HPACK.Context.new expectHeaders)
  let (expectConn, interimWire, interimEvents) ← feed (← connect) ⟨1, 4, 1, expectBlock⟩
  let interim ← frames interimWire
  check (interimEvents.isEmpty && interim.size == 1 && interim[0]!.kind == 1 && interim[0]!.flags == 4) "missing 100-continue HEADERS"
  let (responseDecoder, interimFields) ← hpackOk (HPACK.decode HPACK.Context.new interim[0]!.payload)
  check (interimFields.any (fun h => h.name == ":status".toUTF8 && h.value == "100".toUTF8)) "wrong interim status"
  let (expectConn, _, bodyEvents) ← feed expectConn ⟨0, 1, 1, "data".toUTF8⟩
  check (bodyEvents.size == 1) "expected body did not complete"
  let (_, finalWire) ← ok "response after 100" (expectConn.respond 1 { body := "ok".toUTF8 })
  let finalFrames ← frames finalWire
  let (_, finalFields) ← hpackOk (HPACK.decode responseDecoder finalFrames[0]!.payload)
  check (finalFields.any (fun h => h.name == ":status".toUTF8 && h.value == "200".toUTF8)) "HPACK state after 100"
  let (_, badExpectBlock) ← hpackOk (HPACK.encode HPACK.Context.new (post.push { name := "expect".toUTF8, value := "unsupported".toUTF8 }))
  let date := "Sun, 06 Nov 1994 08:49:37 GMT".toUTF8
  let (afterReject, rejectedWire, rejectedEvents) ← feed ((← connect).setDate date) ⟨1, 4, 1, badExpectBlock⟩
  let rejectedFrames ← frames rejectedWire
  check (rejectedEvents.isEmpty && rejectedFrames.size == 2 && rejectedFrames[0]!.kind == 1 && rejectedFrames[0]!.flags == 5 && rejectedFrames[1]!.kind == 3 && read32 rejectedFrames[1]!.payload == 0 && !afterReject.canRespond 1) "unsupported expectation must send 417 and NO_ERROR reset"
  let (_, rejectedFields) ← hpackOk (HPACK.decode HPACK.Context.new rejectedFrames[0]!.payload)
  check (rejectedFields.any (fun h => h.name == ":status".toUTF8 && h.value == "417".toUTF8) && rejectedFields.any (fun h => h.name == "date".toUTF8 && h.value == date)) "417 status or Date missing"
  let (_, noBodyWire, _) ← feed (← connect) ⟨1, 5, 1, badExpectBlock⟩
  let noBodyFrames ← frames noBodyWire
  check (noBodyFrames.size == 1 && noBodyFrames[0]!.kind == 1 && noBodyFrames[0]!.flags == 5) "bodyless 417 should not reset closed stream"

  let zeroSetting : Frame := ⟨4, 0, 0, ByteArray.mk #[0,4,0,0,0,0]⟩
  let (c, _, _) ← feed (← connect) zeroSetting
  let (c, _, _) ← feed c ⟨1, 5, 1, requestBlock⟩
  let (c, out) ← ok "zero window response" (c.respond 1 { body := "hello".toUTF8 })
  check ((← frames out).size == 1 && c.hasPendingOutput && !c.canDrain) "zero window must pause DATA"
  let (c, out, _) ← feed c ⟨8, 0, 1, b32 3⟩
  let firstData ← frames out
  check (firstData.size == 1 && firstData[0]!.payload == "hel".toUTF8 && firstData[0]!.flags == 0) "partial window DATA"
  let (c, out, _) ← feed c ⟨8, 0, 1, b32 2⟩
  let finalData ← frames out
  check (finalData.size == 1 && finalData[0]!.payload == "lo".toUTF8 && finalData[0]!.flags == 1 && !c.hasPendingOutput) "final window DATA"

  let (c, _, partialEvents) ← feed (← connect) ⟨1, 1, 1, requestBlock.extract 0 1⟩
  check partialEvents.isEmpty "fragmented header completed early"
  let (_, _, completeEvents) ← feed c ⟨9, 4, 1, requestBlock.extract 1 requestBlock.size⟩
  check (completeEvents.size == 1) "CONTINUATION did not complete request"

  -- Exhaust connection credit with stream 1, queue stream 3, then open one
  -- byte of credit at a time: round-robin must not starve the later stream.
  let (_, incrementalBlock) ← hpackOk (HPACK.encode HPACK.Context.new (baseHeaders.push { name := "priority".toUTF8, value := "i".toUTF8 }))
  let (c, _, _) ← feed (← connect) ⟨1, 5, 1, incrementalBlock⟩
  let (c, _) ← ok "queue large response" (c.respond 1 { body := ByteArray.mk (Array.replicate 131070 (65 : UInt8)) })
  let mut fairConn := c
  for _ in [0:4] do
    if fairConn.canDrain then
      let (next, _) ← ok "exhaust connection window" fairConn.drain
      fairConn := next
  let (_, incrementalBlock2) ← hpackOk (HPACK.encode HPACK.Context.new (baseHeaders.push { name := "priority".toUTF8, value := "i".toUTF8 }))
  let (next, _, _) ← feed fairConn ⟨1, 5, 3, incrementalBlock2⟩
  let (next, _) ← ok "queue second response" (next.respond 3 { body := "xy".toUTF8 })
  let (next, _, _) ← feed next ⟨8, 0, 1, b32 1⟩
  let (next, out, _) ← feed next ⟨8, 0, 0, b32 1⟩
  let first ← frames out
  check (first.size == 1 && first[0]!.streamId == 3 && first[0]!.payload == "x".toUTF8) "round robin did not serve later stream"
  let (_, out, _) ← feed next ⟨8, 0, 0, b32 1⟩
  let second ← frames out
  check (second.size == 1 && second[0]!.streamId == 1) "round robin did not return to first stream"

  let (c, _, _) ← feed (← connect) ⟨1, 0, 1, requestBlock.extract 0 1⟩
  check c.hasPartialInput "open CONTINUATION must count as partial"
  let ping ← wire ⟨6, 0, 0, ByteArray.mk #[0,0,0,0,0,0,0,0]⟩
  expectError "interleaved header block" (c.feed ping) .protocolError
  let (c, _, _) ← feed (← connect) ⟨1, 5, 3, requestBlock⟩
  let evenReset ← wire ⟨3, 0, 2, b32 0⟩
  expectError "even idle RST" (c.feed evenReset) .protocolError
  let evenWindow ← wire ⟨8, 0, 2, b32 1⟩
  expectError "even idle WINDOW_UPDATE" (c.feed evenWindow) .protocolError

  let (many, _, _) ← ok "bounded handshake" ((Connection.newWithConfig { maxConcurrentStreams := 32 }).feed (preface.append (← wire settings0)))
  let mut many := many
  let mut batchEncoder := HPACK.Context.new
  for index in [0:32] do
    let (nextEncoder, block) ← hpackOk (HPACK.encode batchEncoder baseHeaders)
    batchEncoder := nextEncoder
    let (next, _, events) ← feed many ⟨1, 5, UInt32.ofNat (2 * index + 1), block⟩
    check (events.size == 1) "valid concurrent request rejected"
    many := next
  let (nextEncoder, refusedBlock) ← hpackOk (HPACK.encode batchEncoder baseHeaders)
  let (next, rejectedWire, rejectedEvents) ← feed many ⟨1, 5, 65, refusedBlock⟩
  let refused ← frames rejectedWire
  check (rejectedEvents.isEmpty && refused.size == 1 && refused[0]!.kind == 3 && read32 refused[0]!.payload == 7) "excess stream was not refused"
  let (next, _) ← ok "release stream slot" (next.respond 1 {})
  let (_, acceptedBlock) ← hpackOk (HPACK.encode nextEncoder baseHeaders)
  let (_, _, acceptedEvents) ← feed next ⟨1, 5, 67, acceptedBlock⟩
  check (acceptedEvents.size == 1) "refused stream desynchronized HPACK or leaked a slot"

  let badHeaders := baseHeaders.filter (fun h => h.name != ":path".toUTF8)
  let (encoder, badBlock) ← hpackOk (HPACK.encode HPACK.Context.new badHeaders)
  let (c, out, events) ← feed (← connect) ⟨1, 5, 1, badBlock⟩
  let resets ← frames out
  check (events.isEmpty && resets.size == 1 && resets[0]!.kind == 3 && read32 resets[0]!.payload == 1) "invalid request must reset stream"
  let (encoder, lateBlock) ← hpackOk (HPACK.encode encoder #[{ name := "x-late".toUTF8, value := "yes".toUTF8 }])
  let (c, out, events) ← feed c ⟨1, 4, 1, lateBlock⟩
  check (out.isEmpty && events.isEmpty) "late reset HEADERS should be decoded and discarded"
  let (c, out, _) ← feed c ⟨0, 0, 1, "abc".toUTF8⟩
  let updates ← frames out
  check updates.isEmpty "tiny discarded DATA must retain connection credit until the update threshold"
  let (_, nextBlock) ← hpackOk (HPACK.encode encoder (baseHeaders.push { name := "x-late".toUTF8, value := "yes".toUTF8 }))
  let (_, _, events) ← feed c ⟨1, 5, 3, nextBlock⟩
  check (events.size == 1) "late header block desynchronized HPACK"

  let (c, _, _) ← feed ((← connect).setTime 100) ⟨1, 4, 1, requestBlock⟩
  let (_, out) ← ok "stream timeout" (c.expireRequests 200 100)
  let resets ← frames out
  check (resets.size == 1 && resets[0]!.kind == 3 && read32 resets[0]!.payload == 8) "request timeout must reset stream"
  let mut fragmented ← connect
  let (_, byteHead) ← hpackOk (HPACK.encode HPACK.Context.new (post.push { name := "content-length".toUTF8, value := "1000".toUTF8 }))
  let (fragNext, _, _) ← feed fragmented ⟨1, 4, 1, byteHead⟩
  fragmented := fragNext
  let mut gotBody := false
  for i in [0:1000] do
    let (next, _, events) ← feed fragmented ⟨0, if i == 999 then 1 else 0, 1, ByteArray.mk #[UInt8.ofNat (i % 256)]⟩
    fragmented := next
    if i == 999 then
      let some event := events[0]? | throw (IO.userError "missing fragmented request")
      check (event.request.body.size == 1000 && event.request.body[999]!.toNat == 231) "fragmented body incorrect"
      gotBody := true
    else check events.isEmpty "fragmented body completed early"
  check gotBody "fragmented body incomplete"

  let (incomplete, _, _) ← feed (← connect) ⟨1, 1, 1, requestBlock.extract 0 1⟩
  let mut flood := incomplete
  for _ in [0:1023] do
    let (next, _, _) ← feed flood ⟨9, 0, 1, ByteArray.empty⟩
    flood := next
  let continuation ← wire ⟨9, 0, 1, ByteArray.empty⟩
  expectError "continuation flood" (flood.feed continuation) .enhanceYourCalm
  IO.println "HTTP/2 connection tests passed"
