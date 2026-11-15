import LeanNet.HTTP1.Machine
import LeanNet.HTTP2.Machine

/- Deterministic, bounded property fuzzing. All protocol inputs stay pure; IO
   only supplies the seed, progress/repro records and explicit work limits. -/
open LeanNet

private def check (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

private def random (rng : IO.Ref UInt64) (bound : Nat) : IO Nat := do
  let next := (← rng.get) * 6364136223846793005 + 1442695040888963407
  rng.set next
  return if bound == 0 then 0 else next.toNat % bound

private def randomBytes (rng : IO.Ref UInt64) (length : Nat) : IO ByteArray := do
  let mut output := ByteArray.emptyWithCapacity length
  for _ in [:length] do output := output.push (UInt8.ofNat (← random rng 256))
  return output

private def hex (bytes : ByteArray) : String := Id.run do
  let mut output := ""
  for byte in bytes do
    for n in [byte.toNat / 16, byte.toNat % 16] do
      output := output.push (Char.ofNat (if n < 10 then 48 + n else 87 + n))
  return output

private def mutate (rng : IO.Ref UInt64) (input : ByteArray) (maximum : Nat) : IO ByteArray := do
  let mut bytes := input
  for _ in [:1 + (← random rng 8)] do
    match ← random rng 4 with
    | 0 =>
      if !bytes.isEmpty then
        let index ← random rng bytes.size
        bytes := bytes.set! index (UInt8.ofNat (← random rng 256))
    | 1 => bytes := bytes.extract 0 (← random rng (bytes.size + 1))
    | 2 =>
      if bytes.size < maximum then
        let index ← random rng (bytes.size + 1)
        bytes := (bytes.extract 0 index).push (UInt8.ofNat (← random rng 256)) ++ bytes.extract index bytes.size
    | _ =>
      if bytes.size < maximum then bytes := bytes ++ (← randomBytes rng (min (maximum - bytes.size) (← random rng 16)))
  return bytes

private def fragments (rng : IO.Ref UInt64) (bytes : ByteArray) : IO (Array ByteArray) := do
  let mut result := #[ByteArray.empty]
  let mut position := 0
  for _ in [:bytes.size + 1] do
    if position == bytes.size then break
    let length := min (bytes.size - position) (1 + (← random rng 31))
    result := result.push (bytes.extract position (position + length))
    position := position + length
  check (position == bytes.size) "fragment generator exhausted its work bound"
  return result.push ByteArray.empty

private def fingerprint (request : HTTP1.Request) : ByteArray := Id.run do
  let mut bytes := (request.method ++ " " ++ request.version ++ " ").toUTF8 ++ request.target
  for field in request.headers ++ request.trailers do
    bytes := bytes ++ ("\n" ++ field.name ++ ":" ++ toString field.value.size ++ ":").toUTF8 ++ field.value
  return bytes ++ ("\nBODY:" ++ toString request.body.size ++ ":").toUTF8 ++ request.body

private def h1Limits : HTTP1.Limits := {
  maxHeaderBytes := 512, maxHeaderCount := 8, maxBodyBytes := 256,
  maxTrailerBytes := 128, maxTrailerCount := 4, maxBodyWireBytes := 1024, maxChunkLineBytes := 64 }

private structure ParseCapture where
  parser : HTTP1.Parser := HTTP1.Parser.new h1Limits
  heads : Nat := 0
  consumed : Nat := 0
  request : Option ByteArray := none
  failed : Bool := false

private def parseH1 (parts : Array ByteArray) : IO ParseCapture := do
  let mut state : ParseCapture := {}
  for part in parts do
    if state.failed || state.request.isSome then break
    let wrapped := ByteArray.mk #[254] ++ part ++ ByteArray.mk #[253]
    let mut cursor := 0
    for _ in [:part.size + 4] do
      if state.failed || state.request.isSome then break
      match state.parser.feedSlice wrapped (cursor + 1) (part.size - cursor) with
      | .error _ used =>
        check (used <= part.size - cursor) "HTTP1 parser error consumed outside input slice"
        state := { state with failed := true, consumed := state.consumed + used }
      | .needMore parser used =>
        check (used == part.size - cursor) "HTTP1 parser needMore lost input bytes"
        state := { state with parser, consumed := state.consumed + used }
        cursor := part.size
        break
      | .head _ framing parser used =>
        check (used <= part.size - cursor && state.heads == 0) "HTTP1 parser head boundary/uniqueness"
        match parser.feedSlice wrapped (cursor + used + 1) (part.size - cursor - used) with
        | .error _ 0 => pure ()
        | _ => throw (IO.userError "HTTP1 parser accepted body before head decision")
        match parser.resumeBody framing with
        | .error error => throw (IO.userError error)
        | .ok parser => state := { state with parser, heads := 1, consumed := state.consumed + used }
        cursor := cursor + used
      | .complete request used =>
        check (used <= part.size - cursor && request.body.size <= h1Limits.maxBodyBytes) "HTTP1 parser completion bound"
        state := { state with request := some (fingerprint request), consumed := state.consumed + used }
    check (state.failed || state.request.isSome || cursor == part.size) "HTTP1 parser exhausted step budget"
  if !state.failed && state.request.isNone then
    match state.parser.finish with
    | .complete request _ => state := { state with request := some (fingerprint request) }
    | .error _ => state := { state with failed := true }
    | _ => pure ()
  return state

private structure H1Capture where
  state : HTTP1.Machine.State := HTTP1.Machine.State.new { limits := h1Limits }
  requests : Array ByteArray := #[]
  output : ByteArray := ByteArray.empty
  lastHead : Nat := 0
  lastRequest : Nat := 0
  lastOutput : Nat := 0
  closed : Nat := 0

private def h1Actions (initial : H1Capture) (actions : List HTTP1.Machine.Action) : IO H1Capture := do
  let mut capture := initial
  let mut pending := actions
  for _ in [:256] do
    let action :: rest := pending | break
    pending := rest
    match action with
    | .inspectHead id _ _ =>
      check (id > capture.lastHead) "HTTP1 duplicate/out-of-order head id"
      let next := capture.state.decideHead id (.accept none)
      capture := { capture with state := next.state, lastHead := id }
      pending := pending ++ next.actions
    | .request id request =>
      check (id == capture.lastHead && id > capture.lastRequest) "HTTP1 request order/decision barrier"
      check (request.body.size <= h1Limits.maxBodyBytes) "HTTP1 machine body exceeds cap"
      let next := capture.state.respond id { response := { body := request.body } }
      capture := { capture with
        state := next.state, lastRequest := id
        requests := capture.requests.push (fingerprint request) }
      pending := pending ++ next.actions
    | .write id parts _ =>
      check (id > capture.lastOutput) "HTTP1 output id reused"
      let output := parts.foldl ByteArray.append capture.output
      check (output.size <= 65536) "HTTP1 output exceeded harness bound"
      let next := capture.state.outputAccepted id
      capture := { capture with state := next.state, lastOutput := id, output }
      pending := pending ++ next.actions
    | .writeObserved .. => throw (IO.userError "output tracking unexpectedly enabled in default HTTP1 fixture")
    | .writeFile .. => throw (IO.userError "HTTP1 generated file output without a file reply")
    | .drainClose | .abort _ => capture := { capture with closed := capture.closed + 1 }
    | .readEnabled _ => pure ()
    | .upgraded _ => throw (IO.userError "HTTP1 unsolicited upgrade")
  check pending.isEmpty "HTTP1 action fuel exhausted"
  check (capture.closed <= 1 && capture.requests.size <= 64) "HTTP1 close/request bounds"
  return capture

private def machineH1 (parts : Array ByteArray) : IO H1Capture := do
  let mut capture : H1Capture := {}
  for part in parts do
    let wrapped := ByteArray.mk #[254] ++ part ++ ByteArray.mk #[253]
    let mut cursor := 0
    let mut stopped := false
    for _ in [:part.size * 2 + 16] do
      if capture.state.isClosing then stopped := true; break
      let next := capture.state.feedSlice wrapped (cursor + 1) (part.size - cursor)
      check (next.consumed <= part.size - cursor) "HTTP1 machine slice conservation"
      cursor := cursor + next.consumed
      capture ← h1Actions { capture with state := next.state } next.actions
      if next.consumed == 0 && next.actions.isEmpty then
        check (cursor == part.size) "HTTP1 machine stalled with available input"
        stopped := true
        break
    check stopped "HTTP1 machine input fuel exhausted"
  let next := capture.state.finish
  capture ← h1Actions { capture with state := next.state } next.actions
  return capture

private def frameWire (frame : HTTP2.Frame) : IO ByteArray := do
  match frame.encode 16384 with
  | .ok bytes => return bytes
  | .error error => throw (IO.userError error.message)

private def frameParse (parts : Array ByteArray) : IO (Bool × Option ByteArray × Nat) := do
  let mut parser := HTTP2.FrameParser.new 16384
  let mut consumed := 0
  for part in parts do
    let wrapped := ByteArray.mk #[254] ++ part ++ ByteArray.mk #[253]
    match parser.feedSlice wrapped 1 part.size with
    | .needMore next used =>
      check (used == part.size) "HTTP2 frame needMore byte conservation"
      parser := next
      consumed := consumed + used
    | .error _ used =>
      check (used <= part.size) "HTTP2 frame error consumed outside slice"
      return (true, none, consumed + used)
    | .complete frame used =>
      check (used <= part.size && frame.payload.size <= 16384) "HTTP2 frame completion bound"
      let identity := ByteArray.mk #[frame.kind, frame.flags] ++ (toString frame.streamId.toNat ++ ":").toUTF8 ++ frame.payload
      return (false, some identity, consumed + used)
  return (match parser.finish with | .error _ => true | .ok _ => false, none, consumed)

private def h2Config : HTTP2.Connection.Config := {
  maxConcurrentStreams := 8, maxHeaderListBytes := 2048, maxHeaderFields := 16,
  maxHeaderBlockBytes := 2048, maxContinuationFrames := 8, maxRequestBodyBytes := 256,
  maxBufferedRequestBytes := 1024, maxResponseBodyBytes := 256, maxQueuedResponseBytes := 2048,
  maxOutputBatchBytes := 32768, maxRequestBatch := 8, maxFramesPerStep := 64,
  maxDataPerDrain := 16384, maxResetHistory := 16, maxPushes := 0 }

private structure H2Capture where
  state : HTTP2.Machine.State := HTTP2.Machine.State.new h2Config
  requests : Array ByteArray := #[]
  ids : Array UInt32 := #[]
  output : ByteArray := ByteArray.empty
  closed : Nat := 0

private def h2Actions (initial : H2Capture) (actions : List HTTP2.Machine.Action) : IO H2Capture := do
  let mut capture := initial
  let mut pending := actions
  for _ in [:128] do
    let action :: rest := pending | break
    pending := rest
    match action with
    | .request event =>
      check (!capture.ids.contains event.streamId && event.request.body.size <= 256) "HTTP2 request uniqueness/body bound"
      capture := { capture with
        ids := capture.ids.push event.streamId
        requests := capture.requests.push (fingerprint event.request) }
      if capture.state.canRespond event.streamId then
        let next := capture.state.respond event.streamId { response := { body := event.request.target } }
        capture := { capture with state := next.state }
        pending := pending ++ next.actions
    | .write parts =>
      let output := parts.foldl ByteArray.append capture.output
      check (output.size <= 131072) "HTTP2 output exceeds harness bound"
      capture := { capture with output }
    | .writeObserved .. | .requestStarted .. | .responseAborted .. |
      .writeTunnel .. | .tunnelData .. | .tunnelReset .. | .headReady .. =>
      throw (IO.userError "unexpected tracking, tunnel or admission action in default HTTP2 fixture")
    | .writePing .. => throw (IO.userError "keepalive unexpectedly enabled in default HTTP2 fixture")
    | .writeParts _ => throw (IO.userError "HTTP2 file output without a file reply")
    | .drainClose => capture := { capture with closed := capture.closed + 1 }
  check (pending.isEmpty && capture.closed <= 1 && capture.ids.size <= 8) "HTTP2 action/request fuel bound"
  return capture

private def machineH2 (parts : Array ByteArray) : IO H2Capture := do
  let mut capture : H2Capture := {}
  for part in parts do
    let wrapped := ByteArray.mk #[254] ++ part ++ ByteArray.mk #[253]
    let mut cursor := 0
    let mut stopped := false
    for _ in [:part.size * 2 + 16] do
      if !capture.state.wantsInput then stopped := true; break
      let next := capture.state.feedSlice wrapped (cursor + 1) (part.size - cursor)
      check (next.consumed <= part.size - cursor) "HTTP2 machine slice conservation"
      cursor := cursor + next.consumed
      capture ← h2Actions { capture with state := next.state } next.actions
      for _ in [:16] do
        if !capture.state.canDrain then break
        let drained := capture.state.drain
        capture ← h2Actions { capture with state := drained.state } drained.actions
      if next.consumed == 0 && next.actions.isEmpty then
        check (cursor == part.size) "HTTP2 machine stalled with available input"
        stopped := true
        break
    check stopped "HTTP2 machine input fuel exhausted"
  let next := capture.state.finish
  capture ← h2Actions { capture with state := next.state } next.actions
  check (!capture.state.hasPendingOutput) "HTTP2 left generated output undrained"
  return capture

private def dataBodies (output : ByteArray) : IO (ByteArray × ByteArray) := do
  let mut cursor := 0
  let mut a := ByteArray.empty
  let mut b := ByteArray.empty
  for _ in [:output.size + 1] do
    if cursor == output.size then break
    match (HTTP2.FrameParser.new 16384).feedSlice output cursor (output.size - cursor) with
    | .complete frame used =>
      check (used > 0) "HTTP2 generated zero-length frame consumption"
      cursor := cursor + used
      if frame.kind == 0 then
        if frame.streamId == 1 then a := a ++ frame.payload
        else if frame.streamId == 3 then b := b ++ frame.payload
        else throw (IO.userError "HTTP2 response DATA for unrequested stream")
    | _ => throw (IO.userError "HTTP2 generated invalid/truncated frame")
  check (cursor == output.size) "HTTP2 output frame conservation"
  return (a, b)

private def hpackCheck (rng : IO.Ref UInt64) (raw : ByteArray) : IO ByteArray := do
  let limits : HTTP2.HPACK.Limits := {
    maxTableBytes := 512, maxEncodedBytes := 2048
    maxStringBytes := 256, maxHeaderListBytes := 2048, maxHeaderFields := 16 }
  let value ← randomBytes rng (← random rng 64)
  let fields : Array HTTP2.HPACK.Header := #[
    { name := "x-fuzz".toUTF8, value },
    { name := "authorization".toUTF8, value := value, sensitive := true }]
  let mut encoder := HTTP2.HPACK.Context.new limits
  let mut decoder := HTTP2.HPACK.Context.new limits
  let mut block := ByteArray.empty
  for _ in [:3] do
    match HTTP2.HPACK.encode encoder fields with
    | .error error => throw (IO.userError error)
    | .ok (nextEncoder, encoded) =>
      block := encoded
      match HTTP2.HPACK.decode decoder encoded with
      | .error error => throw (IO.userError error)
      | .ok (nextDecoder, decoded) =>
        check (decoded.size == fields.size && nextDecoder.dynamicBytes == nextEncoder.dynamicBytes) "HPACK state/table conservation"
        for i in [:fields.size] do
          check (decoded[i]!.name == fields[i]!.name && decoded[i]!.value == fields[i]!.value &&
            decoded[i]!.sensitive == fields[i]!.sensitive) "HPACK field roundtrip"
        encoder := nextEncoder
        decoder := nextDecoder
  match HTTP2.HPACK.huffmanDecode (HTTP2.HPACK.huffmanEncode value) 256 with
  | .ok decoded => check (decoded == value) "Huffman binary roundtrip"
  | .error error => throw (IO.userError error)
  let mutated ← mutate rng block 2048
  for sample in [raw, mutated] do
    match HTTP2.HPACK.decode (HTTP2.HPACK.Context.new limits) sample with
    | .error _ => pure ()
    | .ok (context, headers) =>
      check (context.dynamicBytes <= 512 && headers.size <= 16 &&
        headers.foldl (fun size header => size + header.name.size + header.value.size + 32) 0 <= 2048) "HPACK accepted resource limit violation"
    if let .ok decoded := HTTP2.HPACK.huffmanDecode sample 256 then
      check (decoded.size <= 256) "Huffman output cap"
    for prefixBits in [1:9] do
      if let .ok (_, used) := HTTP2.HPACK.decodeInteger sample 0 prefixBits then
        check (used > 0 && used <= sample.size) "HPACK integer byte conservation"
  return mutated

private def adversarial : IO Unit := do
  for input in [
    "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 9999999999999999999999999999\r\n\r\n",
    "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffffffffffffffffffff\r\nx\r\n",
    "GET / HTTP/1.1\r\nHost: x\r\nX: " ++ String.ofList (List.replicate 513 'a') ++ "\r\n\r\n"] do
    let parsed ← parseH1 #[input.toUTF8]
    check parsed.failed "HTTP1 adversarial budget/framing input accepted"
    discard <| machineH1 #[input.toUTF8]
  let oversized := ByteArray.mk #[255,255,255,250,0,0,0,0,0]
  let parsed ← frameParse #[oversized]
  check (parsed.1 && parsed.2.2 == 9) "HTTP2 oversized frame was not rejected at header boundary"
  let limits : HTTP2.HPACK.Limits := {
    maxEncodedBytes := 32, maxStringBytes := 16
    maxHeaderListBytes := 64, maxHeaderFields := 2 }
  let longInteger := ByteArray.mk (Array.replicate 32 255)
  check (match HTTP2.HPACK.decodeInteger longInteger 0 7 with | .error _ => true | _ => false)
    "HPACK overlong integer accepted"
  check (match HTTP2.HPACK.decode (HTTP2.HPACK.Context.new limits) (ByteArray.mk (Array.replicate 33 130)) with
    | .error _ => true | _ => false) "HPACK encoded-block cap bypassed"

private def runCase (seed : UInt64) (maximum : Nat) : IO Unit := do
  let rng ← IO.mkRef seed
  let body ← randomBytes rng (← random rng 129)
  let chunked ← random rng 2
  let request := if chunked == 0 then
    ("POST /fuzz HTTP/1.1\r\nHost: example.test\r\nContent-Length: " ++ toString body.size ++ "\r\n\r\n").toUTF8 ++ body
    else "POST /fuzz HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n".toUTF8 ++
      (if body.isEmpty then ByteArray.empty else (hex (ByteArray.mk #[UInt8.ofNat body.size]) ++ "\r\n").toUTF8 ++ body ++ "\r\n".toUTF8) ++ "0\r\nX-End: yes\r\n\r\n".toUTF8
  let h1 := request ++ "GET /next HTTP/1.1\r\nHost: example.test\r\n\r\n".toUTF8
  let fields : Array HTTP2.HPACK.Header := #[
    { name := ":method".toUTF8, value := "GET".toUTF8 },
    { name := ":scheme".toUTF8, value := "http".toUTF8 },
    { name := ":authority".toUTF8, value := "example.test".toUTF8 },
    { name := ":path".toUTF8, value := "/fuzz".toUTF8 }]
  let .ok (_, block) := HTTP2.HPACK.encode HTTP2.HPACK.Context.new fields | throw (IO.userError "fuzz HPACK setup")
  let h2 := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toUTF8 ++ (← frameWire ⟨4, 0, 0, ByteArray.empty⟩) ++
    (← frameWire ⟨1, 5, 1, block⟩) ++ (← frameWire ⟨1, 5, 3, block⟩)
  let raw ← randomBytes rng (← random rng (maximum + 1))
  let badH1 ← mutate rng h1 maximum
  let badH2 ← if (← random rng 2) == 0 then mutate rng h2 maximum
    else do
      let prefixSize := 33
      pure (h2.extract 0 prefixSize ++ (← mutate rng (h2.extract prefixSize h2.size) maximum))
  try
    let parsed ← parseH1 #[h1]
    let split ← parseH1 (← fragments rng h1)
    check (!parsed.failed && parsed.request.isSome && parsed.request == split.request && parsed.consumed == split.consumed)
      "valid HTTP1 parser fragmentation changed semantics/consumed boundary"
    let full ← machineH1 #[h1]
    let split ← machineH1 (← fragments rng h1)
    check (full.requests.size == 2 && full.requests == split.requests && full.output == split.output) "valid HTTP1 machine fragmentation changed requests/output"
    for sample in [raw, badH1] do
      let a ← parseH1 #[sample]
      let b ← parseH1 (← fragments rng sample)
      check (a.failed == b.failed && a.request == b.request) "HTTP1 parser mutation fragmentation mismatch"
      let full ← machineH1 #[sample]
      let split ← machineH1 (← fragments rng sample)
      check (full.requests == split.requests && full.output == split.output) "HTTP1 mutated machine fragmentation mismatch"
    let frame ← frameWire ⟨250, UInt8.ofNat (← random rng 256), UInt32.ofNat (← random rng 100000), body⟩
    let a ← frameParse #[frame]
    let b ← frameParse (← fragments rng frame)
    check (a == b && a.2.1.isSome && a.2.2 == frame.size) "HTTP2 frame roundtrip/fragmentation conservation"
    for sample in [raw, ← mutate rng frame maximum] do
      let a ← frameParse #[sample]
      let b ← frameParse (← fragments rng sample)
      check (a.1 == b.1 && a.2.1 == b.2.1) "HTTP2 frame mutation fragmentation mismatch"
    let full ← machineH2 #[h2]
    let split ← machineH2 (← fragments rng h2)
    check (full.ids == #[1, 3] && full.ids == split.ids && full.requests == split.requests) "HTTP2 machine request fragmentation mismatch"
    check ((← dataBodies full.output) == ("/fuzz".toUTF8, "/fuzz".toUTF8) &&
      (← dataBodies full.output) == (← dataBodies split.output)) "HTTP2 DATA conservation across fragmentation"
    for sample in [raw, badH2] do discard <| machineH2 (← fragments rng sample)
    discard <| hpackCheck rng raw
  catch error =>
    IO.eprintln s!"FUZZ_REPRO seed={seed.toNat} maximum={maximum} h1_hex={hex h1} h2_hex={hex h2} raw_hex={hex raw} mutated_h1_hex={hex badH1} mutated_h2_hex={hex badH2}"
    throw error

def main (args : List String) : IO UInt32 := do
  let seed := ((args[0]?).bind String.toNat?).getD 20261114
  let cases := ((args[1]?).bind String.toNat?).getD 1000
  let maximum := ((args[2]?).bind String.toNat?).getD 2048
  if seed > 18446744073709551615 || cases == 0 || cases > 1000000 || maximum < 256 || maximum > 16384 then
    throw (IO.userError "usage: ProtocolFuzz.lean [seedUInt64] [cases1..1000000] [maxBytes256..16384]")
  IO.println s!"FUZZ_START seed={seed} cases={cases} max_input_bytes={maximum} phase=adversarial"
  (← IO.getStdout).flush
  adversarial
  for index in [:cases] do
    let caseSeed := UInt64.ofNat seed + UInt64.ofNat index * 11400714819323198485
    IO.println s!"FUZZ_CASE index={index} seed={caseSeed.toNat}"
    (← IO.getStdout).flush
    try runCase caseSeed maximum
    catch error =>
      IO.eprintln s!"FUZZ_FAILURE base_seed={seed} case={index} case_seed={caseSeed.toNat}: {error}"
      return 1
  IO.println s!"FUZZ_OK seed={seed} cases={cases} max_input_bytes={maximum} families=http1-parser,http1-machine,http2-frame,hpack,http2-machine"
  return 0
