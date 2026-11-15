import LeanNet.HTTP1.Machine
import LeanNet.HTTP2.Machine

open LeanNet

private def check (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

private def byteParts (parts : Array WirePart) : ByteArray :=
  parts.foldl (fun out part => match part with | .bytes bytes => out ++ bytes | .file _ => out) ByteArray.empty

private def h1Output (step : HTTP1.Machine.Step) : IO (Nat × HTTP.ObservedOutput × Bool) := do
  match step.actions.filterMap (fun | .writeObserved id output wait => some (id, output, wait) | _ => none) with
  | [output] => return output
  | _ => throw (IO.userError "expected one observed HTTP1 output")

private def requestId (step : HTTP1.Machine.Step) : IO Nat := do
  match step.actions.filterMap (fun | .inspectHead id _ _ => some id | _ => none) with
  | [id] => return id
  | _ => throw (IO.userError "expected one HTTP1 head decision")

private def h1Ready (method : String := "GET") (track : Bool := true) : IO HTTP1.Machine.State := do
  let head := (method ++ " /resource HTTP/1.1\r\nHost: example.test\r\n\r\n").toUTF8
  let parsed := ((HTTP1.Machine.State.new { trackOutput := track }).setTime 42).feed head
  let id ← requestId parsed
  let accepted := parsed.state.decideHead id (.accept none)
  let complete := accepted.state.feed ByteArray.empty
  check (complete.actions.any (fun | .request actual _ => actual == id | _ => false)) "bodyless request completion"
  return complete.state

private def overlapConservation (output : HTTP.ObservedOutput) : IO Unit := do
  check output.valid "generated payload ranges are invalid"
  let mut cursor := 0
  let mut credited := 0
  for _ in [:output.wireBytes / 7 + 1] do
    let count := min 7 (output.wireBytes - cursor)
    credited := credited + output.payloadOverlap cursor count
    cursor := cursor + count
  check (cursor == output.wireBytes && credited == output.payloadBytes) "physical partial-ACK payload conservation"
  check (output.payloadOverlap output.wireBytes 100 == 0) "credit escaped ticket end"

private def h1Tracking : IO Unit := do
  let head := "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n".toUTF8
  let initial := ((HTTP1.Machine.State.new { trackOutput := true }).setTime 11).feed (head.extract 0 10)
  let inspected := (initial.state.setTime 99).feed (head.extract 10 head.size)
  check (inspected.state.startedAt == 11) "first-byte timestamp restarted across fragments"
  let id ← requestId inspected
  let accepted := inspected.state.decideHead id (.accept none)
  let (continueId, interim, wait) ← h1Output accepted
  check (continueId == 1 && interim.requestId == 1 && interim.status == 100 && !interim.finalResponse && wait &&
    interim.payloadBytes == 0 && interim.startedAt == 11 && interim.head.any (fun h => h.target == "/upload".toUTF8)) "Continue observation metadata"
  let body := ByteArray.mk #[0,255,65]
  let paused := accepted.state.feed body
  check (paused.consumed == 0 && paused.actions.isEmpty) "tracking bypassed Continue write barrier"
  let ack := accepted.state.outputAccepted continueId
  let complete := ack.state.feed body
  let reply : HTTP1.Reply := {
    response := { body }
    informational := #[({ status := 103, headers := #[{ name := "Link", value := "</asset>".toUTF8 }] }, {})]
    options := { framing := some .chunked, trailers := #[{ name := "X-End", value := "yes".toUTF8 }] } }
  let response := complete.state.respond id reply
  let (outputId, output, wait) ← h1Output response
  check (outputId == 2 && output.requestId == id && output.finalResponse && output.status == 200 && !wait && output.payloadBytes == 3) "H1 outputId differs from requestId after informational output"
  let wire := byteParts output.parts
  let ranges := output.payloadRanges.toList
  match ranges with
  | [(start, length)] =>
    check (wire.extract start (start + length) == body && wire.extract (start - 3) start == "3\r\n".toUTF8 &&
      wire.extract (start + length) wire.size == "\r\n0\r\nX-End: yes\r\n\r\n".toUTF8) "chunked framing/trailers counted as body"
  | _ => throw (IO.userError "expected one encoded H1 body chunk")
  overlapConservation output
  check (wire.extract 0 12 == "HTTP/1.1 103".toUTF8) "informational ordering changed"

  let source : FileRegion := { owner := 17, token := 19, offset := 13, length := 100000 }
  let selected := (← h1Ready).respond 1 { response := {}, fileRegion := some source }
  let (_, file, _) ← h1Output selected
  check (file.payloadBytes == source.length && file.parts.size == 2 && file.finalResponse && file.status == 200) "file observation length/parts"
  match file.parts[1]? with
  | some (WirePart.file actual) => check (actual == source) "file identity changed in observation"
  | _ => throw (IO.userError "missing H1 file region")
  overlapConservation file
  let selected := (← h1Ready "HEAD").respond 1 { response := {}, fileRegion := some source }
  let (_, headOnly, _) ← h1Output selected
  check (headOnly.payloadBytes == 0 && headOnly.parts.size == 1 && headOnly.finalResponse) "HEAD counted unsent file bytes"
  let malformed := ((HTTP1.Machine.State.new { trackOutput := true }).setTime 7).feed "BAD\r\n\r\n".toUTF8
  let (_, failure, _) ← h1Output malformed
  check (failure.head.isNone && failure.status == 400 && failure.finalResponse && failure.payloadBytes == 0) "malformed request output metadata"
  let fallback := (← h1Ready).respond 1 { response := { status := 204, body := "forbidden".toUTF8 } }
  let (_, failure, _) ← h1Output fallback
  check (failure.status == 500 && failure.payloadBytes == 0) "fallback reported unvalidated application status/body"
  let legacy := (← h1Ready "GET" false).respond 1 { response := { body := body } }
  check (legacy.actions.any (fun | .write .. => true | _ => false) && !legacy.actions.any (fun | .writeObserved .. => true | _ => false)) "default H1 action shape changed"

  let upgradedHead := "GET /resource HTTP/1.1\r\nHost: example.test\r\nConnection: upgrade\r\nUpgrade: raw-test\r\n\r\n".toUTF8
  let inspected := (HTTP1.Machine.State.new { trackOutput := true }).feed upgradedHead
  let upgrade := inspected.state.decideHead 1 (.upgrade { response := {
    status := 101
    headers := #[{ name := "Upgrade", value := "raw-test".toUTF8 }] } })
  let (_, switch, wait) ← h1Output upgrade
  check (switch.finalResponse && switch.status == 101 && switch.payloadBytes == 0 && wait) "upgrade observation completion fence"

private def h2Wire (frame : HTTP2.Frame) : IO ByteArray := do
  match frame.encode 16777215 with
  | .ok wire => return wire
  | .error error => throw (IO.userError error.message)

private def h2Request (id : UInt32) (ended : Bool := true) : IO ByteArray := do
  let fields : Array HTTP2.HPACK.Header := #[
    { name := ":method".toUTF8, value := (if ended then "GET" else "POST").toUTF8 },
    { name := ":scheme".toUTF8, value := "http".toUTF8 },
    { name := ":authority".toUTF8, value := "example.test".toUTF8 },
    { name := ":path".toUTF8, value := "/resource".toUTF8 }]
  let fields := if ended then fields else fields.push { name := "content-length".toUTF8, value := "3".toUTF8 }
  let .ok (_, block) := HTTP2.HPACK.encode HTTP2.HPACK.Context.new fields | throw (IO.userError "test HPACK encoding")
  h2Wire ⟨1, if ended then 5 else 4, id, block⟩

private def h2Boot (track : Bool := true) : IO HTTP2.Machine.State := do
  let input := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toUTF8 ++ (← h2Wire ⟨4,0,0,ByteArray.empty⟩)
  let step := ((HTTP2.Machine.State.new { trackOutput := track }).setTime 42).feedSlice input 0 input.size
  check (step.consumed == input.size && step.state.wantsInput) "HTTP2 observation setup"
  return step.state

private def outputs (step : HTTP2.Machine.Step) : List HTTP.ObservedOutput :=
  step.actions.filterMap (fun | .writeObserved output => some output | _ => none)

private def h2Bytes (step : HTTP2.Machine.Step) : ByteArray :=
  step.actions.foldl (fun bytes action => match action with
    | .write parts => parts.foldl ByteArray.append bytes
    | .writeParts parts => bytes ++ byteParts parts
    | .writeObserved output => bytes ++ byteParts output.parts
    | _ => bytes) ByteArray.empty

private def h2Tracking : IO Unit := do
  let wire ← h2Request 1
  let parsed := (← h2Boot).feedSlice wire 0 wire.size
  check (parsed.actions.any (fun | .requestStarted 1 head 42 => head.target == "/resource".toUTF8 | _ => false)) "H2 header-start metadata"
  check (parsed.actions.any (fun | .request event => event.startedAt == 42 | _ => false)) "H2 delivery start time"
  let body := ByteArray.mk (Array.replicate 20000 65)
  let selected := parsed.state.respond 1 { response := { body } }
  match outputs selected with
  | [header] => check (header.status == 200 && !header.finalResponse && header.payloadBytes == 0 &&
      header.head.isSome && header.startedAt == 42) "response header observation"
  | _ => throw (IO.userError "expected one H2 initial header block")
  let drained := selected.state.drain
  match outputs drained with
  | [first, last] =>
    check (first.payloadRanges == #[(9,16384)] && first.payloadBytes == 16384 && !first.finalResponse &&
      last.payloadRanges == #[(9,3616)] && last.payloadBytes == 3616 && last.finalResponse && first.status == 0 && last.status == 0) "DATA frame/payload completion boundaries"
    overlapConservation first
    overlapConservation last
  | _ => throw (IO.userError "expected two bounded DATA observations")
  let legacy := (← h2Boot false).feedSlice wire 0 wire.size
  let legacySelected := legacy.state.respond 1 { response := { body } }
  let legacyDrained := legacySelected.state.drain
  check ((outputs legacySelected).isEmpty && (outputs legacyDrained).isEmpty &&
    h2Bytes selected == h2Bytes legacySelected && h2Bytes drained == h2Bytes legacyDrained) "tracking changed default HTTP2 wire bytes/coalescing"

  let region : FileRegion := { owner := 7, token := 11, offset := 17, length := 20000 }
  let selected := parsed.state.respond 1 { response := {}, fileRegion := some region }
  let drained := selected.state.drain
  let mut offset := region.offset.toNat
  for output in outputs drained do
    check (output.valid && output.parts.size == 2 && output.payloadRanges == #[(9,output.payloadBytes)]) "file frame ticket/range"
    match output.parts[0]?, output.parts[1]? with
    | some (WirePart.bytes header), some (WirePart.file file) =>
      check (header.size == 9 && file.owner == region.owner && file.token == region.token &&
        file.offset.toNat == offset && file.length == output.payloadBytes) "file DATA/header pair or cursor changed"
      offset := offset + file.length
    | _, _ => throw (IO.userError "file DATA was not an atomic header+region ticket")
    overlapConservation output
  check (offset == 20017) "file payload conservation"

  let selected := parsed.state.respond 1 {
    response := { body := "abc".toUTF8 }
    options := { trailers := #[{ name := "X-End", value := "yes".toUTF8 }] } }
  match outputs selected.state.drain with
  | [data, trailer] => check (!data.finalResponse && data.payloadBytes == 3 && trailer.finalResponse &&
      trailer.payloadBytes == 0 && trailer.status == 0) "trailer ACK is the final response boundary"
  | _ => throw (IO.userError "expected DATA followed by final trailers")

  let selected := parsed.state.respond 1 { response := {} }
  match outputs selected with
  | [header] => check (header.finalResponse && header.status == 200) "empty response final header"
  | _ => throw (IO.userError "missing empty response observation")
  let reset ← h2Wire ⟨3,0,1,ByteArray.mk #[0,0,0,8]⟩
  let canceled := selected.state.feedSlice reset 0 reset.size
  check (canceled.actions.any (fun | .responseAborted 1 .cancelled => true | _ => false)) "valid RST of pure-closed stream did not cancel pending physical ticket"
  let fallback := parsed.state.respond 1 { response := { status := 999 } }
  match outputs fallback with
  | [header] => check (header.status == 500 && header.finalResponse) "H2 fallback status observation"
  | _ => throw (IO.userError "missing H2 fallback observation")

  let uploadWire ← h2Request 1 false
  let started := (← h2Boot).feedSlice uploadWire 0 uploadWire.size
  check (started.actions.any (fun | .requestStarted 1 _ 42 => true | _ => false) &&
    !started.actions.any (fun | .request _ => true | _ => false)) "partial upload was not counted before body completion"
  let reset := started.state.feedSlice reset 0 reset.size
  check (reset.actions.any (fun | .responseAborted 1 .cancelled => true | _ => false)) "partial upload cancellation"
  let timedOut := started.state.tick 2042 1000
  check (timedOut.actions.any (fun | .responseAborted 1 .timeout => true | _ => false)) "request timeout observation"
  let finished := started.state.finish
  check (finished.actions.any (fun | .responseAborted 1 .cancelled => true | _ => false)) "EOF cancellation observation"

  let longValue := ByteArray.mk (Array.replicate 40000 120)
  let selected := parsed.state.respond 1 { response := { headers := #[{ name := "X-Long", value := longValue }] } }
  match outputs selected with
  | [header] =>
    let bytes := byteParts header.parts
    check (header.finalResponse && header.status == 200 && header.payloadBytes == 0 && bytes.size > 16384 &&
      bytes[3]! == 1 && (bytes[4]! &&& 4) == 0) "CONTINUATION block split the final physical ticket"
    let next := bytes[0]!.toNat * 65536 + bytes[1]!.toNat * 256 + bytes[2]!.toNat + 9
    check (bytes[next + 3]! == 9) "large header test did not contain CONTINUATION"
  | _ => throw (IO.userError "expected one complete observed header block")

  let together := uploadWire ++ (← h2Wire ⟨3,0,1,ByteArray.mk #[0,0,0,8]⟩)
  let canceled := (← h2Boot).feedSlice together 0 together.size
  let order := canceled.actions.filterMap (fun
    | .requestStarted 1 _ _ => some 0
    | .responseAborted 1 .cancelled => some 1
    | _ => none)
  check (order == [0,1] && !canceled.actions.any (fun | .request _ => true | _ => false)) "same-batch partial request was not started then canceled"

private def ranges : IO Unit := do
  let output : HTTP.ObservedOutput := { requestId := 1, parts := #[.bytes (ByteArray.mk (Array.replicate 40 0))], payloadRanges := #[(10,5),(20,3)] }
  check (output.valid && output.payloadOverlap 12 10 == 5 && output.payloadOverlap 0 40 == 8) "disjoint future chunk ranges"
  check (!{ output with payloadRanges := #[(10,5),(14,3)] }.valid) "overlapping ranges accepted"
  check (!{ output with payloadRanges := #[(39,2)] }.valid) "out-of-ticket range accepted"

def main : IO Unit := do
  ranges
  h1Tracking
  h2Tracking
  IO.println "Pure wire observations, partial-ACK payload credit, metadata and cancellation tests passed"
