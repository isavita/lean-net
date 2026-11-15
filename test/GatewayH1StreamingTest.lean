import LeanNet.HTTP1.Machine

open LeanNet.HTTP1

private def check (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

private def fail (message : String) : IO α := throw (IO.userError message)

private def flatten (parts : Array ByteArray) : ByteArray :=
  parts.foldl ByteArray.append ByteArray.empty

private def contains (bytes fragment : ByteArray) : Bool := Id.run do
  for i in [:bytes.size + 1] do
    if i + fragment.size <= bytes.size && bytes.extract i (i + fragment.size) == fragment then
      return true
  return false

private def write (step : Machine.Step) : IO (Nat × ByteArray) := do
  let [result] := step.actions.filterMap (fun
    | .write id parts _ => some (id, flatten parts)
    | _ => none) | fail "expected one streamed output"
  return result

private def observed (step : Machine.Step) : IO (Nat × LeanNet.HTTP.ObservedOutput) := do
  let [result] := step.actions.filterMap (fun
    | .writeObserved id output _ => some (id, output)
    | _ => none) | fail "expected one observed streamed output"
  return result

private def application (version : String := "HTTP/1.1")
    (config : Machine.Config := {}) : IO (Nat × Machine.State) := do
  let wire := s!"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toUTF8
  let wire := if version == "HTTP/1.0" then
    s!"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n".toUTF8 else wire
  let head := (Machine.State.new config).feed wire
  let [id] := head.actions.filterMap (fun | .inspectHead id _ _ => some id | _ => none) |
    fail "expected request head"
  let accepted := head.state.decideHead id (.accept none)
  let complete := accepted.state.feed ByteArray.empty
  check (complete.actions.any (fun | .request actual _ => actual == id | _ => false))
    "expected complete request"
  return (id, complete.state)

private def knownLength : IO Unit := do
  let (id, state) ← application
  let began := state.beginStream id { status := 200, headers := #[{ name := "x-source", value := "upstream".toUTF8 }] } (some 3)
  let (headId, head) ← write began
  check (contains head "Content-Length: 3\r\n".toUTF8 &&
    !contains head "Transfer-Encoding:".toUTF8) "known-length head framing"
  check ((began.state.feed "GET /next HTTP/1.1\r\n\r\n".toUTF8).consumed == 0)
    "stream head did not pause next request"
  let ready := began.state.outputAccepted headId
  let body := ready.state.streamChunk id "abc".toUTF8
  let (bodyId, bytes) ← write body
  check (bytes == "abc".toUTF8) "known-length body was copied into framing"
  let ready := body.state.outputAccepted bodyId
  let ended := ready.state.endStream id
  check (ended.actions.any (fun | .streamFinished actual => actual == id | _ => false))
    "known-length stream lacked final marker"
  check (ended.actions.any (fun | .readEnabled true => true | _ => false))
    "known-length stream did not resume keepalive"
  let next := ended.state.feed "GET /next HTTP/1.1\r\nHost: example.com\r\n\r\n".toUTF8
  check (next.actions.any (fun | .inspectHead actual _ _ => actual == id + 1 | _ => false))
    "next request did not get a fresh identifier"

  let (id, state) ← application
  let began := state.beginStream id { status := 200 } (some 2)
  let (headId, _) ← write began
  let ready := began.state.outputAccepted headId
  let exceeded := ready.state.streamChunk id "abc".toUTF8
  check (exceeded.actions.any (fun | .abort _ => true | _ => false))
    "Content-Length overrun was sent"
  let short := ready.state.streamChunk id "a".toUTF8
  let (bodyId, _) ← write short
  let ready := short.state.outputAccepted bodyId
  let ended := ready.state.endStream id
  check (ended.actions.any (fun | .abort _ => true | _ => false))
    "truncated Content-Length returned to keepalive"

private def chunkedAndTrailers : IO Unit := do
  let (id, state) ← application
  check state.streamSupportsTrailers "HTTP/1.1 request did not support stream trailers"
  let began := state.beginStream id { status := 200 } none #["x-check"]
  let (headId, head) ← write began
  check (contains head "Transfer-Encoding: chunked\r\n".toUTF8 &&
    contains head "Trailer: x-check\r\n".toUTF8) "streamed head lacked chunked declaration"
  let ready := began.state.outputAccepted headId
  let chunk := ready.state.streamChunk id "hello".toUTF8
  let (chunkId, wire) ← write chunk
  check (wire == "5\r\nhello\r\n".toUTF8) "chunk framing mismatch"
  let ready := chunk.state.outputAccepted chunkId
  let endStep := ready.state.endStream id #[{ name := "x-check", value := "yes".toUTF8 }]
  let (endId, terminal) ← write endStep
  check (terminal == "0\r\nx-check: yes\r\n\r\n".toUTF8) "terminal trailer framing mismatch"
  let next := endStep.state.outputAccepted endId
  check (next.state.isIdle) "chunked stream did not resume idle keepalive"

  let (id, state) ← application
  let began := state.beginStream id { status := 200 }
  let (headId, _) ← write began
  let ready := began.state.outputAccepted headId
  let empty := ready.state.streamChunk id ByteArray.empty
  check (empty.actions.any (fun | .abort _ => true | _ => false))
    "empty chunk could terminate response"
  let tooLarge := ready.state.streamChunk id (ByteArray.mk (Array.replicate 65537 65))
  check (tooLarge.actions.any (fun | .abort _ => true | _ => false))
    "oversized chunk was accepted"
  let undeclared := ready.state.endStream id #[{ name := "x-secret", value := "x".toUTF8 }]
  check (undeclared.actions.any (fun | .abort _ => true | _ => false))
    "undeclared trailer crossed stream boundary"

private def legacyAndObservation : IO Unit := do
  let (id, state) ← application "HTTP/1.0"
  check (!state.streamSupportsTrailers) "HTTP/1.0 request claimed trailer support"
  let began := state.beginStream id { status := 200 }
  let (headId, head) ← write began
  check (!contains head "Transfer-Encoding:".toUTF8 &&
    !contains head "Content-Length:".toUTF8 &&
    contains head "Connection: close\r\n".toUTF8) "HTTP/1.0 stream framing"
  let ready := began.state.outputAccepted headId
  let chunk := ready.state.streamChunk id "abc".toUTF8
  let (chunkId, bytes) ← write chunk
  check (bytes == "abc".toUTF8) "close-delimited body framing"
  let ready := chunk.state.outputAccepted chunkId
  let ended := ready.state.endStream id
  check (ended.state.isClosing && ended.actions.any (fun | .drainClose => true | _ => false) &&
    ended.actions.any (fun | .streamFinished _ => true | _ => false))
    "HTTP/1.0 stream did not drain-close"

  let (id, state) ← application "HTTP/1.1" { trackOutput := true }
  let began := state.beginStream id { status := 200 }
  let (headId, headObservation) ← observed began
  check (headObservation.status == 200 && !headObservation.finalResponse &&
    headObservation.payloadRanges.isEmpty) "stream head observation"
  let ready := began.state.outputAccepted headId
  let chunk := ready.state.streamChunk id "abc".toUTF8
  let (chunkId, chunkObservation) ← observed chunk
  check (chunkObservation.payloadRanges == #[(3, 3)] &&
    chunkObservation.payloadBytes == 3 && !chunkObservation.finalResponse)
    "stream chunk payload accounting"
  let ready := chunk.state.outputAccepted chunkId
  let ended := ready.state.endStream id
  let (endId, endObservation) ← observed ended
  check (endObservation.finalResponse && endObservation.payloadBytes == 0)
    "terminal chunk was not marked final"
  let _ := ended.state.outputAccepted endId

def main : IO Unit := do
  knownLength
  chunkedAndTrailers
  legacyAndObservation
  IO.println "gateway HTTP/1 streaming tests passed"
