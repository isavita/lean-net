import LeanNet.HTTP1.Machine

open LeanNet.HTTP1

private instance : Inhabited Request := ⟨{
  method := "GET", target := ByteArray.empty, headers := #[], body := ByteArray.empty }⟩

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do throw (IO.userError message)

private def field (name value : String) : Header := { name, value := value.toUTF8 }
private def flatten (parts : Array ByteArray) : ByteArray := parts.foldl ByteArray.append ByteArray.empty
private def wireStarts (bytes : ByteArray) (text : String) : Bool :=
  bytes.extract 0 text.toUTF8.size == text.toUTF8
private def contains (bytes : ByteArray) (text : String) : Bool := Id.run do
  let needle := text.toUTF8
  for start in [:bytes.size + 1] do
    if start + needle.size <= bytes.size && bytes.extract start (start + needle.size) == needle then return true
  return false
private def noRequest (step : Machine.Step) : Bool :=
  !step.actions.any (fun | .request .. => true | _ => false)
private def enabled (step : Machine.Step) (wanted : Bool) : Bool :=
  step.actions.any (fun | .readEnabled value => value == wanted | _ => false)
private def drains (step : Machine.Step) : Bool :=
  step.actions.any (fun | .drainClose => true | _ => false)
private def aborts (step : Machine.Step) : Bool :=
  step.actions.any (fun | .abort _ => true | _ => false)
private def oneHead (step : Machine.Step) : IO (Nat × RequestHead × BodyFraming) := do
  match step.actions.filterMap (fun | .inspectHead id head framing => some (id, head, framing) | _ => none) with
  | [head] => return head
  | _ => throw (IO.userError "expected exactly one head decision")
private def oneRequest (step : Machine.Step) : IO (Nat × Request) := do
  match step.actions.filterMap (fun | .request id request => some (id, request) | _ => none) with
  | [request] => return request
  | _ => throw (IO.userError "expected exactly one application request")
private def oneWrite (step : Machine.Step) : IO (Nat × Array ByteArray × Bool) := do
  match step.actions.filterMap (fun | .write id parts barrier => some (id, parts, barrier) | _ => none) with
  | [write] => return write
  | _ => throw (IO.userError "expected exactly one output action")
private def bodyless (wire : ByteArray) (state : Machine.State := Machine.State.new) : IO (Nat × Request × Machine.State) := do
  let head := state.feed wire
  let (id, _, framing) ← oneHead head
  check (framing == .none && head.consumed == wire.size) "bodyless head boundary"
  let accepted := head.state.decideHead id (.accept none)
  check (enabled accepted true) "bodyless accept enables progress"
  let complete := accepted.state.feed ByteArray.empty
  let (actual, request) ← oneRequest complete
  check (actual == id && complete.consumed == 0 && request.body.isEmpty) "bodyless completion consumes no next request"
  return (id, request, complete.state)

private structure Capture where
  state : Machine.State := Machine.State.new
  requests : Array (Nat × Request) := #[]
  writes : Array (Nat × ByteArray × Bool) := #[]
  heads : Nat := 0
  closed : Bool := false

/-- Test adapter: application decisions and output completion are explicit.
    Bounded action work prevents a broken machine from spinning this harness. -/
private def applyActions (capture : Capture) (actions : List Machine.Action) : IO Capture := do
  let mut capture := capture
  let mut pending := actions
  for _ in [:128] do
    match pending with
    | [] => break
    | action :: rest =>
      pending := rest
      match action with
      | .inspectHead id _ _ =>
        capture := { capture with heads := capture.heads + 1 }
        let next := capture.state.decideHead id (.accept none)
        capture := { capture with state := next.state }
        pending := pending ++ next.actions
      | .request id request =>
        capture := { capture with requests := capture.requests.push (id, request) }
        let reply : Reply := { response := { body := request.body } }
        let next := capture.state.respond id reply
        capture := { capture with state := next.state }
        pending := pending ++ next.actions
      | .write id parts barrier =>
        capture := { capture with writes := capture.writes.push (id, flatten parts, barrier) }
        let next := capture.state.outputAccepted id
        capture := { capture with state := next.state }
        pending := pending ++ next.actions
      | .readEnabled _ => pure ()
      | .drainClose => capture := { capture with closed := true }
      | .abort reason => throw (IO.userError s!"unexpected machine abort: {reason}")
      | .upgraded _ => throw (IO.userError "unexpected automatic upgrade")
  check pending.isEmpty "machine action fuel exhausted"
  return capture

private def runFragments (fragments : Array ByteArray) : IO Capture := do
  let mut capture : Capture := {}
  for fragment in fragments do
    let wrapped := (ByteArray.mk #[254]).append (fragment.append (ByteArray.mk #[253]))
    let mut position := 0
    let mut stopped := false
    for _ in [:fragment.size * 2 + 16] do
      check (!capture.closed) "persistent test closed before end of input"
      let next := capture.state.feedSlice wrapped (position + 1) (fragment.size - position)
      check (next.consumed <= fragment.size - position) "consumed exceeded caller window"
      position := position + next.consumed
      capture ← applyActions { capture with state := next.state } next.actions
      if next.consumed == 0 && next.actions.isEmpty then
        stopped := true
        break
    check (stopped && position == fragment.size) "fragment processing stalled or exceeded fuel"
  let finished := capture.state.finish
  capture ← applyActions { capture with state := finished.state } finished.actions
  check (capture.closed && capture.state.isClosing) "EOF drains an idle persistent connection"
  return capture

private def fragmentedIntegration : IO Unit := do
  let binary := ByteArray.mk #[0, 255, 13, 10, 65]
  let first := "POST /fixed HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n".toUTF8.append binary
  let second := (("POST /chunk HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n".toUTF8.append (binary.extract 0 2)).append "\r\n3\r\n".toUTF8).append ((binary.extract 2 5).append "\r\n0\r\nX-Check: yes\r\n\r\n".toUTF8)
  let last := "HEAD /last HTTP/1.1\r\nHost: x\r\n\r\n".toUTF8
  let bytes := (first.append second).append last
  let expectedBody := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n".toUTF8.append binary
  for split in [:bytes.size + 1] do
    let result ← runFragments #[bytes.extract 0 split, bytes.extract split bytes.size]
    check (result.heads == 3 && result.requests.size == 3 && result.writes.size == 4) "fragmented head/request/output counts"
    for i in [:3] do check (result.requests[i]!.1 == i + 1) "request identifiers preserve pipeline order"
    check (result.requests[0]!.2.target == "/fixed".toUTF8 && result.requests[0]!.2.body == binary) "fragmented fixed body"
    check (result.requests[1]!.2.target == "/chunk".toUTF8 && result.requests[1]!.2.body == binary) "fragmented chunked body"
    check (result.requests[1]!.2.trailers.size == 1 && result.requests[1]!.2.trailers[0]!.name == "x-check" && result.requests[1]!.2.trailers[0]!.value == "yes".toUTF8) "trailers stay distinct from headers"
    check (result.requests[2]!.2.method == "HEAD" && result.requests[2]!.2.body.isEmpty) "fragmented HEAD request"
    check (result.writes[0]!.2.1 == "HTTP/1.1 100 Continue\r\n\r\n".toUTF8 && result.writes[0]!.2.2) "100 output barrier in fragmented integration"
    check (result.writes[1]!.2.1 == expectedBody && result.writes[2]!.2.1 == expectedBody) "responses remain in request order"
    check (result.writes[3]!.2.1 == "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".toUTF8) "HEAD wire suppression"
    for i in [:4] do check (result.writes[i]!.1 == i + 1) "output IDs increase across interim/final responses"
  let bytewise ← runFragments (bytes.toList.toArray.map (fun byte => ByteArray.mk #[byte]))
  check (bytewise.requests.size == 3 && bytewise.writes.size == 4) "one-byte feeds terminate with complete requests"

private def refusalAndBarriers : IO Unit := do
  let head := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n".toUTF8
  let pipeline := "GET /later HTTP/1.1\r\nHost: x\r\n\r\n".toUTF8
  let input := (head.append "data".toUTF8).append pipeline
  let inspected := (Machine.State.new).feed input
  let (id, requestHead, framing) ← oneHead inspected
  check (id == 1 && framing == .contentLength 4 && requestHead.method == "POST") "expectation head metadata"
  check (inspected.consumed == head.size && enabled inspected false && noRequest inspected) "head pauses before already-supplied body"
  let refused := inspected.state.decideHead id (.reject { response := { status := 417 } })
  let (refusalId, refusalParts, refusalBarrier) ← oneWrite refused
  let refusalWire := flatten refusalParts
  check (wireStarts refusalWire "HTTP/1.1 417 " && !contains refusalWire "100 Continue" && !refusalBarrier) "head refusal emits417 without100"
  let ignored := refused.state.feedSlice input head.size (input.size - head.size)
  check (ignored.consumed == 0 && ignored.actions.isEmpty && noRequest refused) "refused body and pipeline remain unconsumed"
  let closed := refused.state.outputAccepted refusalId
  check (drains closed && closed.state.isClosing) "refusal closes only after output submission"

  let accepted := inspected.state.decideHead id (.accept none)
  let (continueId, continueParts, continueBarrier) ← oneWrite accepted
  check (continueBarrier && flatten continueParts == "HTTP/1.1 100 Continue\r\n\r\n".toUTF8) "100 requires actual WRITTEN acknowledgment"
  let blocked := accepted.state.feedSlice input head.size (input.size - head.size)
  check (blocked.consumed == 0 && blocked.actions.isEmpty && !accepted.state.wantsInput) "body cannot pass100 barrier"
  check (aborts (accepted.state.outputAccepted (continueId + 1))) "wrong output acknowledgment aborts"
  let bodyReady := accepted.state.outputAccepted continueId
  check (bodyReady.state.wantsInput && enabled bodyReady true) "100 completion resumes body"
  let complete := bodyReady.state.feedSlice input head.size (input.size - head.size)
  let (applicationId, request) ← oneRequest complete
  check (complete.consumed == 4 && request.body == "data".toUTF8 && applicationId == id) "body completes before pipeline remainder"
  let final := complete.state.respond id { response := { body := "first".toUTF8 } }
  let (finalId, _, finalBarrier) ← oneWrite final
  check (!finalBarrier && finalId == continueId + 1) "final output uses submitted-FIFO acknowledgment"
  let premature := final.state.feed pipeline
  check (premature.consumed == 0 && premature.actions.isEmpty) "next request waits for final submission"
  let next := final.state.outputAccepted finalId
  check (next.state.isIdle && enabled next true) "submitted final response enables next request before transport drain"
  check (aborts (next.state.outputAccepted finalId)) "duplicate output acknowledgment aborts"
  let second := next.state.feed pipeline
  let (secondId, _, _) ← oneHead second
  check (secondId == id + 1 && second.consumed == pipeline.size) "next request ID follows submitted response"

private def pipelineEOF : IO Unit := do
  let mut input := ByteArray.empty
  for i in [:10] do
    input := input.append (s!"GET /{i} HTTP/1.1\r\nHost: x\r\n\r\n").toUTF8
  let result ← runFragments #[input]
  check (result.requests.size == 10 && result.writes.size == 10 && result.closed) "ten pipelined requests drain before EOF close"
  for i in [:10] do
    check (result.requests[i]!.1 == i + 1 && result.requests[i]!.2.target == (s!"/{i}").toUTF8) "ten-request routing order"
  let (id, _, application) ← bodyless "GET / HTTP/1.1\r\nHost: x\r\n\r\n".toUTF8
  let ended := application.finish
  check (ended.actions.isEmpty && noRequest ended) "EOF remembered while application responds"
  let final := ended.state.respond id { response := {} }
  let (outputId, parts, _) ← oneWrite final
  check (contains (flatten parts) "Connection: close\r\n") "final outstanding reply advertises EOF closure"
  check (drains (final.state.outputAccepted outputId)) "EOF outstanding response drains before close"

private def versionAndEOFPolicies : IO Unit := do
  let pipeline := "GET /next HTTP/1.1\r\nHost: x\r\n\r\n".toUTF8
  let head := "GET / HTTP/1.0\r\n\r\n".toUTF8
  let input := head.append pipeline
  let inspected := (Machine.State.new).feed input
  let (id, requestHead, framing) ← oneHead inspected
  check (requestHead.version == "HTTP/1.0" && framing == .none && inspected.consumed == head.size) "HTTP/1.0 default framing is bodyless"
  let accepted := inspected.state.decideHead id (.accept none)
  let complete := accepted.state.feedSlice input head.size pipeline.size
  let (_, request) ← oneRequest complete
  check (complete.consumed == 0 && request.body.isEmpty) "standard HTTP/1.0 does not absorb request-looking bytes"
  let response := complete.state.respond id { response := { body := "ok".toUTF8 } }
  let (outputId, parts, _) ← oneWrite response
  check (wireStarts (flatten parts) "HTTP/1.0 200 " && contains (flatten parts) "Connection: close\r\n") "HTTP/1.0 default closes"
  let closed := response.state.outputAccepted outputId
  check (drains closed && (closed.state.feed pipeline).consumed == 0) "default HTTP/1.0 does not route pipeline after close"

  let persistent := "GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n".toUTF8
  let (keepId, _, application) ← bodyless persistent
  let kept := application.respond keepId { response := { body := "ok".toUTF8 } }
  let (keepOutput, keepParts, _) ← oneWrite kept
  check (contains (flatten keepParts) "Content-Length: 2\r\nConnection: keep-alive\r\n") "HTTP/1.0 explicit-length persistence"
  let continued := kept.state.outputAccepted keepOutput
  check (continued.state.isIdle && enabled continued true) "HTTP/1.0 persistent connection reopens parsing"
  let next := continued.state.feed pipeline
  let (nextId, _, _) ← oneHead next
  check (nextId == keepId + 1) "HTTP/1.0 persistent next request"

  let legacyHead := "POST /upload HTTP/1.0\r\nConnection: keep-alive\r\n\r\n".toUTF8
  let legacyBody := (ByteArray.mk #[0, 255, 13, 10]).append pipeline
  let legacyInput := legacyHead.append legacyBody
  let paused := (Machine.State.new).feed legacyInput
  let (legacyId, _, _) ← oneHead paused
  let opted := paused.state.decideHead legacyId (.accept (some .closeDelimited))
  check (enabled opted true) "explicit legacy EOF-body decision accepted"
  let buffered := opted.state.feedSlice legacyInput legacyHead.size legacyBody.size
  check (buffered.consumed == legacyBody.size && buffered.actions.isEmpty) "legacy mode consumes request-looking bytes only as content"
  let finished := buffered.state.finish
  let (actualId, legacyRequest) ← oneRequest finished
  check (actualId == legacyId && legacyRequest.body == legacyBody && legacyRequest.version == "HTTP/1.0") "legacy EOF body completes exactly at EOF"
  check ((finished.state.finish).actions.isEmpty) "EOF does not deliver a request twice"
  let legacyReply := finished.state.respond legacyId { response := { body := "ok".toUTF8 } }
  let (legacyOutput, legacyParts, _) ← oneWrite legacyReply
  check (contains (flatten legacyParts) "Connection: close\r\n" && !contains (flatten legacyParts) "Connection: keep-alive") "legacy body forces closure despite request keep-alive"
  check (drains (legacyReply.state.outputAccepted legacyOutput)) "legacy response drains before closure"

  for invalidHead in ["POST / HTTP/1.1\r\nHost: x\r\n\r\n", "POST / HTTP/1.0\r\nContent-Length: 2\r\n\r\n"] do
    let paused := (Machine.State.new).feed invalidHead.toUTF8
    let (invalidId, _, _) ← oneHead paused
    let refused := paused.state.decideHead invalidId (.accept (some .closeDelimited))
    let (_, invalidParts, _) ← oneWrite refused
    check (contains (flatten invalidParts) " 400 " && noRequest refused) "legacy override cannot replace HTTP/1.1 or explicit length framing"

private def malformedEOF : IO Unit := do
  for input in ["GET / HTTP/1.1\r\nHost: x", "GET / HTTP/1.1\r\nHost: x\r", "GET / HTTP/1."] do
    let incomplete := (Machine.State.new).feed input.toUTF8
    check (incomplete.consumed == input.toUTF8.size && incomplete.actions.isEmpty) "incomplete request head waits for input"
    let failure := incomplete.state.finish
    let (outputId, parts, _) ← oneWrite failure
    check (wireStarts (flatten parts) "HTTP/1.1 400 " && noRequest failure) "incomplete head EOF rejects with400"
    check (drains (failure.state.outputAccepted outputId)) "truncated head closes after error submission"
  for (head, body) in [("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n", "da"),
      ("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n", "4\r\nda"),
      ("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n", "0\r\nX: incomplete")] do
    let inspected := (Machine.State.new).feed head.toUTF8
    let (id, _, _) ← oneHead inspected
    let accepted := inspected.state.decideHead id (.accept none)
    let incomplete := accepted.state.feed body.toUTF8
    check (incomplete.consumed == body.toUTF8.size && noRequest incomplete) "incomplete framed body is not delivered"
    let failed := incomplete.state.finish
    let (_, parts, _) ← oneWrite failed
    check (wireStarts (flatten parts) "HTTP/1.1 400 " && noRequest failed) "incomplete framed body EOF rejects"
  let smugglingHead := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n".toUTF8
  let smuggling := (Machine.State.new).feed (smugglingHead.append "0\r\n\r\nGET /next HTTP/1.1\r\nHost: x\r\n\r\n".toUTF8)
  let (_, parts, _) ← oneWrite smuggling
  check (smuggling.consumed <= smugglingHead.size && wireStarts (flatten parts) "HTTP/1.1 400 " && noRequest smuggling) "CL+TE failure cannot route suffix"

private def machineResponses : IO Unit := do
  let get := "GET / HTTP/1.1\r\nHost: x\r\n\r\n".toUTF8
  let (id, _, application) ← bodyless get
  for status in [204, 304] do
    let response := application.respond id { response := { status } }
    let (_, parts, _) ← oneWrite response
    let bytes := flatten parts
    check (!contains bytes "Content-Length" && !contains bytes "Transfer-Encoding" && bytes.extract (bytes.size - 4) bytes.size == "\r\n\r\n".toUTF8) "machine bodyless status emits no body/framing fields"
  let custom := application.respond id { response := { status := 299, body := "x".toUTF8 }, options := { reason := some "Custom Ready" } }
  let (_, customParts, _) ← oneWrite custom
  check (flatten customParts == "HTTP/1.1 299 Custom Ready\r\nContent-Length: 1\r\n\r\nx".toUTF8) "machine custom reason and body"
  let (headId, _, headApplication) ← bodyless "HEAD / HTTP/1.1\r\nHost: x\r\n\r\n".toUTF8
  let head := headApplication.respond headId { response := { body := "representation".toUTF8 } }
  let (_, headParts, _) ← oneWrite head
  check (flatten headParts == "HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\n".toUTF8) "machine HEAD representation length without payload"
  let info := application.respond id { response := { body := "ok".toUTF8 }, informational := #[({ status := 103, headers := #[field "Link" "</style.css>; rel=preload"] }, {})] }
  let (_, infoParts, barrier) ← oneWrite info
  check (!barrier && wireStarts (flatten infoParts) "HTTP/1.1 103 Early Hints\r\n" && contains (flatten infoParts) "HTTP/1.1 200 OK\r\n") "informational reply precedes final without completing request twice"
  for reply in [({ response := {}, informational := #[({ status := 103 }, {}), ({ status := 200 }, {})] } : Reply),
      { response := { status := 100 } },
      { response := {}, informational := #[({ status := 101 }, {})] },
      { response := { headers := #[field "X-Test" "ok\r\nInjected: yes"] } }] do
    let invalid := application.respond id reply
    let (outputId, parts, _) ← oneWrite invalid
    let bytes := flatten parts
    check (wireStarts bytes "HTTP/1.1 500 " && !contains bytes "103 Early Hints" && !contains bytes "Injected") "invalid replies fail atomically with bounded500"
    check (contains bytes "Connection: close\r\n" && drains (invalid.state.outputAccepted outputId)) "invalid application reply closes after500"
  let (limitedId, _, limitedApplication) ← bodyless get (Machine.State.new { maxInformational := 1 })
  let excessive := limitedApplication.respond limitedId { response := {}, informational := #[({ status := 100 }, {}), ({ status := 103 }, {})] }
  let (_, excessiveParts, _) ← oneWrite excessive
  check (wireStarts (flatten excessiveParts) "HTTP/1.1 500 ") "informational response count bound"
  check (aborts (application.respond (id + 1) { response := {} })) "wrong application request ID aborts"

private def upgradeBarrier : IO Unit := do
  let head := "GET /socket HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".toUTF8
  let raw := (ByteArray.mk #[0, 255, 13, 10]).append "GET /raw HTTP/1.1\r\nHost: x\r\n\r\n".toUTF8
  let input := head.append raw
  let inspected := (Machine.State.new).feed input
  let (id, _, framing) ← oneHead inspected
  check (framing == .none && inspected.consumed == head.size) "upgrade head preserves raw tail"
  let reply : Reply := { response := { status := 101, headers := #[field "Upgrade" "websocket"] } }
  let switched := inspected.state.decideHead id (.upgrade reply)
  let (outputId, parts, barrier) ← oneWrite switched
  check (barrier && flatten parts == "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n".toUTF8) "101 upgrade requires WRITTEN barrier"
  let waiting := switched.state.feedSlice input head.size raw.size
  check (waiting.consumed == 0 && waiting.actions.isEmpty) "raw tail cannot pass101 barrier"
  let ready := switched.state.outputAccepted outputId
  match ready.actions with
  | [.upgraded requestHead] => check (requestHead.target == "/socket".toUTF8) "upgraded action carries request metadata"
  | _ => throw (IO.userError "101 completion did not transfer raw protocol ownership")
  check (!ready.state.wantsInput && !ready.state.isClosing) "upgraded state leaves HTTP parsing permanently"
  let untouched := ready.state.feedSlice input head.size raw.size
  check (untouched.consumed == 0 && untouched.actions.isEmpty && input.extract head.size input.size == raw) "raw tail is unconsumed and byte-exact after upgrade"
  let bodyHead := "POST /socket HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 4\r\n\r\n".toUTF8
  let bodyPaused := (Machine.State.new).feed (bodyHead.append "data".toUTF8)
  let (bodyId, _, _) ← oneHead bodyPaused
  let forbidden := bodyPaused.state.decideHead bodyId (.upgrade reply)
  let (_, rejectedParts, rejectedBarrier) ← oneWrite forbidden
  check (!rejectedBarrier && wireStarts (flatten rejectedParts) "HTTP/1.1 400 " && noRequest forbidden) "upgrade cannot bypass unread HTTP request body"

private def recordedEOFDuringDecision : IO Unit := do
  let head := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n".toUTF8
  let paused := (Machine.State.new).feed head
  let (id, _, _) ← oneHead paused
  let continuing := paused.state.decideHead id (.accept none)
  let (continueId, _, _) ← oneWrite continuing
  let eof := continuing.state.finish
  check (eof.actions.isEmpty) "EOF is recorded while100 is outstanding"
  let resumed := eof.state.outputAccepted continueId
  let resumed := if resumed.actions.isEmpty || enabled resumed true then resumed.state.feed ByteArray.empty else resumed
  let (errorId, errorParts, _) ← oneWrite resumed
  check (wireStarts (flatten errorParts) "HTTP/1.1 400 " && noRequest resumed) "recorded EOF truncates body after100 without repeated EOF input"
  check (drains (resumed.state.outputAccepted errorId)) "truncation after100 drains400"

  let eofAtDecision := paused.state.finish
  check (eofAtDecision.actions.isEmpty) "EOF is recorded before head decision"
  let accepted := eofAtDecision.state.decideHead id (.accept none)
  let accepted := if accepted.actions.isEmpty || enabled accepted true then accepted.state.feed ByteArray.empty else accepted
  let (_, parts, barrier) ← oneWrite accepted
  check (!barrier && wireStarts (flatten parts) "HTTP/1.1 400 " && noRequest accepted) "recorded EOF before decision sends400 without pointless100"

  let emptyHead := "GET / HTTP/1.1\r\nHost: x\r\n\r\n".toUTF8
  let emptyPaused := (Machine.State.new).feed emptyHead
  let (emptyId, _, _) ← oneHead emptyPaused
  let emptyEOF := emptyPaused.state.finish
  let acceptedEmpty := emptyEOF.state.decideHead emptyId (.accept none)
  let completedEmpty := if noRequest acceptedEmpty then acceptedEmpty.state.feed ByteArray.empty else acceptedEmpty
  let (actualId, request) ← oneRequest completedEmpty
  check (actualId == emptyId && request.body.isEmpty) "bodyless request survives EOF at head decision"
  let final := completedEmpty.state.respond emptyId { response := {} }
  let (outputId, _, _) ← oneWrite final
  check (drains (final.state.outputAccepted outputId)) "recorded EOF bodyless response closes after output"

private def wrappersAndTimeouts : IO Unit := do
  let date := "Sun, 06 Nov 1994 08:49:37 GMT".toUTF8
  let dated := Machine.step (.date date) Machine.State.new
  check (dated.consumed == 0 && dated.actions.isEmpty && dated.state.isIdle) "pure Date input changes no transport state"
  let get := "GET / HTTP/1.1\r\nHost: x\r\n\r\n".toUTF8
  let inspected := Machine.step (.bytes get 0 get.size) dated.state
  let (id, _, _) ← oneHead inspected
  let accepted := Machine.step (.headDecision id (.accept none)) inspected.state
  let complete := Machine.step (.bytes ByteArray.empty 0 0) accepted.state
  let _ ← oneRequest complete
  let final := Machine.step (.response id { response := {} }) complete.state
  let (outputId, parts, _) ← oneWrite final
  check (contains (flatten parts) "Date: Sun, 06 Nov 1994 08:49:37 GMT\r\n") "driver-supplied cached Date reaches wire"
  check ((Machine.step (.timeout .request) final.state).actions.isEmpty) "stale request timeout cannot replace completed response"
  let reopened := Machine.step (.outputAccepted outputId) final.state
  check ((Machine.step (.timeout .request) reopened.state).actions.isEmpty) "stale request timeout ignored in new idle state"
  check (drains (Machine.step .eof reopened.state)) "Input EOF delegates to graceful drain"
  check (aborts (Machine.step (.timeout .idle) Machine.State.new)) "idle timeout closes idle connection"
  check (aborts (Machine.step (.timeout .write) final.state)) "write timeout aborts outstanding output"
  let incomplete := (Machine.State.new).feed "GET / HTTP/1.1\r\nHost: x".toUTF8
  let deadline := Machine.step (.timeout .request) incomplete.state
  let (_, deadlineParts, _) ← oneWrite deadline
  check (wireStarts (flatten deadlineParts) "HTTP/1.1 408 ") "absolute incomplete-request timeout sends408"
  let post := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n".toUTF8
  let postHead := (Machine.State.new).feed post
  let (postId, _, _) ← oneHead postHead
  let continuing := postHead.state.decideHead postId (.accept none)
  let (oldOutput, _, _) ← oneWrite continuing
  let timedOut := continuing.state.timeout .request
  let (errorOutput, errorParts, errorBarrier) ← oneWrite timedOut
  check (errorOutput > oldOutput && !errorBarrier && wireStarts (flatten errorParts) "HTTP/1.1 408 ") "request deadline remains active across100 barrier"
  let historical := timedOut.state.outputAccepted oldOutput
  check (historical.actions.isEmpty && !historical.state.wantsInput) "historical100 completion cannot reopen timed-out body"
  let closed := historical.state.outputAccepted errorOutput
  check (drains closed && closed.state.isClosing) "408 drains despite late100 completion"

def main : IO Unit := do
  fragmentedIntegration
  refusalAndBarriers
  pipelineEOF
  versionAndEOFPolicies
  malformedEOF
  machineResponses
  upgradeBarrier
  recordedEOFDuringDecision
  wrappersAndTimeouts
  IO.println "HTTP/1 pure machine fragmentation, decisions, barriers, EOF, response and upgrade tests passed"
