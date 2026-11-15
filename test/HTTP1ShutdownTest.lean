import LeanNet.HTTP1.Machine

open LeanNet.HTTP1

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do throw (IO.userError message)

private def drains (step : Machine.Step) : Bool :=
  step.actions.any (fun | .drainClose => true | _ => false)

private def oneHead (step : Machine.Step) : IO Nat := do
  let [id] := step.actions.filterMap (fun | .inspectHead id _ _ => some id | _ => none)
    | throw (IO.userError "expected one header decision")
  return id

private def oneRequest (step : Machine.Step) : IO (Nat × Request) := do
  let [request] := step.actions.filterMap (fun | .request id request => some (id, request) | _ => none)
    | throw (IO.userError "expected one application request")
  return request

private def oneWrite (step : Machine.Step) : IO (Nat × ByteArray × Bool) := do
  let [(id, parts, barrier)] := step.actions.filterMap (fun | .write id parts barrier => some (id, parts, barrier) | _ => none)
    | throw (IO.userError "expected one response")
  return (id, parts.foldl ByteArray.append ByteArray.empty, barrier)

private def contains (bytes : ByteArray) (text : String) : Bool :=
  (List.range (bytes.size + 1)).any fun offset =>
    bytes.extract offset (offset + text.toUTF8.size) == text.toUTF8

private def acceptedGet : IO (Nat × Machine.State) := do
  let head := Machine.State.new.feed "GET / HTTP/1.1\r\nHost: x\r\n\r\n".toUTF8
  let id ← oneHead head
  let ready := (head.state.decideHead id (.accept none)).state.feed ByteArray.empty
  let (actual, _) ← oneRequest ready
  check (actual == id) "request identity changed"
  return (id, ready.state)

private def finalResponse (state : Machine.State) (id : Nat) : IO Unit := do
  let response := state.respond id { response := { body := "finished".toUTF8 } }
  let (output, bytes, _) ← oneWrite response
  check (contains bytes "Connection: close\r\n" && contains bytes "finished") "draining response did not advertise close"
  let done := response.state.outputAccepted output
  check (drains done && done.state.isClosing) "draining response admitted another request"
  let extra := done.state.feed "GET /new HTTP/1.1\r\nHost: x\r\n\r\n".toUTF8
  check (extra.consumed == 0 && extra.actions.isEmpty) "new pipelined request was admitted after shutdown"

def main : IO Unit := do
  let idle := Machine.State.new.shutdown
  check (drains idle && idle.state.isClosing) "idle shutdown did not drain"
  check idle.state.shutdown.actions.isEmpty "shutdown was not idempotent"

  let fragment := Machine.State.new.feed "POST /saved HTTP/1.1\r\nHost: x\r\nContent-Len".toUTF8
  let stopped := fragment.state.shutdown
  check (!drains stopped && stopped.state.wantsInput) "partial current header was discarded"
  let head := stopped.state.feed "gth: 3\r\n\r\n".toUTF8
  let id ← oneHead head
  let body := (head.state.decideHead id (.accept none)).state.feed "abc".toUTF8
  let (actual, request) ← oneRequest body
  check (actual == id && request.body == "abc".toUTF8) "partial current body was discarded"
  finalResponse body.state id

  let (id, application) ← acceptedGet
  finalResponse application.shutdown.state id

  let (id, application) ← acceptedGet
  let selected := application.respond id { response := { body := "already queued".toUTF8 } }
  let (output, _, _) ← oneWrite selected
  check (drains (selected.state.shutdown.state.outputAccepted output)) "queued response was not closed in order"

  let head := Machine.State.new.feed
    "POST /continue HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n".toUTF8
  let id ← oneHead head
  let interim := head.state.decideHead id (.accept none)
  let (output, bytes, barrier) ← oneWrite interim
  check (barrier && contains bytes "100 Continue") "Continue did not retain its wire barrier"
  let admitted := interim.state.shutdown.state.outputAccepted output
  let request := admitted.state.feed "abc".toUTF8
  let (actual, _) ← oneRequest request
  check (actual == id) "Continue request identity changed during shutdown"
  finalResponse request.state id

  let head := Machine.State.new.feed
    "GET /upgrade HTTP/1.1\r\nHost: x\r\nConnection: upgrade\r\nUpgrade: echo\r\n\r\n".toUTF8
  let id ← oneHead head
  let rejected := head.state.shutdown.state.decideHead id
    (.upgrade { response := { status := 101, headers := #[{ name := "Upgrade", value := "echo".toUTF8 }] } })
  let (_, bytes, _) ← oneWrite rejected
  check (contains bytes "503 Service Unavailable") "shutdown accepted a fresh raw upgrade"
  IO.println "HTTP/1 graceful request, output, Continue and upgrade shutdown tests passed"
