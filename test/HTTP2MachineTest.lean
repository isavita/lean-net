import LeanNet.HTTP2.Machine

open LeanNet.HTTP2

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do throw (IO.userError message)
private def ok (value : Except ProtocolError α) : IO α := do
  match value with
  | .ok result => return result
  | .error error => throw (IO.userError (reprStr error))
private def hpack (value : Except String α) : IO α := do
  match value with
  | .ok result => return result
  | .error error => throw (IO.userError error)
private def wire (frame : Frame) : IO ByteArray := ok (frame.encode 16777215)
private def fields (method : String := "GET") (path : String := "/") : Array HPACK.Header := #[
  { name := ":method".toUTF8, value := method.toUTF8 },
  { name := ":scheme".toUTF8, value := "http".toUTF8 },
  { name := ":authority".toUTF8, value := "example.test".toUTF8 },
  { name := ":path".toUTF8, value := path.toUTF8 }]
private def request (id : UInt32) (extra : Array HPACK.Header := #[])
    (ended : Bool := true) : IO ByteArray := do
  let (_, block) ← hpack (HPACK.encode HPACK.Context.new (fields ++ extra))
  wire ⟨1, if ended then 5 else 4, id, block⟩
private def writes (step : Machine.Step) : ByteArray := Id.run do
  let mut output := ByteArray.empty
  for action in step.actions do
    if let .write parts := action then
      for part in parts do output := output.append part
  return output
private def requests (step : Machine.Step) : Array UInt32 := Id.run do
  let mut result := #[]
  for action in step.actions do
    if let .request event := action then result := result.push event.streamId
  return result
private def closes (step : Machine.Step) : Nat := step.actions.foldl (fun n action =>
  match action with | .drainClose => n + 1 | _ => n) 0
private def frames (bytes : ByteArray) : IO (Array Frame) := do
  let mut cursor := 0
  let mut result := #[]
  for _ in [:bytes.size + 1] do
    if cursor == bytes.size then break
    match (FrameParser.new 16777215).feedSlice bytes cursor (bytes.size - cursor) with
    | .complete frame consumed => result := result.push frame; cursor := cursor + consumed
    | .needMore _ _ => throw (IO.userError "truncated output")
    | .error error _ => throw (IO.userError (reprStr error))
  return result
private def boot (config : Connection.Config := {}) (settings : ByteArray := ByteArray.empty) : IO Machine.State := do
  let preface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toUTF8
  let input := preface.append (← wire ⟨4, 0, 0, settings⟩)
  let step := (Machine.State.new config).feedSlice input 0 input.size
  check (step.consumed == input.size && closes step == 0) "pure setup cursor"
  let output ← frames (writes step)
  check (output.size == 2 && output[0]!.kind == 4 && output[0]!.flags == 0 &&
    output[1]!.kind == 4 && output[1]!.flags == 1) "automatic initial SETTINGS before ACK"
  check ((writes step.state.start).isEmpty) "start is idempotent"
  return step.state

def main : IO Unit := do
  let state ← boot
  let input ← request 1
  let parsed := state.feedSlice input 0 input.size
  check (requests parsed == #[1] && parsed.state.canRespond 1) "request action"
  let response := parsed.state.respond 1 { response := { body := "response".toUTF8 } }
  let output ← frames (writes response)
  check (output.size == 1 && output[0]!.kind == 1) "respond queues HEADERS without eager DATA"
  let body := response.state.drain
  let output ← frames (writes body)
  check (output.size == 1 && output[0]!.kind == 0 && output[0]!.payload == "response".toUTF8) "separate body drain"
  check (!(body.state.hasPendingOutput) && closes body == 0) "normal response keeps connection"

  -- Deferred bodies allow priority selection after all same-batch callbacks.
  let a ← request 1 #[{ name := "priority".toUTF8, value := "u=7".toUTF8 }]
  let b ← request 3 #[{ name := "priority".toUTF8, value := "u=0".toUTF8 }]
  let input := a.append b
  let parsed := (← boot).feedSlice input 0 input.size
  check (requests parsed == #[1, 3]) "request action order"
  let first := parsed.state.respond 1 { response := { body := "low".toUTF8 } }
  let second := first.state.respond 3 { response := { body := "high".toUTF8 } }
  let sent ← frames (writes second.state.drain)
  check (sent.size == 2 && sent[0]!.streamId == 3 && sent[1]!.streamId == 1) "batch priority before DATA"

  -- A stream-scoped parser error cannot suppress a healthy following request.
  let input := (← request 1 #[] false).append (ByteArray.mk #[0,0,0,2,0,0,0,0,1])
  let input := input.append (← request 3)
  let result := (← boot).feedSlice input 0 input.size
  let output ← frames (writes result)
  check (requests result == #[3] && closes result == 0 && result.state.wantsInput &&
    output.any (fun f => f.kind == 3 && f.streamId == 1) && !output.any (fun f => f.kind == 7) &&
    result.actions.any (fun | .responseAborted 1 .error => true | _ => false))
    "stream isolation and local reset cancellation"

  -- A discarded DATA frame can replenish connection credit before emitting
  -- RST_STREAM in the same byte part. Cancellation must scan past that frame.
  let limited : Connection.Config := { maxRequestBodyBytes := 1, maxBufferedRequestBytes := 1 }
  let state ← boot limited
  let opening ← request 1 #[] false
  let opened := state.feedSlice opening 0 opening.size
  let data ← wire ⟨0, 0, 1, ByteArray.mk (Array.replicate 16384 65)⟩
  let discarded := opened.state.feedSlice data 0 data.size
  let output ← frames (writes discarded)
  check (output.size == 2 && output[0]!.kind == 8 && output[1]!.kind == 3 &&
    discarded.actions.any (fun | .responseAborted 1 .error => true | _ => false))
    "WINDOW_UPDATE before local RST suppressed cancellation"

  let bad := ByteArray.mk #[0,0,7,6,0,0,0,0,0, 0,0,0,0,0,0,0]
  let result := (← boot).feedSlice bad 0 bad.size
  let output ← frames (writes result)
  check (closes result == 1 && (output.filter (fun f => f.kind == 7)).size == 1) "one fatal GOAWAY"
  check ((writes (result.state.feedSlice bad 0 bad.size)).isEmpty) "closed machine does not repeat fatal output"

  -- A peer's tiny response-header advice may make even 500 unsendable.
  let tiny := ByteArray.mk #[0,6,0,0,0,0]
  let state ← boot {} tiny
  let input := (← request 1).append (← request 3)
  let parsed := state.feedSlice input 0 input.size
  let result := parsed.state.respond 1 { response := { body := "unencodable".toUTF8 } }
  let output ← frames (writes result)
  check (closes result == 0 && result.state.canRespond 3 && output.any (fun f => f.kind == 3 && f.streamId == 1) &&
    !output.any (fun f => f.kind == 7)) "local response failure preserves independent stream"

  let input ← request 1
  let parsed := (← boot).feedSlice input 0 input.size
  let result := parsed.state.respond 1 { response := { body := "parent".toUTF8 } }
    #[{ target := "/asset".toUTF8, response := { body := "asset".toUTF8 } }]
  check (!(← frames (writes result)).any (fun f => f.kind == 5)) "push disabled by default"
  let parsed := (← boot { enablePush := true }).feedSlice input 0 input.size
  let result := parsed.state.respond 1 { response := { body := "parent".toUTF8 } }
    #[{ target := "/asset".toUTF8, response := { body := "asset".toUTF8 } }]
  let output ← frames (writes result)
  check (output[0]!.kind == 5 && output.any (fun f => f.kind == 1 && f.streamId == 2)) "push promised before parent closure"
  let draining := result.state.goAway
  check (closes draining == 0) "GOAWAY waits for accepted responses"
  let drained := draining.state.drain
  check (closes drained == 1 && !drained.state.hasPendingOutput) "complete drain closes exactly once"

  IO.println "HTTP/2 sans-IO action machine tests passed"
