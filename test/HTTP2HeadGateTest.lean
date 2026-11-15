import LeanNet.HTTP2.Connection
import LeanNet.HTTP1.Machine

/-! Head-stage admission: HTTP/2 streams pause at their validated head and
    HTTP/1 heads accept a per-request body bound. -/

open LeanNet.HTTP2
open LeanNet

private def wireText (parts : Array WirePart) : String :=
  (String.fromUTF8? (parts.foldl (fun acc part => match part with | .bytes data => acc ++ data | _ => acc) ByteArray.empty)).getD ""

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do throw (IO.userError message)
private def ok (result : Except ProtocolError α) : IO α := do
  match result with
  | .ok value => return value
  | .error error => throw (IO.userError s!"unexpected protocol error: {repr error}")
private def hp (result : Except String α) : IO α := do
  match result with
  | .ok value => return value
  | .error error => throw (IO.userError error)
private def wire (frame : Frame) : IO ByteArray := ok (frame.encode 16777215)
private def frames (data : ByteArray) : IO (Array Frame) := do
  let mut offset := 0
  let mut out := #[]
  for _ in [:data.size + 1] do
    if offset == data.size then break
    match (FrameParser.new 16777215).feedSlice data offset (data.size - offset) with
    | .complete frame consumed => out := out.push frame; offset := offset + consumed
    | .error error _ => throw (IO.userError s!"invalid output: {repr error}")
    | .needMore _ _ => throw (IO.userError "truncated output")
  return out
private def head (path : String) (extra : Array HPACK.Header := #[]) : Array HPACK.Header := #[
  { name := ":method".toUTF8, value := "POST".toUTF8 },
  { name := ":scheme".toUTF8, value := "https".toUTF8 },
  { name := ":authority".toUTF8, value := "localhost".toUTF8 },
  { name := ":path".toUTF8, value := path.toUTF8 }] ++ extra
private def connect (config : Connection.Config) : IO Connection := do
  let input := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toUTF8.append (← wire ⟨4, 0, 0, ByteArray.empty⟩)
  let (connection, _, _) ← ok ((Connection.newWithConfig config).feed input)
  return connection
private def statusOf (bytes : ByteArray) : IO (Option String) := do
  for frame in ← frames bytes do
    if frame.kind == 1 then
      let (_, fields) ← hp (HPACK.decode HPACK.Context.new frame.payload)
      if let some field := fields.find? (·.name == ":status".toUTF8) then
        return String.fromUTF8? field.value
  return none

private def gated : IO Unit := do
  let config : Connection.Config := { headGate := true }
  let connection ← connect config
  let (_, block) ← hp (HPACK.encode HPACK.Context.new (head "/upload"))
  -- HEADERS (no END_STREAM) immediately followed by DATA in one read.
  let input := (← wire ⟨1, 4, 1, block⟩) ++ (← wire ⟨0, 1, 1, "hello".toUTF8⟩)
  let step := connection.feedSlice input 0 input.size
  check step.error.isNone "gated head failed"
  check (step.heads.size == 1 && step.requests.isEmpty) "head was not paused for admission"
  check (step.consumed < input.size) "DATA was consumed before the admission decision"
  check ((step.heads[0]?.bind (·.gateHead)).any (·.target == "/upload".toUTF8)) "paused head lost its target"
  -- Admit, then feed the remaining DATA: the request completes normally.
  let (connection, _, events) ← ok (step.connection.admitHead 1)
  check events.isEmpty "admission delivered an incomplete request"
  let rest := connection.feedSlice input step.consumed (input.size - step.consumed)
  check (rest.requests.size == 1 && (rest.requests[0]?.map (·.request.body)).getD ByteArray.empty == "hello".toUTF8) "admitted body not delivered"
  -- A second stream is rejected with 429 and Retry-After, before its body.
  let encoder := HPACK.Context.new
  let (_, block) ← hp (HPACK.encode encoder (head "/limited"))
  let input := (← wire ⟨1, 4, 3, block⟩) ++ (← wire ⟨0, 1, 3, "ignored".toUTF8⟩)
  let step := rest.connection.feedSlice input 0 input.size
  check (step.heads.size == 1) "second head not paused"
  let (connection, bytes) ← ok (step.connection.rejectHead 3 429 #[{ name := "retry-after", value := "1".toUTF8 }])
  check ((← statusOf bytes) == some "429") "rejection status not sent"
  check ((← frames bytes).any (fun frame => frame.kind == 3)) "unfinished upload was not reset"
  let after := connection.feedSlice input step.consumed (input.size - step.consumed)
  check (after.error.isNone && after.requests.isEmpty) "rejected stream delivered its body"
  check (!connection.canRespond 3) "rejected stream remains respondable"

private def bodyLimit : IO Unit := do
  let connection ← connect { headGate := true }
  let (_, block) ← hp (HPACK.encode HPACK.Context.new (head "/small"))
  let headers ← wire ⟨1, 4, 1, block⟩
  let step := connection.feedSlice headers 0 headers.size
  let (connection, _, _) ← ok (step.connection.admitHead 1 (some 4))
  let data ← wire ⟨0, 1, 1, "too long".toUTF8⟩
  let step := connection.feedSlice data 0 data.size
  check (step.requests.isEmpty) "oversized body delivered"
  check ((← statusOf (step.output.foldl (· ++ ·) ByteArray.empty)) == some "413") "route body limit did not answer 413"
  -- A declared content-length above the bound is refused at admission.
  let connection ← connect { headGate := true }
  let (_, block) ← hp (HPACK.encode HPACK.Context.new (head "/small" #[{ name := "content-length".toUTF8, value := "100".toUTF8 }]))
  let headers ← wire ⟨1, 4, 1, block⟩
  let step := connection.feedSlice headers 0 headers.size
  let (_, bytes, _) ← ok (step.connection.admitHead 1 (some 10))
  check ((← statusOf bytes) == some "413") "declared length above route bound accepted"

private def ungated : IO Unit := do
  let connection ← connect {}
  let (_, block) ← hp (HPACK.encode HPACK.Context.new (head "/plain"))
  let input ← wire ⟨1, 5, 1, block⟩
  let step := connection.feedSlice input 0 input.size
  check (step.heads.isEmpty && step.requests.size == 1) "ungated connection paused"

private def http1Limit : IO Unit := do
  let wire := "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 20\r\n\r\n".toUTF8
  let state := HTTP1.Machine.State.new {}
  let step := state.feed wire
  let some (.inspectHead requestId _ _) := step.actions.find? (fun | .inspectHead .. => true | _ => false)
    | throw (IO.userError "no HTTP/1 head decision")
  let decided := step.state.decideHead requestId (.accept none (some 10))
  let written := decided.actions.any fun
    | .writeObserved _ output _ => (wireText output.parts).startsWith "HTTP/1.1 413"
    | .write _ parts _ => (String.fromUTF8? (parts.foldl (· ++ ·) ByteArray.empty)).any (·.startsWith "HTTP/1.1 413")
    | _ => false
  check written "HTTP/1 declared body above the admitted bound did not answer 413"
  let chunked := "POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n".toUTF8
  let step := (HTTP1.Machine.State.new {}).feed chunked
  let some (.inspectHead requestId _ _) := step.actions.find? (fun | .inspectHead .. => true | _ => false)
    | throw (IO.userError "no chunked head decision")
  let decided := step.state.decideHead requestId (.accept none (some 3))
  let body := decided.state.feed "a\r\n0123456789\r\n0\r\n\r\n".toUTF8
  let rejected := body.actions.any fun
    | .write _ parts _ => (String.fromUTF8? (parts.foldl (· ++ ·) ByteArray.empty)).any (·.startsWith "HTTP/1.1 413")
    | .writeObserved _ output _ => (wireText output.parts).startsWith "HTTP/1.1 413"
    | _ => false
  check rejected "HTTP/1 chunked body above the admitted bound did not answer 413"

def main : IO Unit := do
  gated
  bodyLimit
  ungated
  http1Limit
  IO.println "HTTP/2 head gate and per-request body limit tests passed"
