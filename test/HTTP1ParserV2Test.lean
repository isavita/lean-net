import LeanNet.HTTP1.Parser

open LeanNet.HTTP1

private def check (value : Bool) (message : String) : IO Unit := do
  unless value do throw (IO.userError message)

private structure State where
  parser : Parser
  heads : Nat := 0
  consumed : Nat := 0
  request : Option Request := none
  remaining : ByteArray := ByteArray.empty

private def feedWindow (state : State) (input : ByteArray) (start length : Nat)
    (headLength : Nat) (expected : BodyFraming) (closeBody : Bool := false) : IO State := do
  if state.request.isSome then
    return { state with remaining := state.remaining.append (input.extract start (start + length)) }
  let progress := state.parser.feedSlice input start length
  match progress with
  | .error message _ => throw (IO.userError message)
  | .needMore parser consumed =>
    check (consumed == length) "needMore left input unconsumed"
    return { state with parser, consumed := state.consumed + consumed }
  | .complete request consumed =>
    check (consumed <= length) "completion exceeded input window"
    return { state with
      request := some request
      consumed := state.consumed + consumed
      remaining := input.extract (start + consumed) (start + length) }
  | .head head framing parser consumed =>
    check (state.heads == 0 && framing == expected) "duplicate head or wrong inferred framing"
    check (state.consumed + consumed == headLength) "head did not stop at its exact wire boundary"
    check (head.version == "HTTP/1.0" || head.version == "HTTP/1.1") "head lost its wire version"
    match parser.feedSlice input (start + consumed) (length - consumed) with
    | .error _ 0 => pure ()
    | _ => throw (IO.userError "paused parser consumed body without a decision")
    let parser ← match parser.resumeBody (if closeBody then .closeDelimited else framing) with
      | .ok parser => pure parser
      | .error message => throw (IO.userError message)
    match parser.feedSlice input (start + consumed) (length - consumed) with
    | .needMore parser used =>
      check (consumed + used == length) "body did not consume its available window"
      return { state with parser, heads := 1, consumed := state.consumed + length }
    | .complete request used =>
      check (consumed + used <= length) "body completion exceeded window"
      return { state with
        parser
        heads := 1
        request := some request
        consumed := state.consumed + consumed + used
        remaining := input.extract (start + consumed + used) (start + length) }
    | .error message _ => throw (IO.userError message)
    | .head .. => throw (IO.userError "resuming body emitted its head twice")

private def allSplits (label : String) (head body expectedBody pipeline : ByteArray)
    (framing : BodyFraming) (version : String := "HTTP/1.1")
    (options : Parser.Options := {}) (closeBody : Bool := false) : IO Unit := do
  let wire := (head.append body).append pipeline
  for split in [:wire.size + 1] do
    let state : State := { parser := Parser.new {} options }
    let state ← feedWindow state wire 0 split head.size framing closeBody
    let state ← feedWindow state wire split (wire.size - split) head.size framing closeBody
    let state ← if closeBody then do
      check state.request.isNone s!"{label}: EOF body completed before EOF"
      match state.parser.finish with
      | .complete request rest => pure { state with request := some request, remaining := rest }
      | _ => throw (IO.userError s!"{label}: EOF body did not complete on finish")
      else pure state
    let some request := state.request | throw (IO.userError s!"{label}, split {split}: incomplete")
    check (state.heads == 1 && request.version == version && request.body == expectedBody && state.remaining == pipeline)
      s!"{label}, split {split}: wrong head/version/body/remainder"
  let mut state : State := { parser := Parser.new {} options }
  for i in [:wire.size] do
    state ← feedWindow state wire i 1 head.size framing closeBody
  if closeBody then
    match state.parser.finish with
    | .complete request _ => check (request.body == expectedBody) s!"{label}: bytewise EOF body"
    | _ => throw (IO.userError s!"{label}: bytewise EOF failed")
  else
    let some request := state.request | throw (IO.userError s!"{label}: bytewise incomplete")
    check (request.body == expectedBody && state.remaining == pipeline) s!"{label}: bytewise body/pipeline"

private def reject (label wire : String) (limits : Limits := {}) (options : Parser.Options := {}) : IO Unit := do
  match (Parser.new limits options).feed wire.toUTF8 with
  | .error _ => pure ()
  | _ => throw (IO.userError s!"{label}: malformed request accepted")

private def decisions : IO Unit := do
  let head := "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\n".toUTF8
  let wire := head.append "dataNEXT".toUTF8
  match (Parser.new).feedSlice wire 0 wire.size with
  | .head _ (.contentLength 4) paused consumed =>
    check (consumed == head.size) "head consumed body bytes"
    for wrong in [BodyFraming.none, .contentLength 5, .chunked, .closeDelimited] do
      match paused.resumeBody wrong with
      | .error _ => pure ()
      | .ok _ => throw (IO.userError "framing override accepted")
    let parser ← match paused.resumeBody (.contentLength 4) with
      | .ok p => pure p | .error e => throw (IO.userError e)
    match parser.resumeBody (.contentLength 4) with
    | .error _ => pure ()
    | _ => throw (IO.userError "body was resumed twice")
    match parser.feedSlice wire consumed (wire.size - consumed) with
    | .complete request 4 => check (request.body == "data".toUTF8) "fixed-body decision lost bytes"
    | _ => throw (IO.userError "fixed body cursor did not stop before pipeline")
  | _ => throw (IO.userError "missing fixed-body head decision")
  let bodyless := "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".toUTF8
  match (Parser.new).feedSlice bodyless 0 bodyless.size with
  | .head _ .none paused _ =>
    match paused.resumeBody .closeDelimited with
    | .error _ => pure ()
    | _ => throw (IO.userError "HTTP/1.1 unframed request accepted EOF override")
    let parser ← match paused.resumeBody .none with | .ok p => pure p | .error e => throw (IO.userError e)
    match parser.feedSlice "pipeline".toUTF8 0 8 with
    | .complete request 0 => check request.body.isEmpty "bodyless completion consumed pipeline"
    | _ => throw (IO.userError "bodyless resumed request did not complete at offset zero")
  | _ => throw (IO.userError "bodyless request did not emit a head event")
  for (start, length) in [(bodyless.size + 1, 0), (0, bodyless.size + 1)] do
    match (Parser.new).feedSlice bodyless start length with
    | .error _ 0 => pure ()
    | _ => throw (IO.userError "invalid ByteArray window accepted")
  let wrapped := ("ignored".toUTF8.append bodyless).append "outside".toUTF8
  let state ← feedWindow { parser := Parser.new } wrapped 7 bodyless.size bodyless.size .none
  check (state.request.isSome && state.remaining.isEmpty) "parser read outside its input slice"
  for limits in [({ maxBodyBytes := 4 } : Limits), ({ maxBodyWireBytes := 4 } : Limits)] do
    let head := "POST / HTTP/1.0\r\n\r\n".toUTF8
    match (Parser.new limits).feedSlice head 0 head.size with
    | .head _ .none paused _ =>
      let parser ← match paused.resumeBody .closeDelimited with | .ok p => pure p | .error e => throw (IO.userError e)
      match parser.feedSlice "abcde".toUTF8 0 5 with
      | .error _ 5 => pure ()
      | _ => throw (IO.userError "close-delimited body bypassed size/wire bounds")
    | _ => throw (IO.userError "missing close-delimited decision")
  check (validAuthority ByteArray.empty && validAuthority ":80".toUTF8 && validAuthority "[::1]:".toUTF8)
    "generic authority semantics changed for HTTP/2 consumers"

private def blockBoundaries : IO Unit := do
  let body := Id.run do
    let mut bytes := ByteArray.empty
    for i in [:8195] do bytes := bytes.push (UInt8.ofNat i)
    return bytes
  let pipeline := "GET /next HTTP/1.1\r\nHost: x\r\n\r\n".toUTF8
  for chunked in [false, true] do
    let head := (if chunked then "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
      else "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 8195\r\n\r\n").toUTF8
    let encoded := if chunked then
      ((((("1001\r\n".toUTF8.append (body.extract 0 4097)).append "\r\n1002\r\n".toUTF8).append
        (body.extract 4097 body.size)).append "\r\n0\r\n\r\n".toUTF8)) else body
    let wire := (head.append encoded).append pipeline
    for step in [1, 127, 4095, 4096, 4097, 8192] do
      let mut state : State := { parser := Parser.new }
      for part in [:(wire.size + step - 1) / step] do
        let start := part * step
        state ← feedWindow state wire start (min step (wire.size - start)) head.size
          (if chunked then .chunked else .contentLength body.size)
      let some request := state.request | throw (IO.userError "block-boundary body incomplete")
      check (request.body == body && state.remaining == pipeline && state.heads == 1)
        s!"block-boundary body changed: chunked={chunked}, feed={step}"
  let bodyPrefix := body.extract 0 4097
  let head := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4100\r\n\r\n".toUTF8
  match (Parser.new).feed (head.append bodyPrefix) with
  | .needMore original =>
    match original.feed "ABC".toUTF8, original.feed "XYZ".toUTF8 with
    | .complete left _, .complete right _ =>
      check (left.body == bodyPrefix.append "ABC".toUTF8 && right.body == bodyPrefix.append "XYZ".toUTF8)
        "branching an immutable parser mutated another body's blocks"
      match original.finish with
      | .error _ => pure ()
      | _ => throw (IO.userError "resuming a parser changed the original state")
    | _, _ => throw (IO.userError "persistent body branches failed to complete")
  | _ => throw (IO.userError "persistent body prefix completed prematurely")

def main : IO Unit := do
  let pipeline := "GET /next HTTP/1.1\r\nHost: example.test\r\n\r\n".toUTF8
  let binary := ByteArray.mk #[0, 255, 13, 10]
  allSplits "HTTP/1.0 bodyless" "GET / HTTP/1.0\r\n\r\n".toUTF8 ByteArray.empty ByteArray.empty pipeline .none "HTTP/1.0"
  allSplits "HTTP/1.0 fixed" "POST / HTTP/1.0\r\nContent-Length: 4\r\n\r\n".toUTF8 binary binary pipeline (.contentLength 4) "HTTP/1.0"
  allSplits "HTTP/1.1 zero length" "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n".toUTF8 ByteArray.empty ByteArray.empty pipeline (.contentLength 0)
  allSplits "chunked trailers" "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: CHUNKED\r\n\r\n".toUTF8
    "4;foo=\"bar\"\r\ndata\r\n0\r\nX-Trailer: yes\r\n\r\n".toUTF8 "data".toUTF8 pipeline .chunked
  allSplits "explicit HTTP/1.0 EOF body" "POST /upload HTTP/1.0\r\n\r\n".toUTF8
    (binary.append pipeline) (binary.append pipeline) ByteArray.empty .none "HTTP/1.0" {} true
  allSplits "unfolded fields" "GET / HTTP/1.1\r\nHost: x\r\nX: first\r\n \tsecond\r\n\tthird \t\r\n\r\n".toUTF8
    ByteArray.empty ByteArray.empty pipeline .none "HTTP/1.1" { allowObsFold := true }
  let folded := "GET / HTTP/1.1\r\nHost: x\r\nX: first\r\n second\r\n\r\n"
  reject "fold disabled" folded
  match (Parser.new {} { allowObsFold := true }).feed folded.toUTF8 with
  | .complete request _ => check (request.headers.any (fun h => h.name == "x" && h.value == "first second".toUTF8)) "fold normalization"
  | _ => throw (IO.userError "enabled field folding failed")
  reject "orphan fold" "GET / HTTP/1.1\r\n x\r\nHost: x\r\n\r\n" {} { allowObsFold := true }
  reject "fold framing ambiguity" "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n 0\r\n\r\n" {} { allowObsFold := true }
  reject "folded field wire bound" folded { maxHeaderBytes := folded.toUTF8.size - 1 } { allowObsFold := true }
  reject "HTTP/0.9" "GET /\r\n"
  reject "HTTP/1.2" "GET / HTTP/1.2\r\nHost: x\r\n\r\n"
  reject "HTTP/1.0 transfer coding" "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
  reject "HTTP/1.1 missing host" "GET / HTTP/1.1\r\n\r\n"
  reject "HTTP/1.0 duplicate host" "GET / HTTP/1.0\r\nHost: a\r\nHost: b\r\n\r\n"
  reject "chunk wire includes terminators" "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n" { maxBodyWireBytes := 10 }
  reject "forbidden connection trailer" "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nConnection: close\r\n\r\n"
  reject "connection-nominated trailer" "POST / HTTP/1.1\r\nHost: x\r\nConnection: x-late\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Late: forbidden\r\n\r\n"
  reject "content-type trailer" "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Type: text/plain\r\n\r\n"
  let badFold := ("GET / HTTP/1.1\r\nHost: x\r\nX: valid\r\n ".toUTF8.append (ByteArray.mk #[0])).append "bad\r\n\r\n".toUTF8
  match (Parser.new {} { allowObsFold := true }).feed badFold with
  | .error _ => pure ()
  | _ => throw (IO.userError "NUL in folded field was accepted")
  decisions
  blockBoundaries
  IO.println "HTTP/1 parser cursor, version, framing, fold and EOF tests passed"
