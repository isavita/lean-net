import LeanNet.WebSocket.Connection
import LeanNet.WebSocket.Handshake

open LeanNet.WebSocket

private def check (condition : Bool) (label : String) : IO Unit :=
  unless condition do throw (IO.userError label)

private def ok (result : Except ε α) (label : String := "unexpected error") : IO α := do
  match result with
  | .ok value => return value
  | .error _ => throw (IO.userError label)

private def bad (result : Except ε α) (label : String) : IO Unit := do
  match result with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError label)

private def bytes (values : List UInt8) : ByteArray := ByteArray.mk values.toArray
private def key := bytes [0x37,0xfa,0x21,0x3d]
private def client (frame : Frame) : IO ByteArray := ok (frame.encode (some key) 16777216)

private def decoded (wire : ByteArray) (masked : Bool := false) : IO Frame := do
  match (FrameParser.new 16777216 masked).feed wire with
  | .complete frame used => check (used == wire.size) "decoder left bytes"; return frame
  | _ => throw (IO.userError "expected a complete frame")

private def rejectFrame (wire : ByteArray) (code : Nat := 1002) : IO Unit := do
  match (FrameParser.new 1048576 true).feed wire with
  | .error error _ => check (error.code == code) "incorrect frame rejection status"
  | _ => throw (IO.userError "invalid frame accepted")

private def pattern (size : Nat) : ByteArray := Id.run do
  let mut out := ByteArray.emptyWithCapacity size
  for index in [:size] do out := out.push (UInt8.ofNat (index * 37 + 11))
  return out

private def frameTests : IO Unit := do
  let hello := bytes [0x81,0x85,0x37,0xfa,0x21,0x3d,0x7f,0x9f,0x4d,0x51,0x58]
  let frame ← decoded hello true
  check (frame.fin && frame.opcode == .text && frame.payload == "Hello".toUTF8) "RFC masked Hello"
  let plain ← ok (frame.encode)
  check (plain == bytes [0x81,5,72,101,108,108,111]) "RFC server Hello"
  for split in [:hello.size + 1] do
    match (FrameParser.new).feed (hello.extract 0 split) with
    | .complete decoded used =>
      check (split == hello.size && used == hello.size && decoded.payload == frame.payload) "early frame completion"
    | .needMore parser used =>
      check (used == split) "split consumed mismatch"
      match parser.feed (hello.extract split hello.size) with
      | .complete decoded count => check (count + split == hello.size && decoded.payload == frame.payload) "split continuation"
      | _ => throw (IO.userError "split frame did not complete")
    | _ => throw (IO.userError "valid split rejected")
  let mut byteParser := FrameParser.new
  for index in [:hello.size] do
    match byteParser.feed (hello.extract index (index + 1)) with
    | .needMore next used => check (used == 1 && index + 1 < hello.size) "bytewise early/incomplete parse"; byteParser := next
    | .complete result used => check (used == 1 && index + 1 == hello.size && result.payload == frame.payload) "bytewise mask offset"
    | _ => throw (IO.userError "bytewise frame rejected")
  for size in [0,1,125,126,65535,65536] do
    let body := pattern size
    let encoded ← client { opcode := .binary, payload := body }
    for chunk in [64,8192] do
      let mut parser := FrameParser.new 1048576 true
      let mut position := 0
      let mut complete := false
      for _ in [:encoded.size + 1] do
        if position == encoded.size then break
        let count := min chunk (encoded.size - position)
        let padded := (bytes [99,98]).append ((encoded.extract position (position + count)).append (bytes [97]))
        match parser.feedSlice padded 2 count with
        | .needMore next used =>
          check (used == count) "chunk did not consume input"; parser := next
        | .complete result used =>
          check (used == count && position + used == encoded.size && result.payload == body) "extended length/mask cursor"
          complete := true
        | .error _ _ => throw (IO.userError "valid extended frame rejected")
        position := position + count
      check complete "extended frame incomplete"
  -- Invalid metadata must fail without waiting for an advertised payload.
  for raw in [bytes [0x81,0], bytes [0xc1,0x80,0,0,0,0], bytes [0x83,0x80,0,0,0,0], bytes [0x09,0x80,0,0,0,0], bytes [0x89,0xfe,0,126,0,0,0,0], bytes [0x82,0xfe,0,1,0,0,0,0], bytes [0x82,0xff,0,0,0,0,0,0,0,126,0,0,0,0], bytes [0x82,0xff,128,0,0,0,0,0,0,0,0,0,0,0]] do rejectFrame raw
  rejectFrame (bytes [0x82,0xff,0,0,0,0,0,32,0,0,0,0,0,0]) 1009
  match (FrameParser.new).feed (hello.extract 0 8) with
  | .needMore parser _ => bad parser.finish "truncated frame accepted at EOF"
  | _ => throw (IO.userError "expected incomplete frame")
  bad ({ opcode := Opcode.ping, fin := false } : Frame).encode "fragmented ping encoded"
  bad (frame.encode (some (bytes [1,2,3]))) "invalid mask encoded"

private def messages (actions : List Connection.Action) : List (Opcode × ByteArray) :=
  actions.filterMap fun action => match action with
    | .message opcode value => some (opcode, value) | _ => none

private def writes (actions : List Connection.Action) : List (Nat × ByteArray) :=
  actions.filterMap fun action => match action with
    | .write id value => some (id, value) | _ => none

private def errors (actions : List Connection.Action) : List Nat :=
  actions.filterMap fun action => match action with
    | .protocolError error => some error.code | _ => none

private def closes (actions : List Connection.Action) : List Connection.CloseInfo :=
  actions.filterMap fun action => match action with
    | .closed info => some info | _ => none

private def input (state : Connection.State) (frames : List Frame) : IO Connection.Step := do
  let mut wire := ByteArray.empty
  for frame in frames do wire := wire.append (← client frame)
  return state.feed wire

private def completeOutputs (initial : Connection.State) (actions : List Connection.Action)
    : IO (Connection.State × Array Frame × List Connection.Action) := do
  let mut state := initial
  let mut pending := actions
  let mut output := #[]
  let mut all := actions
  for _ in [:1024] do
    match writes pending with
    | [] => return (state, output, all)
    | [(id, wire)] =>
      output := output.push (← decoded wire)
      let next := state.outputWritten id
      state := next.state; pending := next.actions; all := all ++ next.actions
    | _ => throw (IO.userError "more than one physical output outstanding")
  throw (IO.userError "output completion fuel exhausted")

private def connectionTests : IO Unit := do
  let state ← ok Connection.State.new
  let next ← input state [
    { fin := false, opcode := .text, payload := bytes [0xf0,0x9f] }, { opcode := .ping, payload := "alive".toUTF8 }, { opcode := .continuation, payload := bytes [0x98,0x80] }]
  check (messages next.actions == [(.text, bytes [0xf0,0x9f,0x98,0x80])]) "UTF8 fragmented/control interleave"
  let (_, output, _) ← completeOutputs next.state next.actions
  check (output.size == 1 && output[0]!.opcode == .pong && output[0]!.payload == "alive".toUTF8) "automatic pong"
  for frames in [
      [{ opcode := Opcode.continuation }], [{ fin := false, opcode := .binary }, { opcode := .text }]] do
    let failed ← input state frames
    check (errors failed.actions == [1002]) "invalid continuation accepted"
  for body in [bytes [0xc0,0xaf], bytes [0xed,0xa0,0x80], bytes [0xf4,0x90,0x80,0x80], bytes [0xe2,0x82]] do
    let failed ← input state [{ opcode := .text, payload := body }]
    check (errors failed.actions == [1007]) "invalid UTF8 accepted"
  let limited ← ok (Connection.State.new { maxMessageBytes := 3, maxMessageFragments := 2 })
  let tooLarge ← input limited [{ fin := false, opcode := .binary, payload := bytes [1,2] }, { opcode := .continuation, payload := bytes [3,4] }]
  check (errors tooLarge.actions == [1009]) "message byte limit missing"
  let tinyFragments ← input limited [{ fin := false, opcode := .binary }, { fin := false, opcode := .continuation }, { opcode := .continuation }]
  check (errors tinyFragments.actions == [1009]) "empty fragment-count limit missing"
  let budgeted ← ok (Connection.State.new { maxFramesPerStep := 2 })
  let part ← client { opcode := .binary }
  let wire := part.append (part.append part)
  let first := budgeted.feed wire
  check (first.consumed == 2 * part.size && (messages first.actions).length == 2) "per-step frame budget"
  let last := first.state.feedSlice wire first.consumed (wire.size - first.consumed)
  check (last.consumed == part.size && (messages last.actions).length == 1) "budget resume cursor"
  let bytesBudget ← ok (Connection.State.new { maxInputBytesPerStep := 3 })
  let incomplete := bytesBudget.feed (← client { opcode := .text, payload := "hello".toUTF8 })
  check (incomplete.consumed == 3 && (messages incomplete.actions).isEmpty) "per-step input budget"
  let invalidSlice := state.feedSlice ByteArray.empty 1 0
  check (errors invalidSlice.actions == [1002]) "invalid zero slice accepted"

private def closeTests : IO Unit := do
  for code in [1000,1001,1002,1003,1007,1008,1009,1010,1011,1012,1013,1014,3000,4999] do
    let _ ← ok (Connection.closePayload (some code) "bye".toUTF8)
  for code in [0,999,1004,1005,1006,1015,2000,2999,5000,65535] do
    bad (Connection.closePayload (some code)) "reserved close code encoded"
  bad (Connection.closePayload none "reason".toUTF8) "reason without code"
  bad (Connection.closePayload (some 1000) (pattern 124)) "long close reason"
  bad (Connection.closePayload (some 1000) (bytes [0xc0])) "invalid close UTF8"
  let state ← ok Connection.State.new
  for payload in [bytes [1], bytes [3,0xed], bytes [3,0xe8,0xc0]] do
    let failed ← input state [{ opcode := .close, payload }]
    check (!(errors failed.actions).isEmpty) "malformed close accepted"
  let payload ← ok (Connection.closePayload (some 1000) "done".toUTF8)
  let emptyClose ← input state [{ opcode := .close }]
  let (emptyClosed, emptyOutput, emptyActions) ← completeOutputs emptyClose.state emptyClose.actions
  check (emptyClosed.isClosed && emptyOutput[0]!.payload.isEmpty && (closes emptyActions).head!.code.isNone) "empty close should not invent code1005 on wire"
  let received ← input state [{ opcode := .close, payload }]
  check (!received.state.isClosed && (closes received.actions).isEmpty) "closed before close write completed"
  let (closed, output, actions) ← completeOutputs received.state received.actions
  check (closed.isClosed && output.size == 1 && output[0]!.opcode == .close && output[0]!.payload == payload) "close echo"
  check ((closes actions).length == 1 && ((closes actions).head!).clean) "clean close exactly once"
  let duplicate ← input closed [{ opcode := .close, payload }]
  check duplicate.actions.isEmpty "duplicate close completion"
  let locally ← ok (state.beginClose)
  let (waiting, _, _) ← completeOutputs locally.state locally.actions
  check (!waiting.isClosed && waiting.isClosing) "local close did not await peer"
  let reply ← input waiting [{ opcode := .close, payload }]
  check (reply.state.isClosed && (closes reply.actions).length == 1) "peer close after local completion"
  let abnormal := state.finish
  check ((closes abnormal.actions).head!.code == some 1006 && (writes abnormal.actions).isEmpty) "abnormal status must stay off wire"
  check (locally.state.closeTimeout.state.isClosed) "close timeout"

private def outputTests : IO Unit := do
  let state ← ok (Connection.State.new { maxFrameBytes := 1024, maxOutputFrameBytes := 125, maxMessageBytes := 1024, maxQueuedOutputBytes := 1024, maxQueuedFrames := 8 })
  let queued ← ok (state.trySend .binary (pattern 300))
  let .queued first := queued | throw (IO.userError "initial output unexpectedly full")
  check (first.state.queuedOutputBytes == 306 && (writes first.actions).length == 1) "output debt excludes in-flight bytes"
  let duplicate := first.state.outputWritten 0
  check (duplicate.state.queuedOutputBytes == 306 && duplicate.actions.isEmpty) "historical ack returned capacity"
  let (drained, output, _) ← completeOutputs first.state first.actions
  check (drained.queuedOutputBytes == 0 && output.size == 3) "fragmented output did not drain"
  check (output[0]!.opcode == .binary && !output[0]!.fin && output[1]!.opcode == .continuation &&
    !output[1]!.fin && output[2]!.fin && output[2]!.opcode == .continuation) "outgoing fragment flags"
  check (output.foldl (fun acc frame => acc.append frame.payload) ByteArray.empty == pattern 300) "outgoing body changed"
  let bounded ← ok (Connection.State.new { maxFrameBytes := 125, maxOutputFrameBytes := 125, maxQueuedOutputBytes := 266, maxQueuedFrames := 2 })
  let .queued busy ← ok (bounded.trySend .binary (pattern 125)) | throw (IO.userError "cannot queue first bounded frame")
  let second ← ok (busy.state.trySend .text "a".toUTF8)
  match second with
  | .wouldBlock => pure ()
  | _ => throw (IO.userError "output queue exceeded limit")
  let (free, _, _) ← completeOutputs busy.state busy.actions
  let .queued _ ← ok (free.trySend .text "a".toUTF8) | throw (IO.userError "completion did not restore capacity")
  let future := first.state.outputWritten 999
  check (errors future.actions == [1002]) "future completion accepted"
  let closing ← ok (first.state.beginClose)
  let (_, actual, all) ← completeOutputs closing.state first.actions
  check (actual.size == 2 && actual[1]!.opcode == .close) "close should retain current flight but cancel unsent data"
  check ((closes all).isEmpty) "local close unexpectedly completed without peer"
  let .queued ping ← ok (state.tryControl .ping "check".toUTF8) | throw (IO.userError "cannot initiate Ping")
  let (_, controls, _) ← completeOutputs ping.state ping.actions
  check (controls.size == 1 && controls[0]!.opcode == .ping && controls[0]!.payload == "check".toUTF8) "initiated Ping"
  bad (state.tryControl .pong (pattern 126)) "large initiated Pong"
  bad (state.beginClose (some 1010)) "server initiated client-only close code"
  bad (state.trySend .text (bytes [0xff])) "invalid outbound UTF8"
  bad (state.trySend .ping ByteArray.empty) "control opcode accepted by message sender"

private def field (name value : String) : LeanNet.HTTP1.Header := { name, value := value.toUTF8 }
private def baseHeaders : Array LeanNet.HTTP1.Header := #[field "host" "example.com", field "upgrade" "websocket", field "connection" "keep-alive, Upgrade", field "sec-websocket-version" "13", field "sec-websocket-key" "dGhlIHNhbXBsZSBub25jZQ==", field "origin" "https://example.com"]
private def policy : Handshake.Policy := { originAllowed := fun value => value == some "https://example.com".toUTF8, subprotocols := #["chat", "binary"] }
private def h1 (headers : Array LeanNet.HTTP1.Header := baseHeaders) : LeanNet.HTTP1.RequestHead :=
  { method := "GET", target := "/chat".toUTF8, headers }
private def responseField (response : LeanNet.HTTP1.Response) (name : String) : Array ByteArray :=
  (response.headers.filter (fun field => field.name.toLower == name)).map (·.value)
private def without (headers : Array LeanNet.HTTP1.Header) (name : String) : Array LeanNet.HTTP1.Header :=
  headers.filter (fun header => header.name.toLower != name)

private def handshakeTests : IO Unit := do
  let digest ← ok (Handshake.acceptDigest "dGhlIHNhbXBsZSBub25jZQ==".toUTF8)
  check (digest == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".toUTF8) "RFC handshake SHA1/base64 vector"
  for (key, expected) in [("AAAAAAAAAAAAAAAAAAAAAA==", "ICX+Yqv66kxgM0FcWaLWlFLwTAI="),
      ("AAECAwQFBgcICQoLDA0ODw==", "Bz3qJYTGdOe8gUSpLosEdiLKDrk="),
      ("MDEyMzQ1Njc4OWFiY2RlZg==", "BACScCJPNqyz+UBoqMH89VmURoA=")] do
    -- Fixed vectors generated independently with Python hashlib/base64.
    let digest ← ok (Handshake.acceptDigest key.toUTF8)
    check (digest == expected.toUTF8) "independent nonce digest vector"
  let accepted ← ok (Handshake.acceptHTTP1 (h1) policy)
  check (accepted.response.status == 101 && responseField accepted.response "sec-websocket-accept" == #[digest]) "HTTP1 handshake response"
  let negotiated ← ok (Handshake.acceptHTTP1 (h1 (baseHeaders.push (field "sec-websocket-protocol" "binary, chat"))) policy)
  check (negotiated.subprotocol == some "chat") "server preference subprotocol"
  let noneSelected ← ok (Handshake.acceptHTTP1 (h1 (baseHeaders.push (field "sec-websocket-extensions" "permessage-deflate"))) policy)
  check ((responseField noneSelected.response "sec-websocket-extensions").isEmpty) "unimplemented compression negotiated"
  for value in ["permessage-deflate; =x", ", ,", "foo;bar=\"unterminated", "foo;bar=\"has space\"", "foo;bar="] do
    bad (Handshake.acceptHTTP1 (h1 (baseHeaders.push (field "sec-websocket-extensions" value))) policy) "malformed extension accepted"
  let lists ← ok (Handshake.acceptHTTP1 (h1 (baseHeaders.push (field "sec-websocket-extensions" ",foo,,bar," ) |>.push (field "sec-websocket-protocol" ",chat,,binary,"))) policy)
  check (lists.subprotocol == some "chat") "HTTP list null members must not create tokens"
  let extension ← ok (Handshake.acceptHTTP1 (h1 (baseHeaders.push (field "sec-websocket-extensions" "foo; bar=\"quoted-token\", permessage-deflate; client_max_window_bits"))) policy)
  check ((responseField extension.response "sec-websocket-extensions").isEmpty) "valid extension offer was negotiated"
  bad (Handshake.acceptHTTP1 (h1 ((without baseHeaders "host").push (field "host" ":443"))) policy) "empty hostname accepted"
  for value in ["", "=", "dGhlIHNhbXBsZSBub25jZQ", "dGhlIHNhbXBsZSBub25jZR==", "dGhlIHNhbXBsZSBub25jZQ__"] do
    bad (Handshake.acceptDigest value.toUTF8) "invalid nonce accepted"
  for head in [{ h1 with method := "POST" }, { h1 with version := "HTTP/1.0" }, h1 (without baseHeaders "host"), h1 (without baseHeaders "connection"), h1 (baseHeaders.push (field "sec-websocket-key" "dGhlIHNhbXBsZSBub25jZQ==")), h1 (baseHeaders.push (field "origin" "https://other.example")), h1 ((without baseHeaders "sec-websocket-version").push (field "sec-websocket-version" "12")), h1 (baseHeaders.push (field "sec-websocket-protocol" "chat, chat")), h1 (baseHeaders.push (field "content-length" "1")), h1 (baseHeaders.push (field "bad" "line\r\nbreak"))] do
    bad (Handshake.acceptHTTP1 head policy) "invalid HTTP1 handshake accepted"
  bad (Handshake.acceptHTTP1 (h1 (without baseHeaders "origin")) policy) "missing Origin bypassed explicit policy"
  bad (Handshake.acceptHTTP1 (h1) { policy with requireSubprotocol := true }) "required subprotocol absent"
  bad (Handshake.acceptHTTP1 (h1) { policy with subprotocols := #["bad token"] }) "invalid server policy"
  bad (Handshake.acceptHTTP1 (h1) { policy with maxHeaderBytes := 1 }) "header budget bypassed"
  let headers := #[field "sec-websocket-version" "13", field "origin" "https://example.com", field "sec-websocket-protocol" "binary, chat"]
  let head : LeanNet.HTTP2.RequestHead := { method := "CONNECT", scheme := "https".toUTF8, authority := "example.com".toUTF8, target := "/chat".toUTF8, headers, contentLength := none, protocol := some "websocket".toUTF8 }
  let h2 ← ok (Handshake.acceptHTTP2 head (some "websocket".toUTF8) policy)
  check (h2.response.status == 200 && h2.subprotocol == some "chat" &&
    (responseField h2.response "sec-websocket-accept").isEmpty &&
    (responseField h2.response "connection").isEmpty && (responseField h2.response "content-length").isEmpty) "RFC8441 handshake fields"
  let ignored ← ok (Handshake.acceptHTTP2 { head with headers := headers.push (field "sec-websocket-key" "not a nonce") }
    (some "websocket".toUTF8) policy)
  check (ignored.response.status == 200) "H2 must ignore legacy nonce"
  bad (Handshake.acceptHTTP2 { head with authority := ":443".toUTF8 } (some "websocket".toUTF8) policy) "empty H2 hostname accepted"
  bad (Handshake.acceptHTTP2 head none policy) "ordinary CONNECT accepted as WebSocket"
  bad (Handshake.acceptHTTP2 { head with method := "GET" } (some "websocket".toUTF8) policy) "non-CONNECT accepted"
  bad (Handshake.acceptHTTP2 head (some "WebSocket".toUTF8) policy) "case-sensitive protocol changed"
  bad (Handshake.acceptHTTP2 { head with headers := headers.push (field "connection" "upgrade") }
    (some "websocket".toUTF8) policy) "H2 connection-specific fields accepted"

def main : IO Unit := do
  frameTests
  connectionTests
  closeTests
  outputTests
  handshakeTests
  IO.println "WebSocket frame/connection/handshake tests passed"
