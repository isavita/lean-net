import LeanNet.HTTP2.Connection

open LeanNet.HTTP2
set_option maxRecDepth 8192

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
private def b32 (n : Nat) : ByteArray := ByteArray.mk #[UInt8.ofNat (n / 16777216), UInt8.ofNat (n / 65536), UInt8.ofNat (n / 256), UInt8.ofNat n]
private def raw (kind flags : UInt8) (id : UInt32) (payload : ByteArray) : ByteArray :=
  (ByteArray.mk #[UInt8.ofNat (payload.size / 65536), UInt8.ofNat (payload.size / 256), UInt8.ofNat payload.size, kind, flags]).append ((b32 id.toNat).append payload)
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
private def flatten (parts : Array ByteArray) : ByteArray := parts.foldl ByteArray.append ByteArray.empty
private def head : Array HPACK.Header := #[
  { name := ":method".toUTF8, value := "GET".toUTF8 },
  { name := ":scheme".toUTF8, value := "https".toUTF8 },
  { name := ":authority".toUTF8, value := "localhost".toUTF8 },
  { name := ":path".toUTF8, value := "/".toUTF8 }]
private def connect (config : Connection.Config := {}) : IO Connection := do
  let input := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toUTF8.append (← wire ⟨4, 0, 0, ByteArray.empty⟩)
  let (connection, _, _) ← ok ((Connection.newWithConfig config).feed input)
  return connection
private def send (connection : Connection) (frame : Frame) : IO Connection.Step := do
  let input ← wire frame
  let step := connection.feedSlice input 0 input.size
  check step.error.isNone "unexpected connection error"
  check (step.consumed == input.size) "single frame was not fully consumed"
  return step
private def requests (connection : Connection) (fields : Array (Array HPACK.Header)) : IO Connection := do
  let mut c := connection
  let mut encoder := HPACK.Context.new
  for i in [:fields.size] do
    let (nextEncoder, block) ← hp (HPACK.encode encoder fields[i]!)
    encoder := nextEncoder
    let step ← send c ⟨1, 5, UInt32.ofNat (2 * i + 1), block⟩
    check (step.requests.size == 1) "request not delivered"
    c := step.connection
  return c
private def priority (urgency : Nat) (incremental : Bool := false) : Array HPACK.Header :=
  head.push { name := "priority".toUTF8, value := s!"u={urgency}{if incremental then ", i" else ""}".toUTF8 }
private def filled (size : Nat) (value : UInt8 := 65) : ByteArray := ByteArray.mk (Array.replicate size value)
private def update (connection : Connection) (id : UInt32) (value : String) : IO Connection := do
  let step ← send connection ⟨16, 0, 0, (b32 id.toNat).append value.toUTF8⟩
  return step.connection

private def cursorAndScope : IO Unit := do
  let c ← connect { maxFramesPerStep := 2 }
  let ping ← wire ⟨6, 0, 0, filled 8⟩
  let buffer := (filled 7).append ((ping.append (ping.append ping)).append (filled 11))
  let first := c.feedSlice buffer 7 (3 * ping.size)
  check (first.consumed == 2 * ping.size && first.output.size == 2 && first.error.isNone) "frame work budget or relative slice cursor"
  let next := first.connection.feedSlice buffer (7 + first.consumed) ping.size
  check (next.consumed == ping.size && next.output.size == 1 && next.error.isNone) "remaining slice resumption"
  let badRange := c.feedSlice buffer buffer.size 1
  check (badRange.consumed == 0 && badRange.error.isSome) "invalid slice range"
  let c ← requests (← connect) #[head, head]
  let malformed := raw 8 0 1 (b32 0)
  let ping ← wire ⟨6, 0, 0, filled 8⟩
  let input := malformed.append ping
  let step := c.feedSlice input 0 input.size
  let out ← frames (flatten step.output)
  check (step.error.isNone && step.consumed == input.size && out.size == 2 && out[0]!.kind == 3 && out[0]!.streamId == 1 && out[1]!.kind == 6) "stream error lost following frame"
  check (!step.connection.canRespond 1 && step.connection.canRespond 3) "stream error canceled independent stream"
  let fatalBytes := ping.append (raw 6 0 0 (filled 7))
  let fatal := c.feedSlice fatalBytes 0 fatalBytes.size
  let out ← frames (flatten fatal.output)
  check (fatal.error.isSome && out.size == 2 && out[0]!.kind == 6 && out[1]!.kind == 7 && fatal.connection.isClosed && !fatal.connection.canRespond 3) "fatal error discarded committed control output"
  let again := fatal.connection.feedSlice ping 0 ping.size
  check (again.output.isEmpty && again.consumed == 0) "terminal error duplicated GOAWAY"

private def settingsAndBudgets : IO Unit := do
  let c ← requests (← connect) (Array.replicate 100 head)
  check (c.canRespond 199) "default rejects the recommended 100 concurrent requests"
  let config : Connection.Config := { initialWindowSize := 0, maxRequestBodyBytes := 8, maxBufferedRequestBytes := 8 }
  let c ← connect config
  let settings ← frames ((Connection.newWithConfig config).settingsFrame)
  check (settings[0]!.payload.size == 30) "configured SETTINGS missing receive or priority limits"
  let (_, block) ← hp (HPACK.encode HPACK.Context.new (head.set! 0 { name := ":method".toUTF8, value := "POST".toUTF8 }))
  let step ← send c ⟨1, 4, 1, block⟩
  let step ← send step.connection ⟨4, 1, 0, ByteArray.empty⟩
  let step ← send step.connection ⟨0, 1, 1, "x".toUTF8⟩
  let output ← frames (flatten step.output)
  check (step.requests.isEmpty && output.any (fun frame => frame.kind == 3 && frame.streamId == 1)) "acknowledged local zero receive window ignored"
  let c ← requests (← connect) #[head]
  let step ← send c ⟨4, 0, 0, (ByteArray.mk #[0,6]).append (b32 50)⟩
  match step.connection.queueResponse 1 {} with
  | .ok _ => throw (IO.userError "peer header-list budget ignored")
  | .error error => check (error.scope == .stream 1) "peer header-list error scope"
  let step ← send (← connect) ⟨4, 0, 0, ByteArray.mk #[0,9,0,0,0,0]⟩
  let changed ← wire ⟨4, 0, 0, ByteArray.mk #[0,9,0,0,0,1]⟩
  check ((step.connection.feedSlice changed 0 changed.size).error.isSome) "priority SETTINGS changed after first frame"
  let initial := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toUTF8.append
    (← wire ⟨4, 0, 0, ByteArray.mk #[0,9,0,0,0,0,0,9,0,0,0,1]⟩)
  let duplicate := Connection.new.feedSlice initial 0 initial.size
  check duplicate.error.isNone "initial SETTINGS duplicate did not use its final value"
  let changed ← wire ⟨4, 0, 0, ByteArray.mk #[0,9,0,0,0,0]⟩
  check ((duplicate.connection.feedSlice changed 0 changed.size).error.isSome) "priority SETTINGS changed after initial duplicate sequence"
  let (_, dynamic) ← hp (HPACK.encode HPACK.Context.new (head.push { name := "x-self".toUTF8, value := "value".toUTF8 }))
  let selfPayload := ((b32 1).push 0).append dynamic
  let step ← send (← connect) ⟨1, 37, 1, selfPayload⟩
  check (step.requests.isEmpty && (← frames (flatten step.output))[0]!.kind == 3) "HEADERS self-dependency not stream-local"
  let (encoder, _) ← hp (HPACK.encode HPACK.Context.new (head.push { name := "x-self".toUTF8, value := "value".toUTF8 }))
  let (_, indexed) ← hp (HPACK.encode encoder (head.push { name := "x-self".toUTF8, value := "value".toUTF8 }))
  let step ← send step.connection ⟨1, 5, 3, indexed⟩
  check (step.requests.size == 1) "self-dependent HEADERS failed to retain HPACK state"
  let c ← requests (← connect) #[head]
  let fragment ← wire ⟨1, 0, 3, ByteArray.mk #[130]⟩
  let step := c.feedSlice fragment 0 fragment.size
  let malformed := raw 2 0 1 (filled 4)
  let interleaved := step.connection.feedSlice malformed 0 malformed.size
  check (interleaved.error.any (fun error => error.scope == .connection && error.code == .protocolError)) "stream frame error bypassed CONTINUATION ordering"
  let early := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toUTF8.append malformed
  let early := Connection.new.feedSlice early 0 early.size
  check (early.error.any (fun error => error.scope == .connection && error.code == .protocolError)) "malformed stream frame bypassed mandatory initial SETTINGS"

private def bulkBodiesAndHistory : IO Unit := do
  let c ← connect { maxResetHistory := 1 }
  let post := (head.set! 0 { name := ":method".toUTF8, value := "POST".toUTF8 }).push
    { name := "content-length".toUTF8, value := "5000".toUTF8 }
  let (encoder, block) ← hp (HPACK.encode HPACK.Context.new post)
  let opened ← send c ⟨1, 4, 1, block⟩
  let bad := head.filter (fun field => field.name != ":path".toUTF8)
  let (encoder, block) ← hp (HPACK.encode encoder bad)
  let rejected ← send opened.connection ⟨1, 5, 3, block⟩
  let (encoder, block) ← hp (HPACK.encode encoder bad)
  let rejected ← send rejected.connection ⟨1, 5, 5, block⟩
  let binary := ByteArray.mk ((Array.range 5000).map UInt8.ofNat)
  let original := binary
  let first ← send rejected.connection ⟨0, 0, 1, binary.extract 0 4097⟩
  check first.requests.isEmpty "bulk body completed before END_STREAM"
  let last ← send first.connection ⟨0, 1, 1, binary.extract 4097 binary.size⟩
  let some event := last.requests[0]? | throw (IO.userError "missing bulk request")
  check (last.requests.size == 1 && event.request.body == original && binary == original) "4KiB body accumulation or active stream under reset watermark"
  let (encoder, block) ← hp (HPACK.encode encoder #[{ name := "x-retired".toUTF8, value := "retained".toUTF8 }])
  let retired ← send last.connection ⟨1, 4, 3, block⟩
  check (retired.requests.isEmpty && retired.output.isEmpty) "retired reset header block was not minimally processed"
  let (_, block) ← hp (HPACK.encode encoder (head.push { name := "x-retired".toUTF8, value := "retained".toUTF8 }))
  let next ← send retired.connection ⟨1, 5, 7, block⟩
  check (next.requests.size == 1) "reset history rollover desynchronized HPACK"
  let c ← requests (← connect) #[head]
  let response : LeanNet.HTTP1.Response := { headers := #[{ name := "X-Large", value := filled 25000 }] }
  let (_, defaultBytes) ← ok (c.queueResponse 1 response)
  let defaultFrames ← frames defaultBytes
  check (defaultFrames.size == 2 && defaultFrames[0]!.kind == 1 && defaultFrames[0]!.flags == 1 &&
    defaultFrames[1]!.kind == 9 && defaultFrames[1]!.flags == 4 && defaultFrames.all (fun frame => frame.payload.size <= 16384)) "response header fragmentation"
  let enlarged ← send c ⟨4, 0, 0, (ByteArray.mk #[0,5]).append (b32 32768)⟩
  let (_, enlargedBytes) ← ok (enlarged.connection.queueResponse 1 response)
  check ((← frames enlargedBytes).size == 1) "peer maximum frame size ignored for header output"
  let c ← requests (← connect { maxOutputBatchBytes := 20000, maxDataPerDrain := 16384 }) #[head]
  match c.queueResponse 1 {} #[{ name := "X-Large", value := filled 25000 }] with
  | .ok _ => throw (IO.userError "oversized trailing section can stall output forever")
  | .error error => check (error.scope == .stream 1) "oversized trailer budget scope"

private def receiveCreditThresholds : IO Unit := do
  let post := head.set! 0 { name := ":method".toUTF8, value := "POST".toUTF8 }
  let (_, block) ← hp (HPACK.encode HPACK.Context.new post)
  let start ← send (← connect { initialWindowSize := 16 }) ⟨1, 4, 1, block⟩
  let ack ← send start.connection ⟨4, 1, 0, ByteArray.empty⟩
  let mut smallWindow := ack.connection
  for i in [:4] do
    let step ← send smallWindow ⟨0, 0, 1, "a".toUTF8⟩
    let output ← frames (flatten step.output)
    if i < 3 then check output.isEmpty "tiny DATA emitted WINDOW_UPDATE before stream threshold"
    else check (output.size == 1 && output[0]!.kind == 8 && output[0]!.streamId == 1 && output[0]!.payload == b32 4) "stream threshold credit is not exact"
    smallWindow := step.connection
  let beforeSettings ← send (← connect { initialWindowSize := 16 }) ⟨1, 4, 1, block⟩
  let beforeAck ← send beforeSettings.connection ⟨0, 0, 1, filled 10000⟩
  check beforeAck.output.isEmpty "pre-ACK receive threshold changed too early"
  let acknowledged ← send beforeAck.connection ⟨4, 1, 0, ByteArray.empty⟩
  let updates ← frames (flatten acknowledged.output)
  check (updates.size == 1 && updates[0]!.kind == 8 && updates[0]!.streamId == 1 && updates[0]!.payload == b32 10000) "ACK window reduction stranded consumed credit"
  let resumed ← send acknowledged.connection ⟨0, 0, 1, filled 16⟩
  check (resumed.requests.isEmpty && (← frames (flatten resumed.output)).all (fun frame => frame.kind == 8)) "ACK reduction credit failed to restore incoming DATA"
  let start ← send (← connect) ⟨1, 4, 1, block⟩
  let below ← send start.connection ⟨0, 0, 1, filled 16382⟩
  check below.output.isEmpty "connection credit returned below quarter-window threshold"
  let threshold ← send below.connection ⟨0, 0, 1, "a".toUTF8⟩
  let output ← frames (flatten threshold.output)
  check (output.size == 2 && output.all (fun frame => frame.kind == 8 && frame.payload == b32 16383)) "connection/stream quarter-window credits are not exact"
  let (encoder, firstBlock) ← hp (HPACK.encode HPACK.Context.new post)
  let first ← send (← connect) ⟨1, 4, 1, firstBlock⟩
  let (_, secondBlock) ← hp (HPACK.encode encoder post)
  let second ← send first.connection ⟨1, 4, 3, secondBlock⟩
  let consumed ← send second.connection ⟨0, 0, 1, filled 8000⟩
  check consumed.output.isEmpty "early connection credit on partial request"
  let (c, _) ← ok (consumed.connection.cancel 1)
  let discarded ← send c ⟨0, 0, 1, filled 5000⟩
  check discarded.output.isEmpty "discarded credit was returned before aggregate threshold"
  let other ← send discarded.connection ⟨0, 0, 3, filled 3383⟩
  let output ← frames (flatten other.output)
  check (output.size == 1 && output[0]!.streamId == 0 && output[0]!.payload == b32 16383) "cancel/discard lost aggregate connection credit"
  let last ← send other.connection ⟨0, 1, 3, filled 1⟩
  check (last.output.isEmpty && last.requests.size == 1) "END_STREAM emitted unnecessary stream credit"

private def scheduling : IO Unit := do
  let c ← requests (← connect) #[priority 7, priority 0]
  let (c, _) ← ok (c.queueResponse 1 { body := filled 40000 1 })
  let (c, _) ← ok (c.queueResponse 3 { body := filled 40000 3 })
  let (_, out) ← ok c.drain
  let output ← frames out
  check (output[0]!.streamId == 3 && output[1]!.streamId == 3 && output[2]!.streamId == 3) "higher urgency body not prioritized"
  let c ← requests (← connect) #[head, head]
  let (c, _) ← ok (c.queueResponse 1 { body := filled 20000 })
  let (c, _) ← ok (c.queueResponse 3 { body := filled 20000 })
  let (_, out) ← ok c.drain
  let output ← frames out
  check (output.size == 4 && output[0]!.streamId == 1 && output[1]!.streamId == 1 && output[2]!.streamId == 3) "nonincremental bodies did not serialize"
  let c ← requests (← connect) #[priority 3 true, priority 3 true]
  let (c, _) ← ok (c.queueResponse 1 { body := filled 30000 })
  let (c, _) ← ok (c.queueResponse 3 { body := filled 30000 })
  let (_, out) ← ok c.drain
  let output ← frames out
  check (output.size == 4 && output[0]!.streamId == 1 && output[1]!.streamId == 3 && output[2]!.streamId == 1 && output[3]!.streamId == 3) "incremental bodies did not interleave"
  let c ← requests (← connect) #[head, priority 3 true]
  let (c, _) ← ok (c.queueResponse 1 { body := filled 200000 })
  let (c, _) ← ok (c.queueResponse 3 { body := filled 200000 })
  let (c, _) ← ok c.drain
  let step ← send c ⟨8, 0, 0, b32 65536⟩
  let step ← send step.connection ⟨8, 0, 1, b32 65536⟩
  let (c, first) ← ok step.connection.drain
  let (c, second) ← ok c.drain
  let output ← frames (first.append second)
  check (output.any (fun frame => frame.streamId == 3)) "incremental response starved behind serial body"
  let mixed ← requests (← connect) #[head, priority 3 true, priority 3 true]
  let (mixed, _) ← ok (mixed.queueResponse 1 { body := filled 200000 })
  let (mixed, _) ← ok (mixed.queueResponse 3 { body := filled 200000 })
  let (mixed, _) ← ok (mixed.queueResponse 5 { body := filled 200000 })
  let mut mixedConnection := mixed
  let mut incrementalIds : Array UInt32 := #[]
  for turn in [:3] do
    if turn > 0 then
      let credit ← send mixedConnection ⟨8, 0, 0, b32 65536⟩
      let credit ← send credit.connection ⟨8, 0, 1, b32 65536⟩
      mixedConnection := credit.connection
    let (next, bytes) ← ok mixedConnection.drain
    for frame in (← frames bytes) do
      if frame.streamId == 3 || frame.streamId == 5 then incrementalIds := incrementalIds.push frame.streamId
    mixedConnection := next
  check (incrementalIds.contains 3 && incrementalIds.contains 5) "serial bursts reset incremental round-robin cursor and starved a peer"
  let interrupted ← requests (← connect { maxDataPerDrain := 1 }) #[priority 0 true, priority 3 true, priority 3 true]
  let (interrupted, _) ← ok (interrupted.queueResponse 1 { body := filled 1 })
  let (interrupted, _) ← ok (interrupted.queueResponse 3 { body := filled 100 })
  let (interrupted, _) ← ok (interrupted.queueResponse 5 { body := filled 100 })
  let (interrupted, highWire) ← ok interrupted.drain
  check ((← frames highWire)[0]!.streamId == 1) "initial urgent frame missing"
  let (interrupted, lowWire) ← ok interrupted.drain
  check ((← frames lowWire)[0]!.streamId == 3) "initial lower-urgency turn missing"
  let (_, urgentBlock) ← hp (HPACK.encode HPACK.Context.new (priority 0 true))
  let urgent ← send interrupted ⟨1, 5, 7, urgentBlock⟩
  let (interrupted, _) ← ok (urgent.connection.queueResponse 7 { body := filled 1 })
  let (interrupted, highWire) ← ok interrupted.drain
  check ((← frames highWire)[0]!.streamId == 7) "urgent interruption missing"
  let (_, lowWire) ← ok interrupted.drain
  check ((← frames lowWire)[0]!.streamId == 5) "urgent interruption reset lower-urgency round-robin cursor"
  let burstBase ← requests (← connect { maxDataPerDrain := 32768 }) #[head, priority 3 true]
  let (burstBase, _) ← ok (burstBase.queueResponse 1 { body := filled 200000 })
  let (burstBase, _) ← ok (burstBase.queueResponse 3 { body := filled 200000 })
  let mut interruptedBurst := burstBase
  let mut sawIncremental := false
  for turn in [:4] do
    let (_, urgentBlock) ← hp (HPACK.encode HPACK.Context.new (priority 0 true))
    let urgentId := UInt32.ofNat (5 + 2 * turn)
    let urgent ← send interruptedBurst ⟨1, 5, urgentId, urgentBlock⟩
    let (next, _) ← ok (urgent.connection.queueResponse urgentId { body := filled 1 })
    interruptedBurst := next
    if turn > 0 then
      let credit ← send interruptedBurst ⟨8, 0, 0, b32 32768⟩
      let credit ← send credit.connection ⟨8, 0, 1, b32 32768⟩
      interruptedBurst := credit.connection
    let (next, bytes) ← ok interruptedBurst.drain
    sawIncremental := sawIncremental || (← frames bytes).any (fun frame => frame.streamId == 3)
    interruptedBurst := next
  check sawIncremental "urgent interruptions reset serial burst accounting and starved incremental peer"
  let c ← update c 3 "u=0, i"
  let step ← send c ⟨8, 0, 0, b32 16384⟩
  let (_, out) ← ok step.connection.drain
  check ((← frames out)[0]!.streamId == 3) "PRIORITY_UPDATE not applied at credit refill"
  let c ← update (← connect { maxConcurrentStreams := 2 }) 3 "u=0"
  let c ← update c 5 "u=1"
  let overflow ← wire ⟨16, 0, 0, (b32 7).append "u=2".toUTF8⟩
  check ((c.feedSlice overflow 0 overflow.size).error.isSome) "idle priority budget not enforced"
  let idlePush ← wire ⟨16, 0, 0, (b32 2).append "u=2".toUTF8⟩
  let c ← connect
  check ((c.feedSlice idlePush 0 idlePush.size).error.isSome) "idle push priority target accepted"
  let c ← requests (← connect) #[head]
  let (c, _) ← ok (c.queueResponse 1 {})
  let c ← update c 1 "u=0"
  check (!c.isClosed) "closed priority update changed connection lifetime"

private def pushAndDrain : IO Unit := do
  let c ← requests (← connect) #[head]
  check (!c.canPush) "server push enabled by default"
  let c ← requests (← connect { enablePush := true }) #[head]
  check c.canPush "opt-in push unavailable"
  let (c, output, id) ← ok (c.pushPath 1 "/asset".toUTF8 #[{ name := "cookie", value := "secret".toUTF8 }] { body := "asset".toUTF8 })
  let output ← frames output
  check (id == 2 && output.size == 2 && output[0]!.kind == 5 && output[0]!.streamId == 1 && output[1]!.streamId == 2 && output.all (fun frame => frame.kind != 0)) "push ID/reservation or eager DATA"
  let (decoder, promised) ← hp (HPACK.decode HPACK.Context.new (output[0]!.payload.extract 4 output[0]!.payload.size))
  check (promised.any (fun h => h.name == ":path".toUTF8 && h.value == "/asset".toUTF8) && promised.any (fun h => h.name == "cookie".toUTF8 && h.sensitive)) "invalid or indexed sensitive promise"
  let (_, fields) ← hp (HPACK.decode decoder output[1]!.payload)
  check (fields.any (fun h => h.name == ":status".toUTF8 && h.value == "200".toUTF8)) "push response HPACK state"
  let step ← send c ⟨3, 0, 2, b32 8⟩
  check (!step.connection.hasPendingOutput && step.connection.canRespond 1) "push cancellation canceled parent or retained body"
  let step ← send step.connection ⟨4, 0, 0, ByteArray.mk #[0,2,0,0,0,0]⟩
  check (!step.connection.canPush) "peer disabled push ignored"
  let c ← requests (← connect { enablePush := true }) #[head]
  let step ← send c ⟨4, 0, 0, ByteArray.mk #[0,3,0,0,0,0]⟩
  check (!step.connection.canPush) "peer concurrent push limit ignored"
  let c ← requests (← connect { enablePush := true }) #[head]
  let (c, _, _) ← ok (c.pushPath 1 "/asset".toUTF8 #[] { body := "asset".toUTF8 })
  let step ← send c ⟨7, 0, 0, (b32 0).append (b32 0)⟩
  check (!step.connection.hasPendingOutput && !step.connection.canPush && step.connection.canRespond 1) "peer GOAWAY did not cancel unprocessed push independently"
  let (c, goAway) ← ok step.connection.beginGoAway
  check ((← frames goAway).size == 1 && c.draining && !c.drainComplete) "graceful GOAWAY state"
  let (_, block) ← hp (HPACK.encode HPACK.Context.new head)
  let late ← send c ⟨1, 5, 3, block⟩
  check (late.requests.isEmpty && late.connection.canRespond 1 && (← frames (flatten late.output))[0]!.kind == 3) "GOAWAY accepted new request or lost active one"
  let (c, _) ← ok (late.connection.queueResponse 1 {})
  check (c.drainComplete && c.isClosed) "graceful drain did not complete"

private def peerGoAwayControlLiveness : IO Unit := do
  for code in #[0, 255] do
    let c ← connect { enablePush := true }
    let received ← send c ⟨7, 0, 0, (b32 0).append (b32 code)⟩
    check (received.connection.draining && !received.connection.drainComplete &&
      !received.connection.isClosed && !received.connection.canPush) "peer-only GOAWAY prematurely closes an idle connection"
    let ping := filled 8 80
    let answered ← send received.connection ⟨6, 0, 0, ping⟩
    let output ← frames (flatten answered.output)
    check (output.size == 1 && output[0]!.kind == 6 && output[0]!.flags == 1 &&
      output[0]!.payload == ping && !answered.connection.drainComplete) "PING after peer GOAWAY was not acknowledged on a live connection"
    let (_, block) ← hp (HPACK.encode HPACK.Context.new head)
    let rejected ← send answered.connection ⟨1, 5, 1, block⟩
    let output ← frames (flatten rejected.output)
    check (rejected.requests.isEmpty && output.size == 1 && output[0]!.kind == 3 &&
      output[0]!.payload == b32 7 && !rejected.connection.drainComplete) "peer-GOAWAY draining policy accepted a new request or closed control traffic"
    let ended := rejected.connection.finish
    let output ← frames (flatten ended.output)
    check (ended.error.isNone && ended.connection.drainComplete && ended.connection.isClosed &&
      output.any (fun frame => frame.kind == 7 && frame.payload.extract 4 8 == b32 0)) "peer EOF after GOAWAY did not complete the drain with our own GOAWAY"
    let (locallyDraining, output) ← ok received.connection.beginGoAway
    check (locallyDraining.drainComplete && locallyDraining.isClosed && (← frames output).any (fun frame => frame.kind == 7)) "local GOAWAY did not finish an empty peer drain"

private def responseAndEOF : IO Unit := do
  let date := "Sun, 06 Nov 1994 08:49:37 GMT".toUTF8
  let c ← requests ((← connect).setDate date) #[head]
  let (c, info) ← ok (c.informational 1 { status := 103, headers := #[{ name := "Link", value := "</x>".toUTF8 }] })
  let info ← frames info
  check (info[0]!.flags == 4 && c.canRespond 1) "informational response ended stream"
  let (decoder, fields) ← hp (HPACK.decode HPACK.Context.new info[0]!.payload)
  check (fields.any (fun h => h.name == "date".toUTF8 && h.value == date)) "informational Date cache missing"
  let (c, headers) ← ok (c.queueResponse 1 { body := "body".toUTF8 } #[{ name := "X-Checksum", value := "sum".toUTF8 }, { name := "Set-Cookie", value := "secret".toUTF8 }])
  let headers ← frames headers
  let (decoder, fields) ← hp (HPACK.decode decoder headers[0]!.payload)
  check (fields.any (fun h => h.name == "date".toUTF8 && h.value == date)) "final Date cache missing"
  let (c, output) ← ok c.drain
  let output ← frames output
  check (output.size == 2 && output[0]!.kind == 0 && output[0]!.flags == 0 && output[1]!.kind == 1 && output[1]!.flags == 5 && !c.hasPendingOutput) "trailing HEADERS ordering or END_STREAM"
  let (_, trailing) ← hp (HPACK.decode decoder output[1]!.payload)
  check (trailing.any (fun h => h.name == "set-cookie".toUTF8 && h.sensitive)) "trailer credentials were indexed"
  let changedLimit ← requests (← connect) #[head, head]
  let (changedLimit, _) ← ok (changedLimit.queueResponse 1 { body := "one".toUTF8 }
    #[{ name := "X-End", value := "yes".toUTF8 }])
  let (changedLimit, _) ← ok (changedLimit.queueResponse 3 { body := "three".toUTF8 })
  let limited ← send changedLimit ⟨4, 0, 0, (ByteArray.mk #[0,6]).append (b32 0)⟩
  let (_, out) ← ok limited.connection.drain
  let output ← frames out
  check (output.size == 2 && output[0]!.kind == 3 && output[0]!.streamId == 1 && output[1]!.kind == 0 && output[1]!.streamId == 3 && output[1]!.payload == "three".toUTF8) "changed peer trailer limit broke an independent response"
  let blocked ← requests (← connect) #[head]
  let blocked ← send blocked ⟨4, 0, 0, ByteArray.mk #[0,4,0,0,0,0]⟩
  let (blocked, _) ← ok (blocked.connection.queueResponse 1 { body := "body".toUTF8 }
    #[{ name := "X-End", value := "yes".toUTF8 }])
  let limited ← send blocked ⟨4, 0, 0, (ByteArray.mk #[0,6]).append (b32 0)⟩
  check limited.connection.canDrain "invalidated trailers cannot reset a zero-window stream"
  let (closed, out) ← ok limited.connection.drain
  check ((← frames out)[0]!.kind == 3 && !closed.hasPendingOutput) "zero-window changed trailer limit stalled forever"
  let c ← requests (← connect) #[head]
  let step ← send c ⟨4, 0, 0, ByteArray.mk #[0,4,0,0,0,0]⟩
  let (c, _) ← ok (step.connection.queueResponse 1 {} #[{ name := "X-End", value := "yes".toUTF8 }])
  check c.canDrain "zero-window empty trailers cannot make progress"
  let (c, out) ← ok c.drain
  check ((← frames out).size == 1 && !c.hasPendingOutput) "zero-window trailers missing"
  let c ← requests (← connect) #[head]
  let eof := c.finish
  check (eof.error.isNone && eof.connection.canRespond 1 && eof.connection.draining) "EOF discarded accepted request"
  let (c, _) ← ok (eof.connection.queueResponse 1 {})
  check c.drainComplete "EOF response failed to drain"
  let (_, block) ← hp (HPACK.encode HPACK.Context.new head)
  let step ← send (← connect) ⟨1, 4, 1, block⟩
  let eof := step.connection.finish
  check (eof.error.isNone && eof.connection.drainComplete && (← frames (flatten eof.output)).any (fun frame => frame.kind == 3)) "incomplete request EOF not canceled"
  let c ← connect
  let fragment := c.feedSlice (raw 6 0 0 (filled 8)) 0 4
  check fragment.connection.finish.error.isSome "truncated frame EOF accepted"

def main : IO Unit := do
  cursorAndScope
  settingsAndBudgets
  bulkBodiesAndHistory
  receiveCreditThresholds
  scheduling
  pushAndDrain
  peerGoAwayControlLiveness
  responseAndEOF
  IO.println "HTTP/2 connection V2 tests passed"
