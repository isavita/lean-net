import LeanNet.HTTP2.Machine

open LeanNet LeanNet.HTTP2

private def check (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)
private def ok (value : Except ProtocolError α) : IO α := do
  match value with
  | .ok result => return result
  | .error error => throw (IO.userError (reprStr error))
private def encoded (frame : Frame) : IO ByteArray := ok (frame.encode 16777215)
private def settings : IO ByteArray := encoded ⟨4, 0, 0, ByteArray.empty⟩
private def input (state : Machine.State) (bytes : ByteArray) : Machine.Step :=
  state.feedSlice bytes 0 bytes.size
private def preface : ByteArray := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toUTF8
private def config : Connection.Config := { pingIntervalMs := 100, pingTimeoutMs := 30 }

private def boot (cfg : Connection.Config := config) : IO Machine.State := do
  let state := ((Machine.State.new cfg).setTime 1000).start.state
  let step := input state (preface ++ (← settings))
  check (step.consumed == preface.size + 9 && step.state.wantsInput) "valid peer setup"
  return step.state

private def ping (step : Machine.Step) : IO (UInt64 × ByteArray) := do
  match step.actions.filterMap (fun | .writePing nonce bytes => some (nonce, bytes) | _ => none) with
  | [(nonce, bytes)] =>
    match (FrameParser.new).feedSlice bytes 0 bytes.size with
    | .complete frame consumed =>
      check (consumed == 17 && bytes.size == 17 && frame.kind == 6 && frame.streamId == 0 &&
        frame.flags == 0 && frame.payload.size == 8) "PING control frame layout"
      let decoded := frame.payload.foldl (fun n byte => n * 256 + byte.toNat) 0
      check (decoded == nonce.toNat && nonce != 0) "nonce is exact big-endian eight bytes"
    | _ => throw (IO.userError "PING frame did not parse")
    check (!step.actions.any (fun | .request _ | .requestStarted .. | .writeObserved _ => true | _ => false))
      "control PING created a request/log observation"
    return (nonce, bytes)
  | _ => throw (IO.userError "expected exactly one PING")

private def ack (bytes : ByteArray) : ByteArray :=
  bytes.set! 4 1

private def outputFrames (step : Machine.Step) : IO (Array Frame) := do
  let bytes := step.actions.foldl (fun out action => match action with
    | .write parts => parts.foldl ByteArray.append out
    | .writePing _ bytes => out ++ bytes
    | _ => out) ByteArray.empty
  let mut cursor := 0
  let mut frames := #[]
  for _ in [:bytes.size + 1] do
    if cursor == bytes.size then break
    match (FrameParser.new 16777215).feedSlice bytes cursor (bytes.size - cursor) with
    | .complete frame consumed => frames := frames.push frame; cursor := cursor + consumed
    | _ => throw (IO.userError "output frame invalid")
  return frames

private def request (id : UInt32) (ended : Bool := false) : IO ByteArray := do
  let fields : Array HPACK.Header := #[
    { name := ":method".toUTF8, value := "GET".toUTF8 },
    { name := ":scheme".toUTF8, value := "http".toUTF8 },
    { name := ":authority".toUTF8, value := "example.test".toUTF8 },
    { name := ":path".toUTF8, value := "/keepalive".toUTF8 }]
  let block ← match HPACK.encode HPACK.Context.new fields with
    | .ok (_, block) => pure block
    | .error error => throw (IO.userError error)
  encoded ⟨1, if ended then 5 else 4, id, block⟩

private def lifecycle : IO Unit := do
  let raw := ((Machine.State.new config).setTime 1000).start
  check raw.state.keepaliveDeadline.isNone "keepalive armed before client preface"
  check ((raw.state.pingTimer 5000).actions.isEmpty) "PING sent before client preface"
  let part := input raw.state (preface.extract 0 10)
  check part.state.keepaliveDeadline.isNone "partial preface armed keepalive"
  let complete := input part.state (preface.extract 10 preface.size)
  check complete.state.keepaliveDeadline.isNone "missing first SETTINGS armed keepalive"
  let ready := input complete.state (← settings)
  check (ready.state.keepaliveDeadline == some 1100) "first interval starts at protocol readiness"
  check ((ready.state.pingTimer 1099).actions.isEmpty) "early timer emitted PING"
  let queued := ready.state.pingTimer 1100
  let (nonce, bytes) ← ping queued
  check queued.state.keepaliveDeadline.isNone "ACK deadline started while PING was only queued"
  check ((queued.state.pingTimer 5000).actions.isEmpty) "queued probe duplicated or timed out without WN"
  let written := queued.state.pingWritten nonce 5000
  check (written.state.keepaliveDeadline == some 5030) "physical WN did not start absolute ACK timeout"
  let duplicate := written.state.pingWritten nonce 5010
  check (duplicate.state.keepaliveDeadline == some 5030) "duplicate WN extended ACK deadline"
  let stale := duplicate.state.pingWritten (nonce + 1) 5015
  check (stale.state.keepaliveDeadline == some 5030) "wrong WN changed current probe"
  check ((stale.state.pingTimer 5029).actions.isEmpty) "ACK timer fired early"
  let received := input (stale.state.setTime 5029) (ack bytes)
  check (received.state.keepaliveDeadline == some 5129 && received.actions.isEmpty) "matching ACK did not schedule next periodic probe"
  let next := received.state.pingTimer 5129
  let (nextNonce, _) ← ping next
  check (nextNonce != nonce) "nonce reused"
  let old := next.state.pingWritten nonce 5130
  check old.state.keepaliveDeadline.isNone "old WN armed timeout on newer queued probe"

private def earlyAndStale : IO Unit := do
  let queued := (← boot).pingTimer 1100
  let (nonce, bytes) ← ping queued
  let early := input (queued.state.setTime 1101) (ack bytes)
  check (early.state.keepaliveDeadline == some 1201) "ACK before WN did not clear queued probe"
  let late := early.state.pingWritten nonce 1190
  check (late.state.keepaliveDeadline == some 1201) "late old WN changed next interval"
  let next := late.state.pingTimer 1201
  let (freshNonce, freshBytes) ← ping next
  let fresh := next.state.pingWritten freshNonce 1202
  let stale := input (fresh.state.setTime 1203) (ack bytes)
  check (stale.state.keepaliveDeadline == some 1232) "stale ACK cleared newer probe"
  let split := ack freshBytes
  let fragment := input stale.state (split.extract 0 12)
  check (fragment.state.keepaliveDeadline == some 1232) "partial ACK cleared probe"
  let full := input (fragment.state.setTime 1204) (split.extract 12 split.size)
  check (full.state.keepaliveDeadline == some 1304) "fragmented ACK was not matched"
  let duplicate := input (full.state.setTime 1210) split
  check (duplicate.state.keepaliveDeadline == some 1304) "duplicate ACK extended next interval"

private def timeoutAndDisable : IO Unit := do
  let state ← boot { config with trackOutput := true }
  let started := input state (← request 1)
  let active := input started.state (← request 3 true)
  let queued := active.state.pingTimer 1100
  let (nonce, _) ← ping queued
  let timed := (queued.state.pingWritten nonce 1101).state.pingTimer 1131
  let frames ← outputFrames timed
  check (!timed.state.wantsInput && timed.state.keepaliveDeadline.isNone &&
    frames.size == 1 && frames[0]!.kind == 7 && frames[0]!.payload[7]! == 1)
    "timeout did not emit protocol-error GOAWAY and close"
  check ((timed.actions.filterMap (fun | .responseAborted id .timeout => some id | _ => none)) == [1, 3])
    "PING timeout did not mark live request outcomes"
  check (timed.actions.any (fun | .drainClose => true | _ => false)) "PING timeout omitted drain-close"
  check ((timed.state.pingTimer 9999).actions.isEmpty) "closed probe repeated timeout"
  for state in [active.state.goAway.state, active.state.finish.state] do
    check (state.keepaliveDeadline.isNone && (state.pingTimer 5000).actions.isEmpty) "GOAWAY/EOF kept probes enabled"
  let peerGoAway ← encoded ⟨7, 0, 0, ByteArray.mk #[0,0,0,0,0,0,0,0]⟩
  let peer := input active.state peerGoAway
  check (peer.state.keepaliveDeadline.isNone && (peer.state.pingTimer 5000).actions.isEmpty)
    "peer GOAWAY kept probes enabled"

private def activityAndValidation : IO Unit := do
  let state ← boot
  let active := input (state.setTime 1090) (← request 1)
  check (active.state.keepaliveDeadline == some 1100) "request activity postponed periodic probe"
  let bytes ← encoded ⟨6, 0, 0, ByteArray.mk #[1,2,3,4,5,6,7,8]⟩
  let echoed := input (active.state.setTime 1095) bytes
  check (echoed.state.keepaliveDeadline == some 1100 && (← outputFrames echoed).size == 1)
    "peer PING activity postponed server probe or was not acknowledged"
  let disabled ← boot {}
  check (disabled.keepaliveDeadline.isNone && (disabled.pingTimer 999999).actions.isEmpty) "default-off changed behavior"
  for cfg in [({ pingIntervalMs := 1, pingTimeoutMs := 0 } : Connection.Config),
      { pingIntervalMs := 9223372036854775808 }, { pingTimeoutMs := 9223372036854775808 }] do
    check (match cfg.validate with | .error _ => true | .ok _ => false) "invalid PING duration accepted"
  let overflow := input (((Machine.State.new config).setTime 9223372036854775800).start.state) (preface ++ (← settings))
  check (!overflow.state.wantsInput && overflow.state.keepaliveDeadline.isNone) "deadline clock addition overflow accepted"
  let hugeTimeout := (← boot { config with pingTimeoutMs := 9223372036854775807 }).pingTimer 1100
  let (nonce, _) ← ping hugeTimeout
  check (!(hugeTimeout.state.pingWritten nonce 1100).state.wantsInput) "physical-write ACK deadline overflow accepted"
  let badAck := ack bytes |>.extract 0 16
  let incomplete := input state badAck
  check (incomplete.state.keepaliveDeadline == some 1100) "incomplete ACK changed timer"

private def acknowledgedMetadata : IO Unit := do
  let initial := Connection.newWithConfig config
  let setup := initial.feedSlice (preface ++ (← settings)) 0 (preface.size + 9)
  let bytes ← encoded ⟨6, 1, 0, ByteArray.mk #[255,254,253,252,251,250,249,248]⟩
  let result := setup.connection.feedSlice bytes 0 bytes.size
  check (result.error.isNone && result.pingAcks == #[18446460386757245432] && result.output.isEmpty)
    "validated ACK payload metadata lost high bits"
  let invalid ← encoded ⟨6, 1, 0, ByteArray.mk #[1,2,3,4,5,6,7,8]⟩
  let invalid := (invalid.set! 2 7).extract 0 16
  let bad := setup.connection.feedSlice invalid 0 invalid.size
  check (bad.error.isSome && bad.pingAcks.isEmpty) "malformed ACK produced metadata"
  let coalesced := bytes ++ invalid
  let mixed := setup.connection.feedSlice coalesced 0 coalesced.size
  check (mixed.error.isSome && mixed.pingAcks == result.pingAcks) "later frame failure discarded valid prior ACK metadata"
  let premature := (initial.feedSlice (preface ++ bytes) 0 (preface.size + bytes.size))
  check (premature.error.isSome && premature.pingAcks.isEmpty) "ACK before mandatory SETTINGS produced metadata"
  let plain := Connection.new.feedSlice (preface ++ (← settings)) 0 (preface.size + 9)
  check ((plain.connection.feedSlice bytes 0 bytes.size).pingAcks.isEmpty) "default-off path allocated ACK metadata"

private def frameBoundaries : IO Unit := do
  let state ← boot
  let requested := input state (← request 1 true)
  let response := requested.state.respond 1 { response := {
    headers := #[{ name := "x-large", value := ByteArray.mk (Array.replicate 32000 120) }], body := "body".toUTF8 } }
  let headers ← outputFrames response
  check (headers.size > 1 && headers[0]!.kind == 1 && headers[0]!.flags &&& 4 == 0 &&
    headers[headers.size - 1]!.kind == 9 && headers[headers.size - 1]!.flags &&& 4 != 0)
    "large response did not produce a complete contiguous continuation block"
  let probe := response.state.pingTimer 1100
  discard <| ping probe
  let together ← outputFrames { probe with actions := response.actions ++ probe.actions }
  check (together.size == headers.size + 1 && together[together.size - 1]!.kind == 6 &&
    (together.extract 0 headers.size).all (fun frame => frame.kind == 1 || frame.kind == 9))
    "PING interleaved an outgoing header continuation block"
  let requested := input (← boot) (← request 1 true)
  let queued := requested.state.respond 1 { response := {}, fileRegion := some { owner := 1, token := 1, length := 40000 } }
  let drained := queued.state.drain
  let probes := drained.state.pingTimer 1100
  discard <| ping probes
  match drained.actions with
  | [.writeParts parts] =>
    check (parts.size > 1 && match parts[0]?, parts[1]? with
      | some (WirePart.bytes bytes), some (WirePart.file region) => bytes.size == 9 && region.length > 0
      | _, _ => false) "file DATA header/region are not an immutable ordered action pair"
  | _ => throw (IO.userError "file output unexpectedly changed action shape")

def main : IO Unit := do
  lifecycle
  earlyAndStale
  timeoutAndDisable
  activityAndValidation
  acknowledgedMetadata
  frameBoundaries
  IO.println "HTTP/2 keepalive pure lifecycle, fences, ACK matching and timeout tests passed"
