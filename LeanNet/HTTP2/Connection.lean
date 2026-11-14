import LeanNet.HTTP2.Frame
import LeanNet.HTTP2.Stream
import LeanNet.HTTP2.HPACK
import LeanNet.HTTP2.Request
import LeanNet.HTTP1.Response

namespace LeanNet.HTTP2

/-- A completed HTTP/2 request for the shared application router. -/
structure RequestEvent where
  streamId : UInt32
  request : HTTP1.Request

private structure PendingResponse where
  body : ByteArray
  offset : Nat := 0

private structure Exchange where
  stream : Stream
  head : Option RequestHead := none
  bodyBlocks : List ByteArray := []
  bodyRev : List UInt8 := []
  bodyBlockSize : Nat := 0
  bodySize : Nat := 0
  trailers : Array HTTP1.Header := #[]
  pending : Option PendingResponse := none
  delivered : Bool := false
  startedAt : Nat := 0

private structure HeaderAssembly where
  streamId : UInt32
  fragments : List ByteArray := []
  blockSize : Nat := 0
  fragmentCount : Nat := 1
  endStream : Bool
  reject : Option ErrorCode := none
  discard : Bool := false

/-- Server-side HTTP/2 connection state. All budgets are deliberately bounded. -/
structure Connection where
  private prefaceRead : Nat := 0
  private parser : FrameParser := FrameParser.new
  private peerSettings : Bool := false
  private awaitingAck : Bool := true
  private decoder : HPACK.Context := HPACK.Context.new
  private encoder : HPACK.Context := HPACK.Context.new
  private peerInitialWindow : Nat := defaultWindow
  private peerFrameSize : Nat := 16384
  private flow : Flow := {}
  private streams : Array Exchange := #[]
  private highestStream : UInt32 := 0
  private resetStreams : Array UInt32 := #[]
  private lastDrained : UInt32 := 0
  private processedStream : UInt32 := 0
  private assembly : Option HeaderAssembly := none
  private peerGoAway : Bool := false
  private now : Nat := 0
  private currentDate : Option ByteArray := none

def Connection.new : Connection := {}

private def connError (code : ErrorCode) (message : String) : ProtocolError :=
  ⟨code, .connection, message⟩
private def streamError (id : UInt32) (code : ErrorCode) (message : String) : ProtocolError :=
  ⟨code, .stream id, message⟩
private def flag (value mask : UInt8) : Bool := (value &&& mask) != 0
private def u32 (value : UInt32) : ByteArray := Id.run do
  let n := value.toNat
  return ByteArray.mk #[UInt8.ofNat (n / 16777216), UInt8.ofNat (n / 65536), UInt8.ofNat (n / 256), UInt8.ofNat n]
private def readU32 (payload : ByteArray) (offset : Nat := 0) : Nat :=
  (payload[offset]!).toNat * 16777216 + (payload[offset + 1]!).toNat * 65536 +
    (payload[offset + 2]!).toNat * 256 + (payload[offset + 3]!).toNat
private def wire (frame : Frame) : Except ProtocolError ByteArray := frame.encode 16777215
private def rst (id : UInt32) (code : ErrorCode) : Except ProtocolError ByteArray :=
  wire ⟨3, 0, id, u32 code.toUInt32⟩
private def windowUpdate (id : UInt32) (size : Nat) : Except ProtocolError ByteArray :=
  wire ⟨8, 0, id, u32 (UInt32.ofNat size)⟩

/-- The server's initial SETTINGS frame. Send once immediately after recognizing
    the client preface. -/
def Connection.initialSettings : ByteArray :=
  ByteArray.mk #[0,0,12,4,0,0,0,0,0, 0,3,0,0,0,32, 0,6,0,1,0,0]

/-- Fatal connection errors are reported with a GOAWAY using the last request
    stream handed to the application. -/
def Connection.goAway (connection : Connection) (error : ProtocolError) : ByteArray :=
  match wire ⟨7, 0, 0, (u32 connection.processedStream).append (u32 error.code.toUInt32)⟩ with
  | .ok result => result
  | .error _ => ByteArray.empty

private def findStream (connection : Connection) (id : UInt32) : Option Exchange :=
  connection.streams.find? (fun entry => entry.stream.id == id)
private def putStream (connection : Connection) (entry : Exchange) : Connection :=
  { connection with streams := connection.streams.map (fun previous => if previous.stream.id == entry.stream.id then entry else previous) }
private def removeStream (connection : Connection) (id : UInt32) : Connection :=
  { connection with streams := connection.streams.filter (fun entry => entry.stream.id != id) }

/-- A complete request may have been canceled by a later frame in the same
    read. Routers should dispatch only while this predicate remains true. -/
def Connection.canRespond (connection : Connection) (id : UInt32) : Bool :=
  match findStream connection id with
  | some entry => entry.delivered && entry.pending.isNone
  | none => false

private def markReset (connection : Connection) (id : UInt32) : Except ProtocolError Connection := do
  let connection := removeStream connection id
  if connection.resetStreams.contains id then return connection
  if connection.resetStreams.size >= 256 then
    throw (connError .enhanceYourCalm "too many reset streams")
  return { connection with resetStreams := connection.resetStreams.push id }

private def resetStream (connection : Connection) (id : UInt32) (code : ErrorCode) :
    Except ProtocolError (Connection × ByteArray × Array RequestEvent) := do
  return (← markReset connection id, ← rst id code, #[])

private def appendBody (entry : Exchange) (data : ByteArray) : Exchange := Id.run do
  let mut entry := entry
  for byte in data do
    let rev := byte :: entry.bodyRev
    if entry.bodyBlockSize + 1 == 4096 then
      entry := { entry with bodyBlocks := ByteArray.mk rev.reverse.toArray :: entry.bodyBlocks,
                            bodyRev := [], bodyBlockSize := 0, bodySize := entry.bodySize + 1 }
    else
      entry := { entry with bodyRev := rev, bodyBlockSize := entry.bodyBlockSize + 1,
                            bodySize := entry.bodySize + 1 }
  return entry

private def bodyBytes (entry : Exchange) : ByteArray := Id.run do
  let mut body := ByteArray.empty
  for block in entry.bodyBlocks.reverse do body := body.append block
  return body.append (ByteArray.mk entry.bodyRev.reverse.toArray)

private def finishRequest (connection : Connection) (entry : Exchange) : Except ProtocolError (Connection × Array RequestEvent) := do
  let some head := entry.head | throw (streamError entry.stream.id .protocolError "DATA before request headers")
  match head.complete (bodyBytes entry) entry.trailers with
  | .error message => throw (streamError entry.stream.id .protocolError message)
  | .ok request =>
    let connection := putStream connection { entry with delivered := true, bodyBlocks := [], bodyRev := [], bodyBlockSize := 0, bodySize := 0 }
    return ({ connection with processedStream := max connection.processedStream entry.stream.id }, #[⟨entry.stream.id, request⟩])

private def headerFragment (frame : Frame) : ByteArray := Id.run do
  let mut offset := 0
  let mut padding := 0
  if flag frame.flags 8 then
    padding := (frame.payload[0]!).toNat
    offset := 1
  if flag frame.flags 32 then offset := offset + 5
  return frame.payload.extract offset (frame.payload.size - padding)

private def headerBlock (assembly : HeaderAssembly) : ByteArray := Id.run do
  let mut block := ByteArray.empty
  for fragment in assembly.fragments.reverse do
    for byte in fragment do block := block.push byte
  return block

private inductive Expectation where
  | none | continue | unsupported

private def expectation (headers : Array HTTP1.Header) : Expectation := Id.run do
  let mut result := Expectation.none
  for header in headers do
    if header.name == "expect" then
      let text := header.value.toList.map fun b =>
        if b.toNat >= 65 && b.toNat <= 90 then UInt8.ofNat (b.toNat + 32) else b
      let parts := (ByteArray.mk text.toArray).toList.splitOn 44
      for part in parts do
        let part := ((part.dropWhile (fun b => b == 32 || b == 9)).reverse.dropWhile (fun b => b == 32 || b == 9)).reverse
        if part != "100-continue".toUTF8.toList then return .unsupported
        result := .continue
  return result

private def expectationResponse (connection : Connection) (entry : Exchange)
    (status : Nat) (endStream : Bool) (remoteEnded : Bool) :
    Except ProtocolError (Connection × ByteArray × Array RequestEvent) := do
  let mut fields : Array HPACK.Header := #[{ name := ":status".toUTF8, value := (toString status).toUTF8 }]
  if endStream then
    fields := fields.push { name := "content-length".toUTF8, value := "0".toUTF8 }
    if let some date := connection.currentDate then
      fields := fields.push { name := "date".toUTF8, value := date }
  let (encoder, block) ← match HPACK.encode connection.encoder fields with
    | .ok result => pure result
    | .error message => throw (connError .internalError message)
  let (stream, _) ← entry.stream.apply .server (.headers .outbound endStream)
  let connection := putStream { connection with encoder } { entry with stream }
  let output ← wire ⟨1, if endStream then 5 else 4, stream.id, block⟩
  if !endStream then return (connection, output, #[])
  if remoteEnded then return (removeStream connection stream.id, output, #[])
  let connection ← markReset connection stream.id
  return (connection, output.append (← rst stream.id .noError), #[])

private def finishHeaders (connection : Connection) (assembly : HeaderAssembly) :
    Except ProtocolError (Connection × ByteArray × Array RequestEvent) := do
  let (decoder, headers) ← match HPACK.decode connection.decoder (headerBlock assembly) with
    | .error message => throw (connError .compressionError message)
    | .ok result => pure result
  let connection := { connection with decoder, assembly := none }
  if assembly.discard then return (connection, ByteArray.empty, #[])
  if let some code := assembly.reject then
    return ← resetStream connection assembly.streamId code
  let some entry := findStream connection assembly.streamId |
    throw (connError .protocolError "missing stream for header block")
  if entry.head.isNone then
    match validateRequestHead headers with
    | .error _ => return ← resetStream connection assembly.streamId .protocolError
    | .ok head =>
      let entry := { entry with head := some head }
      let connection := putStream connection entry
      match expectation head.headers with
      | .unsupported => return ← expectationResponse connection entry 417 true assembly.endStream
      | .continue =>
        if !assembly.endStream then return ← expectationResponse connection entry 100 false false
      | .none => pure ()
      if assembly.endStream then
        match finishRequest connection entry with
        | .ok (next, events) => return (next, ByteArray.empty, events)
        | .error error => return ← resetStream connection assembly.streamId error.code
      return (connection, ByteArray.empty, #[])
  else
    if !assembly.endStream || entry.delivered then
      return ← resetStream connection assembly.streamId .protocolError
    match validateTrailers headers with
    | .error _ => return ← resetStream connection assembly.streamId .protocolError
    | .ok trailers =>
      let entry := { entry with trailers }
      match finishRequest (putStream connection entry) entry with
      | .ok (next, events) => return (next, ByteArray.empty, events)
      | .error error => return ← resetStream connection assembly.streamId error.code

private def settings (connection : Connection) (frame : Frame) : Except ProtocolError (Connection × ByteArray) := do
  if flag frame.flags 1 then
    if !connection.awaitingAck then throw (connError .protocolError "unexpected SETTINGS ACK")
    return ({ connection with awaitingAck := false }, ByteArray.empty)
  let mut connection := connection
  for i in [0:frame.payload.size / 6] do
    let offset := i * 6
    let id := (frame.payload[offset]!).toNat * 256 + (frame.payload[offset + 1]!).toNat
    let value := readU32 frame.payload (offset + 2)
    if id == 1 then
      let encoder := connection.encoder.setMaximum value
      let capacity := min value 4096
      let encoder ← match encoder.setCapacity capacity with
        | .ok encoder => pure encoder
        | .error message => throw (connError .internalError message)
      connection := { connection with encoder }
    else if id == 4 then
      let delta := Int.ofNat value - Int.ofNat connection.peerInitialWindow
      let mut streams := #[]
      for entry in connection.streams do
        let stream ← entry.stream.adjustInitialSend delta
        streams := streams.push { entry with stream }
      connection := { connection with streams, peerInitialWindow := value }
    else if id == 5 then connection := { connection with peerFrameSize := value }
  return ({ connection with peerSettings := true }, ← wire ⟨4, 1, 0, ByteArray.empty⟩)

private def receiveHeaders (connection : Connection) (frame : Frame) :
    Except ProtocolError (Connection × ByteArray × Array RequestEvent) := do
  let id := frame.streamId
  let mut connection := connection
  let mut reject : Option ErrorCode := none
  if connection.resetStreams.contains id then
    let block := headerFragment frame
    let assembly : HeaderAssembly := { streamId := id, fragments := [block], blockSize := block.size, endStream := flag frame.flags 1, discard := true }
    if flag frame.flags 4 then return ← finishHeaders connection assembly
    return ({ connection with assembly := some assembly }, ByteArray.empty, #[])
  let entry ← match findStream connection id with
    | some entry => pure entry
    | none =>
      if id.toNat % 2 == 0 then
        throw (connError .protocolError "invalid client stream id")
      if id <= connection.highestStream then
        throw (connError .streamClosed "HEADERS on closed stream")
      let stream ← Stream.new id connection.peerInitialWindow
      connection := { connection with highestStream := id }
      if connection.streams.size >= 32 then reject := some .refusedStream
      let entry : Exchange := { stream, startedAt := connection.now }
      connection := { connection with streams := connection.streams.push entry }
      pure entry
  let ended := flag frame.flags 1
  let stream ← match entry.stream.apply .server (.headers .inbound ended) with
    | .ok (stream, .process) => pure stream
    | .ok (_, _) =>
      reject := some .streamClosed
      pure entry.stream
    | .error error =>
      if error.scope == .connection then throw error
      reject := some error.code
      pure entry.stream
  connection := putStream connection { entry with stream }
  let block := headerFragment frame
  if block.size > 65536 then throw (connError .enhanceYourCalm "compressed header block too large")
  let assembly : HeaderAssembly := { streamId := id, fragments := [block], blockSize := block.size, endStream := ended, reject }
  if flag frame.flags 4 then finishHeaders connection assembly
  else return ({ connection with assembly := some assembly }, ByteArray.empty, #[])

private def discardData (connection : Connection) (id : UInt32) (code : ErrorCode)
    (size : Nat) : Except ProtocolError (Connection × ByteArray × Array RequestEvent) := do
  let mut connection ← markReset connection id
  let mut output := ByteArray.empty
  if size > 0 then
    connection := { connection with flow := ← connection.flow.updateReceive size }
    output := ← windowUpdate 0 size
  return (connection, output.append (← rst id code), #[])

private def receiveData (connection : Connection) (frame : Frame) :
    Except ProtocolError (Connection × ByteArray × Array RequestEvent) := do
  let id := frame.streamId
  let some entry := findStream connection id |
    if connection.resetStreams.contains id then
      let size := frame.payload.size
      if Int.ofNat size > connection.flow.recvWindow then
        throw (connError .flowControlError "connection receive window exceeded")
      -- The payload is discarded immediately, so its connection credit can be returned.
      let output ← if size == 0 then pure ByteArray.empty else windowUpdate 0 size
      return (connection, output, #[])
    else if id.toNat % 2 == 1 && id <= connection.highestStream then
      throw (connError .streamClosed "DATA on closed stream")
    else throw (connError .protocolError "DATA on idle stream")
  let (flow, result) ← connection.flow.receiveData entry.stream frame.payload.size
  let connection := { connection with flow }
  let stream ← match result with
    | .error error => return ← discardData connection id error.code frame.payload.size
    | .ok stream => pure stream
  let ended := flag frame.flags 1
  let stream ← match stream.apply .server (.data .inbound ended) with
    | .ok (stream, .process) => pure stream
    | .ok (_, _) => return ← discardData connection id .streamClosed frame.payload.size
    | .error error =>
      if error.scope == .connection then throw error
      return ← discardData connection id error.code frame.payload.size
  let padding := if flag frame.flags 8 then (frame.payload[0]!).toNat else 0
  let start := if flag frame.flags 8 then 1 else 0
  let data := frame.payload.extract start (frame.payload.size - padding)
  let buffered := connection.streams.foldl (fun n e => n + e.bodySize) 0
  if entry.bodySize + data.size > 1048576 || buffered + data.size > 8 * 1024 * 1024 then
    return ← discardData connection id .enhanceYourCalm frame.payload.size
  let mut connection := connection
  let mut stream := stream
  let mut output := ByteArray.empty
  if frame.payload.size > 0 then
    connection := { connection with flow := ← connection.flow.updateReceive frame.payload.size }
    stream ← stream.updateReceive frame.payload.size
    output := (← windowUpdate 0 frame.payload.size).append (← windowUpdate id frame.payload.size)
  let entry := appendBody { entry with stream } data
  connection := putStream connection entry
  if ended then
    match finishRequest connection entry with
    | .ok (next, events) => return (next, output, events)
    | .error error =>
      let (next, reset, events) ← resetStream connection id error.code
      return (next, output.append reset, events)
  return (connection, output, #[])

/-- Supply the current validated HTTP Date bytes for protocol-generated final responses. -/
def Connection.setDate (connection : Connection) (date : ByteArray) : Connection :=
  { connection with currentDate := some date }

/-- Supply current monotonic milliseconds before feeding a new network read. -/
def Connection.setTime (connection : Connection) (now : Nat) : Connection :=
  { connection with now }

/-- Reset requests whose absolute deadline expired. A timed-out incomplete
    header block terminates the connection because discarding it would desync HPACK. -/
def Connection.expireRequests (connection : Connection) (now timeoutMs : Nat) :
    Except ProtocolError (Connection × ByteArray) := do
  let mut connection := { connection with now }
  let mut output := ByteArray.empty
  for entry in connection.streams do
    if !entry.delivered && now - entry.startedAt >= timeoutMs then
      if connection.assembly.any (fun block => block.streamId == entry.stream.id) then
        throw (connError .enhanceYourCalm "incomplete header block timed out")
      output := output.append (← rst entry.stream.id .cancel)
      connection ← markReset connection entry.stream.id
  return (connection, output)

/-- A fragmented preface, frame, or header block still needs an absolute
    transport parsing deadline even when no new bytes arrive. -/
def Connection.hasPartialInput (connection : Connection) : Bool :=
  connection.prefaceRead < 24 || connection.assembly.isSome ||
    match connection.parser.finish with | .ok _ => false | .error _ => true

private def receiveWindow (connection : Connection) (frame : Frame) : Except ProtocolError (Connection × ByteArray) := do
  let increment := readU32 frame.payload % 2147483648
  if frame.streamId != 0 && frame.streamId.toNat % 2 == 0 then
    throw (connError .protocolError "WINDOW_UPDATE on idle server-initiated stream")
  if frame.streamId == 0 then
    return ({ connection with flow := ← connection.flow.updateSend increment }, ByteArray.empty)
  let some entry := findStream connection frame.streamId |
    if frame.streamId > connection.highestStream then throw (connError .protocolError "WINDOW_UPDATE on idle stream")
    else return (connection, ByteArray.empty)
  match entry.stream.updateSend increment with
  | .error error => return (← markReset connection frame.streamId, ← rst frame.streamId error.code)
  | .ok stream => return (putStream connection { entry with stream }, ByteArray.empty)

private def handleFrame (connection : Connection) (frame : Frame) :
    Except ProtocolError (Connection × ByteArray × Array RequestEvent) := do
  if let some assembly := connection.assembly then
    if frame.kind != 9 || frame.streamId != assembly.streamId then
      throw (connError .protocolError "interleaved header block")
    let blockSize := assembly.blockSize + frame.payload.size
    if blockSize > 65536 || assembly.fragmentCount >= 1024 then
      throw (connError .enhanceYourCalm "compressed header block exceeds resource limits")
    let assembly := { assembly with fragments := frame.payload :: assembly.fragments,
                                    fragmentCount := assembly.fragmentCount + 1, blockSize }
    if flag frame.flags 4 then return ← finishHeaders connection assembly
    return ({ connection with assembly := some assembly }, ByteArray.empty, #[])
  if !connection.peerSettings && (frame.kind != 4 || flag frame.flags 1) then
    throw (connError .protocolError "first client frame must be SETTINGS")
  match frame.kind.toNat with
  | 0 => receiveData connection frame
  | 1 => receiveHeaders connection frame
  | 2 => return (connection, ByteArray.empty, #[])
  | 3 =>
    if frame.streamId.toNat % 2 == 0 then
      throw (connError .protocolError "RST_STREAM on idle server-initiated stream")
    if (findStream connection frame.streamId).isNone && frame.streamId > connection.highestStream then
      throw (connError .protocolError "RST_STREAM on idle stream")
    return (removeStream connection frame.streamId, ByteArray.empty, #[])
  | 4 =>
    let (connection, output) ← settings connection frame
    return (connection, output, #[])
  | 5 => throw (connError .protocolError "client PUSH_PROMISE is forbidden")
  | 6 =>
    if flag frame.flags 1 then return (connection, ByteArray.empty, #[])
    return (connection, ← wire ⟨6, 1, 0, frame.payload⟩, #[])
  | 7 => return ({ connection with peerGoAway := true }, ByteArray.empty, #[])
  | 8 =>
    let (connection, output) ← receiveWindow connection frame
    return (connection, output, #[])
  | 9 => throw (connError .protocolError "unexpected CONTINUATION")
  | _ => return (connection, ByteArray.empty, #[])

/-- True only when a queued body can currently make progress. A zero-credit
    connection must wait for WINDOW_UPDATE rather than busy-polling. -/
def Connection.canDrain (connection : Connection) : Bool :=
  connection.flow.sendWindow > 0 && connection.streams.any fun entry =>
    entry.pending.isSome && entry.stream.sendWindow > 0

def Connection.hasPendingOutput (connection : Connection) : Bool :=
  connection.streams.any (fun entry => entry.pending.isSome)

/-- Emit at most 64 KiB of DATA payload; call again after the socket queue has
    room while `canDrain` is true. This preserves DATA ordering per stream. -/
def Connection.drain (connection : Connection) : Except ProtocolError (Connection × ByteArray) := do
  let mut connection := connection
  let mut output := ByteArray.empty
  let mut budget := 65536
  let ordered := connection.streams.filter (fun e => e.stream.id > connection.lastDrained) ++
    connection.streams.filter (fun e => e.stream.id <= connection.lastDrained)
  for old in ordered do
    if budget == 0 then break
    let some entry := findStream connection old.stream.id | continue
    let some pending := entry.pending | continue
    let available := min budget (min connection.peerFrameSize (min 16384
      (min connection.flow.sendWindow.toNat entry.stream.sendWindow.toNat)))
    let size := min available (pending.body.size - pending.offset)
    if size == 0 then continue
    let final := pending.offset + size == pending.body.size
    let some (flow, stream) := connection.flow.sendData entry.stream size final | continue
    let (stream, _) ← stream.apply .server (.data .outbound final)
    let data := pending.body.extract pending.offset (pending.offset + size)
    output := output.append (← wire ⟨0, if final then 1 else 0, stream.id, data⟩)
    connection := { connection with flow, lastDrained := stream.id }
    if final then connection := removeStream connection stream.id
    else connection := putStream connection { entry with stream, pending := some { pending with offset := pending.offset + size } }
    budget := budget - size
  return (connection, output)

private def encodedHeaders (encoder : HPACK.Context) (fields : Array HPACK.Header)
    (id : UInt32) (endStream : Bool) (maxFrame : Nat) : Except ProtocolError (HPACK.Context × ByteArray) := do
  let (encoder, block) ← match HPACK.encode encoder fields with
    | .error message => throw (connError .internalError message)
    | .ok result => pure result
  let mut output := ByteArray.empty
  let mut offset := 0
  let mut first := true
  for _ in [0:block.size / maxFrame + 1] do
    if !first && offset >= block.size then break
    let stop := min block.size (offset + maxFrame)
    let last := stop == block.size
    let flags : UInt8 := (if last then 4 else 0) + (if first && endStream then 1 else 0)
    output := output.append (← wire ⟨if first then 1 else 9, flags, id, block.extract offset stop⟩)
    first := false
    offset := stop
  return (encoder, output)

/-- Queue a bounded application response and emit its HEADERS plus available
    DATA. The caller supplies Date before invoking this pure function. -/
def Connection.respond (connection : Connection) (id : UInt32) (response : HTTP1.Response) :
    Except ProtocolError (Connection × ByteArray) := do
  let some entry := findStream connection id | throw (streamError id .streamClosed "response stream is closed")
  if !entry.delivered || entry.pending.isSome then throw (streamError id .protocolError "response is not expected")
  let some head := entry.head | throw (streamError id .internalError "missing request head")
  if response.body.size > 8 * 1024 * 1024 then throw (streamError id .internalError "response exceeds limit")
  let queued := connection.streams.foldl (fun n e => n + match e.pending with | some p => p.body.size | none => 0) 0
  if queued + response.body.size > 8 * 1024 * 1024 then throw (streamError id .internalError "response queue exceeds limit")
  match response.validate head.method with
  | .error message => throw (streamError id .internalError message)
  | .ok _ => pure ()
  let noBody := head.method == "HEAD" || response.status == 204 || response.status == 205 || response.status == 304 || response.body.isEmpty
  let mut fields : Array HPACK.Header := #[{ name := ":status".toUTF8, value := (toString response.status).toUTF8 }]
  for h in response.headers do
    let name := h.name.toLower
    if ["keep-alive", "proxy-connection", "upgrade", "te"].contains name then
      throw (streamError id .internalError "connection-specific HTTP/2 response field")
    fields := fields.push { name := name.toUTF8, value := h.value,
                            sensitive := ["set-cookie", "authorization", "proxy-authorization", "cookie"].contains name }
  if response.status != 204 && response.status != 304 then
    fields := fields.push { name := "content-length".toUTF8, value := (toString response.body.size).toUTF8 }
  let (encoder, headers) ← encodedHeaders connection.encoder fields id noBody connection.peerFrameSize
  let (stream, _) ← entry.stream.apply .server (.headers .outbound noBody)
  let connection := { connection with encoder }
  if noBody then return (removeStream connection id, headers)
  let connection := putStream connection { entry with stream, pending := some { body := response.body } }
  let (connection, data) ← connection.drain
  return (connection, headers.append data)

/-- Feed any fragment, including the client connection preface. Returns wire
    output and complete request events, preserving partial frames and blocks. -/
def Connection.feed (connection : Connection) (input : ByteArray) :
    Except ProtocolError (Connection × ByteArray × Array RequestEvent) := do
  let preface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toUTF8
  let mut connection := connection
  let mut offset := 0
  for _ in [:input.size] do
    if connection.prefaceRead >= preface.size then break
    if input[offset]! != preface[connection.prefaceRead]! then
      throw (connError .protocolError "invalid client connection preface")
    connection := { connection with prefaceRead := connection.prefaceRead + 1 }
    offset := offset + 1
  let mut remaining := input.extract offset input.size
  let mut output := ByteArray.empty
  let mut requests := #[]
  for _ in [:remaining.size + 1] do
    if remaining.isEmpty then break
    match connection.parser.feed remaining with
    | .needMore parser =>
      connection := { connection with parser }
      remaining := ByteArray.empty
    | .error error _ =>
      throw ⟨error.code, .connection, error.message⟩
    | .complete frame rest =>
      let (next, bytes, events) ← handleFrame { connection with parser := FrameParser.new } frame
      connection := next
      output := output.append bytes
      requests := requests ++ events
      remaining := rest
      if output.size > 1048576 || requests.size > 32 then
        throw (connError .enhanceYourCalm "connection output or request batch limit exceeded")
  let (next, pending) ← connection.drain
  let liveRequests := requests.filter (fun event => next.canRespond event.streamId)
  return (next, output.append pending, liveRequests)

end LeanNet.HTTP2
