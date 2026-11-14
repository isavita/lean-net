import LeanNet.HTTP2.Frame
import LeanNet.HTTP2.Stream
import LeanNet.HTTP2.HPACK
import LeanNet.HTTP2.Request
import LeanNet.HTTP2.Priority
import LeanNet.HTTP1.Response

namespace LeanNet.HTTP2

/-- A completed HTTP/2 request for the shared application router. -/
structure RequestEvent where
  streamId : UInt32
  request : HTTP1.Request

private structure PendingResponse where
  body : ByteArray
  offset : Nat := 0
  trailers : Array HPACK.Header := #[]

private structure Exchange where
  stream : Stream
  head : Option RequestHead := none
  bodyBlocks : List ByteArray := []
  body : ByteArray := ByteArray.empty
  bodySize : Nat := 0
  trailers : Array HTTP1.Header := #[]
  pending : Option PendingResponse := none
  delivered : Bool := false
  startedAt : Nat := 0
  priority : Priority := {}
  receiveCredit : Nat := 0

private structure HeaderAssembly where
  streamId : UInt32
  fragments : List ByteArray := []
  blockSize : Nat := 0
  fragmentCount : Nat := 1
  endStream : Bool
  reject : Option ErrorCode := none
  discard : Bool := false

namespace Connection

/-- Bounds are per connection; peer SETTINGS independently constrain output. -/
structure Config where
  maxConcurrentStreams : Nat := 128
  maxFrameSize : Nat := 16384
  initialWindowSize : Nat := 65535
  maxHeaderListBytes : Nat := 65536
  maxHeaderFields : Nat := 100
  maxHeaderBlockBytes : Nat := 65536
  maxContinuationFrames : Nat := 1024
  maxRequestBodyBytes : Nat := 1048576
  maxBufferedRequestBytes : Nat := 8 * 1024 * 1024
  maxResponseBodyBytes : Nat := 8 * 1024 * 1024
  maxQueuedResponseBytes : Nat := 8 * 1024 * 1024
  maxOutputBatchBytes : Nat := 1048576
  maxRequestBatch : Nat := 128
  maxFramesPerStep : Nat := 256
  maxDataPerDrain : Nat := 65536
  maxResetHistory : Nat := 256
  maxPushes : Nat := 128
  enablePush : Bool := false
  deriving Repr

def Config.validate (config : Config) : Except String Unit := do
  if config.maxConcurrentStreams == 0 || config.maxConcurrentStreams > 1000000 ||
      config.maxFrameSize < 16384 || config.maxFrameSize > 16777215 ||
      config.initialWindowSize > 2147483647 || config.maxHeaderListBytes == 0 ||
      config.maxHeaderListBytes > 4294967295 ||
      config.maxHeaderFields == 0 || config.maxHeaderBlockBytes == 0 ||
      config.maxContinuationFrames == 0 || config.maxRequestBodyBytes == 0 ||
      config.maxBufferedRequestBytes < config.maxRequestBodyBytes ||
      config.maxResponseBodyBytes == 0 || config.maxQueuedResponseBytes < config.maxResponseBodyBytes ||
      config.maxOutputBatchBytes < 16393 || config.maxRequestBatch == 0 ||
      config.maxFramesPerStep == 0 || config.maxDataPerDrain == 0 ||
      config.maxDataPerDrain + 9 > config.maxOutputBatchBytes || config.maxResetHistory == 0 ||
      config.maxPushes > 1000000 then throw "invalid HTTP/2 connection budgets"

end Connection

/-- Server-side HTTP/2 connection state. All budgets are deliberately bounded. -/
structure Connection where
  private config : Connection.Config := {}
  private prefaceRead : Nat := 0
  private parser : FrameParser := FrameParser.new
  private peerSettings : Bool := false
  private awaitingAck : Bool := true
  private decoder : HPACK.Context := HPACK.Context.new
  private encoder : HPACK.Context := HPACK.Context.new
  private peerInitialWindow : Nat := defaultWindow
  private peerFrameSize : Nat := 16384
  private peerHeaderListBytes : Nat := 4294967295
  private peerMaxConcurrentStreams : Nat := 4294967295
  private peerEnablePush : Bool := true
  private peerNoPriorities : Bool := false
  private pendingPriorities : Array (UInt32 × Priority) := #[]
  private nextPushStream : Nat := 2
  private pushes : Nat := 0
  private flow : Flow := {}
  private receiveCredit : Nat := 0
  private streams : Array Exchange := #[]
  private highestStream : UInt32 := 0
  private resetStreams : Array UInt32 := #[]
  private incrementalCursors : Array UInt32 := #[0,0,0,0,0,0,0,0]
  private nonIncrementalBytes : Array Nat := #[0,0,0,0,0,0,0,0]
  private discardThrough : UInt32 := 0
  private processedStream : UInt32 := 0
  private assembly : Option HeaderAssembly := none
  private peerGoAway : Bool := false
  private peerLastStream : UInt32 := 2147483647
  private localGoAway : Option UInt32 := none
  private failure : Option ProtocolError := none
  private inputEnded : Bool := false
  private now : Nat := 0
  private currentDate : Option ByteArray := none

/-- Compatibility default constructor. -/
def Connection.new : Connection := {}

def Connection.newWithConfig (config : Connection.Config) : Connection :=
  let limits : HPACK.Limits := { maxEncodedBytes := config.maxHeaderBlockBytes, maxStringBytes := config.maxHeaderListBytes, maxHeaderListBytes := config.maxHeaderListBytes, maxHeaderFields := config.maxHeaderFields }
  { config, parser := FrameParser.new config.maxFrameSize, decoder := HPACK.Context.new limits }

namespace Connection

structure Step where
  connection : Connection
  consumed : Nat := 0
  output : Array ByteArray := #[]
  requests : Array RequestEvent := #[]
  error : Option ProtocolError := none

end Connection

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

/-- Advertise the configured receive limits and RFC 9218 priority support. -/
def Connection.settingsFrame (connection : Connection) : ByteArray := Id.run do
  let mut payload := ByteArray.empty
  for (id, value) in (#[(3, connection.config.maxConcurrentStreams), (4, connection.config.initialWindowSize), (5, connection.config.maxFrameSize), (6, connection.config.maxHeaderListBytes), (9, 1)] : Array (Nat × Nat)) do
    payload := payload.append (ByteArray.mk #[UInt8.ofNat (id / 256), UInt8.ofNat id])
    payload := payload.append (u32 (UInt32.ofNat value))
  return match wire ⟨4, 0, 0, payload⟩ with | .ok bytes => bytes | .error _ => ByteArray.empty

/-- Default server SETTINGS, retained for existing transport adapters. -/
def Connection.initialSettings : ByteArray := Connection.new.settingsFrame

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
  { connection with streams := connection.streams.filter (fun entry => entry.stream.id != id), pendingPriorities := connection.pendingPriorities.filter (fun entry => entry.1 != id) }

/-- A complete request may have been canceled by a later frame in the same
    read. Routers should dispatch only while this predicate remains true. -/
def Connection.canRespond (connection : Connection) (id : UInt32) : Bool :=
  connection.failure.isNone && match findStream connection id with
  | some entry => entry.delivered && entry.pending.isNone
  | none => false

private def markReset (connection : Connection) (id : UInt32) : Except ProtocolError Connection := do
  let connection := removeStream connection id
  if connection.resetStreams.contains id then return connection
  let history := if connection.resetStreams.size >= connection.config.maxResetHistory then
    connection.resetStreams.extract 1 connection.resetStreams.size else connection.resetStreams
  let discarded := if connection.resetStreams.size >= connection.config.maxResetHistory then
    max connection.discardThrough (connection.resetStreams[0]!) else connection.discardThrough
  return { connection with resetStreams := history.push id, discardThrough := discarded }

private def resetStream (connection : Connection) (id : UInt32) (code : ErrorCode) :
    Except ProtocolError (Connection × ByteArray × Array RequestEvent) := do
  return (← markReset connection id, ← rst id code, #[])

/-- Cancel one active application exchange without closing independent streams. -/
def Connection.cancel (connection : Connection) (id : UInt32) (code : ErrorCode := .cancel) :
    Except ProtocolError (Connection × ByteArray) := do
  if (findStream connection id).isNone then return (connection, ByteArray.empty)
  return (← markReset connection id, ← rst id code)

private def appendBody (entry : Exchange) (data : ByteArray) : Exchange := Id.run do
  let mut blocks := entry.bodyBlocks
  let mut active := entry.body
  let mut offset := 0
  for _ in [:data.size / 4096 + 2] do
    if offset == data.size then break
    let count := min (data.size - offset) (4096 - active.size)
    active := data.copySlice offset active active.size count false
    offset := offset + count
    if active.size == 4096 then
      blocks := active :: blocks
      active := ByteArray.empty
  return { entry with bodyBlocks := blocks, body := active, bodySize := entry.bodySize + data.size }

private def bodyBytes (entry : Exchange) : ByteArray := Id.run do
  let mut body := ByteArray.emptyWithCapacity entry.bodySize
  for block in entry.bodyBlocks.reverse do body := body.append block
  return body.append entry.body

private def finishRequest (connection : Connection) (entry : Exchange) : Except ProtocolError (Connection × Array RequestEvent) := do
  let some head := entry.head | throw (streamError entry.stream.id .protocolError "DATA before request headers")
  match head.complete (bodyBytes entry) entry.trailers with
  | .error message => throw (streamError entry.stream.id .protocolError message)
  | .ok request =>
    let connection := putStream connection { entry with delivered := true, bodyBlocks := [], body := ByteArray.empty, bodySize := 0 }
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
    block := block.append fragment
  return block

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

private def headerListSize (fields : Array HPACK.Header) : Nat :=
  fields.foldl (fun size field => size + field.name.size + field.value.size + 32) 0

private def requestPriority (headers : Array HTTP1.Header) : Priority := Id.run do
  let mut value := ByteArray.empty
  for header in headers do
    if header.name == "priority" then
      if !value.isEmpty then value := value.append ", ".toUTF8
      value := value.append header.value
  return match Priority.parse value with | .ok priority => priority | .error _ => {}

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
  if headerListSize fields > connection.peerHeaderListBytes then
    throw (connError .enhanceYourCalm "peer header-list limit prevents generated response")
  let (encoder, output) ← encodedHeaders connection.encoder fields entry.stream.id endStream connection.peerFrameSize
  let (stream, _) ← entry.stream.apply .server (.headers .outbound endStream)
  let connection := putStream { connection with encoder } { entry with stream }
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
    match validateRequestHead headers connection.config.maxRequestBodyBytes with
    | .error _ => return ← resetStream connection assembly.streamId .protocolError
    | .ok head =>
      let priority := (connection.pendingPriorities.find? (fun p => p.1 == assembly.streamId)).map (·.2)
      let entry := { entry with head := some head, priority := priority.getD (requestPriority head.headers) }
      let connection := { connection with pendingPriorities := connection.pendingPriorities.filter (fun p => p.1 != assembly.streamId) }
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
    let delta := Int.ofNat connection.config.initialWindowSize - Int.ofNat defaultWindow
    let mut streams := #[]
    let mut output := ByteArray.empty
    for entry in connection.streams do
      let mut stream ← entry.stream.adjustInitialReceive delta
      let mut credit := entry.receiveCredit
      -- The peer may have used the default window before receiving our SETTINGS.
      -- Return consumed credit under the new threshold so a negative window can recover.
      if credit > 0 && credit >= max 1 (connection.config.initialWindowSize / 4) then
        stream ← stream.updateReceive credit
        output := output.append (← windowUpdate stream.id credit)
        credit := 0
      streams := streams.push { entry with stream, receiveCredit := credit }
    return ({ connection with awaitingAck := false, streams }, output)
  let mut connection := connection
  for i in [0:frame.payload.size / 6] do
    let offset := i * 6
    let id := (frame.payload[offset]!).toNat * 256 + (frame.payload[offset + 1]!).toNat
    let value := readU32 frame.payload (offset + 2)
    if id == 1 then
      let encoder := connection.encoder.setMaximum value
      let encoder ← match encoder.setCapacity (min value 4096) with
        | .ok encoder => pure encoder
        | .error message => throw (connError .internalError message)
      connection := { connection with encoder }
    else if id == 2 then connection := { connection with peerEnablePush := value == 1 }
    else if id == 3 then connection := { connection with peerMaxConcurrentStreams := value }
    else if id == 4 then
      let delta := Int.ofNat value - Int.ofNat connection.peerInitialWindow
      let mut streams := #[]
      for entry in connection.streams do
        let stream ← entry.stream.adjustInitialSend delta
        streams := streams.push { entry with stream }
      connection := { connection with streams, peerInitialWindow := value }
    else if id == 5 then connection := { connection with peerFrameSize := value }
    else if id == 6 then connection := { connection with peerHeaderListBytes := value }
    else if id == 9 then
      if connection.peerSettings && (value == 1) != connection.peerNoPriorities then
        throw (connError .protocolError "SETTINGS_NO_RFC7540_PRIORITIES changed")
      connection := { connection with peerNoPriorities := value == 1 }
  return ({ connection with peerSettings := true }, ← wire ⟨4, 1, 0, ByteArray.empty⟩)

private def activeRequests (connection : Connection) : Nat :=
  (connection.streams.filter (fun entry => entry.stream.id.toNat % 2 == 1)).size

private def closedStream (connection : Connection) (id : UInt32) : Bool :=
  if id.toNat % 2 == 1 then id <= connection.highestStream else id.toNat < connection.nextPushStream

private def discardedStream (connection : Connection) (id : UInt32) : Bool :=
  connection.resetStreams.contains id ||
    (id != 0 && id <= connection.discardThrough && closedStream connection id)

private def receiveHeaders (connection : Connection) (frame : Frame) :
    Except ProtocolError (Connection × ByteArray × Array RequestEvent) := do
  let id := frame.streamId
  let block := headerFragment frame
  if block.size > connection.config.maxHeaderBlockBytes then
    throw (connError .enhanceYourCalm "compressed header block too large")
  let mut connection := connection
  let mut reject : Option ErrorCode := none
  let ended := flag frame.flags 1
  if (findStream connection id).isNone && discardedStream connection id then
    let assembly : HeaderAssembly := { streamId := id, fragments := [block], blockSize := block.size, endStream := ended, discard := true }
    if flag frame.flags 4 then return ← finishHeaders connection assembly
    return ({ connection with assembly := some assembly }, ByteArray.empty, #[])
  let entry ← match findStream connection id with
    | some entry => pure entry
    | none =>
      if id.toNat % 2 == 0 then throw (connError .protocolError "invalid client stream id")
      if id <= connection.highestStream then throw (connError .streamClosed "HEADERS on closed stream")
      let stream ← Stream.new id connection.peerInitialWindow
        (if connection.awaitingAck then defaultWindow else connection.config.initialWindowSize)
      let pending := connection.pendingPriorities.filter (fun p => p.1 >= id)
      let otherPriorities := pending.filter (fun p => p.1 != id)
      if activeRequests connection + otherPriorities.size >= connection.config.maxConcurrentStreams ||
          connection.localGoAway.isSome || connection.peerGoAway || connection.inputEnded then reject := some .refusedStream
      connection := { connection with highestStream := id, pendingPriorities := pending }
      let entry : Exchange := { stream, startedAt := connection.now }
      connection := { connection with streams := connection.streams.push entry }
      pure entry
  if flag frame.flags 32 then
    let offset := if flag frame.flags 8 then 1 else 0
    if readU32 frame.payload offset % 2147483648 == id.toNat then reject := some .protocolError
  let stream ← match entry.stream.apply .server (.headers .inbound ended) with
    | .ok (stream, .process) => pure stream
    | .ok (_, _) => reject := some .streamClosed; pure entry.stream
    | .error error =>
      if error.scope == .connection then throw error
      reject := some error.code
      pure entry.stream
  connection := putStream connection { entry with stream }
  let assembly : HeaderAssembly := { streamId := id, fragments := [block], blockSize := block.size, endStream := ended, reject }
  if flag frame.flags 4 then finishHeaders connection assembly
  else return ({ connection with assembly := some assembly }, ByteArray.empty, #[])

private def consumeConnection (connection : Connection) (size : Nat) : Except ProtocolError (Connection × ByteArray) := do
  let credit := connection.receiveCredit + size
  if credit < defaultWindow / 4 then return ({ connection with receiveCredit := credit }, ByteArray.empty)
  let flow ← connection.flow.updateReceive credit
  return ({ connection with flow, receiveCredit := 0 }, ← windowUpdate 0 credit)

private def consumeStream (connection : Connection) (entry : Exchange) (size : Nat) (ended : Bool) :
    Except ProtocolError (Exchange × ByteArray) := do
  let credit := entry.receiveCredit + size
  if ended then return ({ entry with receiveCredit := 0 }, ByteArray.empty)
  let initial := if connection.awaitingAck then defaultWindow else connection.config.initialWindowSize
  if credit < max 1 (initial / 4) then return ({ entry with receiveCredit := credit }, ByteArray.empty)
  let stream ← entry.stream.updateReceive credit
  return ({ entry with stream, receiveCredit := 0 }, ← windowUpdate entry.stream.id credit)

private def discardData (connection : Connection) (id : UInt32) (code : ErrorCode)
    (size : Nat) : Except ProtocolError (Connection × ByteArray × Array RequestEvent) := do
  let connection ← markReset connection id
  let (connection, output) ← consumeConnection connection size
  return (connection, output.append (← rst id code), #[])

private def receiveData (connection : Connection) (frame : Frame) :
    Except ProtocolError (Connection × ByteArray × Array RequestEvent) := do
  let id := frame.streamId
  let some entry := findStream connection id |
    if discardedStream connection id then
      let size := frame.payload.size
      if Int.ofNat size > connection.flow.recvWindow then
        throw (connError .flowControlError "connection receive window exceeded")
      let connection := { connection with flow := { connection.flow with recvWindow := connection.flow.recvWindow - Int.ofNat size } }
      let (connection, output) ← consumeConnection connection size
      return (connection, output, #[])
    else if closedStream connection id then
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
  if entry.bodySize + data.size > connection.config.maxRequestBodyBytes || buffered + data.size > connection.config.maxBufferedRequestBytes then
    return ← discardData connection id .enhanceYourCalm frame.payload.size
  let (connection, connectionOutput) ← consumeConnection connection frame.payload.size
  let (entry, streamOutput) ← consumeStream connection { entry with stream } frame.payload.size ended
  let output := connectionOutput.append streamOutput
  let entry := appendBody entry data
  let connection := putStream connection entry
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
    if output.size + 13 > connection.config.maxOutputBatchBytes then break
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
  if frame.streamId == 0 then
    return ({ connection with flow := ← connection.flow.updateSend increment }, ByteArray.empty)
  let some entry := findStream connection frame.streamId |
    if !closedStream connection frame.streamId then throw (connError .protocolError "WINDOW_UPDATE on idle stream")
    else return (connection, ByteArray.empty)
  match entry.stream.updateSend increment with
  | .error error => return (← markReset connection frame.streamId, ← rst frame.streamId error.code)
  | .ok stream => return (putStream connection { entry with stream }, ByteArray.empty)

private def receivePriority (connection : Connection) (frame : Frame) : Except ProtocolError Connection := do
  let update ← PriorityUpdate.decode frame
  let some entry := findStream connection update.target |
    if closedStream connection update.target then return connection
    if update.target.toNat % 2 == 0 then throw (connError .protocolError "priority update on idle push stream")
    let priority ← match Priority.parse update.fieldValue with
      | .ok priority => pure priority
      | .error _ => return connection
    let pending := connection.pendingPriorities.filter (fun p => p.1 != update.target)
    if pending.size + activeRequests connection >= connection.config.maxConcurrentStreams then
      throw (connError .protocolError "too many active and idle prioritized streams")
    return { connection with pendingPriorities := pending.push (update.target, priority) }
  if entry.stream.state == .halfClosedLocal then return connection
  match Priority.parse update.fieldValue with
  | .ok priority => return putStream connection { entry with priority }
  | .error _ => return connection

private def handleFrame (connection : Connection) (frame : Frame) :
    Except ProtocolError (Connection × ByteArray × Array RequestEvent) := do
  if let some assembly := connection.assembly then
    if frame.kind != 9 || frame.streamId != assembly.streamId then
      throw (connError .protocolError "interleaved header block")
    let blockSize := assembly.blockSize + frame.payload.size
    if blockSize > connection.config.maxHeaderBlockBytes || assembly.fragmentCount >= connection.config.maxContinuationFrames then
      throw (connError .enhanceYourCalm "compressed header block exceeds resource limits")
    let assembly := { assembly with fragments := frame.payload :: assembly.fragments, fragmentCount := assembly.fragmentCount + 1, blockSize }
    if flag frame.flags 4 then return ← finishHeaders connection assembly
    return ({ connection with assembly := some assembly }, ByteArray.empty, #[])
  if !connection.peerSettings && (frame.kind != 4 || flag frame.flags 1) then
    throw (connError .protocolError "first client frame must be SETTINGS")
  match frame.kind.toNat with
  | 0 => receiveData connection frame
  | 1 => receiveHeaders connection frame
  | 2 => return (connection, ByteArray.empty, #[])
  | 3 =>
    if (findStream connection frame.streamId).isNone && !closedStream connection frame.streamId then
      throw (connError .protocolError "RST_STREAM on idle stream")
    return (removeStream connection frame.streamId, ByteArray.empty, #[])
  | 4 =>
    let (connection, output) ← settings connection frame
    return (connection, output, #[])
  | 5 => throw (connError .protocolError "client PUSH_PROMISE is forbidden")
  | 6 =>
    if flag frame.flags 1 then return (connection, ByteArray.empty, #[])
    return (connection, ← wire ⟨6, 1, 0, frame.payload⟩, #[])
  | 7 =>
    let last := UInt32.ofNat (readU32 frame.payload % 2147483648)
    if connection.peerGoAway && last > connection.peerLastStream then
      throw (connError .protocolError "GOAWAY last stream increased")
    let streams := connection.streams.filter (fun e => e.stream.id.toNat % 2 == 1 || e.stream.id <= last)
    return ({ connection with peerGoAway := true, peerLastStream := last, streams }, ByteArray.empty, #[])
  | 8 =>
    let (connection, output) ← receiveWindow connection frame
    return (connection, output, #[])
  | 9 => throw (connError .protocolError "unexpected CONTINUATION")
  | 16 => return (← receivePriority connection frame, ByteArray.empty, #[])
  | _ => return (connection, ByteArray.empty, #[])

private def pendingReady (connection : Connection) (entry : Exchange) : Bool :=
  match entry.pending with
  | none => false
  | some pending => pending.offset == pending.body.size ||
      headerListSize pending.trailers > connection.peerHeaderListBytes ||
      (connection.flow.sendWindow > 0 && entry.stream.sendWindow > 0)

/-- Empty trailing HEADERS do not consume flow-control credit. -/
def Connection.canDrain (connection : Connection) : Bool :=
  connection.failure.isNone && connection.streams.any (pendingReady connection)

def Connection.hasPendingOutput (connection : Connection) : Bool :=
  connection.streams.any (fun entry => entry.pending.isSome)

private def choosePending (connection : Connection) : Option Exchange := Id.run do
  let eligible := connection.streams.filter (pendingReady connection)
  let some first := eligible[0]? | return none
  let urgency := eligible.foldl (fun u entry => min u entry.priority.urgency) first.priority.urgency
  let peers := eligible.filter (fun entry => entry.priority.urgency == urgency)
  let incremental := peers.filter (fun entry => entry.priority.incremental)
  let nonIncremental := peers.find? (fun entry => !entry.priority.incremental)
  let yieldIncremental := connection.nonIncrementalBytes[urgency.toNat]! >= 65536
  if nonIncremental.isSome && (!yieldIncremental || incremental.isEmpty) then return nonIncremental
  let roundRobin := incremental.find? (fun entry => entry.stream.id > connection.incrementalCursors[urgency.toNat]!)
  return roundRobin.orElse (fun _ => incremental[0]?)

/-- Emit bounded DATA using urgency, serial non-incremental bodies, and round-robin
    incremental bodies. Each 64 KiB serial burst yields to an incremental peer. -/
def Connection.drain (connection : Connection) : Except ProtocolError (Connection × ByteArray) := do
  let mut connection := connection
  let mut output := ByteArray.empty
  let mut budget := connection.config.maxDataPerDrain
  for _ in [:connection.config.maxFramesPerStep] do
    if connection.failure.isSome then break
    let some entry := choosePending connection | break
    let some pending := entry.pending | break
    if headerListSize pending.trailers > connection.peerHeaderListBytes then
      if output.size + 13 > connection.config.maxOutputBatchBytes then break
      connection ← markReset connection entry.stream.id
      output := output.append (← rst entry.stream.id .internalError)
      continue
    if pending.offset == pending.body.size then
      let (encoder, bytes) ← encodedHeaders connection.encoder pending.trailers entry.stream.id true connection.peerFrameSize
      if output.size + bytes.size > connection.config.maxOutputBatchBytes then break
      let _ ← entry.stream.apply .server (.headers .outbound true)
      connection := removeStream { connection with encoder } entry.stream.id
      output := output.append bytes
      continue
    if budget == 0 then break
    let available := min budget (min connection.peerFrameSize (min 16384
      (min connection.flow.sendWindow.toNat entry.stream.sendWindow.toNat)))
    let size := min available (pending.body.size - pending.offset)
    if size == 0 || output.size + size + 9 > connection.config.maxOutputBatchBytes then break
    let finalBody := pending.offset + size == pending.body.size
    let final := finalBody && pending.trailers.isEmpty
    let some (flow, stream) := connection.flow.sendData entry.stream size final | break
    let (stream, _) ← stream.apply .server (.data .outbound final)
    let data := pending.body.extract pending.offset (pending.offset + size)
    output := output.append (← wire ⟨0, if final then 1 else 0, stream.id, data⟩)
    let burst := if entry.priority.incremental then 0 else min 65536 (connection.nonIncrementalBytes[entry.priority.urgency.toNat]! + size)
    connection := { connection with flow, incrementalCursors := if entry.priority.incremental then connection.incrementalCursors.set! entry.priority.urgency.toNat stream.id else connection.incrementalCursors, nonIncrementalBytes := connection.nonIncrementalBytes.set! entry.priority.urgency.toNat burst }
    if final then connection := removeStream connection stream.id
    else connection := putStream connection { entry with stream, pending := some { pending with offset := pending.offset + size } }
    budget := budget - size
  return (connection, output)

private def sensitiveName (name : String) : Bool :=
  ["set-cookie", "authorization", "proxy-authorization", "cookie"].contains name

private def responseFields (connection : Connection) (id : UInt32) (response : HTTP1.Response) : Except ProtocolError (Array HPACK.Header) := do
  let mut fields : Array HPACK.Header := #[{ name := ":status".toUTF8, value := (toString response.status).toUTF8 }]
  for header in response.headers do
    let name := header.name.toLower
    if ["connection", "transfer-encoding", "keep-alive", "proxy-connection", "upgrade", "te"].contains name then
      throw (streamError id .internalError "connection-specific HTTP/2 response field")
    if !header.value.isEmpty && (header.value[0]! == 32 || header.value[0]! == 9 ||
        header.value[header.value.size - 1]! == 32 || header.value[header.value.size - 1]! == 9) then
      throw (streamError id .internalError "HTTP/2 field value has surrounding whitespace")
    fields := fields.push { name := name.toUTF8, value := header.value, sensitive := sensitiveName name }
  if !response.headers.any (fun header => header.name.toLower == "date") then
    if let some date := connection.currentDate then
      fields := fields.push { name := "date".toUTF8, value := date }
  return fields

private def checkPeerHeaders (connection : Connection) (id : UInt32) (fields : Array HPACK.Header) : Except ProtocolError Unit := do
  if fields.size > connection.config.maxHeaderFields || headerListSize fields > connection.config.maxHeaderListBytes ||
      headerListSize fields > connection.peerHeaderListBytes then
    throw (streamError id .internalError "response header-list limit exceeded")

private def encodedTrailers (connection : Connection) (id : UInt32) (trailers : Array HTTP1.Header) :
    Except ProtocolError (Array HPACK.Header) := do
  let fields := trailers.map (fun header => ({ name := header.name.toLower.toUTF8, value := header.value, sensitive := sensitiveName header.name.toLower } : HPACK.Header))
  match validateTrailers fields with
  | .error message => throw (streamError id .internalError message)
  | .ok _ => pure ()
  checkPeerHeaders connection id fields
  let bound := headerListSize fields + 20
  if !fields.isEmpty && bound + (bound / connection.peerFrameSize + 1) * 9 > connection.config.maxOutputBatchBytes then
    throw (streamError id .internalError "trailer output limit exceeded")
  return fields

/-- Emit an informational response without ending or committing the final response. -/
def Connection.informational (connection : Connection) (id : UInt32) (response : HTTP1.Response) :
    Except ProtocolError (Connection × ByteArray) := do
  let some entry := findStream connection id | throw (streamError id .streamClosed "response stream is closed")
  if !entry.delivered || entry.pending.isSome || response.status < 100 || response.status >= 200 ||
      response.status == 101 || !response.body.isEmpty then
    throw (streamError id .internalError "invalid informational HTTP/2 response")
  match ({ response with status := 200 } : HTTP1.Response).validate "GET" with
  | .error message => throw (streamError id .internalError message)
  | .ok _ => pure ()
  let fields ← responseFields connection id response
  checkPeerHeaders connection id fields
  let (encoder, bytes) ← encodedHeaders connection.encoder fields id false connection.peerFrameSize
  if bytes.size > connection.config.maxOutputBatchBytes then throw (streamError id .internalError "response output limit exceeded")
  let (stream, _) ← entry.stream.apply .server (.headers .outbound false)
  return (putStream { connection with encoder } { entry with stream }, bytes)

/-- Queue a final response's HEADERS and body without scheduling DATA. -/
def Connection.queueResponse (connection : Connection) (id : UInt32) (response : HTTP1.Response)
    (trailers : Array HTTP1.Header := #[]) : Except ProtocolError (Connection × ByteArray) := do
  let some entry := findStream connection id | throw (streamError id .streamClosed "response stream is closed")
  if !entry.delivered || entry.pending.isSome then throw (streamError id .protocolError "response is not expected")
  let some head := entry.head | throw (streamError id .internalError "missing request head")
  if connection.failure.isSome then throw (streamError id .streamClosed "connection failed")
  if response.body.size > connection.config.maxResponseBodyBytes then throw (streamError id .internalError "response exceeds limit")
  let queued := connection.streams.foldl (fun n entry => n + match entry.pending with | some p => p.body.size | none => 0) 0
  if queued + response.body.size > connection.config.maxQueuedResponseBytes then throw (streamError id .internalError "response queue exceeds limit")
  match response.validate head.method with
  | .error message => throw (streamError id .internalError message)
  | .ok _ => pure ()
  let bodyForbidden := head.method == "HEAD" || response.status == 204 || response.status == 205 || response.status == 304
  if bodyForbidden && !trailers.isEmpty then throw (streamError id .internalError "trailers forbidden for this response")
  let trailing ← encodedTrailers connection id trailers
  let noBody := bodyForbidden || response.body.isEmpty
  let endStream := noBody && trailing.isEmpty
  let mut fields ← responseFields connection id response
  if response.status != 204 && response.status != 304 then
    fields := fields.push { name := "content-length".toUTF8, value := (toString response.body.size).toUTF8 }
  checkPeerHeaders connection id fields
  let (encoder, headers) ← encodedHeaders connection.encoder fields id endStream connection.peerFrameSize
  if headers.size > connection.config.maxOutputBatchBytes then throw (streamError id .internalError "response output limit exceeded")
  let (stream, _) ← entry.stream.apply .server (.headers .outbound endStream)
  let connection := { connection with encoder }
  if endStream then return (removeStream connection id, headers)
  let body := if bodyForbidden then ByteArray.empty else response.body
  return (putStream connection { entry with stream, pending := some { body, trailers := trailing } }, headers)

/-- Compatibility helper: queue HEADERS, then schedule a bounded body batch. -/
def Connection.respond (connection : Connection) (id : UInt32) (response : HTTP1.Response) :
    Except ProtocolError (Connection × ByteArray) := do
  let (connection, headers) ← connection.queueResponse id response
  let (connection, data) ← connection.drain
  return (connection, headers.append data)

/-- Whether a new locally initiated pushed stream is allowed. -/
def Connection.canPush (connection : Connection) : Bool :=
  connection.config.enablePush && connection.peerEnablePush && !connection.peerGoAway &&
    connection.localGoAway.isNone && connection.failure.isNone && !connection.inputEnded &&
    connection.nextPushStream <= 2147483647 && connection.pushes < connection.config.maxPushes &&
    (connection.streams.filter (fun e => e.stream.id.toNat % 2 == 0)).size < connection.peerMaxConcurrentStreams

private def encodedPromise (connection : Connection) (parent promised : UInt32) (fields : Array HPACK.Header) :
    Except ProtocolError (HPACK.Context × ByteArray) := do
  let (encoder, block) ← match HPACK.encode connection.encoder fields with
    | .ok result => pure result
    | .error message => throw (streamError parent .internalError message)
  let mut output := ByteArray.empty
  let mut offset := 0
  let mut first := true
  for _ in [:block.size / (connection.peerFrameSize - 4) + 2] do
    if !first && offset == block.size then break
    let capacity := connection.peerFrameSize - if first then 4 else 0
    let stop := min block.size (offset + capacity)
    let fragment := block.extract offset stop
    let payload := if first then (u32 promised).append fragment else fragment
    output := output.append (← wire ⟨if first then 5 else 9, if stop == block.size then 4 else 0, parent, payload⟩)
    offset := stop
    first := false
  return (encoder, output)

/-- Reserve an even stream and queue its response; DATA waits for `drain`. -/
def Connection.push (connection : Connection) (parent : UInt32) (request : RequestHead) (response : HTTP1.Response) :
    Except ProtocolError (Connection × ByteArray × UInt32) := do
  if !connection.canPush then throw (streamError parent .refusedStream "server push is disabled or exhausted")
  let some entry := findStream connection parent | throw (streamError parent .streamClosed "push parent is closed")
  let some head := entry.head | throw (streamError parent .protocolError "push parent has no request head")
  if parent.toNat % 2 == 0 || (entry.stream.state != .open && entry.stream.state != .halfClosedRemote) then
    throw (streamError parent .protocolError "push parent state forbids PUSH_PROMISE")
  if (request.method != "GET" && request.method != "HEAD") || request.contentLength.getD 0 != 0 ||
      request.scheme != head.scheme || request.authority != head.authority then
    throw (streamError parent .internalError "push must be a bodyless same-origin GET or HEAD")
  let mut fields : Array HPACK.Header := #[{ name := ":method".toUTF8, value := request.method.toUTF8 }, { name := ":scheme".toUTF8, value := request.scheme }, { name := ":authority".toUTF8, value := request.authority }, { name := ":path".toUTF8, value := request.target }]
  for header in request.headers do
    fields := fields.push { name := header.name.toUTF8, value := header.value, sensitive := sensitiveName header.name }
  let validated ← match validateRequestHead fields 0 with
    | .ok validated => pure validated
    | .error message => throw (streamError parent .internalError message)
  checkPeerHeaders connection parent fields
  let id := UInt32.ofNat connection.nextPushStream
  let (encoder, promise) ← encodedPromise connection parent id fields
  let stream ← Stream.new id connection.peerInitialWindow
    (if connection.awaitingAck then defaultWindow else connection.config.initialWindowSize)
  let (stream, _) ← stream.apply .server .reserveLocal
  let exchange : Exchange := { stream, head := some validated, delivered := true, startedAt := connection.now, priority := requestPriority request.headers }
  let connection := { connection with encoder, nextPushStream := connection.nextPushStream + 2, pushes := connection.pushes + 1, streams := connection.streams.push exchange }
  let (connection, headers) ← connection.queueResponse id response
  if promise.size + headers.size > connection.config.maxOutputBatchBytes then
    throw (streamError parent .internalError "push output limit exceeded")
  return (connection, promise.append headers, id)

/-- A safe same-origin path convenience for an application's push hook. -/
def Connection.pushPath (connection : Connection) (parent : UInt32) (target : ByteArray)
    (headers : Array HTTP1.Header) (response : HTTP1.Response) : Except ProtocolError (Connection × ByteArray × UInt32) := do
  let some entry := findStream connection parent | throw (streamError parent .streamClosed "push parent is closed")
  let some head := entry.head | throw (streamError parent .protocolError "push parent has no request head")
  if target.isEmpty || target[0]! != 47 then throw (streamError parent .internalError "push path must be origin-form")
  connection.push parent { method := "GET", scheme := head.scheme, authority := head.authority, target, headers, contentLength := none } response

/-- Start a graceful drain at the highest accepted client stream. -/
def Connection.beginGoAway (connection : Connection) (code : ErrorCode := .noError) :
    Except ProtocolError (Connection × ByteArray) := do
  if connection.localGoAway.isSome then return (connection, ByteArray.empty)
  let cutoff := connection.highestStream
  return ({ connection with localGoAway := some cutoff, pendingPriorities := #[] }, ← wire ⟨7, 0, 0, (u32 cutoff).append (u32 code.toUInt32)⟩)

def Connection.draining (connection : Connection) : Bool :=
  connection.localGoAway.isSome || connection.peerGoAway || connection.inputEnded

/-- A peer GOAWAY stops new work but keeps control traffic live until peer EOF,
    idle timeout, or our own GOAWAY. Closing immediately can reset unread PINGs. -/
def Connection.drainComplete (connection : Connection) : Bool :=
  (connection.localGoAway.isSome || connection.inputEnded) && connection.streams.isEmpty

def Connection.isClosed (connection : Connection) : Bool :=
  connection.failure.isSome || connection.drainComplete

private def failedStep (connection : Connection) (error : ProtocolError) (consumed : Nat)
    (output : Array ByteArray := #[]) (requests : Array RequestEvent := #[]) : Connection.Step :=
  { connection := { connection with failure := some error }, consumed, output := output.push (connection.goAway error), requests, error := some error }

/-- Parse at most the configured frame/request budget from a borrowed range.
    State and earlier output survive errors; stream failures emit RST_STREAM. -/
def Connection.feedSlice (connection : Connection) (input : ByteArray) (offset length : Nat) : Connection.Step := Id.run do
  if let some error := connection.failure then return { connection, error := some error }
  if connection.inputEnded then return failedStep connection (connError .protocolError "input after EOF") 0
  if offset > input.size || length > input.size - offset then
    return failedStep connection (connError .internalError "invalid input slice") 0
  let preface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toUTF8
  let mut connection := connection
  let mut consumed := 0
  let mut output := #[]
  let mut outputSize := 0
  let mut requests := #[]
  for _ in [:min length 24] do
    if connection.prefaceRead == 24 then break
    if input[offset + consumed]! != preface[connection.prefaceRead]! then
      return failedStep connection (connError .protocolError "invalid client connection preface") (consumed + 1)
    connection := { connection with prefaceRead := connection.prefaceRead + 1 }
    consumed := consumed + 1
  for _ in [:connection.config.maxFramesPerStep] do
    if consumed == length || requests.size >= connection.config.maxRequestBatch || outputSize >= connection.config.maxOutputBatchBytes then break
    match connection.parser.feedSlice input (offset + consumed) (length - consumed) with
    | .needMore parser used =>
      connection := { connection with parser }
      consumed := consumed + used
      break
    | .error error used =>
      consumed := consumed + used
      connection := { connection with parser := FrameParser.new connection.config.maxFrameSize }
      if error.scope == .connection then return failedStep connection error consumed output requests
      if connection.assembly.isSome || !connection.peerSettings then
        return failedStep connection (connError .protocolError "invalid frame during mandatory SETTINGS or CONTINUATION sequence") consumed output requests
      match error.scope with
      | .connection => return failedStep connection error consumed output requests
      | .stream id =>
        match resetStream connection id error.code with
        | .error fatal => return failedStep connection fatal consumed output requests
        | .ok (next, bytes, _) => connection := next; output := output.push bytes; outputSize := outputSize + bytes.size
    | .complete frame used =>
      consumed := consumed + used
      connection := { connection with parser := FrameParser.new connection.config.maxFrameSize }
      match handleFrame connection frame with
      | .error error =>
        match error.scope with
        | .connection => return failedStep connection error consumed output requests
        | .stream id =>
          match resetStream connection id error.code with
          | .error fatal => return failedStep connection fatal consumed output requests
          | .ok (next, bytes, _) => connection := next; output := output.push bytes; outputSize := outputSize + bytes.size
      | .ok (next, bytes, events) =>
        connection := next
        if !bytes.isEmpty then output := output.push bytes
        outputSize := outputSize + bytes.size
        requests := requests ++ events
    if outputSize > connection.config.maxOutputBatchBytes then
      return failedStep connection (connError .enhanceYourCalm "connection output batch exceeded") consumed output requests
  return { connection, consumed, output, requests := requests.filter (fun event => connection.canRespond event.streamId) }

/-- Mark peer EOF. Partial framing is fatal; incomplete requests are canceled, while accepted requests and queued responses can finish draining. -/
def Connection.finish (connection : Connection) : Connection.Step := Id.run do
  if let some error := connection.failure then return { connection, error := some error }
  if connection.inputEnded then return { connection }
  if connection.hasPartialInput || !connection.peerSettings then
    return failedStep connection (connError .protocolError "truncated HTTP/2 input") 0
  let mut connection := { connection with inputEnded := true }
  let mut output := #[]
  for entry in connection.streams do
    if !entry.delivered then
      match resetStream connection entry.stream.id .cancel with
      | .ok (next, bytes, _) => connection := next; output := output.push bytes
      | .error error => return failedStep connection error 0 output
  match connection.beginGoAway with
  | .ok (next, bytes) =>
    if !bytes.isEmpty then output := output.push bytes
    return { connection := next, output }
  | .error error => return failedStep connection error 0 output

/-- Legacy owned-input adapter. The reactor path uses `feedSlice` directly. -/
def Connection.feed (connection : Connection) (input : ByteArray) :
    Except ProtocolError (Connection × ByteArray × Array RequestEvent) := do
  let mut connection := connection
  let mut consumed := 0
  let mut output := ByteArray.empty
  let mut requests := #[]
  for _ in [:input.size + 1] do
    if consumed == input.size then break
    let step := connection.feedSlice input consumed (input.size - consumed)
    if let some error := step.error then throw error
    connection := step.connection
    for bytes in step.output do output := output.append bytes
    requests := requests ++ step.requests
    consumed := consumed + step.consumed
    if step.consumed == 0 then break
  let (next, pending) ← connection.drain
  return (next, output.append pending, requests.filter (fun event => next.canRespond event.streamId))

end LeanNet.HTTP2
