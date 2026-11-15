namespace LeanNet.HTTP2

/-- Standard HTTP/2 error codes, encoded as their RFC wire values. -/
inductive ErrorCode where
  | noError | protocolError | internalError | flowControlError | settingsTimeout
  | streamClosed | frameSizeError | refusedStream | cancel | compressionError
  | connectError | enhanceYourCalm | inadequateSecurity | http11Required
  deriving Repr, BEq, Inhabited

def ErrorCode.toUInt32 : ErrorCode → UInt32
  | .noError => 0 | .protocolError => 1 | .internalError => 2 | .flowControlError => 3
  | .settingsTimeout => 4 | .streamClosed => 5 | .frameSizeError => 6
  | .refusedStream => 7 | .cancel => 8 | .compressionError => 9 | .connectError => 10
  | .enhanceYourCalm => 11 | .inadequateSecurity => 12 | .http11Required => 13

inductive ErrorScope where
  | connection
  | stream (id : UInt32)
  deriving Repr, BEq, Inhabited

structure ProtocolError where
  code : ErrorCode
  scope : ErrorScope
  message : String
  deriving Repr, BEq, Inhabited

/-- A decoded frame. Reserved header bits are discarded on receipt; unknown
    types and flags are preserved for extension handling by the caller. -/
structure Frame where
  kind : UInt8
  flags : UInt8
  streamId : UInt32
  payload : ByteArray
  deriving BEq, Inhabited

private def connError (code : ErrorCode) (message : String) : ProtocolError :=
  ⟨code, .connection, message⟩

private def streamError (id : UInt32) (code : ErrorCode) (message : String) : ProtocolError :=
  ⟨code, .stream id, message⟩

private def bit (value : UInt8) (mask : UInt8) : Bool := (value &&& mask) != 0

private def read32 (payload : ByteArray) (offset : Nat) : Nat :=
  (payload[offset]!).toNat * 16777216 + (payload[offset + 1]!).toNat * 65536 +
    (payload[offset + 2]!).toNat * 256 + (payload[offset + 3]!).toNat

private def checkSettings (payload : ByteArray) : Except ProtocolError Unit := do
  for i in [0:payload.size / 6] do
    let offset := i * 6
    let id := (payload[offset]!).toNat * 256 + (payload[offset + 1]!).toNat
    let value := read32 payload (offset + 2)
    if id == 2 && value > 1 then
      throw (connError .protocolError "invalid SETTINGS_ENABLE_PUSH")
    if id == 4 && value > 2147483647 then
      throw (connError .flowControlError "invalid SETTINGS_INITIAL_WINDOW_SIZE")
    if id == 5 && (value < 16384 || value > 16777215) then
      throw (connError .protocolError "invalid SETTINGS_MAX_FRAME_SIZE")
    if id == 9 && value > 1 then
      throw (connError .protocolError "invalid SETTINGS_NO_RFC7540_PRIORITIES")
    if id == 8 && value > 1 then
      throw (connError .protocolError "invalid SETTINGS_ENABLE_CONNECT_PROTOCOL")

/-- Validate wire-level frame constraints; stream sequencing and peer-specific
    semantics (such as client PUSH_PROMISE) belong to the connection layer. -/
def Frame.validate (frame : Frame) (maxFrameSize : Nat := 16384) : Except ProtocolError Unit := do
  let size := frame.payload.size
  let kind := frame.kind.toNat
  let stream := frame.streamId
  if stream.toNat > 2147483647 then throw (connError .protocolError "reserved stream bit set")
  if size > 16777215 || size > maxFrameSize then
    throw (connError .frameSizeError "frame exceeds maximum size")
  if [0, 1, 2, 3, 5, 9].contains kind && stream == 0 then
    throw (connError .protocolError "frame requires a stream")
  if [4, 6, 7].contains kind && stream != 0 then
    throw (connError .protocolError "connection frame has a stream id")
  if kind == 2 && size != 5 then throw (streamError stream .frameSizeError "invalid PRIORITY size")
  if kind == 3 && size != 4 then throw (connError .frameSizeError "invalid RST_STREAM size")
  if kind == 4 then
    if (bit frame.flags 1 && size != 0) || size % 6 != 0 then
      throw (connError .frameSizeError "invalid SETTINGS size")
    checkSettings frame.payload
  if kind == 6 && size != 8 then throw (connError .frameSizeError "invalid PING size")
  if kind == 7 && size < 8 then throw (connError .frameSizeError "invalid GOAWAY size")
  if kind == 8 then
    if size != 4 then throw (connError .frameSizeError "invalid WINDOW_UPDATE size")
    if read32 frame.payload 0 % 2147483648 == 0 then
      if stream == 0 then throw (connError .protocolError "zero connection window increment")
      else throw (streamError stream .protocolError "zero stream window increment")
  if kind == 16 then
    if stream != 0 then throw (connError .protocolError "PRIORITY_UPDATE requires the control stream")
    if size < 4 then throw (connError .frameSizeError "PRIORITY_UPDATE omits the prioritized stream id")
    if read32 frame.payload 0 % 2147483648 == 0 then
      throw (connError .protocolError "PRIORITY_UPDATE has a zero prioritized stream id")
  if kind == 0 || kind == 1 || kind == 5 then
    let padded := bit frame.flags 8
    let prefixLen := if padded then 1 else 0
    let extra := if kind == 1 && bit frame.flags 32 then 5 else if kind == 5 then 4 else 0
    if size < prefixLen + extra then
      throw (connError .frameSizeError "frame omits mandatory fields")
    let padding := if padded then (frame.payload[0]!).toNat else 0
    if padding > size - prefixLen - extra then
      throw (connError .protocolError "invalid frame padding")
    -- HEADERS dependency semantics belong to the connection: its HPACK block
    -- must still be decoded before resetting a self-dependent stream.
    if kind == 5 && read32 frame.payload prefixLen % 2147483648 == 0 then
      throw (connError .protocolError "invalid promised stream id")
  if kind == 2 && read32 frame.payload 0 % 2147483648 == stream.toNat then
    throw (streamError stream .protocolError "stream depends on itself")

/-- Encode a complete frame using the peer's advertised size limit. -/
def Frame.encode (frame : Frame) (maxFrameSize : Nat := 16384) : Except ProtocolError ByteArray := do
  frame.validate maxFrameSize
  let len := frame.payload.size
  let stream := frame.streamId.toNat
  let header := ByteArray.mk #[UInt8.ofNat (len / 65536), UInt8.ofNat (len / 256), UInt8.ofNat len,
    frame.kind, frame.flags, UInt8.ofNat (stream / 16777216), UInt8.ofNat (stream / 65536),
    UInt8.ofNat (stream / 256), UInt8.ofNat stream]
  -- Padding is ignored by receivers but must be zero when sending.
  if (frame.kind == 0 || frame.kind == 1 || frame.kind == 5) && bit frame.flags 8 then
    let padding := (frame.payload[0]!).toNat
    for i in [size - padding:size] do
      if frame.payload[i]! != 0 then throw (connError .protocolError "nonzero outgoing padding")
  return header.append frame.payload
where
  size := frame.payload.size

/-- Bounded, resumable frame parser. Payload spans are copied into owned 4K
    blocks; retaining an old parser bounds copy-on-write to one active block.
    No parser state borrows or retains the caller's receive ByteArray. -/
structure FrameParser where
  private maxFrameSize : Nat := 16384
  private header : ByteArray := ByteArray.empty
  private expected : Option Nat := none
  private kind : UInt8 := 0
  private flags : UInt8 := 0
  private streamId : UInt32 := 0
  private bodyBlocks : List ByteArray := []
  private body : ByteArray := ByteArray.empty
  private bodySize : Nat := 0

def FrameParser.new (maxFrameSize : Nat := 16384) : FrameParser :=
  { maxFrameSize := min maxFrameSize 16777215 }

inductive FrameParseResult where
  | needMore (parser : FrameParser)
  | complete (frame : Frame) (remaining : ByteArray)
  /-- A stream-scoped error is emitted only after the whole frame is consumed;
      the caller can resume a new parser with `remaining`. -/
  | error (error : ProtocolError) (remaining : ByteArray)

/-- One-frame progress within a supplied byte range. `consumed` is relative to
    that range, never an absolute offset. Errors preserve their original scope;
    except for an oversized header, the complete frame has been consumed. -/
inductive FrameSliceResult where
  | needMore (parser : FrameParser) (consumed : Nat)
  | complete (frame : Frame) (consumed : Nat)
  | error (error : ProtocolError) (consumed : Nat)

private def copyPayloadSpans (input : ByteArray) (offset count : Nat)
    (initialBlocks : List ByteArray) (initial : ByteArray) : List ByteArray × ByteArray := Id.run do
  let mut blocks := initialBlocks
  let mut active := initial
  let mut cursor := offset
  let mut remaining := count
  for _ in [:count / 4096 + 2] do
    if remaining == 0 then break
    let amount := min remaining (4096 - active.size)
    active := input.copySlice cursor active active.size amount false
    cursor := cursor + amount
    remaining := remaining - amount
    if active.size == 4096 then
      blocks := active :: blocks
      active := ByteArray.empty
  return (blocks, active)

private def appendPayloadSpan (parser : FrameParser) (input : ByteArray)
    (offset count : Nat) : FrameParser :=
  let (bodyBlocks, body) := copyPayloadSpans input offset count parser.bodyBlocks parser.body
  { parser with bodyBlocks, body, bodySize := parser.bodySize + count }

private def finishFrame (parser : FrameParser) : Frame := Id.run do
  if parser.bodyBlocks.isEmpty then
    return ⟨parser.kind, parser.flags, parser.streamId, parser.body⟩
  let mut payload := ByteArray.emptyWithCapacity parser.bodySize
  for block in parser.bodyBlocks.reverse do payload := payload.append block
  payload := payload.append parser.body
  return ⟨parser.kind, parser.flags, parser.streamId, payload⟩

/-- Parse at most one frame without copying the unconsumed suffix. Only the
    nine-byte header and consumed payload spans enter the owned parser state.
    Invalid source ranges are rejected without consuming any bytes. -/
def FrameParser.feedSlice (initial : FrameParser) (input : ByteArray)
    (offset length : Nat) : FrameSliceResult := Id.run do
  if offset > input.size || length > input.size - offset then
    return .error (connError .internalError "invalid frame input slice") 0
  let mut parser := initial
  let mut consumed := 0
  if parser.expected.isNone then
    let amount := min length (9 - parser.header.size)
    let header := input.copySlice offset parser.header parser.header.size amount false
    parser := { parser with header }
    consumed := amount
    if header.size < 9 then return .needMore parser consumed
    let expected := (header[0]!).toNat * 65536 + (header[1]!).toNat * 256 + (header[2]!).toNat
    if expected > parser.maxFrameSize then
      return .error (connError .frameSizeError "frame exceeds maximum size") consumed
    parser := { parser with
      expected := some expected
      kind := header[3]!
      flags := header[4]!
      streamId := UInt32.ofNat (read32 header 5 % 2147483648) }
  let some expected := parser.expected
    | return .error (connError .internalError "missing frame payload length") consumed
  let amount := min (length - consumed) (expected - parser.bodySize)
  parser := appendPayloadSpan parser input (offset + consumed) amount
  consumed := consumed + amount
  if parser.bodySize < expected then return .needMore parser consumed
  let frame := finishFrame parser
  match frame.validate parser.maxFrameSize with
  | .ok () => return .complete frame consumed
  | .error error => return .error error consumed

/-- Compatibility adapter returning an owned remainder. New connection loops
    use `feedSlice` and advance their cursor without copying that suffix. -/
def FrameParser.feed (parser : FrameParser) (input : ByteArray) : FrameParseResult :=
  match parser.feedSlice input 0 input.size with
  | .needMore next _ => .needMore next
  | .complete frame consumed => .complete frame (input.extract consumed input.size)
  | .error error consumed => .error error (input.extract consumed input.size)

/-- EOF is clean only between frames. -/
def FrameParser.finish (parser : FrameParser) : Except ProtocolError Unit :=
  if parser.header.isEmpty then .ok ()
  else .error (connError .protocolError "truncated frame")

end LeanNet.HTTP2
