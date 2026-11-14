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
  if kind == 0 || kind == 1 || kind == 5 then
    let padded := bit frame.flags 8
    let prefixLen := if padded then 1 else 0
    let extra := if kind == 1 && bit frame.flags 32 then 5 else if kind == 5 then 4 else 0
    if size < prefixLen + extra then
      throw (connError .frameSizeError "frame omits mandatory fields")
    let padding := if padded then (frame.payload[0]!).toNat else 0
    if padding > size - prefixLen - extra then
      throw (connError .protocolError "invalid frame padding")
    if kind == 1 && extra == 5 && read32 frame.payload prefixLen % 2147483648 == stream.toNat then
      throw (streamError stream .protocolError "stream depends on itself")
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

/-- Bounded, resumable frame parser. The caller chooses its advertised local
    frame limit; bytes are processed once and payload storage never exceeds it. -/
structure FrameParser where
  private maxFrameSize : Nat := 16384
  private header : ByteArray := ByteArray.empty
  private expected : Option Nat := none
  private kind : UInt8 := 0
  private flags : UInt8 := 0
  private streamId : UInt32 := 0
  private bodyBlocks : List ByteArray := []
  private bodyRev : List UInt8 := []
  private bodyBlockSize : Nat := 0
  private bodySize : Nat := 0

def FrameParser.new (maxFrameSize : Nat := 16384) : FrameParser :=
  { maxFrameSize := min maxFrameSize 16777215 }

inductive FrameParseResult where
  | needMore (parser : FrameParser)
  | complete (frame : Frame) (remaining : ByteArray)
  /-- A stream-scoped error is emitted only after the whole frame is consumed;
      the caller can resume a new parser with `remaining`. -/
  | error (error : ProtocolError) (remaining : ByteArray)

private def appendPayload (parser : FrameParser) (byte : UInt8) : FrameParser :=
  let active := byte :: parser.bodyRev
  if parser.bodyBlockSize + 1 == 4096 then
    { parser with bodyBlocks := ByteArray.mk active.reverse.toArray :: parser.bodyBlocks,
                  bodyRev := [], bodyBlockSize := 0, bodySize := parser.bodySize + 1 }
  else
    { parser with bodyRev := active, bodyBlockSize := parser.bodyBlockSize + 1,
                  bodySize := parser.bodySize + 1 }

private def finishFrame (parser : FrameParser) : Frame := Id.run do
  let mut payload := ByteArray.empty
  for block in parser.bodyBlocks.reverse do payload := payload.append block
  payload := payload.append (ByteArray.mk parser.bodyRev.reverse.toArray)
  return ⟨parser.kind, parser.flags, parser.streamId, payload⟩

private inductive FrameAdvance where
  | more (parser : FrameParser)
  | done (frame : Frame)
  | fail (error : ProtocolError)

private def completeFrame (parser : FrameParser) : FrameAdvance :=
  let frame := finishFrame parser
  match frame.validate parser.maxFrameSize with
  | .ok () => .done frame
  | .error error => .fail error

private def advanceFrame (parser : FrameParser) (byte : UInt8) : FrameAdvance :=
  match parser.expected with
  | some expected =>
    let next := appendPayload parser byte
    if next.bodySize == expected then completeFrame next else .more next
  | none =>
    let header := parser.header.push byte
    if header.size < 9 then .more { parser with header := header }
    else
      let length := (header[0]!).toNat * 65536 + (header[1]!).toNat * 256 + (header[2]!).toNat
      if length > parser.maxFrameSize then .fail (connError .frameSizeError "frame exceeds maximum size")
      else
        let next := { parser with header := header, expected := some length,
                                  kind := header[3]!, flags := header[4]!,
                                  streamId := UInt32.ofNat (read32 header 5 % 2147483648) }
        if length == 0 then completeFrame next else .more next

/-- Feed bytes, returning the unconsumed suffix after a frame or error. -/
def FrameParser.feed (parser : FrameParser) (input : ByteArray) : FrameParseResult :=
  go parser 0 input.size
where
  go (parser : FrameParser) (index remaining : Nat) : FrameParseResult :=
    match remaining with
    | 0 => .needMore parser
    | count + 1 =>
      match advanceFrame parser input[index]! with
      | .more next => go next (index + 1) count
      | .done frame => .complete frame (input.extract (index + 1) input.size)
      | .fail error => .error error (input.extract (index + 1) input.size)

/-- EOF is clean only between frames. -/
def FrameParser.finish (parser : FrameParser) : Except ProtocolError Unit :=
  if parser.header.isEmpty then .ok ()
  else .error (connError .protocolError "truncated frame")

end LeanNet.HTTP2
