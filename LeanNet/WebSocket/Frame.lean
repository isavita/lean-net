import LeanNet.Bytes

namespace LeanNet.WebSocket

inductive Opcode where
  | continuation | text | binary | close | ping | pong
  deriving BEq, Repr, Inhabited

def Opcode.wire : Opcode → UInt8
  | .continuation => 0 | .text => 1 | .binary => 2
  | .close => 8 | .ping => 9 | .pong => 10

def Opcode.parse? : UInt8 → Option Opcode
  | 0 => some .continuation | 1 => some .text | 2 => some .binary
  | 8 => some .close | 9 => some .ping | 10 => some .pong | _ => none

def Opcode.control (opcode : Opcode) : Bool := opcode.wire >= 8

structure Error where
  code : Nat := 1002
  message : String
  deriving BEq, Repr

structure Frame where
  fin : Bool := true
  opcode : Opcode
  payload : ByteArray := ByteArray.empty
  deriving Inhabited

namespace Frame

def validate (frame : Frame) (maxFrameBytes : Nat := 1048576) : Except Error Unit := do
  if frame.opcode.control && (!frame.fin || frame.payload.size > 125) then
    throw ⟨1002, "invalid control frame"⟩
  if frame.payload.size > maxFrameBytes then throw ⟨1009, "frame exceeds configured limit"⟩

/-- Masking is explicit: server adapters pass none; clients supply a fresh
    unpredictable four-byte key. This pure function never generates randomness. -/
def encode (frame : Frame) (mask : Option ByteArray := none)
    (maxFrameBytes : Nat := 1048576) : Except Error ByteArray := do
  frame.validate maxFrameBytes
  if mask.any (fun key => key.size != 4) then throw ⟨1002, "mask must contain four bytes"⟩
  let size := frame.payload.size
  if size > 9223372036854775807 then throw ⟨1009, "frame length exceeds wire range"⟩
  let mut out := ByteArray.empty.push ((if frame.fin then 128 else 0) ||| frame.opcode.wire)
  let marker : UInt8 := if size < 126 then UInt8.ofNat size else if size < 65536 then 126 else 127
  out := out.push (marker ||| (if mask.isSome then 128 else 0))
  if marker == 126 then
    out := (out.push (UInt8.ofNat (size / 256))).push (UInt8.ofNat size)
  else if marker == 127 then
    for index in [:8] do out := out.push (UInt8.ofNat (size / 2 ^ (56 - 8 * index)))
  if let some key := mask then
    out := out.append key
    for index in [:size] do out := out.push (frame.payload[index]! ^^^ key[index % 4]!)
  else out := out.append frame.payload
  return out

end Frame

structure FrameParser where
  private maxFrameBytes : Nat := 1048576
  private expectMasked : Bool := true
  private header : ByteArray := ByteArray.empty
  private headerTarget : Nat := 2
  private payloadLength : Option Nat := none
  private opcode : Opcode := .continuation
  private fin : Bool := true
  private mask : ByteArray := ByteArray.empty
  private blocks : List ByteArray := []
  private body : ByteArray := ByteArray.empty
  private bodySize : Nat := 0

def FrameParser.new (maxFrameBytes : Nat := 1048576) (expectMasked : Bool := true) : FrameParser :=
  { maxFrameBytes := min maxFrameBytes 16777216, expectMasked }

def FrameParser.isEmpty (parser : FrameParser) : Bool := parser.header.isEmpty

inductive FrameProgress where
  | needMore (parser : FrameParser) (consumed : Nat)
  | complete (frame : Frame) (consumed : Nat)
  | error (error : Error) (consumed : Nat)

private def decodeHeader (parser : FrameParser) : Except Error (Bool × Opcode × Nat × ByteArray) := do
  let head := parser.header
  if head.size < 2 then throw ⟨1002, "incomplete frame header"⟩
  if head[0]! &&& 112 != 0 then throw ⟨1002, "extensions are not negotiated"⟩
  let some opcode := Opcode.parse? (head[0]! &&& 15) | throw ⟨1002, "reserved opcode"⟩
  let fin := head[0]! &&& 128 != 0
  let masked := head[1]! &&& 128 != 0
  if masked != parser.expectMasked then throw ⟨1002, "incorrect peer masking"⟩
  let marker := (head[1]! &&& 127).toNat
  let extension := if marker == 126 then 2 else if marker == 127 then 8 else 0
  if head.size != 2 + extension + (if masked then 4 else 0) then
    throw ⟨1002, "invalid frame header length"⟩
  let mut size := marker
  if extension != 0 then
    if marker == 127 && head[2]! >= 128 then throw ⟨1002, "negative 64-bit frame length"⟩
    size := 0
    for index in [:extension] do size := size * 256 + head[2 + index]!.toNat
    if marker == 126 && size < 126 || marker == 127 && size < 65536 then
      throw ⟨1002, "nonminimal frame length"⟩
  if opcode.control && (!fin || size > 125) then throw ⟨1002, "invalid control frame"⟩
  if size > parser.maxFrameBytes then throw ⟨1009, "frame exceeds configured limit"⟩
  let key := if masked then head.extract (2 + extension) head.size else ByteArray.empty
  return (fin, opcode, size, key)

private def frameOf (parser : FrameParser) : Frame := Id.run do
  let mut bytes := ByteArray.emptyWithCapacity parser.bodySize
  for block in parser.blocks.reverse do bytes := bytes.append block
  bytes := bytes.append parser.body
  return { fin := parser.fin, opcode := parser.opcode, payload := bytes }

/-- At most one frame; consumed is relative to the supplied range. Header
    storage is at most14 bytes, body storage is bounded before payload copying. -/
def FrameParser.feedSlice (initial : FrameParser) (input : ByteArray)
    (offset length : Nat) : FrameProgress := Id.run do
  if offset > input.size || length > input.size - offset then
    return .error ⟨1002, "invalid input slice"⟩ 0
  let mut parser := initial
  let mut used := 0
  for _ in [:16] do
    if parser.payloadLength.isNone then
      let count := min (parser.headerTarget - parser.header.size) (length - used)
      if count == 0 then return .needMore parser used
      let header := input.copySlice (offset + used) parser.header parser.header.size count false
      used := used + count
      parser := { parser with header }
      if header.size < parser.headerTarget then return .needMore parser used
      if parser.headerTarget == 2 then
        let marker := (header[1]! &&& 127).toNat
        let target := 2 + (if marker == 126 then 2 else if marker == 127 then 8 else 0) +
          (if header[1]! &&& 128 != 0 then 4 else 0)
        parser := { parser with headerTarget := target }
      if parser.header.size < parser.headerTarget then continue
      match decodeHeader parser with
      | .error error => return .error error used
      | .ok (fin, opcode, size, key) =>
        parser := { parser with payloadLength := some size, fin, opcode, mask := key }
    let size := parser.payloadLength.getD 0
    let count := min (size - parser.bodySize) (length - used)
    let mut blocks := parser.blocks
    let mut active := parser.body
    for index in [:count] do
      let byte := input[offset + used + index]!
      let byte := if parser.mask.isEmpty then byte else byte ^^^ parser.mask[(parser.bodySize + index) % 4]!
      active := active.push byte
      if active.size == 4096 then
        blocks := active :: blocks
        active := ByteArray.empty
    used := used + count
    parser := { parser with blocks, body := active, bodySize := parser.bodySize + count }
    if parser.bodySize == size then return .complete (frameOf parser) used
    return .needMore parser used
  return .error ⟨1002, "frame parser work invariant"⟩ used

def FrameParser.feed (parser : FrameParser) (input : ByteArray) : FrameProgress :=
  parser.feedSlice input 0 input.size

def FrameParser.finish (parser : FrameParser) : Except Error Unit :=
  if parser.isEmpty then .ok () else .error ⟨1002, "truncated frame"⟩

end LeanNet.WebSocket
