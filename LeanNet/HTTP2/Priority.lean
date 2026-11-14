import LeanNet.HTTP2.Frame

namespace LeanNet.HTTP2

/-- RFC 9218 request priority; smaller urgency means higher precedence. -/
structure Priority where
  urgency : UInt8 := 3
  incremental : Bool := false
  deriving BEq, Repr, Inhabited

/-- Construct a priority only when its urgency is in the RFC-defined range. -/
def Priority.ofValues (urgency : UInt8) (incremental : Bool := false) : Except String Priority :=
  if urgency <= 7 then .ok ⟨urgency, incremental⟩ else .error "urgency is outside 0..7"

/-- Check values supplied through Lean's public structure constructor. -/
def Priority.valid (priority : Priority) : Bool := priority.urgency <= 7

/-- Sort by urgency; non-incremental responses precede incremental peers.
    Equal priorities preserve the caller's existing ordering. -/
def Priority.precedes (a b : Priority) : Bool :=
  a.urgency < b.urgency || (a.urgency == b.urgency && !a.incremental && b.incremental)

private inductive Bare where
  | integer (value : Int)
  | boolean (value : Bool)
  | other

private def digit (c : UInt8) : Bool := c >= 48 && c <= 57
private def lower (c : UInt8) : Bool := c >= 97 && c <= 122
private def alpha (c : UInt8) : Bool := lower c || (c >= 65 && c <= 90)
private def keyChar (c : UInt8) : Bool := lower c || digit c || [42, 45, 46, 95].contains c.toNat
private def tokenChar (c : UInt8) : Bool :=
  alpha c || digit c || [33,35,36,37,38,39,42,43,45,46,47,58,94,95,96,124,126].contains c.toNat
private def base64Char (c : UInt8) : Bool := alpha c || digit c || c == 43 || c == 47
private def ows (c : UInt8) : Bool := c == 32 || c == 9
private def peekByte (input : ByteArray) (index : Nat) : Option UInt8 := input[index]?

private def skipWhile (input : ByteArray) (start : Nat) (predicate : UInt8 → Bool) : Nat := Id.run do
  let mut position := start
  for i in [start:input.size] do
    if predicate input[i]! then position := i + 1 else break
  return position

private def parseKey (input : ByteArray) (start : Nat) : Except String (ByteArray × Nat) := do
  let some first := peekByte input start | throw "expected structured-field key"
  if !lower first && first != 42 then throw "invalid structured-field key"
  let stop := skipWhile input (start + 1) keyChar
  return (input.extract start stop, stop)

private def parseNumber (input : ByteArray) (start : Nat) : Except String (Bare × Nat) := do
  let negative := peekByte input start == some 45
  let digitsStart := start + if negative then 1 else 0
  let stop := skipWhile input digitsStart digit
  let digits := stop - digitsStart
  if digits == 0 || digits > 15 then throw "invalid structured number"
  if peekByte input stop == some 46 then
    if digits > 12 then throw "structured decimal too long"
    let endDigits := skipWhile input (stop + 1) digit
    let fraction := endDigits - (stop + 1)
    if fraction == 0 || fraction > 3 then throw "invalid structured decimal"
    return (.other, endDigits)
  let mut n : Nat := 0
  for i in [digitsStart:stop] do n := n * 10 + input[i]!.toNat - 48
  return (.integer (if negative then -(Int.ofNat n) else Int.ofNat n), stop)

private def parseString (input : ByteArray) (start : Nat) : Except String Nat := do
  let mut position := start + 1
  let mut closed := false
  for _ in [start + 1:input.size] do
    if position >= input.size then break
    let c := input[position]!
    if c == 34 then
      position := position + 1
      closed := true
      break
    else if c == 92 then
      position := position + 1
      if position >= input.size || (input[position]! != 34 && input[position]! != 92) then
        throw "invalid structured string escape"
      position := position + 1
    else
      if c < 32 || c > 126 then throw "invalid structured string byte"
      position := position + 1
  if !closed then throw "unterminated structured string"
  return position

private def parseBytes (input : ByteArray) (start : Nat) : Except String Nat := do
  let stop := skipWhile input (start + 1) (fun c => base64Char c || c == 61)
  if peekByte input stop != some 58 then throw "invalid structured byte sequence"
  let encoded := input.extract (start + 1) stop
  let mut padding := 0
  let mut sawPadding := false
  for c in encoded do
    if c == 61 then
      sawPadding := true
      padding := padding + 1
    else if sawPadding then throw "invalid base64 padding"
  let unpadded := encoded.size - padding
  let remainder := unpadded % 4
  let requiredPadding := (4 - remainder) % 4
  if padding > 2 || remainder == 1 || padding > requiredPadding then
    throw "invalid base64 length"
  return stop + 1

private def parseBare (input : ByteArray) (start : Nat) : Except String (Bare × Nat) := do
  let some c := peekByte input start | throw "missing structured-field item"
  if c == 45 || digit c then return ← parseNumber input start
  if c == 34 then return (.other, ← parseString input start)
  if c == 58 then return (.other, ← parseBytes input start)
  if c == 63 then
    match peekByte input (start + 1) with
    | some 48 => return (.boolean false, start + 2)
    | some 49 => return (.boolean true, start + 2)
    | _ => throw "invalid structured boolean"
  if alpha c || c == 42 then return (.other, skipWhile input (start + 1) tokenChar)
  throw "invalid structured-field item"

private def parseParams (input : ByteArray) (start : Nat) : Except String Nat := do
  let mut position := start
  for _ in [:input.size + 1] do
    if peekByte input position != some 59 then break
    position := skipWhile input (position + 1) (· == 32)
    let (_, next) ← parseKey input position
    position := next
    if peekByte input position == some 61 then
      let (_, next) ← parseBare input (position + 1)
      position := next
  return position

private def parseInner (input : ByteArray) (start : Nat) : Except String Nat := do
  let mut position := start + 1
  let mut closed := false
  for _ in [:input.size + 1] do
    position := skipWhile input position (· == 32)
    if peekByte input position == some 41 then
      position := position + 1
      closed := true
      break
    let (_, next) ← parseBare input position
    position ← parseParams input next
    if peekByte input position != some 32 && peekByte input position != some 41 then
      throw "invalid structured inner list separator"
  if !closed then throw "unterminated structured inner list"
  parseParams input position

private def parseMember (input : ByteArray) (start : Nat) : Except String (Bare × Nat) := do
  if peekByte input start == some 40 then return (.other, ← parseInner input start)
  let (value, next) ← parseBare input start
  return (value, ← parseParams input next)

/-- Parse an RFC 8941 Dictionary. Malformed dictionaries fail as a whole;
    RFC 9218 requires unknown, out-of-range and wrong-typed values be ignored.
    Duplicate keys replace earlier values, including when the last value is ignored. -/
def Priority.parse (input : ByteArray) : Except String Priority := do
  let mut position := skipWhile input 0 ows
  let mut urgency : UInt8 := 3
  let mut incremental := false
  if position == input.size then return {}
  for _ in [:input.size + 1] do
    let (key, next) ← parseKey input position
    position := next
    let mut value := Bare.boolean true
    if peekByte input position == some 61 then
      let (item, next) ← parseMember input (position + 1)
      value := item
      position := next
    else
      position ← parseParams input position
    if key == "u".toUTF8 then
      urgency := match value with
        | .integer n => if n >= 0 && n <= 7 then UInt8.ofNat n.toNat else 3
        | _ => 3
    else if key == "i".toUTF8 then
      incremental := match value with | .boolean b => b | _ => false
    position := skipWhile input position ows
    if position == input.size then return ⟨urgency, incremental⟩
    if peekByte input position != some 44 then throw "invalid structured dictionary separator"
    position := skipWhile input (position + 1) ows
    if position == input.size then throw "trailing structured dictionary comma"
  throw "invalid structured dictionary"

/-- The HTTP/2 PRIORITY_UPDATE payload. The field is parsed independently so
    a malformed Structured Field can be ignored without a connection error. -/
structure PriorityUpdate where
  target : UInt32
  fieldValue : ByteArray

private def updateError (code : ErrorCode) (message : String) : ProtocolError :=
  ⟨code, .connection, message⟩

def PriorityUpdate.decode (frame : Frame) : Except ProtocolError PriorityUpdate := do
  if frame.kind != 16 then throw (updateError .protocolError "not PRIORITY_UPDATE")
  if frame.streamId != 0 then throw (updateError .protocolError "PRIORITY_UPDATE must use stream zero")
  if frame.payload.size < 4 then throw (updateError .frameSizeError "short PRIORITY_UPDATE")
  let n := ((frame.payload[0]!).toNat % 128) * 16777216 + (frame.payload[1]!).toNat * 65536 +
    (frame.payload[2]!).toNat * 256 + (frame.payload[3]!).toNat
  if n == 0 then throw (updateError .protocolError "zero prioritized stream")
  return ⟨UInt32.ofNat n, frame.payload.extract 4 frame.payload.size⟩

def PriorityUpdate.encode (update : PriorityUpdate) : Except ProtocolError Frame := do
  let n := update.target.toNat
  if n == 0 || n > 2147483647 then throw (updateError .protocolError "invalid prioritized stream")
  if update.fieldValue.size > 16777211 then throw (updateError .frameSizeError "PRIORITY_UPDATE too large")
  match Priority.parse update.fieldValue with
  | .error _ => throw (updateError .protocolError "invalid PRIORITY_UPDATE field")
  | .ok _ => pure ()
  let bytes := ByteArray.mk #[UInt8.ofNat (n / 16777216), UInt8.ofNat (n / 65536), UInt8.ofNat (n / 256), UInt8.ofNat n]
  return ⟨16, 0, 0, bytes.append update.fieldValue⟩

end LeanNet.HTTP2
