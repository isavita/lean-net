namespace LeanNet.HTTP.Static

structure DecodedPath where
  path : ByteArray
  query : ByteArray := ByteArray.empty
  trailingSlash : Bool := false
  deriving Inhabited

private def hex? (byte : UInt8) : Option UInt8 :=
  let n := byte.toNat
  if n >= 48 && n <= 57 then some (byte - 48)
  else if n >= 65 && n <= 70 then some (byte - 55)
  else if n >= 97 && n <= 102 then some (byte - 87)
  else none

private def forbiddenDevice (text : String) : Bool := Id.run do
  let stem := String.ofList ((((text.splitOn ".").head!).toLower.toList.reverse.dropWhile (· == ' ')).reverse)
  if ["con", "prn", "aux", "nul"].contains stem then return true
  for devicePrefix in ["com", "lpt"] do
    for digit in [1:10] do
      if stem == devicePrefix ++ toString digit then return true
  return false

private def segment (raw : ByteArray) : Except String ByteArray := do
  let mut output := ByteArray.empty
  let mut next := 0
  for index in [:raw.size] do
    if index < next then continue
    let mut byte := raw[index]!
    if byte == 37 then
      if index + 2 >= raw.size then throw "incomplete percent escape"
      let some high := hex? raw[index + 1]! | throw "invalid percent escape"
      let some low := hex? raw[index + 2]! | throw "invalid percent escape"
      byte := high * 16 + low
      next := index + 3
    if byte.toNat < 32 || byte == 127 || byte == 47 || byte == 92 || byte == 58 then
      throw "unsafe path segment"
    output := output.push byte
  let some value := String.fromUTF8? output | throw "path is not UTF-8"
  if value == "." || value == ".." || value.isEmpty || forbiddenDevice value then
    throw "unsafe path segment"
  if output[output.size - 1]! == 32 || output[output.size - 1]! == 46 then
    throw "ambiguous trailing path character"
  return output

/-- Origin-form static paths use one percent-decode pass per segment. Query
    separation precedes decoding, and encoded separators cannot change routing.
    The returned key is for catalog lookup, never a filesystem path to reopen. -/
def decodePath (target : ByteArray) : Except String DecodedPath := do
  if target.isEmpty || target[0]! != 47 then throw "static target must be origin-form"
  if target.toList.any (· == 35) then throw "fragments are not request targets"
  let split := (target.data.findIdx? (· == 63)).getD target.size
  let path := target.extract 0 split
  let query := if split < target.size then target.extract (split + 1) target.size else ByteArray.empty
  let mut output := "/".toUTF8
  let mut start := 1
  for index in [1:path.size + 1] do
    if index == path.size || path[index]! == 47 then
      if index == start then
        if index == path.size && (path.size == 1 || path[path.size - 1]! == 47) then continue
        throw "empty path segment"
      output := output ++ (← segment (path.extract start index))
      if index < path.size then output := output.push 47
      start := index + 1
  return { path := output, query, trailingSlash := path.size > 0 && path[path.size - 1]! == 47 }

private def unreserved (byte : UInt8) : Bool :=
  let n := byte.toNat
  (n >= 65 && n <= 90) || (n >= 97 && n <= 122) || (n >= 48 && n <= 57) ||
    [45, 46, 95, 126].contains n

private def hexDigit (value : Nat) : UInt8 := UInt8.ofNat (if value < 10 then 48 + value else 55 + value)

def encodeSegment (bytes : ByteArray) : ByteArray := Id.run do
  let mut output := ByteArray.empty
  for byte in bytes do
    if unreserved byte then output := output.push byte
    else output := ((output.push 37).push (hexDigit (byte.toNat / 16))).push (hexDigit (byte.toNat % 16))
  return output

/-- Escape catalog keys for Location or href generation without introducing
    new delimiters from a filename. Existing slash separators are retained. -/
def encodePath (bytes : ByteArray) : ByteArray := Id.run do
  let mut output := ByteArray.empty
  for byte in bytes do
    if byte == 47 || unreserved byte then output := output.push byte
    else output := ((output.push 37).push (hexDigit (byte.toNat / 16))).push (hexDigit (byte.toNat % 16))
  return output

def escapeHtml (value : String) : String := Id.run do
  let mut output := ""
  for char in value.toList do
    output := output ++ match char with
      | '&' => "&amp;"
      | '<' => "&lt;"
      | '>' => "&gt;"
      | '"' => "&quot;"
      | '\'' => "&#39;"
      | _ => String.singleton char
  return output

end LeanNet.HTTP.Static
