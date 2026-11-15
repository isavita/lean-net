import LeanNet.HTTP1.Parser
import LeanNet.HTTP2.HPACK

namespace LeanNet.HTTP2

/-- Validated HTTP/2 request head; wire values and request target stay bytes. -/
structure RequestHead where
  method : String
  scheme : ByteArray
  authority : ByteArray
  target : ByteArray
  headers : Array HTTP1.Header
  contentLength : Option Nat
  protocol : Option ByteArray := none

private def tokenByte (b : UInt8) : Bool :=
  let n := b.toNat
  (n >= 48 && n <= 57) || (n >= 65 && n <= 90) || (n >= 97 && n <= 122) ||
    [33,35,36,37,38,39,42,43,45,46,94,95,96,124,126].contains n

private def validValue (value : ByteArray) : Bool :=
  value.toList.all (fun c => c == 9 || (c.toNat >= 32 && c.toNat != 127)) &&
    (value.isEmpty || ((value[0]! != 32 && value[0]! != 9) &&
      (value[value.size - 1]! != 32 && value[value.size - 1]! != 9)))

private def asciiLower (value : ByteArray) : ByteArray := Id.run do
  let mut out := ByteArray.empty
  for c in value do
    let n := c.toNat
    out := out.push (if n >= 65 && n <= 90 then UInt8.ofNat (n + 32) else c)
  return out

private def isHex (c : UInt8) : Bool :=
  (c.toNat >= 48 && c.toNat <= 57) || (c.toNat >= 65 && c.toNat <= 70) ||
    (c.toNat >= 97 && c.toNat <= 102)

private def validPathBytes : List UInt8 → Bool
  | [] => true
  | 37 :: a :: b :: rest => isHex a && isHex b && validPathBytes rest
  | 37 :: _ => false
  | c :: rest =>
    let n := c.toNat
    ((n >= 48 && n <= 57) || (n >= 65 && n <= 90) || (n >= 97 && n <= 122) ||
      [33,36,38,39,40,41,42,43,44,45,46,47,58,59,61,63,64,95,126].contains n) &&
        validPathBytes rest

private def validConnectAuthority (value : ByteArray) : Bool :=
  if !HTTP1.validAuthority value then false
  else
    match value.toList with
    | 91 :: rest =>
      match rest.dropWhile (· != 93) with
      | 93 :: 58 :: port => !port.isEmpty
      | _ => false
    | raw =>
      match raw.dropWhile (· != 58) with
      | 58 :: port => !port.isEmpty && raw.head! != 58
      | _ => false

private def decimal (value : ByteArray) (bound : Nat) : Except String Nat := do
  if value.isEmpty then throw "empty content-length"
  let mut n := 0
  for c in value do
    if c.toNat < 48 || c.toNat > 57 then throw "invalid content-length"
    n := n * 10 + c.toNat - 48
    if n > bound then throw "body limit exceeded"
  return n

/-- Validate HTTP/2 request pseudo-fields and connection-specific restrictions. -/
def validateRequestHead (fields : Array HPACK.Header) (maxBodyBytes : Nat := 1048576)
    (enableConnectProtocol : Bool := false) : Except String RequestHead := do
  let mut method : Option ByteArray := none
  let mut scheme : Option ByteArray := none
  let mut path : Option ByteArray := none
  let mut authority : Option ByteArray := none
  let mut protocol : Option ByteArray := none
  let mut regular := false
  let mut headers : Array HTTP1.Header := #[]
  let mut host : Option ByteArray := none
  let mut cookieIndex : Option Nat := none
  let mut length : Option Nat := none
  for field in fields do
    if field.name.isEmpty || !validValue field.value then throw "invalid HTTP/2 field"
    let name := field.name.toList
    if name.head? == some 58 then
      if regular then throw "pseudo-field after regular field"
      if field.name == ":method".toUTF8 then
        if method.isSome then throw "duplicate :method"
        method := some field.value
      else if field.name == ":scheme".toUTF8 then
        if scheme.isSome then throw "duplicate :scheme"
        scheme := some field.value
      else if field.name == ":path".toUTF8 then
        if path.isSome then throw "duplicate :path"
        path := some field.value
      else if field.name == ":authority".toUTF8 then
        if authority.isSome then throw "duplicate :authority"
        authority := some field.value
      else if field.name == ":protocol".toUTF8 then
        if protocol.isSome then throw "duplicate :protocol"
        if !enableConnectProtocol || field.value.isEmpty || !field.value.toList.all tokenByte then
          throw "invalid or unadvertised :protocol"
        protocol := some field.value
      else throw "unsupported request pseudo-field"
    else
      regular := true
      if !name.all tokenByte || name.any (fun c => c.toNat >= 65 && c.toNat <= 90) then
        throw "invalid HTTP/2 field name"
      let some text := String.fromUTF8? field.name | throw "invalid HTTP/2 field name"
      if ["connection", "proxy-connection", "keep-alive", "upgrade", "transfer-encoding"].contains text then
        throw "connection-specific HTTP/2 field"
      if text == "te" && asciiLower field.value != "trailers".toUTF8 then
        throw "invalid HTTP/2 TE field"
      if text == "host" then
        if host.isSome then throw "duplicate host"
        host := some field.value
      if text == "content-length" then
        if length.isSome then throw "duplicate content-length"
        let n ← decimal field.value maxBodyBytes
        if n > maxBodyBytes then throw "body limit exceeded"
        length := some n
      if text == "cookie" then
        match cookieIndex with
        | none =>
          cookieIndex := some headers.size
          headers := headers.push { name := text, value := field.value }
        | some index =>
          let prior := headers[index]!
          headers := headers.set! index { prior with value := (prior.value.append "; ".toUTF8).append field.value }
      else
        headers := headers.push { name := text, value := field.value }
  let some methodBytes := method | throw "missing :method"
  if methodBytes.isEmpty || !methodBytes.toList.all tokenByte then throw "invalid :method"
  let some methodText := String.fromUTF8? methodBytes | throw "invalid :method"
  let authorityBytes := authority.getD (host.getD ByteArray.empty)
  if !HTTP1.validAuthority authorityBytes then throw "invalid :authority or host"
  if authority.isSome && host.isSome && asciiLower authorityBytes != asciiLower (host.getD ByteArray.empty) then
    throw "host disagrees with :authority"
  if authority.isSome then
    if host.isSome then
      headers := headers.map (fun field => if field.name == "host" then { field with value := authorityBytes } else field)
    else if !authorityBytes.isEmpty then
      headers := headers.push { name := "host", value := authorityBytes }
  if methodText == "CONNECT" then
    if protocol.isNone then
      if !validConnectAuthority authorityBytes || scheme.isSome || path.isSome then throw "invalid CONNECT pseudo-fields"
      return { method := methodText, scheme := ByteArray.empty, authority := authorityBytes, target := authorityBytes, headers := headers, contentLength := length }
    if length.isSome then throw "extended CONNECT cannot declare content length"
  else if protocol.isSome then throw ":protocol requires CONNECT"
  let some schemeBytes := scheme | throw "missing :scheme"
  let some pathBytes := path | throw "missing :path"
  if schemeBytes.isEmpty then throw "empty :scheme"
  let lowerScheme := asciiLower schemeBytes
  if (lowerScheme == "http".toUTF8 || lowerScheme == "https".toUTF8) &&
      (authorityBytes.isEmpty || authorityBytes[0]! == 58) then
    throw "http(s) authority requires a host"
  if pathBytes.isEmpty then
    if lowerScheme == "http".toUTF8 || lowerScheme == "https".toUTF8 then throw "empty http(s) :path"
  else if pathBytes == "*".toUTF8 then
    if methodText != "OPTIONS" then throw "invalid asterisk :path"
  else if (lowerScheme == "http".toUTF8 || lowerScheme == "https".toUTF8) && pathBytes[0]! != 47 then
    throw "invalid :path"
  if !validPathBytes pathBytes.toList then throw "invalid :path"
  if !((schemeBytes[0]!.toNat >= 97 && schemeBytes[0]!.toNat <= 122) ||
      (schemeBytes[0]!.toNat >= 65 && schemeBytes[0]!.toNat <= 90)) then throw "invalid :scheme"
  if !schemeBytes.toList.all (fun c => (c.toNat >= 97 && c.toNat <= 122) || (c.toNat >= 65 && c.toNat <= 90) ||
      (c.toNat >= 48 && c.toNat <= 57) || [43,45,46].contains c.toNat) then
    throw "invalid :scheme"
  return { method := methodText, scheme := schemeBytes, authority := authorityBytes, target := pathBytes, headers := headers, contentLength := length, protocol }

/-- Validate trailing fields without merging them into the request headers. -/
def validateTrailers (fields : Array HPACK.Header) : Except String (Array HTTP1.Header) := do
  let mut result : Array HTTP1.Header := #[]
  for field in fields do
    let name := field.name.toList
    if name.isEmpty || !name.all tokenByte ||
        name.any (fun c => c.toNat >= 65 && c.toNat <= 90) || !validValue field.value then
      throw "invalid HTTP/2 trailer field"
    let some text := String.fromUTF8? field.name | throw "invalid trailer name"
    if ["connection", "proxy-connection", "keep-alive", "upgrade", "transfer-encoding",
        "content-length", "host", "trailer", "te"].contains text then
      throw "forbidden HTTP/2 trailer field"
    result := result.push { name := text, value := field.value }
  return result

/-- Convert a completed HTTP/2 request to the shared application router type. -/
def RequestHead.complete (head : RequestHead) (body : ByteArray) (trailers : Array HTTP1.Header := #[]) : Except String HTTP1.Request := do
  if let some n := head.contentLength then
    if n != body.size then throw "content-length does not match body"
  return { method := head.method, version := "HTTP/2", target := head.target, headers := head.headers, body := body, trailers := trailers }

end LeanNet.HTTP2
