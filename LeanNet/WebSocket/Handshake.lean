import LeanNet.HTTP1.Response
import LeanNet.HTTP1.Protocol
import LeanNet.HTTP2.Request

namespace LeanNet.WebSocket.Handshake

/-- The application must choose an Origin policy, including what missing Origin
    means. Subprotocol selection follows server preference and is case-sensitive.
    No extension (including compression) is negotiated by these helpers. -/
structure Policy where
  originAllowed : Option ByteArray → Bool
  subprotocols : Array String := #[]
  requireSubprotocol : Bool := false
  maxHeaderBytes : Nat := 16384
  maxHeaderCount : Nat := 100

structure Rejection where
  status : Nat := 400
  message : String
  headers : Array HTTP1.Header := #[]

structure Accepted where
  response : HTTP1.Response
  subprotocol : Option String := none

private def tokenByte (byte : UInt8) : Bool :=
  let n := byte.toNat
  (n >= 48 && n <= 57) || (n >= 65 && n <= 90) || (n >= 97 && n <= 122) ||
    [33,35,36,37,38,39,42,43,45,46,94,95,96,124,126].contains n

private def trim (bytes : ByteArray) : ByteArray :=
  let ows := fun byte => byte == 32 || byte == 9
  ByteArray.mk (((bytes.toList.dropWhile ows).reverse.dropWhile ows).reverse.toArray)

private def fields (headers : Array HTTP1.Header) (name : String) : Array ByteArray :=
  (headers.filter (fun field => field.name.toLower == name)).map (fun field => trim field.value)

private def field (name value : String) : HTTP1.Header := { name, value := value.toUTF8 }

private def validateHeaders (headers : Array HTTP1.Header) (policy : Policy) : Except Rejection Unit := do
  if policy.maxHeaderCount == 0 || policy.maxHeaderCount > 1000 ||
      policy.maxHeaderBytes == 0 || policy.maxHeaderBytes > 65536 then
    throw ⟨500, "invalid WebSocket handshake limits", #[]⟩
  if headers.size > policy.maxHeaderCount then throw ⟨431, "too many handshake headers", #[]⟩
  let mut bytes := 0
  for header in headers do
    bytes := bytes + header.name.toUTF8.size + header.value.size + 4
    if bytes > policy.maxHeaderBytes then throw ⟨431, "handshake headers exceed limit", #[]⟩
    if header.name.isEmpty || !header.name.toUTF8.toList.all tokenByte ||
        !header.value.toList.all (fun b => b == 9 || (b >= 32 && b != 127)) then
      throw ⟨400, "invalid handshake field", #[]⟩

private def tokens (values : Array ByteArray) : Except Rejection (Array String) := do
  let mut result := #[]
  for value in values do
    let some text := String.fromUTF8? value | throw ⟨400, "non-ASCII protocol token", #[]⟩
    for piece in text.splitOn "," do
      let item := trim piece.toUTF8
      if item.isEmpty then continue
      if !item.toList.all tokenByte then throw ⟨400, "invalid protocol token", #[]⟩
      let some token := String.fromUTF8? item | throw ⟨400, "invalid protocol token", #[]⟩
      if result.contains token then throw ⟨400, "duplicate protocol token", #[]⟩
      result := result.push token
  if !values.isEmpty && result.isEmpty then throw ⟨400, "empty subprotocol offer", #[]⟩
  return result

private def extensionValue (value : ByteArray) : Bool := Id.run do
  if value.isEmpty then return false
  if value[0]! != 34 then return value.toList.all tokenByte
  if value.size < 3 || value[value.size - 1]! != 34 then return false
  let mut escaped := false
  let mut decoded := 0
  for i in [1:value.size - 1] do
    let byte := value[i]!
    if escaped then
      if !tokenByte byte then return false
      escaped := false; decoded := decoded + 1
    else if byte == 92 then escaped := true
    else
      if !tokenByte byte then return false
      decoded := decoded + 1
  return !escaped && decoded != 0

/-- RFC6455 extension syntax is checked even though no extension is selected.
    Quoted values must decode to tokens, so commas/semicolons within a quoted
    value cannot conceal list or parameter boundaries. -/
private def validateExtensions (headers : Array HTTP1.Header) : Except Rejection Unit := do
  let values := fields headers "sec-websocket-extensions"
  let mut actual := 0
  for value in values do
    let some text := String.fromUTF8? value | throw ⟨400, "invalid extension field", #[]⟩
    for extension in text.splitOn "," do
      if (trim extension.toUTF8).isEmpty then continue
      actual := actual + 1
      let parts := extension.splitOn ";"
      let name := trim parts.head!.toUTF8
      if name.isEmpty || !name.toList.all tokenByte then throw ⟨400, "invalid extension name", #[]⟩
      for parameter in parts.drop 1 do
        let pair := parameter.splitOn "="
        let name := trim pair.head!.toUTF8
        if name.isEmpty || !name.toList.all tokenByte || pair.length > 2 then
          throw ⟨400, "invalid extension parameter", #[]⟩
        if pair.length == 2 && !extensionValue (trim pair[1]!.toUTF8) then
          throw ⟨400, "invalid extension parameter value", #[]⟩
  if !values.isEmpty && actual == 0 then throw ⟨400, "empty extension offer", #[]⟩

private def common (headers : Array HTTP1.Header) (policy : Policy) : Except Rejection (Option String) := do
  validateHeaders headers policy
  validateExtensions headers
  let versions := fields headers "sec-websocket-version"
  if versions.size != 1 || versions[0]! != "13".toUTF8 then
    throw ⟨426, "unsupported WebSocket version", #[field "Sec-WebSocket-Version" "13"]⟩
  let origins := fields headers "origin"
  if origins.size > 1 then throw ⟨400, "duplicate Origin", #[]⟩
  if !policy.originAllowed origins[0]? then throw ⟨403, "Origin is not allowed", #[]⟩
  if policy.subprotocols.size > 64 then throw ⟨500, "too many server subprotocols", #[]⟩
  let mut seen : Array String := #[]
  for protocol in policy.subprotocols do
    if protocol.isEmpty || protocol.toUTF8.size > 256 || !protocol.toUTF8.toList.all tokenByte || seen.contains protocol then
      throw ⟨500, "invalid server subprotocol policy", #[]⟩
    seen := seen.push protocol
  let offered ← tokens (fields headers "sec-websocket-protocol")
  let selected := policy.subprotocols.find? offered.contains
  if policy.requireSubprotocol && selected.isNone then throw ⟨400, "no acceptable subprotocol", #[]⟩
  return selected

private def rotate (word : UInt32) (bits : UInt32) : UInt32 :=
  (word <<< bits) ||| (word >>> (32 - bits))

/-- SHA-1 is used only for the RFC6455 challenge, never for authentication.
    The caller supplies the fixed-size validated24-byte nonce representation. -/
private def sha1 (input : ByteArray) : ByteArray := Id.run do
  let mut message := input.push 128
  for _ in [:(56 + 64 - message.size % 64) % 64] do message := message.push 0
  let bits := input.size * 8
  for i in [:8] do message := message.push (UInt8.ofNat (bits / 2 ^ (56 - 8 * i)))
  let mut hash : Array UInt32 := #[0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
  for chunk in [:message.size / 64] do
    let mut words : Array UInt32 := #[]
    for i in [:16] do
      let position := chunk * 64 + i * 4
      let word := (message[position]!.toUInt32 <<< 24) ||| (message[position + 1]!.toUInt32 <<< 16) |||
        (message[position + 2]!.toUInt32 <<< 8) ||| message[position + 3]!.toUInt32
      words := words.push word
    for i in [16:80] do
      words := words.push (rotate (words[i - 3]! ^^^ words[i - 8]! ^^^ words[i - 14]! ^^^ words[i - 16]!) 1)
    let mut a := hash[0]!
    let mut b := hash[1]!
    let mut c := hash[2]!
    let mut d := hash[3]!
    let mut e := hash[4]!
    for i in [:80] do
      let (f, k) := if i < 20 then ((b &&& c) ||| ((~~~b) &&& d), (0x5a827999 : UInt32))
        else if i < 40 then (b ^^^ c ^^^ d, 0x6ed9eba1)
        else if i < 60 then ((b &&& c) ||| (b &&& d) ||| (c &&& d), 0x8f1bbcdc)
        else (b ^^^ c ^^^ d, 0xca62c1d6)
      let next := rotate a 5 + f + e + k + words[i]!
      e := d; d := c; c := rotate b 30; b := a; a := next
    hash := #[hash[0]! + a, hash[1]! + b, hash[2]! + c, hash[3]! + d, hash[4]! + e]
  let mut result := ByteArray.empty
  for word in hash do
    for shift in [24,16,8,0] do result := result.push ((word >>> UInt32.ofNat shift).toUInt8)
  return result

private def alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toUTF8

private def base64 (bytes : ByteArray) : ByteArray := Id.run do
  let mut out := ByteArray.empty
  for i in [:(bytes.size + 2) / 3] do
    let position := i * 3
    let a := bytes[position]!.toNat
    let b := if position + 1 < bytes.size then bytes[position + 1]!.toNat else 0
    let c := if position + 2 < bytes.size then bytes[position + 2]!.toNat else 0
    out := (out.push alphabet[a / 4]!).push alphabet[(a % 4) * 16 + b / 16]!
    out := out.push (if position + 1 < bytes.size then alphabet[(b % 16) * 4 + c / 64]! else 61)
    out := out.push (if position + 2 < bytes.size then alphabet[c % 64]! else 61)
  return out

private def validKey (key : ByteArray) : Bool := Id.run do
  -- A16-byte nonce has exactly22 base64 digits and two padding characters.
  if key.size != 24 || key[22]! != 61 || key[23]! != 61 then return false
  let mut final := 0
  for i in [:22] do
    let mut found := false
    for j in [:64] do
      if alphabet[j]! == key[i]! then found := true; final := j
    if !found then return false
  return final % 16 == 0

/-- RFC6455 section4.2.2 challenge. Accepts only canonical base64 encoding of a
   16-byte nonce; surrounding HTTP whitespace is handled by the header helper. -/
def acceptDigest (key : ByteArray) : Except Rejection ByteArray := do
  if !validKey key then throw ⟨400, "invalid Sec-WebSocket-Key", #[]⟩
  return base64 (sha1 (key.append "258EAFA5-E914-47DA-95CA-C5AB0DC85B11".toUTF8))

private def selectedHeaders (protocol : Option String) : Array HTTP1.Header :=
  match protocol with
  | none => #[]
  | some value => #[field "Sec-WebSocket-Protocol" value]

/-- Validate a bodyless HTTP/1.1 WebSocket GET. The existing accepted-upgrade
    encoder supplies Connection: Upgrade and its physical101 write barrier. -/
def acceptHTTP1 (head : HTTP1.RequestHead) (policy : Policy) : Except Rejection Accepted := do
  if head.method != "GET" then throw ⟨405, "WebSocket requires GET", #[field "Allow" "GET"]⟩
  if head.version != "HTTP/1.1" then throw ⟨400, "WebSocket requires HTTP/1.1", #[]⟩
  let selected ← common head.headers policy
  let hosts := fields head.headers "host"
  if hosts.size != 1 || hosts[0]!.isEmpty || hosts[0]![0]! == 58 || !HTTP1.validAuthority hosts[0]! then
    throw ⟨400, "invalid Host", #[]⟩
  if head.target.isEmpty || head.target.toList.any (fun b => b < 33 || b == 127) then
    throw ⟨400, "invalid request target", #[]⟩
  let connection ← match HTTP1.connectionTokens head.headers with
    | .ok values => pure values
    | .error _ => throw ⟨400, "invalid Connection", #[]⟩
  if !connection.contains "upgrade" || connection.contains "close" then
    throw ⟨400, "Connection does not permit upgrade", #[]⟩
  let mut offered := false
  for value in fields head.headers "upgrade" do
    let some text := String.fromUTF8? value | throw ⟨400, "invalid Upgrade", #[]⟩
    for piece in text.splitOn "," do
      let item := trim piece.toUTF8
      let parts := (String.fromUTF8! item).splitOn "/"
      if parts.isEmpty || parts.length > 2 || parts.any (fun part => part.isEmpty || !part.toUTF8.toList.all tokenByte) then
        throw ⟨400, "invalid Upgrade", #[]⟩
      if item == "websocket".toUTF8 || (String.fromUTF8! item).toLower == "websocket" then offered := true
  if !offered then throw ⟨400, "WebSocket was not offered", #[]⟩
  if !(fields head.headers "transfer-encoding").isEmpty then throw ⟨400, "handshake cannot contain a body", #[]⟩
  let lengths := fields head.headers "content-length"
  if lengths.size > 1 || lengths.any (fun value => value.isEmpty || !value.toList.all (· == 48)) then
    throw ⟨400, "handshake cannot contain a body", #[]⟩
  let keys := fields head.headers "sec-websocket-key"
  if keys.size != 1 then throw ⟨400, "exactly one Sec-WebSocket-Key is required", #[]⟩
  let digest ← acceptDigest keys[0]!
  return { response := { status := 101, headers :=
    (#[field "Upgrade" "websocket", { name := "Sec-WebSocket-Accept", value := digest }]).append (selectedHeaders selected) }, subprotocol := selected }

/-- RFC8441 extended CONNECT. The connection layer must first have advertised
    SETTINGS_ENABLE_CONNECT_PROTOCOL=1. Key/Accept have no meaning over H2;
    response DATA contains the same masked-client RFC6455 frame stream. -/
def acceptHTTP2 (head : HTTP2.RequestHead) (protocol : Option ByteArray)
    (policy : Policy) : Except Rejection Accepted := do
  if head.method != "CONNECT" || protocol != some "websocket".toUTF8 || head.protocol != protocol then
    throw ⟨400, "WebSocket requires extended CONNECT", #[]⟩
  let selected ← common head.headers policy
  if (head.scheme != "https".toUTF8 && head.scheme != "http".toUTF8) ||
      head.authority.isEmpty || head.authority[0]! == 58 || !HTTP1.validAuthority head.authority || head.target.isEmpty || head.target[0]! != 47 then
    throw ⟨400, "invalid extended CONNECT target", #[]⟩
  if head.contentLength.isSome then throw ⟨400, "extended CONNECT cannot declare content length", #[]⟩
  for header in head.headers do
    if ["connection", "upgrade", "keep-alive", "proxy-connection", "transfer-encoding"].contains header.name.toLower then
      throw ⟨400, "connection-specific field over HTTP/2", #[]⟩
  return { response := { status := 200, headers := selectedHeaders selected }, subprotocol := selected }

end LeanNet.WebSocket.Handshake
