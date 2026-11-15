import LeanNet.HTTP2.Request

namespace LeanNet.HTTP2.Upgrade

/-- Decode base64url (RFC 4648 §5), tolerating omitted or present padding. -/
def base64url (input : ByteArray) : Option ByteArray := Id.run do
  let value := fun (c : UInt8) =>
    if c >= 65 && c <= 90 then some (c - 65)
    else if c >= 97 && c <= 122 then some (c - 71)
    else if c >= 48 && c <= 57 then some (c + 4)
    else if c == 45 then some 62
    else if c == 95 then some 63
    else none
  let mut data := input.data
  while data.size > 0 && data.back! == 61 do data := data.pop
  if data.size % 4 == 1 then return none
  let mut out := ByteArray.empty
  let mut buffer : Nat := 0
  let mut bits := 0
  for c in data do
    let some digit := value c | return none
    buffer := (buffer * 64 + digit.toNat) % 65536
    bits := bits + 6
    if bits >= 8 then
      bits := bits - 8
      out := out.push (UInt8.ofNat (buffer / 2 ^ bits % 256))
  return some out

private def lower (bytes : ByteArray) : String :=
  ((String.fromUTF8? bytes).getD "").toLower

/-- Comma-separated, case-insensitive tokens across all fields with `name`. -/
private def tokens (headers : Array HTTP1.Header) (name : String) : Array String := Id.run do
  let mut out := #[]
  for header in headers do
    if header.name == name then
      for item in (lower header.value).splitOn "," do
        let token := item.trimAscii.toString
        if !token.isEmpty then out := out.push token
  return out

/-- Validate a SETTINGS payload carried by HTTP2-Settings (RFC 9113 §6.5.2). -/
def validSettings (payload : ByteArray) : Bool := Id.run do
  if payload.size % 6 != 0 then return false
  for i in [:payload.size / 6] do
    let p := i * 6
    let id := payload[p]!.toNat * 256 + payload[p + 1]!.toNat
    let value := (payload[p + 2]!.toNat <<< 24) + (payload[p + 3]!.toNat <<< 16) +
      (payload[p + 4]!.toNat <<< 8) + payload[p + 5]!.toNat
    if id == 2 && value > 1 then return false
    if id == 4 && value > 2147483647 then return false
    if id == 5 && (value < 16384 || value > 16777215) then return false
  return true

private def hopByHop : List String :=
  ["connection", "upgrade", "http2-settings", "keep-alive", "proxy-connection", "transfer-encoding", "host"]

/-- An HTTP/1.1 request eligible for `Upgrade: h2c` (RFC 7540 §3.2): a bodyless
    origin-form request offering `h2c`, nominating `Upgrade` and
    `HTTP2-Settings` in `Connection`, with exactly one valid HTTP2-Settings.
    Returns the decoded SETTINGS payload and the request as HTTP/2 stream 1.
    Ineligible requests are simply served over HTTP/1.1. -/
def candidate (head : HTTP1.RequestHead) (framing : HTTP1.BodyFraming) (maxBodyBytes : Nat) :
    Option (ByteArray × RequestHead) := do
  if head.version != "HTTP/1.1" then none
  match framing with
  | .none | .contentLength 0 => pure ()
  | _ => none
  if !(tokens head.headers "upgrade").contains "h2c" then none
  let connection := tokens head.headers "connection"
  if !connection.contains "upgrade" || !connection.contains "http2-settings" then none
  let fields := head.headers.filter (·.name == "http2-settings")
  if fields.size != 1 then none
  let settings ← base64url fields[0]!.value
  if !validSettings settings then none
  if head.target.size == 0 || (head.target[0]! != 47 && head.target != "*".toUTF8) then none
  let host := (head.headers.find? (·.name == "host")).map (·.value) |>.getD ByteArray.empty
  let mut hpack : Array HPACK.Header := #[
    { name := ":method".toUTF8, value := head.method.toUTF8 },
    { name := ":scheme".toUTF8, value := "http".toUTF8 },
    { name := ":authority".toUTF8, value := host },
    { name := ":path".toUTF8, value := head.target }]
  for header in head.headers do
    if hopByHop.contains header.name then continue
    if header.name == "te" && lower header.value != "trailers" then continue
    hpack := hpack.push { name := header.name.toUTF8, value := header.value }
  match validateRequestHead hpack maxBodyBytes with
  | .ok request => some (settings, request)
  | .error _ => none

end LeanNet.HTTP2.Upgrade
