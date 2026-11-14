import LeanNet.HTTP1.Protocol
import LeanNet.HTTP1.Response

namespace LeanNet.HTTP1

/-- The driver supplies request context and its per-second cached Date. Encoding
    never reads a clock, socket, or mutable cache. -/
structure EncodeContext where
  version : Version := .http11
  requestMethod : String := "GET"
  requestHeaders : Array Header := #[]
  date : Option ByteArray := none

/-- Framing and metadata for the new encoder, separate from the legacy Response
    constructor used by existing HTTP/2 and TLS consumers. -/
structure ResponseOptions where
  reason : Option String := none
  framing : Option BodyFraming := none
  trailers : Array Header := #[]
  forceClose : Bool := false

inductive ResponseNext where
  | informational
  | nextRequest (action : KeepAliveAction)
  | upgrade
  deriving BEq, DecidableEq, Repr, Inhabited

/-- Body segments reference the application's ByteArray; encoding a response
    does not concatenate or copy its complete body into a second wire buffer. -/
structure EncodedResponse where
  parts : Array ByteArray
  framing : BodyFraming
  next : ResponseNext

/-- One final application response, optionally preceded by informational
    responses. Upgrades are an explicit machine decision, not inferred here. -/
structure Reply where
  response : Response
  options : ResponseOptions := {}
  informational : Array (Response × ResponseOptions) := #[]

private def fieldTokenByte (b : UInt8) : Bool :=
  let n := b.toNat
  (n >= 48 && n <= 57) || (n >= 65 && n <= 90) || (n >= 97 && n <= 122) ||
    [33, 35, 36, 37, 38, 39, 42, 43, 45, 46, 94, 95, 96, 124, 126].contains n

private def fieldValueByte (b : UInt8) : Bool :=
  b == 9 || (b.toNat >= 32 && b.toNat != 127)

private def validateField (header : Header) : Except String Unit := do
  let name := header.name.toUTF8.toList
  if name.isEmpty || !name.all fieldTokenByte then throw "invalid response field name"
  if !header.value.toList.all fieldValueByte then throw "invalid response field value"

private def defaultReason (status : Nat) : String :=
  match status with
  | 100 => "Continue"
  | 101 => "Switching Protocols"
  | 102 => "Processing"
  | 103 => "Early Hints"
  | 200 => "OK"
  | 201 => "Created"
  | 202 => "Accepted"
  | 203 => "Non-Authoritative Information"
  | 204 => "No Content"
  | 205 => "Reset Content"
  | 206 => "Partial Content"
  | 207 => "Multi-Status"
  | 208 => "Already Reported"
  | 226 => "IM Used"
  | 300 => "Multiple Choices"
  | 301 => "Moved Permanently"
  | 302 => "Found"
  | 303 => "See Other"
  | 304 => "Not Modified"
  | 305 => "Use Proxy"
  | 307 => "Temporary Redirect"
  | 308 => "Permanent Redirect"
  | 400 => "Bad Request"
  | 401 => "Unauthorized"
  | 402 => "Payment Required"
  | 403 => "Forbidden"
  | 404 => "Not Found"
  | 405 => "Method Not Allowed"
  | 406 => "Not Acceptable"
  | 407 => "Proxy Authentication Required"
  | 408 => "Request Timeout"
  | 409 => "Conflict"
  | 410 => "Gone"
  | 411 => "Length Required"
  | 412 => "Precondition Failed"
  | 413 => "Content Too Large"
  | 414 => "URI Too Long"
  | 415 => "Unsupported Media Type"
  | 416 => "Range Not Satisfiable"
  | 417 => "Expectation Failed"
  | 421 => "Misdirected Request"
  | 422 => "Unprocessable Content"
  | 423 => "Locked"
  | 424 => "Failed Dependency"
  | 425 => "Too Early"
  | 426 => "Upgrade Required"
  | 428 => "Precondition Required"
  | 429 => "Too Many Requests"
  | 431 => "Request Header Fields Too Large"
  | 451 => "Unavailable For Legal Reasons"
  | 500 => "Internal Server Error"
  | 501 => "Not Implemented"
  | 502 => "Bad Gateway"
  | 503 => "Service Unavailable"
  | 504 => "Gateway Timeout"
  | 505 => "HTTP Version Not Supported"
  | 506 => "Variant Also Negotiates"
  | 507 => "Insufficient Storage"
  | 508 => "Loop Detected"
  | 510 => "Not Extended"
  | 511 => "Network Authentication Required"
  | _ => "Response"

private def responseReason (response : Response) (options : ResponseOptions) : Except String ByteArray := do
  let reason := (options.reason.getD (defaultReason response.status)).toUTF8
  if !reason.toList.all fieldValueByte then throw "invalid response reason phrase"
  return reason

private def responseFields (response : Response) (context : EncodeContext) : Except String (Array Header) := do
  if response.status < 100 || response.status > 599 then throw "HTTP status must be from 100 to 599"
  let mut dates := 0
  for header in response.headers do
    validateField header
    let name := header.name.toLower
    if ["content-length", "transfer-encoding", "connection", "trailer"].contains name then
      throw "response framing fields are managed by the encoder"
    if name == "date" then dates := dates + 1
  if dates > 1 then throw "multiple Date fields"
  if dates == 0 && response.status >= 200 then
    if let some date := context.date then
      let field : Header := { name := "Date", value := date }
      validateField field
      return response.headers.push field
  return response.headers

private def responseFraming (response : Response) (context : EncodeContext)
    (options : ResponseOptions) : Except String BodyFraming := do
  if response.status < 200 then
    if context.version == .http10 then throw "HTTP/1.0 does not support informational responses"
    if !response.body.isEmpty || !options.trailers.isEmpty then throw "informational responses cannot contain a body or trailers"
    if options.forceClose then throw "informational responses cannot select connection closure"
    if let some framing := options.framing then
      if framing != .none then throw "informational responses cannot carry framing fields"
    return .none
  if context.requestMethod == "CONNECT" && response.status < 300 then
    throw "successful CONNECT requires an explicit tunnel handoff"
  if response.status == 204 || response.status == 304 then
    if !response.body.isEmpty || !options.trailers.isEmpty then throw "this status forbids a body or trailers"
    if let some framing := options.framing then
      if framing != .none then throw "this status forbids framing fields"
    return .none
  if response.status == 205 then
    if !response.body.isEmpty || !options.trailers.isEmpty then throw "205 responses cannot contain content or trailers"
    if let some framing := options.framing then
      if framing != .contentLength 0 then throw "205 responses use Content-Length 0"
    return .contentLength 0
  if context.requestMethod == "HEAD" then
    if !options.trailers.isEmpty then throw "HEAD responses cannot contain trailers"
    match options.framing with
    | none => return .contentLength response.body.size
    | some (.contentLength length) => return .contentLength length
    | _ => throw "HEAD responses require the corresponding GET Content-Length"
  let framing := options.framing.getD (.contentLength response.body.size)
  match framing with
  | .none => throw "ordinary responses require length, chunked, or close framing"
  | .contentLength length =>
    if length != response.body.size then throw "Content-Length does not match the response body"
  | .chunked =>
    if context.version == .http10 then throw "HTTP/1.0 does not support chunked responses"
  | .closeDelimited => pure ()
  if !options.trailers.isEmpty && framing != .chunked then throw "trailers require chunked framing"
  return framing

private def trailerFields (options : ResponseOptions) (context : EncodeContext) : Except String ByteArray := do
  let connectionNames := match connectionTokens context.requestHeaders with
    | .ok names => names
    | .error _ => #[]
  let mut names : Array String := #[]
  let mut declaration := ByteArray.empty
  for header in options.trailers do
    validateField header
    let name := header.name.toLower
    if forbiddenTrailerName name || connectionNames.contains name then throw "forbidden response trailer"
    if !names.contains name then
      if !names.isEmpty then declaration := declaration.append ", ".toUTF8
      declaration := declaration.append name.toUTF8
      names := names.push name
  return declaration

private def appendField (wire : ByteArray) (name : String) (value : ByteArray) : ByteArray :=
  (((wire.append name.toUTF8).append ": ".toUTF8).append value).append "\r\n".toUTF8

private def responseHead (response : Response) (context : EncodeContext) (fields : Array Header)
    (reason : ByteArray) (framing : BodyFraming) (next : ResponseNext)
    (trailerNames : ByteArray) : ByteArray := Id.run do
  let mut wire := context.version.wire.toUTF8
  wire := wire.append " ".toUTF8
  wire := wire.append (toString response.status).toUTF8
  wire := wire.append " ".toUTF8
  wire := wire.append reason
  wire := wire.append "\r\n".toUTF8
  for header in fields do wire := appendField wire header.name header.value
  match framing with
  | .none | .closeDelimited => pure ()
  | .contentLength length => wire := appendField wire "Content-Length" (toString length).toUTF8
  | .chunked =>
    wire := appendField wire "Transfer-Encoding" "chunked".toUTF8
    if !trailerNames.isEmpty then wire := appendField wire "Trailer" trailerNames
  match next with
  | .informational => pure ()
  | .upgrade => wire := appendField wire "Connection" "upgrade".toUTF8
  | .nextRequest .close => wire := appendField wire "Connection" "close".toUTF8
  | .nextRequest .keepAlive =>
    if context.version == .http10 then wire := appendField wire "Connection" "keep-alive".toUTF8
  return wire.append "\r\n".toUTF8

private def hexLength (length : Nat) : ByteArray := Id.run do
  let mut remaining := length
  let mut digits : List UInt8 := []
  for _ in [:length + 1] do
    let digit := remaining % 16
    digits := UInt8.ofNat (if digit < 10 then 48 + digit else 87 + digit) :: digits
    if remaining < 16 then break
    remaining := remaining / 16
  return ByteArray.mk digits.toArray

private def chunkEnd (trailers : Array Header) : ByteArray := Id.run do
  let mut wire := "0\r\n".toUTF8
  for header in trailers do wire := appendField wire header.name header.value
  return wire.append "\r\n".toUTF8

/-- Pure complete-response encoder. Finite bodies stay as shallow output
    segments. Explicit HEAD lengths can describe a GET representation (such as
    a file) without loading that representation into memory. -/
def Response.encodeFor (response : Response) (context : EncodeContext)
    (options : ResponseOptions := {}) : Except String EncodedResponse := do
  let fields ← responseFields response context
  if response.status == 101 then throw "101 requires an explicit accepted upgrade"
  let reason ← responseReason response options
  let framing ← responseFraming response context options
  let names ← trailerFields options context
  let next := if response.status < 200 then ResponseNext.informational
    else .nextRequest (if options.forceClose then .close else connAction context.version context.requestHeaders framing)
  let head := responseHead response context fields reason framing next names
  if response.status < 200 || context.requestMethod == "HEAD" || response.status == 204 ||
      response.status == 205 || response.status == 304 then
    return { parts := #[head], framing, next }
  if framing == .chunked then
    if response.body.isEmpty then return { parts := #[head, chunkEnd options.trailers], framing, next }
    return { parts := #[head, (hexLength response.body.size).append "\r\n".toUTF8,
      response.body, "\r\n".toUTF8, chunkEnd options.trailers], framing, next }
  return { parts := if response.body.isEmpty then #[head] else #[head, response.body], framing, next }

private def splitProtocols (value : ByteArray) : List (List UInt8) := go value.toList [] []
where
  go (remaining current : List UInt8) (out : List (List UInt8)) : List (List UInt8) :=
    match remaining with
    | [] => (current.reverse :: out).reverse
    | 44 :: rest => go rest [] (current.reverse :: out)
    | b :: rest => go rest (b :: current) out

private def protocolId (raw : List UInt8) : Except String (String × Option String) := do
  let whitespace := fun c : UInt8 => c == 32 || c == 9
  let raw := ((raw.dropWhile whitespace).reverse.dropWhile whitespace).reverse
  let some text := String.fromUTF8? (ByteArray.mk raw.toArray) | throw "invalid Upgrade protocol"
  let valid := fun s : String => !s.isEmpty && s.toUTF8.toList.all fieldTokenByte
  match text.splitOn "/" with
  | [name] =>
    if !valid name then throw "invalid Upgrade protocol"
    return (name.toLower, none)
  | [name, version] =>
    if !valid name || !valid version then throw "invalid Upgrade protocol"
    return (name.toLower, some version)
  | _ => throw "invalid Upgrade protocol"

/-- Encode an explicitly accepted HTTP/1.1 upgrade. The application's 101 must
    select exactly one Upgrade protocol offered by the request. The driver
    transfers raw-byte ownership only after this output's write barrier. -/
def Response.encodeAcceptedUpgrade (response : Response) (context : EncodeContext)
    (options : ResponseOptions := {}) : Except String EncodedResponse := do
  if context.version != .http11 then throw "upgrades require HTTP/1.1"
  if response.status != 101 then throw "accepted upgrade requires status 101"
  let fields ← responseFields response context
  let reason ← responseReason response options
  let framing ← responseFraming response context options
  let tokens ← connectionTokens context.requestHeaders
  if !tokens.contains "upgrade" || tokens.contains "close" then throw "request did not permit an upgrade"
  let selectedFields := response.headers.filter (fun h => h.name.toLower == "upgrade")
  if selectedFields.size != 1 then throw "accepted upgrade must select one protocol"
  let selected ← protocolId selectedFields[0]!.value.toList
  let mut offered := false
  for header in context.requestHeaders do
    if header.name.toLower == "upgrade" then
      for item in splitProtocols header.value do
        if (← protocolId item) == selected then offered := true
  if !offered then throw "selected Upgrade protocol was not offered"
  let head := responseHead response context fields reason framing .upgrade ByteArray.empty
  return { parts := #[head], framing, next := .upgrade }

end LeanNet.HTTP1
