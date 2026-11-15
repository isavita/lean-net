import LeanNet.Gate.Policy
import LeanNet.HTTP1.Protocol
import LeanNet.HTTP1.ClientResponse

/-! HTTP/1.1 request serialization for an admitted reverse-proxy route.
The route's authority is the only Host sent upstream. Client-supplied
forwarding metadata is discarded and rebuilt from sealed transport facts.
Connection-nominated fields and hop-by-hop fields never cross the hop. -/

namespace LeanNet.Gateway

open LeanNet
open LeanNet.Gate
open LeanNet.HTTP1

inductive WireError where
  | notProxyRoute
  | invalidConnection
  | invalidHeader
  | invalidTrailer
  deriving BEq, Repr

private def hexDigit (n : Nat) : UInt8 :=
  UInt8.ofNat (if n < 10 then 48 + n else 87 + n)

private def hexGroup (n : Nat) : ByteArray := Id.run do
  let mut digits := ByteArray.empty
  let mut remaining := n
  repeat
    digits := (ByteArray.mk #[hexDigit (remaining % 16)]).append digits
    remaining := remaining / 16
    if remaining == 0 then break
  return digits

/-- Numeric peer address for forwarding metadata. The native reactor supplies
    4 or 16 binary bytes, never a client-controlled header string. -/
def peerText (peer : ByteArray) : Option ByteArray := Id.run do
  if peer.size == 4 then
    let mut out := ByteArray.empty
    for i in [:4] do
      if i != 0 then out := out.push 46
      out := out.append (toString peer[i]!.toNat).toUTF8
    return some out
  if peer.size == 16 then
    let mut out := ByteArray.empty
    for i in [:8] do
      if i != 0 then out := out.push 58
      let group := peer[2 * i]!.toNat * 256 + peer[2 * i + 1]!.toNat
      out := out.append (hexGroup group)
    return some out
  return none

private def hopField (name : String) : Bool :=
  ["connection", "keep-alive", "proxy-connection", "te", "trailer",
   "transfer-encoding", "upgrade", "proxy-authenticate", "proxy-authorization",
   "content-length", "host", "expect", "via"].contains name

/-- Client fields must not become proxy attestation for the upstream. In
    particular RFC 9440 certificate fields and common deployment-specific
    identity prefixes are never forwarded from an untrusted request. -/
private def untrustedIdentityField (name : String) : Bool :=
  ["forwarded", "x-real-ip", "x-remote-user", "client-cert",
   "client-cert-chain"].contains name ||
  name.startsWith "x-forwarded-" || name.startsWith "x-ssl-" ||
  name.startsWith "x-client-" || name.startsWith "ssl-client-"

private def barredRequestField (name : String) : Bool :=
  hopField name || untrustedIdentityField name

/-- A client cannot nominate a field that the gateway must construct from
    trusted transport or routing state. An upgrade also needs a separate
    tunnel path, which this HTTP/1.1 proxy serializer does not provide. -/
private def forbiddenConnectionOption (name : String) : Bool :=
  ["host", "content-length", "transfer-encoding", "upgrade"].contains name ||
  untrustedIdentityField name

private def responseHopField (name : String) : Bool :=
  ["connection", "keep-alive", "proxy-connection", "proxy-authenticate",
   "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
   "content-length"].contains name

private def responseHeader (field : ClientResponse.Header) : Except WireError Header := do
  let some name := String.fromUTF8? field.name | throw .invalidHeader
  let header : Header := { name, value := field.value }
  if !fieldOk header then throw .invalidHeader
  return header

/-- Validated names advertised by an upstream `Trailer` field. HTTP/1.1
    downstream streaming must declare these before sending response HEADERS. -/
def declaredTrailers (head : ClientResponse.Head) : Except WireError (Array String) := do
  let mut raw : Array Header := #[]
  for field in head.headers do raw := raw.push (← responseHeader field)
  let nominated ← match connectionTokens raw with
    | .ok values => pure values
    | .error _ => throw .invalidConnection
  let mut names : Array String := #[]
  for field in raw do
    if field.name.toLower != "trailer" then continue
    let some text := String.fromUTF8? field.value | throw .invalidTrailer
    for part in text.splitOn "," do
      let name := part.trimAscii.toString.toLower
      if name.isEmpty || forbiddenTrailerName name || responseHopField name ||
          nominated.contains name || !fieldOk { name, value := ByteArray.empty } then
        throw .invalidTrailer
      if !names.contains name then names := names.push name
  return names

private def appendHeader (bytes : ByteArray) (name : String) (value : ByteArray) : ByteArray :=
  (((bytes.append name.toUTF8).append ": ".toUTF8).append value).append "\r\n".toUTF8

private def canonicalTarget (path : NormalPath) : ByteArray :=
  if path.query.isEmpty then path.path else (path.path.append "?".toUTF8).append path.query

private def forwardedValue (a : Admitted) : ByteArray := Id.run do
  let peer := (peerText a.facts.peer).getD "unknown".toUTF8
  let peer := if a.facts.peer.size == 16 then ("[".toUTF8.append peer).append "]".toUTF8 else peer
  let scheme := if a.facts.secure then "https".toUTF8 else "http".toUTF8
  let host := a.authority.render
  let mut value := "for=\"".toUTF8.append peer
  value := value.append "\";proto=".toUTF8
  value := value.append scheme
  value := value.append ";host=\"".toUTF8
  value := value.append host
  return value.append "\"".toUTF8

/-- A bounded request already admitted by the gate, serialized as a head and
    body without copying the body into the head. Trailers are sent with chunked
    framing after filtering the same hop fields as the head. -/
def encodeRequest (a : Admitted) (request : Request) : Except WireError (Array ByteArray) := do
  if a.backend?.isNone then throw .notProxyRoute
  let nominated ← match connectionTokens request.headers with
    | .ok values => pure values
    | .error _ => throw .invalidConnection
  if nominated.any forbiddenConnectionOption then throw .invalidConnection
  let mut head := a.head.method.toUTF8.append " ".toUTF8
  head := (head.append (canonicalTarget a.path)).append " HTTP/1.1\r\n".toUTF8
  head := appendHeader head "Host" a.authority.render
  let mut trailers : Array Header := #[]
  for field in request.headers do
    if !fieldOk field then throw .invalidHeader
    let name := field.name.toLower
    if !barredRequestField name && !nominated.contains name then
      head := appendHeader head field.name field.value
  for field in request.trailers do
    if !fieldOk field then throw .invalidTrailer
    let name := field.name.toLower
    if forbiddenTrailerName name || barredRequestField name ||
        nominated.contains name then throw .invalidTrailer
    trailers := trailers.push field
  head := appendHeader head "Forwarded" (forwardedValue a)
  if let some peer := peerText a.facts.peer then
    head := appendHeader head "X-Forwarded-For" peer
  head := appendHeader head "X-Forwarded-Host" a.authority.render
  head := appendHeader head "X-Forwarded-Proto" (if a.facts.secure then "https".toUTF8 else "http".toUTF8)
  head := appendHeader head "Via" "1.1 lean-net".toUTF8
  head := appendHeader head "Connection" "keep-alive".toUTF8
  if trailers.isEmpty then
    head := appendHeader head "Content-Length" (toString request.body.size).toUTF8
    return #[head.append "\r\n".toUTF8, request.body]
  let mut names := ByteArray.empty
  for field in trailers do
    if !names.isEmpty then names := names.append ", ".toUTF8
    names := names.append field.name.toUTF8
  head := appendHeader head "Transfer-Encoding" "chunked".toUTF8
  head := appendHeader head "Trailer" names
  let mut tail := ByteArray.empty
  if !request.body.isEmpty then
    tail := (((hexGroup request.body.size).append "\r\n".toUTF8).append request.body).append "\r\n".toUTF8
  tail := tail.append "0\r\n".toUTF8
  for field in trailers do tail := appendHeader tail field.name field.value
  return #[head.append "\r\n".toUTF8, tail.append "\r\n".toUTF8]

/-- Build a downstream reply from one completely parsed upstream response.
    Framing is regenerated by the server encoder; no upstream framing or
    connection-specific field is allowed to survive. -/
def decodeReply (head : ClientResponse.Head) (body : ByteArray)
    (trailers : Array ClientResponse.Header := #[]) : Except WireError Reply := do
  let _ ← declaredTrailers head
  let mut raw : Array Header := #[]
  for field in head.headers do raw := raw.push (← responseHeader field)
  let nominated ← match connectionTokens raw with
    | .ok values => pure values
    | .error _ => throw .invalidConnection
  let mut headers : Array Header := #[]
  for field in raw do
    let name := field.name.toLower
    if !responseHopField name && !nominated.contains name then
      headers := headers.push field
  headers := headers.push { name := "via", value := "1.1 lean-net".toUTF8 }
  let mut trailing : Array Header := #[]
  for field in trailers do
    let header ← responseHeader field
    if forbiddenTrailerName header.name || nominated.contains header.name then throw .invalidTrailer
    trailing := trailing.push header
  let options : ResponseOptions :=
    if trailing.isEmpty then {} else { framing := some .chunked, trailers := trailing }
  return { response := { status := head.status.toNat, headers, body }, options }

end LeanNet.Gateway
