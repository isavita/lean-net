import LeanNet.HTTP1.Request

namespace LeanNet.Proxy

/-- The parser has already separated the request fields. Names and values stay
    as wire bytes; adapters must pass the HTTP/2 `:authority` separately. -/
structure Header where
  name : ByteArray
  value : ByteArray

inductive Protocol where
  | http1
  | http2
  deriving BEq

/-- A head-stage view. The body is deliberately absent: admission can happen
    before an upload is read. -/
structure ParsedHead where
  protocol : Protocol
  method : ByteArray
  target : ByteArray
  authority : ByteArray
  scheme : Option ByteArray := none
  headers : Array Header

/-- The future reactor adapter supplies these facts from the actual socket and
    TLS handshake. This public prototype record is not socket provenance. -/
structure TransportFacts where
  secure : Bool := false
  sni : Option ByteArray := none

/-- Backend destinations are supplied only by trusted configuration. -/
inductive UpstreamTransport where
  | plain
  | tls (verifyName : ByteArray)
  deriving Inhabited

structure Backend where
  address : ByteArray
  port : UInt16
  transport : UpstreamTransport := .plain
  deriving Inhabited

/-- `authority` is an exact host or host:port key. A route owns its backend;
    no forwarding API needs to accept a separately chosen destination. -/
structure Route where
  authority : ByteArray
  backend : Backend
  allowedMethods : Array ByteArray := #[]
  requiredHeaders : Array ByteArray := #[]
  maxBodyBytes : Nat := 1048576
  deriving Inhabited

structure Limits where
  maxHeaderCount : Nat := 100
  maxHeaderBytes : Nat := 16384

inductive ConfigError where
  | invalidLimits
  | invalidAuthority
  | duplicateAuthority
  | invalidBackend
  | invalidMethod
  deriving BEq, Repr

inductive ProxyError where
  | badHeaders
  | tooManyHeaders
  | badTarget
  | badAuthority
  | missingRequiredHeader
  | unknownHost
  | misdirected
  | forbiddenMethod
  | bodyTooLarge
  | rateLimited (retryAfterSeconds : UInt32)
  deriving BEq, Repr

def ProxyError.status : ProxyError → Nat
  | .badHeaders | .badTarget | .badAuthority | .missingRequiredHeader => 400
  | .tooManyHeaders => 431
  | .unknownHost | .forbiddenMethod => 403
  | .misdirected => 421
  | .bodyTooLarge => 413
  | .rateLimited _ => 429

private def lower (c : UInt8) : UInt8 :=
  if c >= 65 && c <= 90 then c + 32 else c

private def equalFold (a b : ByteArray) : Bool := Id.run do
  if a.size != b.size then return false
  for i in [:a.size] do
    if lower a[i]! != lower b[i]! then return false
  return true

private def token (c : UInt8) : Bool :=
  (c >= 48 && c <= 57) || (c >= 65 && c <= 90) ||
  (c >= 97 && c <= 122) ||
  match c.toNat with
  | 33 | 35 | 36 | 37 | 38 | 39 | 42 | 43 | 45 | 46 | 94 | 95 | 96 | 124 | 126 => true
  | _ => false

private def tokenBytes (value : ByteArray) : Bool := Id.run do
  if value.isEmpty then return false
  for c in value do
    if !token c then return false
  return true

private def safeValue (value : ByteArray) : Bool := Id.run do
  for c in value do
    if c != 9 && (c < 32 || c == 127) then return false
  return true

/-- Strict DNS authority syntax for this first gateway profile. An optional
    decimal port is part of the route key. IP literals, percent-encoding,
    trailing dots, and userinfo are rejected rather than normalized. -/
private def authorityHostEnd (value : ByteArray) : Option Nat := Id.run do
  if value.isEmpty || value.size > 259 then return none
  let mut hostEnd := value.size
  for i in [:value.size] do
    if value[i]! == 58 then
      hostEnd := i
      break
  if hostEnd == 0 || hostEnd > 253 then return none
  let mut labelStart := 0
  for i in [:hostEnd] do
    let c := lower value[i]!
    if c == 46 then
      if i == labelStart || i - labelStart > 63 || value[i - 1]! == 45 then return none
      labelStart := i + 1
    else if !((c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c == 45) then
      return none
    else if c == 45 && i == labelStart then return none
  if labelStart == hostEnd || hostEnd - labelStart > 63 || value[hostEnd - 1]! == 45 then return none
  if hostEnd < value.size then
    if hostEnd + 1 == value.size then return none
    if hostEnd + 2 < value.size && value[hostEnd + 1]! == 48 then return none
    let mut port := 0
    for i in [hostEnd + 1:value.size] do
      let c := value[i]!
      if c < 48 || c > 57 then return none
      port := port * 10 + c.toNat - 48
      if port > 65535 then return none
    if port == 0 then return none
  return some hostEnd

private def canonicalAuthority (value : ByteArray) : Bool := Id.run do
  if (authorityHostEnd value).isNone then return false
  for c in value do
    if c >= 65 && c <= 90 then return false
  return true

/-- Immutable, startup-checked route snapshot. Keep a snapshot alive for each
    admitted request when replacing configuration. -/
structure Policy where
  private mk ::
  routes : Array Route
  limits : Limits
  generation : UInt64

def Policy.compile (routes : Array Route) (limits : Limits := {}) (generation : UInt64 := 0) :
    Except ConfigError Policy := do
  if limits.maxHeaderCount == 0 || limits.maxHeaderCount > 100 ||
      limits.maxHeaderBytes == 0 || limits.maxHeaderBytes > 65536 then
    throw .invalidLimits
  for i in [:routes.size] do
    let route := routes[i]!
    if !canonicalAuthority route.authority then throw .invalidAuthority
    if route.backend.port == 0 || !canonicalAuthority route.backend.address ||
        (authorityHostEnd route.backend.address) != some route.backend.address.size then
      throw .invalidBackend
    if let .tls verifyName := route.backend.transport then
      if !canonicalAuthority verifyName ||
          (authorityHostEnd verifyName) != some verifyName.size then
        throw .invalidBackend
    for method in route.allowedMethods do
      if !tokenBytes method then throw .invalidMethod
    for name in route.requiredHeaders do
      if !tokenBytes name then throw .invalidMethod
      for c in name do
        if c >= 65 && c <= 90 then throw .invalidMethod
    for j in [:i] do
      if equalFold route.authority routes[j]!.authority then throw .duplicateAuthority
  return ⟨routes, limits, generation⟩

private def validTarget (target : ByteArray) : Bool := Id.run do
  if target.isEmpty || target[0]! != 47 then return false
  let mut i := 0
  while i < target.size do
    let c := target[i]!
    if c == 37 then
      if i + 2 >= target.size then return false
      for k in [i + 1:i + 3] do
        let h := target[k]!
        if !((h >= 48 && h <= 57) || (h >= 65 && h <= 70) || (h >= 97 && h <= 102)) then
          return false
      i := i + 2
    else if !((c >= 48 && c <= 57) || (c >= 65 && c <= 90) ||
        (c >= 97 && c <= 122) ||
        match c.toNat with
        | 33 | 36 | 38 | 39 | 40 | 41 | 42 | 43 | 44 | 45 | 46 | 47 |
          58 | 59 | 61 | 63 | 64 | 95 | 126 => true
        | _ => false) then
      return false
    i := i + 1
  return true

private def checkedAuthority (transport : TransportFacts) (head : ParsedHead) :
    Except ProxyError ByteArray := do
  let mut host : Option ByteArray := none
  for field in head.headers do
    if equalFold field.name "host".toUTF8 then
      if host.isSome then throw .badAuthority
      host := some field.value
  let authority ← match head.protocol with
    | .http1 =>
      let some value := host | throw .badAuthority
      if !equalFold value head.authority || head.scheme.isSome then throw .badAuthority
      pure value
    | .http2 =>
      if host.any (fun value => !equalFold value head.authority) then throw .badAuthority
      let expected := if transport.secure then "https".toUTF8 else "http".toUTF8
      if head.scheme != some expected then throw .misdirected
      pure head.authority
  if (authorityHostEnd authority).isNone then throw .badAuthority
  return authority

/-- The only constructor is this admission function. The proof field is erased
    by Lean; the untrusted byte scans and route lookup still run once. -/
structure ValidatedRequest where
  private mk ::
  head : ParsedHead
  route : Route
  private policy : Policy
  private transport : TransportFacts
  private countBound : head.headers.size ≤ 100

def admit (policy : Policy) (transport : TransportFacts) (head : ParsedHead) :
    Except ProxyError ValidatedRequest := do
  if h : head.headers.size ≤ 100 then
    if head.headers.size > policy.limits.maxHeaderCount then throw .tooManyHeaders
    let mut bytes := 0
    for field in head.headers do
      if !tokenBytes field.name || !safeValue field.value then throw .badHeaders
      if head.protocol == .http2 then
        if !field.value.isEmpty &&
            (field.value[0]! == 32 || field.value[0]! == 9 ||
             field.value[field.value.size - 1]! == 32 ||
             field.value[field.value.size - 1]! == 9) then throw .badHeaders
        for c in field.name do
          if c >= 65 && c <= 90 then throw .badHeaders
      bytes := bytes + field.name.size + field.value.size + 4
      if bytes > policy.limits.maxHeaderBytes then throw .tooManyHeaders
    if !tokenBytes head.method || !validTarget head.target then throw .badTarget
    let authority ← checkedAuthority transport head
    if transport.secure then
      let some sni := transport.sni | throw .misdirected
      let some endIndex := authorityHostEnd authority | throw .badAuthority
      if (authorityHostEnd sni) != some sni.size ||
          !equalFold sni (authority.extract 0 endIndex) then throw .misdirected
    else if transport.sni.isSome then throw .misdirected
    let some route := policy.routes.find? (fun route => equalFold authority route.authority) |
      throw .unknownHost
    if !route.allowedMethods.isEmpty && !route.allowedMethods.any (· == head.method) then
      throw .forbiddenMethod
    for name in route.requiredHeaders do
      if !head.headers.any (fun field => equalFold name field.name) then
        throw .missingRequiredHeader
    return ⟨head, route, policy, transport, h⟩
  else throw .tooManyHeaders

/-- A dispatcher can only obtain the upstream destination from the route bound
    during admission. It never accepts a client-provided backend address. -/
def ValidatedRequest.backend (request : ValidatedRequest) : Backend := request.route.backend

def ValidatedRequest.policyGeneration (request : ValidatedRequest) : UInt64 :=
  request.policy.generation

/-- Invoke after each received body chunk using the parser's cumulative byte
    count. A streaming forwarder must stop before forwarding an oversized chunk. -/
def ValidatedRequest.checkBodySize (request : ValidatedRequest) (receivedBytes : Nat) :
    Except ProxyError Unit :=
  if receivedBytes > request.route.maxBodyBytes then .error .bodyTooLarge else .ok ()

end LeanNet.Proxy
