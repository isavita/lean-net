import LeanNet.HTTP1.Request

/-! Byte-level building blocks of the gate: header field safety with
    soundness lemmas, strict authorities, host patterns, CIDR blocks and
    strict path normalisation. Everything operates on `ByteArray`. -/

namespace LeanNet.Gate

def lowerByte (c : UInt8) : UInt8 := if c >= 65 && c <= 90 then c + 32 else c

def equalFold (a b : ByteArray) : Bool := Id.run do
  if a.size != b.size then return false
  for i in [:a.size] do
    if lowerByte a[i]! != lowerByte b[i]! then return false
  return true

def lowerBytes (bytes : ByteArray) : ByteArray := ⟨bytes.data.map lowerByte⟩

def startsWith (bytes pre : ByteArray) : Bool :=
  pre.size <= bytes.size && (bytes.extract 0 pre.size) == pre

/-! ## Header field safety -/

/-- A field-value byte: HTAB or visible/obs-text, never CR, LF, NUL or DEL. -/
def valueByte (c : UInt8) : Bool := c == 9 || (c >= 32 && c != 127)

def tokenByte (c : UInt8) : Bool :=
  (c >= 48 && c <= 57) || (c >= 97 && c <= 122) || (c >= 65 && c <= 90) ||
  c == 33 || c == 35 || c == 36 || c == 37 || c == 38 || c == 39 || c == 42 || c == 43 ||
  c == 45 || c == 46 || c == 94 || c == 95 || c == 96 || c == 124 || c == 126

/-- Lowercase token name and safe value: the invariant every admitted field holds. -/
def fieldOk (field : HTTP1.Header) : Bool :=
  !field.name.isEmpty && field.name.all (fun c => c.toNat < 128 && tokenByte c.toUInt8 && !c.isUpper) &&
  !(field.value.data[0]?.any (fun c => c == 32 || c == 9)) &&
  !(field.value.data.back?.any (fun c => c == 32 || c == 9)) &&
  field.value.data.all valueByte

theorem valueByte_cr : valueByte 13 = false := by decide
theorem valueByte_lf : valueByte 10 = false := by decide
theorem valueByte_nul : valueByte 0 = false := by decide

/-- A safe value byte is never CR or LF, so admitted values cannot inject lines. -/
theorem valueByte_not_crlf {c : UInt8} (h : valueByte c = true) : c ≠ 13 ∧ c ≠ 10 := by
  constructor
  · intro heq; subst heq; exact absurd h (by decide)
  · intro heq; subst heq; exact absurd h (by decide)

/-- Soundness: every byte of an admitted field value is neither CR nor LF. -/
theorem fieldOk_no_crlf {field : HTTP1.Header} (h : fieldOk field = true) :
    ∀ c ∈ field.value.data, c ≠ 13 ∧ c ≠ 10 := by
  intro c hc
  simp only [fieldOk, Bool.and_eq_true] at h
  exact valueByte_not_crlf ((Array.all_eq_true'.mp h.2) c hc)

/-! ## Authorities -/

/-- Canonical authority: lowercase DNS-style host (or dotted IPv4 text) and an
    optional explicit port. Userinfo, IP literals in brackets, percent-encoding,
    trailing dots and empty or zero ports are rejected rather than normalised. -/
structure Authority where
  host : ByteArray
  port : Option UInt16
  deriving DecidableEq, Inhabited

def Authority.render (authority : Authority) : ByteArray :=
  match authority.port with
  | some port => authority.host ++ s!":{port}".toUTF8
  | none => authority.host

def validHost (host : ByteArray) : Bool := Id.run do
  if host.isEmpty || host.size > 253 then return false
  let mut labelStart := 0
  for i in [:host.size] do
    let c := lowerByte host[i]!
    if c == 46 then
      if i == labelStart || i - labelStart > 63 || host[i - 1]! == 45 then return false
      labelStart := i + 1
    else if !((c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c == 45) then return false
    else if c == 45 && i == labelStart then return false
  return labelStart != host.size && host.size - labelStart <= 63 && host[host.size - 1]! != 45

def Authority.parse (raw : ByteArray) : Option Authority := do
  if raw.isEmpty || raw.size > 259 then none
  let colon := (raw.data.findIdx? (· == 58)).getD raw.size
  let host := raw.extract 0 colon
  if !validHost host then none
  if colon == raw.size then return { host := lowerBytes host, port := none }
  let digits := raw.extract (colon + 1) raw.size
  if digits.isEmpty || digits.size > 5 || (digits.size > 1 && digits[0]! == 48) then none
  let mut port := 0
  for c in digits.data do
    if c < 48 || c > 57 then none
    port := port * 10 + (c - 48).toNat
  if port == 0 || port > 65535 then none
  return { host := lowerBytes host, port := some port.toUInt16 }

/-! ## Host patterns -/

inductive HostPattern where
  /-- Exact host; `port`, when set, must also match. -/
  | exact (host : ByteArray) (port : Option UInt16)
  /-- `*.suffix`: exactly one extra DNS label (never the apex). -/
  | wildcard (suffix : ByteArray)
  /-- `_`: any authority (catch-all virtual host). -/
  | any
  deriving DecidableEq, Inhabited

def HostPattern.parse (text : String) : Option HostPattern := do
  if text == "_" then return .any
  let bytes := text.toUTF8
  if text.startsWith "*." then
    let suffix := bytes.extract 2 bytes.size
    if !validHost suffix then none
    return .wildcard (lowerBytes suffix)
  let authority ← Authority.parse bytes
  return .exact authority.host authority.port

def HostPattern.matches (pattern : HostPattern) (authority : Authority) : Bool :=
  match pattern with
  | .any => true
  | .exact host port => authority.host == host && (port.isNone || port == authority.port)
  | .wildcard suffix =>
    let host := authority.host
    host.size > suffix.size + 1 &&
      host.extract (host.size - suffix.size) host.size == suffix &&
      host[host.size - suffix.size - 1]! == 46 &&
      !(host.extract 0 (host.size - suffix.size - 1)).data.contains 46

/-- Host part used for SNI agreement. -/
def HostPattern.render : HostPattern → String
  | .any => "_"
  | .exact host port => ((String.fromUTF8? host).getD "") ++ (port.map (fun p => s!":{p}")).getD ""
  | .wildcard suffix => "*." ++ (String.fromUTF8? suffix).getD ""

/-! ## CIDR blocks -/

structure Cidr where
  address : ByteArray
  prefixBits : Nat
  deriving BEq, Inhabited

private def parseIPv4 (text : String) : Option ByteArray := do
  let parts := text.splitOn "."
  if parts.length != 4 then none
  let mut out := ByteArray.empty
  for part in parts do
    let value ← part.toNat?
    if part.isEmpty || part.length > 3 || value > 255 || (part.length > 1 && part.startsWith "0") then none
    out := out.push value.toUInt8
  return out

private def hexGroup (text : String) : Option Nat := do
  if text.isEmpty || text.length > 4 then none
  let mut value := 0
  for c in text.toList do
    let digit ← if c.isDigit then some (c.toNat - 48)
      else if c >= 'a' && c <= 'f' then some (c.toNat - 87)
      else if c >= 'A' && c <= 'F' then some (c.toNat - 55) else none
    value := value * 16 + digit
  return value

/-- RFC 4291 text form, with at most one `::` and no embedded IPv4 tail. -/
private def parseIPv6 (text : String) : Option ByteArray := do
  let halves := text.splitOn "::"
  if halves.length > 2 then none
  let groupsOf := fun (part : String) => if part.isEmpty then [] else part.splitOn ":"
  let left := groupsOf halves[0]!
  let right := if halves.length == 2 then groupsOf halves[1]! else []
  let missing := 8 - left.length - right.length
  if (halves.length == 1 && left.length != 8) || (halves.length == 2 && left.length + right.length > 7) then none
  let groups := left ++ (if halves.length == 2 then List.replicate missing "0" else []) ++ right
  let mut out := ByteArray.empty
  for group in groups do
    let value ← hexGroup group
    out := (out.push (value / 256).toUInt8).push (value % 256).toUInt8
  if out.size != 16 then none
  return out

def parseAddress (text : String) : Option ByteArray :=
  if text.contains ':' then parseIPv6 text else parseIPv4 text

def Cidr.parse (text : String) : Option Cidr := do
  match text.splitOn "/" with
  | [address] =>
    let bytes ← parseAddress address
    return { address := bytes, prefixBits := bytes.size * 8 }
  | [address, bits] =>
    let bytes ← parseAddress address
    let prefixBits ← bits.toNat?
    if prefixBits > bytes.size * 8 then none
    return { address := bytes, prefixBits }
  | _ => none

/-- Peer bytes come from `Transport.Facts.peer` (4 or 16 bytes). -/
def Cidr.contains (cidr : Cidr) (peer : ByteArray) : Bool := Id.run do
  if peer.size != cidr.address.size then return false
  let whole := cidr.prefixBits / 8
  for i in [:whole] do
    if peer[i]! != cidr.address[i]! then return false
  let rest := cidr.prefixBits % 8
  if rest == 0 then return true
  let mask : UInt8 := (0xFF : UInt8) <<< (8 - rest).toUInt8
  return (peer[whole]! &&& mask) == (cidr.address[whole]! &&& mask)

/-! ## Strict path normalisation -/

private def hexValue (c : UInt8) : Option UInt8 :=
  if c >= 48 && c <= 57 then some (c - 48)
  else if c >= 65 && c <= 70 then some (c - 55)
  else if c >= 97 && c <= 102 then some (c - 87) else none

private def unreserved (c : UInt8) : Bool :=
  (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) ||
  c == 45 || c == 46 || c == 95 || c == 126

private def upperHex (n : UInt8) : UInt8 := if n < 10 then 48 + n else 55 + n

inductive PathError where
  | notOriginForm | dotSegment | emptySegment | encodedSeparator | badEscape | tooDeep
  deriving BEq, Repr

/-- Normalised origin-form path, split from its query. Unreserved escapes are
    decoded and other escapes upper-cased, so `/%61dmin` and `/admin` are one
    path. Encoded `/`, `\` or NUL, raw `\`, `.`/`..` segments and empty inner
    segments are rejected. The router, the application and an upstream all
    see this same normalised path. -/
structure NormalPath where
  path : ByteArray
  query : ByteArray
  segments : Array ByteArray
  deriving Inhabited

def normalizePath (target : ByteArray) (maxDepth : Nat := 32) : Except PathError NormalPath := do
  if target.isEmpty || target[0]! != 47 then throw .notOriginForm
  let stop := (target.data.findIdx? (· == 63)).getD target.size
  let query := if stop < target.size then target.extract (stop + 1) target.size else ByteArray.empty
  -- Common case: no escapes or backslashes, so the path is one slice.
  let plain := !target.data.any (fun c => c == 37 || c == 92) 0 stop
  let mut path := if plain then target.extract 0 stop else ByteArray.empty
  let mut i := if plain then stop else 0
  while i < stop do
    let c := target[i]!
    if c == 92 then throw .encodedSeparator
    if c == 37 then
      if i + 2 >= stop then throw .badEscape
      let some high := hexValue target[i + 1]! | throw .badEscape
      let some low := hexValue target[i + 2]! | throw .badEscape
      let decoded := high * 16 + low
      if decoded == 47 || decoded == 92 || decoded == 0 then throw .encodedSeparator
      if unreserved decoded then path := path.push decoded
      else path := ((path.push 37).push (upperHex high)).push (upperHex low)
      i := i + 3
    else
      path := path.push c
      i := i + 1
  let mut segments : Array ByteArray := #[]
  let mut start := 1
  for j in [1:path.size + 1] do
    if j == path.size || path[j]! == 47 then
      let segment := path.extract start j
      let last := j == path.size
      if segment.isEmpty && !last then throw .emptySegment
      if segment == ".".toUTF8 || segment == "..".toUTF8 then throw .dotSegment
      if !segment.isEmpty then segments := segments.push segment
      start := j + 1
  if segments.size > maxDepth then throw .tooDeep
  return { path, query, segments }

end LeanNet.Gate
