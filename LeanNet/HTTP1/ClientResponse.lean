import LeanNet.Bytes
import LeanNet.HTTP1.Protocol

namespace LeanNet.HTTP1.ClientResponse

/-- Lowercase ASCII name and uninterpreted value bytes from an upstream. -/
structure Header where
  name : ByteArray
  value : ByteArray
  deriving Inhabited

structure Limits where
  maxHeadBytes : Nat := 65536
  maxHeaderCount : Nat := 100
  maxLineBytes : Nat := 8192
  maxBodyBytes : Nat := 16 * 1024 * 1024
  maxBodyWireBytes : Nat := 32 * 1024 * 1024
  maxTrailerBytes : Nat := 16384
  maxTrailerCount : Nat := 100
  maxChunkLineBytes : Nat := 1024
  maxInformational : Nat := 8
  deriving Inhabited

inductive Error where
  | invalidInput
  | invalidLimits
  | invalidStatus
  | invalidHeader
  | invalidFraming
  | invalidChunk
  | forbiddenTrailer
  | headLimit
  | lineLimit
  | headerCount
  | bodyLimit
  | wireLimit
  | trailerLimit
  | informationalLimit
  | truncated
  deriving BEq, Repr

structure Head where
  version : Version
  status : UInt16
  reason : ByteArray
  headers : Array Header
  framing : BodyFraming
  /-- A pool may reuse this connection only after `.complete` and when no
      unconsumed bytes remain in the read buffer. -/
  reusable : Bool

/-- Body events borrow the input `ByteArray`. Consumers must finish using the
    view before releasing or recycling a native buffer that backs it. -/
inductive Event where
  | informational (head : Head)
  | head (head : Head)
  | body (view : LeanNet.ByteSlice)
  | trailers (fields : Array Header)
  | complete
  /-- 101 or successful CONNECT: remaining input belongs to a tunnel, not
      another HTTP response. The connection is never poolable. -/
  | tunnel (head : Head)

private inductive Stage where
  | status | headers | fixed (remaining : Nat) | chunkLine | chunkData (remaining : Nat)
  | chunkCR | chunkLF | trailers | closeDelimited | done
  deriving BEq, Inhabited

/-- One response transaction. A connection pool should create a fresh parser
    for each request and never pipeline requests on a reused connection. -/
structure Parser where
  limits : Limits
  requestMethod : ByteArray
  private stage : Stage := .status
  private line : ByteArray := ByteArray.empty
  private sawCR : Bool := false
  private headBytes : Nat := 0
  private trailerBytes : Nat := 0
  private wireBytes : Nat := 0
  private bodyBytes : Nat := 0
  private headerCount : Nat := 0
  private informationalCount : Nat := 0
  private headers : Array Header := #[]
  private trailers : Array Header := #[]
  private version : Version := .http11
  private status : UInt16 := 0
  private reason : ByteArray := ByteArray.empty

structure Step where
  parser : Parser
  /-- Relative to the supplied input view. Bytes after a final response or
      tunnel header are intentionally left unconsumed. -/
  consumed : Nat
  events : Array Event

private def lower (c : UInt8) : UInt8 :=
  if c >= 65 && c <= 90 then c + 32 else c

private def token (c : UInt8) : Bool :=
  (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) ||
  match c.toNat with
  | 33 | 35 | 36 | 37 | 38 | 39 | 42 | 43 | 45 | 46 | 94 | 95 | 96 | 124 | 126 => true
  | _ => false

private def safeValue (c : UInt8) : Bool := c == 9 || (c >= 32 && c != 127)
private def ows (c : UInt8) : Bool := c == 32 || c == 9

private def equalFold (bytes text : ByteArray) : Bool := Id.run do
  if bytes.size != text.size then return false
  for i in [:bytes.size] do
    if lower bytes[i]! != lower text[i]! then return false
  return true

private def trim (bytes : ByteArray) : ByteArray := Id.run do
  let mut start := 0
  while start < bytes.size && ows bytes[start]! do start := start + 1
  let mut stop := bytes.size
  while stop > start && ows bytes[stop - 1]! do stop := stop - 1
  return bytes.extract start stop

private def validMethod (bytes : ByteArray) : Bool := Id.run do
  if bytes.isEmpty then return false
  for c in bytes do
    if !token c then return false
  return true

def Parser.new (requestMethod : ByteArray) (limits : Limits := {}) : Except Error Parser := do
  if !validMethod requestMethod then throw .invalidInput
  if limits.maxHeadBytes == 0 || limits.maxHeaderCount == 0 || limits.maxLineBytes == 0 ||
      limits.maxBodyBytes == 0 || limits.maxBodyWireBytes == 0 ||
      limits.maxTrailerBytes == 0 || limits.maxTrailerCount == 0 ||
      limits.maxChunkLineBytes == 0 || limits.maxInformational == 0 then
    throw .invalidLimits
  return { limits, requestMethod }

private def Parser.chargeLineByte (p : Parser) : Except Error Parser := do
  match p.stage with
  | .status | .headers =>
    if p.headBytes >= p.limits.maxHeadBytes then throw .headLimit
    return { p with headBytes := p.headBytes + 1 }
  | .chunkLine =>
    if p.wireBytes >= p.limits.maxBodyWireBytes then throw .wireLimit
    return { p with wireBytes := p.wireBytes + 1 }
  | .trailers =>
    if p.trailerBytes >= p.limits.maxTrailerBytes then throw .trailerLimit
    if p.wireBytes >= p.limits.maxBodyWireBytes then throw .wireLimit
    return { p with trailerBytes := p.trailerBytes + 1, wireBytes := p.wireBytes + 1 }
  | _ => throw .invalidInput

/-- Read one CRLF-terminated line without copying whole input buffers. A split
    CR is retained as one bit, and bare LF/CR are errors. -/
private def Parser.readLine (p : Parser) (input : ByteArray) (start stop : Nat) :
    Except Error (Parser × Nat × Option ByteArray) := do
  let mut p := p
  let mut cursor := start
  let maximum := if p.stage == .chunkLine then p.limits.maxChunkLineBytes
    else p.limits.maxLineBytes
  while cursor < stop do
    let c := input[cursor]!
    cursor := cursor + 1
    p ← p.chargeLineByte
    if p.sawCR then
      if c != 10 then throw .invalidHeader
      let line := p.line
      return ({ p with line := ByteArray.empty, sawCR := false }, cursor, some line)
    if c == 13 then
      p := { p with sawCR := true }
    else if c == 10 then throw .invalidHeader
    else
      if p.line.size >= maximum then throw .lineLimit
      p := { p with line := p.line.push c }
  return (p, cursor, none)

private def parseStatus (line : ByteArray) : Except Error (Version × UInt16 × ByteArray) := do
  if line.size < 13 || line[8]! != 32 || line[12]! != 32 then throw .invalidStatus
  let version ← if line.extract 0 8 == "HTTP/1.1".toUTF8 then pure Version.http11
    else if line.extract 0 8 == "HTTP/1.0".toUTF8 then pure Version.http10
    else throw .invalidStatus
  let mut status := 0
  for i in [9:12] do
    let c := line[i]!
    if c < 48 || c > 57 then throw .invalidStatus
    status := status * 10 + c.toNat - 48
  if status < 100 || status > 599 then throw .invalidStatus
  let reason := line.extract 13 line.size
  for c in reason do
    if !safeValue c then throw .invalidStatus
  return (version, UInt16.ofNat status, reason)

private def parseHeader (line : ByteArray) : Except Error Header := do
  let mut colon := line.size
  for i in [:line.size] do
    if line[i]! == 58 then
      colon := i
      break
  if colon == 0 || colon == line.size then throw .invalidHeader
  let mut name := ByteArray.emptyWithCapacity colon
  for i in [:colon] do
    let c := line[i]!
    if !token c then throw .invalidHeader
    name := name.push (lower c)
  for i in [colon + 1:line.size] do
    if !safeValue line[i]! then throw .invalidHeader
  return { name, value := trim (line.extract (colon + 1) line.size) }

private def decimal (bytes : ByteArray) : Except Error Nat := do
  if bytes.isEmpty || bytes.size > 20 then throw .invalidFraming
  let mut value := 0
  for c in bytes do
    if c < 48 || c > 57 then throw .invalidFraming
    value := value * 10 + c.toNat - 48
    if value > 18446744073709551615 then throw .invalidFraming
  return value

private def connectionOptions (value : ByteArray) : Except Error (Array ByteArray) := do
  let mut result := #[]
  let mut start := 0
  for i in [:value.size + 1] do
    if i == value.size || value[i]! == 44 then
      let item := trim (value.extract start i)
      if item.isEmpty then throw .invalidHeader
      let mut lowered := ByteArray.emptyWithCapacity item.size
      for c in item do
        if !token c then throw .invalidHeader
        lowered := lowered.push (lower c)
      result := result.push lowered
      start := i + 1
  return result

private def forbiddenTrailer (name : ByteArray) : Bool :=
  #["content-length".toUTF8, "transfer-encoding".toUTF8, "host".toUTF8,
    "trailer".toUTF8, "connection".toUTF8, "te".toUTF8, "upgrade".toUTF8,
    "keep-alive".toUTF8, "proxy-connection".toUTF8, "content-encoding".toUTF8,
    "content-type".toUTF8, "content-range".toUTF8, "authorization".toUTF8,
    "proxy-authorization".toUTF8, "proxy-authenticate".toUTF8,
    "www-authenticate".toUTF8, "cookie".toUTF8, "set-cookie".toUTF8,
    "expect".toUTF8].contains name

/-- Framing-relevant facts gathered from one response head (RFC 9112 §6.3). -/
structure FramingFacts where
  contentLength : Option Nat := none
  chunked : Bool := false
  close : Bool := false
  keepAlive : Bool := false
  deriving Inhabited

/-- Fold one header into the framing facts. A second Content-Length, any
Transfer-Encoding other than one `chunked` coding, and Transfer-Encoding in an
HTTP/1.0 response are framing errors. -/
def FramingFacts.add (version : Version) (facts : FramingFacts) (h : Header) :
    Except Error FramingFacts :=
  if h.name == "content-length".toUTF8 then
    if facts.contentLength.isSome then .error .invalidFraming
    else match decimal h.value with
      | .ok n => .ok { facts with contentLength := some n }
      | .error e => .error e
  else if h.name == "transfer-encoding".toUTF8 then
    if facts.chunked || version == .http10 || !equalFold h.value "chunked".toUTF8 then
      .error .invalidFraming
    else .ok { facts with chunked := true }
  else if h.name == "connection".toUTF8 then
    match connectionOptions h.value with
    | .ok tokens => .ok { facts with
        close := facts.close || tokens.contains "close".toUTF8
        keepAlive := facts.keepAlive || tokens.contains "keep-alive".toUTF8 }
    | .error e => .error e
  else .ok facts

def scanFraming (version : Version) (headers : Array Header) : Except Error FramingFacts :=
  headers.foldlM (FramingFacts.add version) {}

/-- The message-length decision for one response head. -/
structure Framing where
  framing : BodyFraming
  /-- The connection may return to a pool after the complete response. -/
  reusable : Bool
  /-- Remaining bytes belong to a protocol switch, never to HTTP. -/
  tunnel : Bool

def delimitedByClose : BodyFraming → Bool
  | .closeDelimited => true
  | _ => false

/-- RFC 9112 §6.3 message-length selection for a head, before validation. -/
def selectFraming (requestMethod : ByteArray) (version : Version) (status : Nat)
    (facts : FramingFacts) : Framing :=
  let tunnel := status == 101 ||
    (requestMethod == "CONNECT".toUTF8 && status >= 200 && status < 300)
  let bodyless := requestMethod == "HEAD".toUTF8 || status < 200 || status == 204 ||
    status == 304
  let framing : BodyFraming :=
    if bodyless || tunnel then .none
    else if facts.chunked then .chunked
    else match facts.contentLength with
      | some n => .contentLength n
      | none => .closeDelimited
  { framing, tunnel,
    reusable := !tunnel && !delimitedByClose framing && !facts.close &&
      (version == .http11 || facts.keepAlive) }

/-- The first framing rule a head violates, if any: both TE and CL, a framed
1xx/204, a framed tunnel, content on 205, or a length over the body limit. -/
def framingViolation (limits : Limits) (status : Nat) (facts : FramingFacts)
    (d : Framing) : Option Error :=
  let framed := facts.chunked || facts.contentLength.isSome
  if facts.chunked && facts.contentLength.isSome then some .invalidFraming
  else if (status < 200 || status == 204) && framed then some .invalidFraming
  else if d.tunnel && framed then some .invalidFraming
  else if status == 205 && facts.contentLength.any (· != 0) then some .invalidFraming
  else match d.framing with
    | .contentLength n => if n > limits.maxBodyBytes then some .bodyLimit else none
    | _ => none

def decideFraming (limits : Limits) (requestMethod : ByteArray) (version : Version)
    (status : Nat) (facts : FramingFacts) : Except Error Framing :=
  let d := selectFraming requestMethod version status facts
  match framingViolation limits status facts d with
  | some e => .error e
  | none => .ok d

/-- Framing of a complete response head: scan its fields, then decide. -/
def frameHead (limits : Limits) (requestMethod : ByteArray) (version : Version)
    (status : Nat) (headers : Array Header) : Except Error Framing :=
  match scanFraming version headers with
  | .ok facts => decideFraming limits requestMethod version status facts
  | .error e => .error e

private def Parser.finalHead (p : Parser) : Except Error (Head × Stage × Bool) := do
  let { framing, reusable, tunnel } ←
    frameHead p.limits p.requestMethod p.version p.status.toNat p.headers
  let head : Head := { version := p.version, status := p.status, reason := p.reason, headers := p.headers, framing, reusable }
  let stage := if tunnel || framing == .contentLength 0 then .done
    else match framing with
      | .contentLength n => .fixed n
      | .chunked => .chunkLine
      | .closeDelimited => .closeDelimited
      | .none => .done
  -- RFC 9112 permits a 101 to leave protocol bytes after the empty line. It
  -- must not be returned to a pooled HTTP parser as another response.
  return (head, stage, tunnel)

private def hexDigit (c : UInt8) : Nat :=
  if c >= 48 && c <= 57 then c.toNat - 48
  else if c >= 65 && c <= 70 then c.toNat - 55
  else if c >= 97 && c <= 102 then c.toNat - 87
  else 16

/-- Accumulate hex digits `line[i:stop]`, failing as soon as the running size
exceeds `remaining`. -/
private def hexDigits (line : ByteArray) (remaining stop : Nat) (i acc : Nat) :
    Except Error Nat :=
  if i < stop then
    let digit := hexDigit line[i]!
    if digit == 16 then .error .invalidChunk
    else
      let next := acc * 16 + digit
      if next > remaining then .error .bodyLimit
      else hexDigits line remaining stop (i + 1) next
  else .ok acc
termination_by stop - i

private def semicolonIndex (line : ByteArray) : Nat := Id.run do
  for i in [:line.size] do
    if line[i]! == 59 then return i
  return line.size

/-- Chunk extensions after `;` must be a token-led sequence of safe bytes. -/
private def chunkExtensionOk (line : ByteArray) (stop : Nat) : Bool := Id.run do
  if stop < line.size then
    if stop + 1 == line.size || !token line[stop + 1]! then return false
    for i in [stop + 1:line.size] do
      if !safeValue line[i]! then return false
  return true

private def parseChunkSize (line : ByteArray) (remaining : Nat) : Except Error Nat :=
  let stop := semicolonIndex line
  if stop == 0 then .error .invalidChunk
  else match hexDigits line remaining stop 0 0 with
    | .error e => .error e
    | .ok size => if chunkExtensionOk line stop then .ok size else .error .invalidChunk

private def Parser.connectionNominates (p : Parser) (name : ByteArray) : Bool := Id.run do
  for h in p.headers do
    if h.name == "connection".toUTF8 then
      match connectionOptions h.value with
      | .ok options => if options.contains name then return true
      | .error _ => return true
  return false

/-- Parse one input range and emit bounded events. `consumed` can be shorter
    than the range only after the final response or a tunnel switch. -/
def Parser.feedSlice (initial : Parser) (input : ByteArray) (offset length : Nat) :
    Except Error Step := do
  if offset > input.size || length > input.size - offset then throw .invalidInput
  let mut p := initial
  let mut cursor := offset
  let stop := offset + length
  let mut events : Array Event := #[]
  while cursor < stop && p.stage != .done do
    match p.stage with
    | .status | .headers | .chunkLine | .trailers =>
      let (next, after, line?) ← p.readLine input cursor stop
      p := next
      cursor := after
      let some line := line? | continue
      match p.stage with
      | .status =>
        let (version, status, reason) ← parseStatus line
        p := { p with version, status, reason, headers := #[], headerCount := 0, stage := .headers }
      | .headers =>
        if line.isEmpty then
          let (head, stage, tunnel) ← p.finalHead
          if tunnel then
            events := events.push (.tunnel head)
            p := { p with stage }
          else if head.status.toNat < 200 then
            if p.informationalCount >= p.limits.maxInformational then throw .informationalLimit
            events := events.push (.informational head)
            p := { p with stage := .status, headers := #[], headerCount := 0, informationalCount := p.informationalCount + 1 }
          else
            events := events.push (.head head)
            p := { p with stage }
            if stage == .done then events := events.push .complete
        else
          if p.headerCount >= p.limits.maxHeaderCount then throw .headerCount
          let field ← parseHeader line
          p := { p with headers := p.headers.push field, headerCount := p.headerCount + 1 }
      | .chunkLine =>
        let size ← parseChunkSize line (p.limits.maxBodyBytes - p.bodyBytes)
        if p.status == 205 && size != 0 then throw .invalidFraming
        p := { p with stage := if size == 0 then .trailers else .chunkData size }
      | .trailers =>
        if line.isEmpty then
          if !p.trailers.isEmpty then events := events.push (.trailers p.trailers)
          events := events.push .complete
          p := { p with stage := .done }
        else
          if p.trailers.size >= p.limits.maxTrailerCount then throw .trailerLimit
          let field ← parseHeader line
          if forbiddenTrailer field.name || p.connectionNominates field.name then
            throw .forbiddenTrailer
          p := { p with trailers := p.trailers.push field }
      | _ => pure ()
    | .fixed remaining | .chunkData remaining =>
      let count := min remaining (stop - cursor)
      if p.bodyBytes + count > p.limits.maxBodyBytes then throw .bodyLimit
      if p.wireBytes + count > p.limits.maxBodyWireBytes then throw .wireLimit
      if count > 0 then
        events := events.push (.body ((LeanNet.ByteSlice.full input).drop cursor |>.take count))
        cursor := cursor + count
        let stage := if count == remaining then
          (if p.stage == .fixed remaining then Stage.done else .chunkCR)
          else if p.stage == .fixed remaining then Stage.fixed (remaining - count)
          else .chunkData (remaining - count)
        p := { p with stage, bodyBytes := p.bodyBytes + count, wireBytes := p.wireBytes + count }
        if stage == .done then events := events.push .complete
    | .chunkCR =>
      if p.wireBytes >= p.limits.maxBodyWireBytes then throw .wireLimit
      if input[cursor]! != 13 then throw .invalidChunk
      p := { p with stage := .chunkLF, wireBytes := p.wireBytes + 1 }
      cursor := cursor + 1
    | .chunkLF =>
      if p.wireBytes >= p.limits.maxBodyWireBytes then throw .wireLimit
      if input[cursor]! != 10 then throw .invalidChunk
      p := { p with stage := .chunkLine, wireBytes := p.wireBytes + 1 }
      cursor := cursor + 1
    | .closeDelimited =>
      let count := stop - cursor
      -- A 205 without explicit framing may only end with a connection close.
      -- It cannot carry content or consume bytes of a following response.
      if p.status == 205 && count > 0 then throw .invalidFraming
      if p.bodyBytes + count > p.limits.maxBodyBytes then throw .bodyLimit
      if p.wireBytes + count > p.limits.maxBodyWireBytes then throw .wireLimit
      if count > 0 then
        events := events.push (.body ((LeanNet.ByteSlice.full input).drop cursor |>.take count))
        p := { p with bodyBytes := p.bodyBytes + count, wireBytes := p.wireBytes + count }
      cursor := stop
    | .done => pure ()
  return { parser := p, consumed := cursor - offset, events }

def Parser.feed (parser : Parser) (input : ByteArray) : Except Error Step :=
  parser.feedSlice input 0 input.size

/-- EOF completes a close-delimited response; every other unfinished stage is
    truncated and disqualifies the socket from a pool. -/
def Parser.eof (parser : Parser) : Except Error Step :=
  match parser.stage with
  | .closeDelimited => .ok { parser := { parser with stage := .done }, consumed := 0, events := #[.complete] }
  | .done => .ok { parser, consumed := 0, events := #[] }
  | _ => .error .truncated


/-! ## Verified framing rules (RFC 9112 §6.3)

`Parser.finalHead` frames every final upstream response head with
`frameHead`, and chunk sizes are read with `parseChunkSize`. The theorems below
are about those production functions. They are the gateway's defence against
response smuggling: an upstream cannot make one connection carry an ambiguous
message length, or get a desynchronized connection returned to the pool. -/

section Proofs

private abbrev CL : ByteArray := "content-length".toUTF8
private abbrev TE : ByteArray := "transfer-encoding".toUTF8

/-- Close every branch of an unfolded `FramingFacts.add` equation. -/
local macro "add_cases" hadd:ident : tactic =>
  `(tactic| (unfold FramingFacts.add at $hadd:ident
             repeat' (split at $hadd:ident)
             all_goals (first | (cases $hadd:ident; done) | (cases $hadd:ident; simp_all) | simp_all)))

private theorem add_keeps_contentLength {version : Version} {f f' : FramingFacts} {h : Header}
    (hadd : FramingFacts.add version f h = .ok f') (hf : f.contentLength.isSome) :
    f'.contentLength.isSome := by
  add_cases hadd

private theorem add_keeps_chunked {version : Version} {f f' : FramingFacts} {h : Header}
    (hadd : FramingFacts.add version f h = .ok f') (hf : f.chunked = true) :
    f'.chunked = true := by
  add_cases hadd

private theorem add_contentLength_sets {version : Version} {f f' : FramingFacts} {h : Header}
    (hn : h.name = CL) (hadd : FramingFacts.add version f h = .ok f') :
    f'.contentLength.isSome := by
  unfold FramingFacts.add at hadd
  rw [hn, ite_eq_left (by decide)] at hadd
  repeat' (split at hadd)
  all_goals (first | (cases hadd; done) | (cases hadd; rfl) | simp_all)

private theorem add_contentLength_dup {version : Version} {f f' : FramingFacts} {h : Header}
    (hn : h.name = CL) (hf : f.contentLength.isSome) :
    FramingFacts.add version f h ≠ .ok f' := by
  intro hadd
  unfold FramingFacts.add at hadd
  rw [hn, ite_eq_left (by decide), ite_eq_left hf] at hadd
  cases hadd

private theorem add_chunked_sets {version : Version} {f f' : FramingFacts} {h : Header}
    (hn : h.name = TE) (hadd : FramingFacts.add version f h = .ok f') : f'.chunked = true := by
  unfold FramingFacts.add at hadd
  rw [hn, ite_eq_right (by decide), ite_eq_left (by decide)] at hadd
  repeat' (split at hadd)
  all_goals (first | (cases hadd; done) | (cases hadd; rfl) | simp_all)

private theorem add_chunked_http10 {f f' : FramingFacts} {h : Header} (hn : h.name = TE) :
    FramingFacts.add .http10 f h ≠ .ok f' := by
  intro hadd
  unfold FramingFacts.add at hadd
  rw [hn, ite_eq_right (by decide), ite_eq_left (by decide),
    ite_eq_left (by rw [show (Version.http10 == Version.http10) = true from by decide]; simp)] at hadd
  cases hadd

private theorem foldlM_ok_of_cons {version : Version} {f f' : FramingFacts} {a : Header}
    {rest : List Header} (h : (a :: rest).foldlM (FramingFacts.add version) f = .ok f') :
    ∃ f₁, FramingFacts.add version f a = .ok f₁ ∧
      rest.foldlM (FramingFacts.add version) f₁ = .ok f' := by
  rw [List.foldlM_cons] at h
  cases hstep : FramingFacts.add version f a with
  | error e => rw [hstep] at h; cases h
  | ok f₁ => rw [hstep] at h; exact ⟨f₁, rfl, h⟩

private theorem foldlM_keeps {version : Version} {P : FramingFacts → Prop}
    (keep : ∀ {f f' h}, FramingFacts.add version f h = .ok f' → P f → P f') :
    ∀ (l : List Header) (f f' : FramingFacts),
      l.foldlM (FramingFacts.add version) f = .ok f' → P f → P f'
  | [], f, f', h, hp => by cases h; exact hp
  | a :: rest, f, f', h, hp => by
    obtain ⟨f₁, h₁, h₂⟩ := foldlM_ok_of_cons h
    exact foldlM_keeps keep rest f₁ f' h₂ (keep h₁ hp)

private theorem foldlM_establishes {version : Version} {P : FramingFacts → Prop} {x : Header}
    (keep : ∀ {f f' h}, FramingFacts.add version f h = .ok f' → P f → P f')
    (sets : ∀ {f f'}, FramingFacts.add version f x = .ok f' → P f') :
    ∀ (l : List Header) (f f' : FramingFacts), x ∈ l →
      l.foldlM (FramingFacts.add version) f = .ok f' → P f'
  | [], _, _, hm, _ => by cases hm
  | a :: rest, f, f', hm, h => by
    obtain ⟨f₁, h₁, h₂⟩ := foldlM_ok_of_cons h
    cases hm with
    | head => exact foldlM_keeps keep rest f₁ f' h₂ (sets h₁)
    | tail _ hm => exact foldlM_establishes keep sets rest f₁ f' hm h₂

private theorem scan_toList {version : Version} {headers : Array Header} {facts : FramingFacts}
    (h : scanFraming version headers = .ok facts) :
    headers.toList.foldlM (FramingFacts.add version) {} = .ok facts := by
  rw [Array.foldlM_toList]; exact h

private theorem decide_ok {limits : Limits} {method : ByteArray} {version : Version}
    {status : Nat} {facts : FramingFacts} {d : Framing}
    (h : decideFraming limits method version status facts = .ok d) :
    d = selectFraming method version status facts ∧
      framingViolation limits status facts d = none := by
  unfold decideFraming at h
  dsimp only at h
  cases hv : framingViolation limits status facts (selectFraming method version status facts) with
  | some e => rw [hv] at h; cases h
  | none => rw [hv] at h; cases h; exact ⟨rfl, hv⟩

private theorem frameHead_ok {limits : Limits} {method : ByteArray} {version : Version}
    {status : Nat} {headers : Array Header} {d : Framing}
    (h : frameHead limits method version status headers = .ok d) :
    ∃ facts, scanFraming version headers = .ok facts ∧
      d = selectFraming method version status facts ∧
      framingViolation limits status facts d = none := by
  unfold frameHead at h
  cases hs : scanFraming version headers with
  | error e => rw [hs] at h; cases h
  | ok facts => rw [hs] at h; exact ⟨facts, rfl, decide_ok h⟩

/-- **No duplicate Content-Length.** A response head with two Content-Length
fields is rejected, even when their values agree. -/
theorem frameHead_rejects_duplicate_contentLength (limits : Limits) (method : ByteArray)
    (version : Version) (status : Nat) (headers : Array Header) (xs ys : List Header)
    (h₁ h₂ : Header) (split : headers.toList = xs ++ h₁ :: ys) (hm : h₂ ∈ ys)
    (n₁ : h₁.name = CL) (n₂ : h₂.name = CL) :
    ∀ d, frameHead limits method version status headers ≠ .ok d := by
  intro d hd
  obtain ⟨facts, hscan, -⟩ := frameHead_ok hd
  have hl := scan_toList hscan
  rw [split, List.foldlM_append] at hl
  cases hxs : xs.foldlM (FramingFacts.add version) {} with
  | error e => rw [hxs] at hl; cases hl
  | ok f₀ =>
    rw [hxs] at hl
    obtain ⟨f₁, hadd₁, hrest⟩ := foldlM_ok_of_cons hl
    -- Every later field keeps Content-Length present; the second one fails.
    have dup : ∀ (l : List Header) (f f' : FramingFacts), h₂ ∈ l → f.contentLength.isSome →
        l.foldlM (FramingFacts.add version) f ≠ .ok f' := by
      intro l
      induction l with
      | nil => intro _ _ hm; cases hm
      | cons a rest ih =>
        intro f f' hm hf hfold
        obtain ⟨g, hg, hgrest⟩ := foldlM_ok_of_cons hfold
        cases hm with
        | head => exact add_contentLength_dup n₂ hf hg
        | tail _ hm => exact ih g f' hm (add_keeps_contentLength hg hf) hgrest
    exact dup ys f₁ facts hm (add_contentLength_sets n₁ hadd₁) hrest

/-- **No Transfer-Encoding with Content-Length** (RFC 9112 §6.3 rule 3). A
proxy must not choose either length when both are present. -/
theorem frameHead_rejects_transferEncoding_with_contentLength (limits : Limits)
    (method : ByteArray) (version : Version) (status : Nat) (headers : Array Header)
    (h₁ h₂ : Header) (m₁ : h₁ ∈ headers.toList) (m₂ : h₂ ∈ headers.toList)
    (n₁ : h₁.name = CL) (n₂ : h₂.name = TE) :
    ∀ d, frameHead limits method version status headers ≠ .ok d := by
  intro d hd
  obtain ⟨facts, hscan, -, hv⟩ := frameHead_ok hd
  have hl := scan_toList hscan
  have hcl : facts.contentLength.isSome = true :=
    foldlM_establishes (P := fun f => f.contentLength.isSome = true)
      add_keeps_contentLength (add_contentLength_sets n₁) _ _ _ m₁ hl
  have hte : facts.chunked = true :=
    foldlM_establishes (P := fun f => f.chunked = true)
      add_keeps_chunked (add_chunked_sets n₂) _ _ _ m₂ hl
  simp [framingViolation, hcl, hte] at hv

/-- **No chunked HTTP/1.0 responses.** HTTP/1.0 has no Transfer-Encoding, so
a 1.0 response carrying one is rejected instead of being guessed at. -/
theorem frameHead_rejects_transferEncoding_http10 (limits : Limits) (method : ByteArray)
    (status : Nat) (headers : Array Header) (h : Header) (m : h ∈ headers.toList)
    (n : h.name = TE) :
    ∀ d, frameHead limits method .http10 status headers ≠ .ok d := by
  intro d hd
  obtain ⟨facts, hscan, -⟩ := frameHead_ok hd
  exact (foldlM_establishes (P := fun _ => False) (fun _ hp => hp)
    (fun hadd => absurd hadd (add_chunked_http10 n)) _ _ _ m (scan_toList hscan)).elim

/-- **Framed interim and 204 responses are rejected.** A 1xx or 204 head that
declares a body length is malformed, not a body. -/
theorem frameHead_rejects_framed_bodyless_status (limits : Limits) (method : ByteArray)
    (version : Version) (status : Nat) (headers : Array Header)
    (hs : status < 200 ∨ status = 204) (h : Header) (m : h ∈ headers.toList)
    (n : h.name = CL ∨ h.name = TE) :
    ∀ d, frameHead limits method version status headers ≠ .ok d := by
  intro d hd
  obtain ⟨facts, hscan, -, hv⟩ := frameHead_ok hd
  have hl := scan_toList hscan
  have framed : (facts.chunked || facts.contentLength.isSome) = true := by
    rcases n with n | n
    · simp [foldlM_establishes (P := fun f => f.contentLength.isSome = true)
        add_keeps_contentLength (add_contentLength_sets n) _ _ _ m hl]
    · simp [foldlM_establishes (P := fun f => f.chunked = true)
        add_keeps_chunked (add_chunked_sets n) _ _ _ m hl]
  have hstatus : (decide (status < 200) || status == 204) = true := by
    rcases hs with hs | hs
    · simp [hs]
    · subst hs; simp
  simp only [framingViolation, framed, hstatus, Bool.and_true] at hv
  split at hv
  · cases hv
  · simp at hv

/-- **Bodyless responses carry no body.** Responses to HEAD and 1xx, 204 and
304 responses never consume body bytes, whatever their headers claim. -/
theorem frameHead_bodyless (limits : Limits) (method : ByteArray) (version : Version)
    (status : Nat) (headers : Array Header) (d : Framing)
    (h : frameHead limits method version status headers = .ok d)
    (hb : method = "HEAD".toUTF8 ∨ status < 200 ∨ status = 204 ∨ status = 304) :
    d.framing = .none := by
  obtain ⟨facts, -, rfl, -⟩ := frameHead_ok h
  have : (method == "HEAD".toUTF8 || decide (status < 200) || status == 204 ||
      status == 304) = true := by
    rcases hb with hb | hb | hb | hb
    · subst hb; rw [show ("HEAD".toUTF8 == "HEAD".toUTF8) = true from by decide]; simp
    · simp [hb]
    · subst hb; simp
    · subst hb; simp
  simp only [selectFraming, this, Bool.true_or, ite_eq_left]

/-- **Tunnels are never framed as HTTP.** After a 101 or a successful CONNECT
the parser stops, and the connection is never pooled. -/
theorem frameHead_tunnel (limits : Limits) (method : ByteArray) (version : Version)
    (status : Nat) (headers : Array Header) (d : Framing)
    (h : frameHead limits method version status headers = .ok d) (ht : d.tunnel = true) :
    d.framing = .none ∧ d.reusable = false := by
  obtain ⟨facts, -, rfl, -⟩ := frameHead_ok h
  unfold selectFraming at ht ⊢
  dsimp only at ht ⊢
  rw [ht]
  simp

/-- **Pool safety.** A connection is reusable only when its response length is
self-delimiting (never read-until-close), it is not a tunnel, and the upstream
did not send `Connection: close`. -/
theorem frameHead_reusable (limits : Limits) (method : ByteArray) (version : Version)
    (status : Nat) (headers : Array Header) (d : Framing)
    (h : frameHead limits method version status headers = .ok d) (hr : d.reusable = true) :
    d.tunnel = false ∧ d.framing ≠ .closeDelimited ∧
      ∃ facts, scanFraming version headers = .ok facts ∧ facts.close = false := by
  obtain ⟨facts, hscan, rfl, -⟩ := frameHead_ok h
  simp only [selectFraming, Bool.and_eq_true, Bool.not_eq_eq_eq_not, Bool.not_true] at hr ⊢
  obtain ⟨⟨⟨ht, hc⟩, hclose⟩, -⟩ := hr
  refine ⟨ht, ?_, facts, hscan, hclose⟩
  intro hf
  rw [hf] at hc
  simp [delimitedByClose] at hc

/-- **Declared lengths respect the body limit** before any body byte is read. -/
theorem frameHead_contentLength_bounded (limits : Limits) (method : ByteArray)
    (version : Version) (status : Nat) (headers : Array Header) (d : Framing) (n : Nat)
    (h : frameHead limits method version status headers = .ok d)
    (hn : d.framing = .contentLength n) : n ≤ limits.maxBodyBytes := by
  obtain ⟨facts, -, -, hv⟩ := frameHead_ok h
  apply Nat.le_of_not_lt
  intro hlt
  simp only [framingViolation, hn] at hv
  repeat' (split at hv)
  all_goals simp_all

private theorem hexDigits_le (line : ByteArray) (remaining stop : Nat) :
    ∀ i acc n, acc ≤ remaining → hexDigits line remaining stop i acc = .ok n →
      n ≤ remaining := by
  intro i acc n hacc h
  induction i, acc using hexDigits.induct line remaining stop with
  | case1 i acc hi digit hdigit =>
    rw [hexDigits, ite_eq_left hi] at h
    dsimp only at h
    rw [ite_eq_left (show (hexDigit line[i]! == 16) = true from hdigit)] at h
    cases h
  | case2 i acc hi digit hdigit next hnext =>
    rw [hexDigits, ite_eq_left hi] at h
    dsimp only at h
    rw [ite_eq_right (show ¬(hexDigit line[i]! == 16) = true from hdigit),
      ite_eq_left (show acc * 16 + hexDigit line[i]! > remaining from hnext)] at h
    cases h
  | case3 i acc hi digit hdigit next hnext ih =>
    rw [hexDigits, ite_eq_left hi] at h
    dsimp only at h
    rw [ite_eq_right (show ¬(hexDigit line[i]! == 16) = true from hdigit),
      ite_eq_right (show ¬acc * 16 + hexDigit line[i]! > remaining from hnext)] at h
    exact ih (by omega) h
  | case4 i acc hi =>
    rw [hexDigits, ite_eq_right hi] at h
    cases h
    exact hacc

/-- **Chunk sizes respect the remaining body budget.** A chunk-size line can
never announce more bytes than the response may still deliver, so an upstream
cannot make the gateway wait for or buffer an over-limit chunk. -/
theorem parseChunkSize_bounded (line : ByteArray) (remaining n : Nat)
    (h : parseChunkSize line remaining = .ok n) : n ≤ remaining := by
  unfold parseChunkSize at h
  dsimp only at h
  split at h
  · cases h
  · cases hsize : hexDigits line remaining (semicolonIndex line) 0 0 with
    | error e => rw [hsize] at h; cases h
    | ok size =>
      rw [hsize] at h
      dsimp only at h
      split at h
      · cases h; exact hexDigits_le line remaining _ 0 0 _ (Nat.zero_le _) hsize
      · cases h


end Proofs

end LeanNet.HTTP1.ClientResponse
