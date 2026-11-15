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

private def Parser.finalHead (p : Parser) : Except Error (Head × Stage × Bool) := do
  let mut contentLength : Option Nat := none
  let mut transferEncoding := false
  let mut close := false
  let mut keepAlive := false
  for h in p.headers do
    if h.name == "content-length".toUTF8 then
      if contentLength.isSome then throw .invalidFraming
      contentLength := some (← decimal h.value)
    else if h.name == "transfer-encoding".toUTF8 then
      if transferEncoding || p.version == .http10 ||
          !equalFold h.value "chunked".toUTF8 then throw .invalidFraming
      transferEncoding := true
    else if h.name == "connection".toUTF8 then
      let tokens ← connectionOptions h.value
      if tokens.contains "close".toUTF8 then close := true
      if tokens.contains "keep-alive".toUTF8 then keepAlive := true
  if transferEncoding && contentLength.isSome then throw .invalidFraming
  let status := p.status.toNat
  if (status < 200 || status == 204) && (transferEncoding || contentLength.isSome) then
    throw .invalidFraming
  let tunnel := status == 101 || (p.requestMethod == "CONNECT".toUTF8 && status >= 200 && status < 300)
  let bodyless := p.requestMethod == "HEAD".toUTF8 || status < 200 || status == 204 ||
    status == 304
  if tunnel && (transferEncoding || contentLength.isSome) then throw .invalidFraming
  if status == 205 && contentLength.any (· != 0) then throw .invalidFraming
  let framing : BodyFraming :=
    if bodyless || tunnel then .none
    else if transferEncoding then .chunked
    else if let some n := contentLength then .contentLength n
    else .closeDelimited
  if let .contentLength n := framing then
    if n > p.limits.maxBodyBytes then throw .bodyLimit
  let reusable := !tunnel && framing != .closeDelimited && !close &&
    (p.version == .http11 || keepAlive)
  let head : Head := { version := p.version, status := p.status, reason := p.reason, headers := p.headers, framing, reusable }
  let stage := if tunnel || bodyless || framing == .contentLength 0 then .done
    else match framing with
      | .contentLength n => .fixed n
      | .chunked => .chunkLine
      | .closeDelimited => .closeDelimited
      | .none => .done
  -- RFC 9112 permits a 101 to leave protocol bytes after the empty line. It
  -- must not be returned to a pooled HTTP parser as another response.
  return (head, stage, tunnel)

private def parseChunkSize (line : ByteArray) (remaining : Nat) : Except Error Nat := do
  let mut stop := line.size
  for i in [:line.size] do
    if line[i]! == 59 then
      stop := i
      break
  if stop == 0 then throw .invalidChunk
  let mut size := 0
  for i in [:stop] do
    let c := line[i]!
    let digit := if c >= 48 && c <= 57 then c.toNat - 48
      else if c >= 65 && c <= 70 then c.toNat - 55
      else if c >= 97 && c <= 102 then c.toNat - 87
      else 16
    if digit == 16 then throw .invalidChunk
    size := size * 16 + digit
    if size > remaining then throw .bodyLimit
  if stop < line.size then
    if stop + 1 == line.size || !token line[stop + 1]! then throw .invalidChunk
    for i in [stop + 1:line.size] do
      if !safeValue line[i]! then throw .invalidChunk
  return size

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

end LeanNet.HTTP1.ClientResponse
