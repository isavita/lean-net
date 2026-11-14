import LeanNet.HTTP1.Request

namespace LeanNet.HTTP1

private def bytes (xs : List UInt8) : ByteArray := ByteArray.mk xs.toArray
private def tokenByte (b : UInt8) : Bool :=
  let n := b.toNat
  (n >= 48 && n <= 57) || (n >= 65 && n <= 90) || (n >= 97 && n <= 122) ||
    [33, 35, 36, 37, 38, 39, 42, 43, 45, 46, 94, 95, 96, 124, 126].contains n
private def whitespace (b : UInt8) : Bool := b == 32 || b == 9
private def trim (xs : List UInt8) : List UInt8 :=
  ((xs.dropWhile whitespace).reverse.dropWhile whitespace).reverse

private def splitOnce (xs : List UInt8) (separator : UInt8) : Option (List UInt8 × List UInt8) :=
  go xs []
where
  go (input : List UInt8) (acc : List UInt8) : Option (List UInt8 × List UInt8) :=
    match input with
    | [] => none
    | x :: rest => if x == separator then some (acc.reverse, rest) else go rest (x :: acc)

private def validPercentEncoding : List UInt8 → Bool
  | [] => true
  | 37 :: a :: b :: rest =>
    let hex := fun c : UInt8 =>
      (c.toNat >= 48 && c.toNat <= 57) || (c.toNat >= 65 && c.toNat <= 70) ||
        (c.toNat >= 97 && c.toNat <= 102)
    hex a && hex b && validPercentEncoding rest
  | 37 :: _ => false
  | _ :: rest => validPercentEncoding rest

private def parseHeader (line : List UInt8) : Except String Header := do
  let some (name, value) := splitOnce line 58 | throw "malformed header"
  if name.isEmpty || !name.all tokenByte then throw "invalid header name"
  if !value.all (fun c => c == 9 || (c.toNat >= 32 && c.toNat != 127)) then
    throw "invalid header value"
  let some nameText := String.fromUTF8? (bytes name) | throw "invalid header name"
  return { name := nameText.toLower, value := bytes (trim value) }

private def isHex (c : UInt8) : Bool :=
  (c.toNat >= 48 && c.toNat <= 57) || (c.toNat >= 65 && c.toNat <= 70) ||
    (c.toNat >= 97 && c.toNat <= 102)

private def validPort (port : List UInt8) : Bool :=
  port.all (fun c => c.toNat >= 48 && c.toNat <= 57)

private def validRegName (name : List UInt8) : Bool :=
  validPercentEncoding name && name.all (fun c =>
    let n := c.toNat
    (n >= 65 && n <= 90) || (n >= 97 && n <= 122) || (n >= 48 && n <= 57) ||
      [33, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 59, 61, 95, 126].contains n)

private def validIPv4 (text : String) : Bool :=
  let octets := text.splitOn "."
  octets.length == 4 && octets.all (fun part =>
    !part.isEmpty && part.toUTF8.size <= 3 &&
      !(part.toUTF8.size > 1 && part.startsWith "0") &&
      part.toUTF8.toList.all (fun c => c.toNat >= 48 && c.toNat <= 57) &&
      match part.toNat? with | some n => n <= 255 | none => false)

private def ipv6Groups (groups : List String) : Option Nat :=
  go groups 0
where
  go (groups : List String) (count : Nat) : Option Nat :=
    match groups with
    | [] => some count
    | group :: rest =>
      if group.toUTF8.toList.contains 46 then
        if rest.isEmpty && validIPv4 group then some (count + 2) else none
      else if group.isEmpty || group.toUTF8.size > 4 || !group.toUTF8.toList.all isHex then none
      else go rest (count + 1)

private def validIPv6 (raw : List UInt8) : Bool :=
  match String.fromUTF8? (bytes raw) with
  | none => false
  | some text =>
    let parts := text.splitOn "::"
    let groups := fun (s : String) => if s.isEmpty then [] else s.splitOn ":"
    match parts with
    | [one] => match ipv6Groups (groups one) with | some n => n == 8 | none => false
    | [left, right] =>
      -- A dotted IPv4 suffix can occur only at the very end.
      if left.toUTF8.toList.contains 46 then false
      else match ipv6Groups (groups left ++ groups right) with | some n => n < 8 | none => false
    | _ => false

private def validIPvFuture (raw : List UInt8) : Bool :=
  match raw with
  | v :: rest =>
    if v != 86 && v != 118 then false
    else match splitOnce rest 46 with
      | none => false
      | some (version, address) =>
        !version.isEmpty && version.all isHex && !address.isEmpty &&
          address.all (fun c =>
            let n := c.toNat
            (n >= 65 && n <= 90) || (n >= 97 && n <= 122) || (n >= 48 && n <= 57) ||
              [33,36,38,39,40,41,42,43,44,45,46,58,59,61,95,126].contains n)
  | [] => false

def validAuthority (value : ByteArray) : Bool :=
  let raw := value.toList
  match raw with
  | 91 :: rest =>
    match splitOnce rest 93 with
    | none => false
    | some (address, suffix) =>
      (validIPv6 address || validIPvFuture address) && (suffix.isEmpty ||
        match suffix with | 58 :: port => validPort port | _ => false)
  | _ =>
    match splitOnce raw 58 with
    | none => validRegName raw
    | some (name, port) => validRegName name && validPort port

private def validUserInfo (value : List UInt8) : Bool :=
  value.all (fun c =>
    let n := c.toNat
    (n >= 65 && n <= 90) || (n >= 97 && n <= 122) || (n >= 48 && n <= 57) ||
      [33,36,37,38,39,40,41,42,43,44,45,46,58,59,61,95,126].contains n)

private def parseRequestLine (line : List UInt8) : Except String (String × ByteArray) := do
  let some (method, afterMethod) := splitOnce line 32 | throw "invalid request line"
  let some (target, version) := splitOnce afterMethod 32 | throw "invalid request line"
  if method.isEmpty || !method.all tokenByte then throw "invalid method"
  let validUriByte := fun c : UInt8 =>
    let n := c.toNat
    (n >= 65 && n <= 90) || (n >= 97 && n <= 122) || (n >= 48 && n <= 57) ||
      [33,36,37,38,39,40,41,42,43,44,45,46,47,58,59,61,63,64,91,93,95,126].contains n
  if target.isEmpty || !target.all validUriByte || !validPercentEncoding target then
    throw "invalid request target"
  if target == [42] then
    if method != "OPTIONS".toUTF8.toList then throw "asterisk target requires OPTIONS"
  else if method == "CONNECT".toUTF8.toList then
    let port := match target with
      | 91 :: rest => match splitOnce rest 93 with
        | some (_, 58 :: port) => port
        | _ => []
      | _ => match splitOnce target 58 with | some (_, port) => port | none => []
    if !validAuthority (bytes target) || target.head! == 58 || port.isEmpty || !validPort port then
      throw "invalid CONNECT authority"
  else if target.head! == 47 then
    if target.contains 91 || target.contains 93 then throw "invalid origin request target"
  else
    let some (scheme, schemeRest) := splitOnce target 58 | throw "invalid absolute request target"
    let alpha := fun c : UInt8 =>
      (c.toNat >= 65 && c.toNat <= 90) || (c.toNat >= 97 && c.toNat <= 122)
    if scheme.isEmpty || !alpha scheme.head! || !scheme.all (fun c =>
        alpha c || (c.toNat >= 48 && c.toNat <= 57) || [43,45,46].contains c.toNat) then
      throw "invalid URI scheme"
    let schemeText := ((String.fromUTF8? (bytes scheme)).getD "").toLower
    match schemeRest with
    | 47 :: 47 :: authorityAndPath =>
      let authority := authorityAndPath.takeWhile (fun c => c != 47 && c != 63)
      let pathAndQuery := authorityAndPath.drop authority.length
      let hostPort := match splitOnce authority 64 with
        | none => authority
        | some (userInfo, host) =>
          if (schemeText == "http" || schemeText == "https") || !validUserInfo userInfo || host.contains 64 then [64] else host
      if !validAuthority (bytes hostPort) || pathAndQuery.contains 91 || pathAndQuery.contains 93 then
        throw "invalid absolute request target"
      if (schemeText == "http" || schemeText == "https") &&
          (hostPort.isEmpty || hostPort.head! == 58) then throw "empty HTTP authority"
    | _ =>
      if schemeText == "http" || schemeText == "https" ||
          schemeRest.contains 91 || schemeRest.contains 93 then
        throw "invalid absolute request target"
  if version != "HTTP/1.1".toUTF8.toList then throw "unsupported HTTP version"
  let some methodText := String.fromUTF8? (bytes method) | throw "invalid method"
  return (methodText, bytes target)

private def parseDecimal (xs : List UInt8) (bound : Nat) : Except String Nat := do
  if xs.isEmpty then throw "empty content length"
  let mut n := 0
  for c in xs do
    if c.toNat < 48 || c.toNat > 57 then throw "invalid content length"
    n := n * 10 + (c.toNat - 48)
    if n > bound then throw "body limit exceeded"
  return n

private def framing (headers : Array Header) (limits : Limits) : Except String (Option Nat) := do
  let hosts := headers.filter (fun h => h.name == "host")
  if hosts.size != 1 || !validAuthority hosts[0]!.value then throw "exactly one valid host is required"
  let cls := headers.filter (fun h => h.name == "content-length")
  let tes := headers.filter (fun h => h.name == "transfer-encoding")
  if !cls.isEmpty && !tes.isEmpty then throw "content-length with transfer-encoding"
  if cls.size > 1 then throw "duplicate content-length"
  if tes.size > 1 then throw "duplicate transfer-encoding"
  if !tes.isEmpty then
    let some coding := String.fromUTF8? tes[0]!.value | throw "invalid transfer-encoding"
    if coding.toLower != "chunked" then throw "unsupported transfer-encoding"
    return none
  if cls.isEmpty then return some 0
  return some (← parseDecimal cls[0]!.value.toList (min limits.maxBodyBytes limits.maxBodyWireBytes))

private def hexDigit (c : UInt8) : Option Nat :=
  let n := c.toNat
  if n >= 48 && n <= 57 then some (n - 48)
  else if n >= 65 && n <= 70 then some (n - 55)
  else if n >= 97 && n <= 102 then some (n - 87)
  else none

private def quotedTail : List UInt8 → Option (List UInt8)
  | [] => none
  | 34 :: rest => some rest
  | 92 :: c :: rest =>
    if c == 9 || (c.toNat >= 32 && c.toNat != 127) then quotedTail rest else none
  | 92 :: [] => none
  | c :: rest =>
    if c == 9 || (c.toNat >= 32 && c.toNat != 127) then quotedTail rest else none

private def validExtensions (input : List UInt8) : Bool := go input (input.length + 1)
where
  go (input : List UInt8) (fuel : Nat) : Bool :=
    match fuel with
    | 0 => false
    | fuel + 1 =>
      let input := input.dropWhile whitespace
      match input with
      | [] => true
      | 59 :: rest =>
        let rest := rest.dropWhile whitespace
        let name := rest.takeWhile tokenByte
        if name.isEmpty then false
        else
          let rest := (rest.drop name.length).dropWhile whitespace
          match rest with
          | 61 :: value =>
            let value := value.dropWhile whitespace
            match value with
            | 34 :: quoted =>
              match quotedTail quoted with
              | none => false
              | some tail => go tail fuel
            | _ =>
              let token := value.takeWhile tokenByte
              if token.isEmpty then false else go (value.drop token.length) fuel
          | _ => go rest fuel
      | _ => false

private def parseChunkSize (line : List UInt8) (bound : Nat) : Except String Nat := do
  -- Extensions are validated separately so they cannot alter the size grammar.
  let (size, extension) := match splitOnce line 59 with
    | some (a, b) => ((a.reverse.dropWhile whitespace).reverse, some (59 :: b))
    | none => (line, none)
  if size.isEmpty then throw "empty chunk size"
  let mut n := 0
  for c in size do
    let some digit := hexDigit c | throw "invalid chunk size"
    n := n * 16 + digit
    if n > bound then throw "body limit exceeded"
  if let some ext := extension then
    if !validExtensions ext then throw "invalid chunk extension"
  return n


private inductive Stage where
  | requestLine | headers | fixed (remaining : Nat)
  | chunkLine | chunkData (remaining : Nat) | chunkCR | chunkLF | trailers
  deriving Inhabited

/-- Incremental parser. Internal state is retained across feeds; each wire byte
    is processed once, and the body, head, chunk overhead and trailers are bounded. -/
structure Parser where
  private stage : Stage := .requestLine
  private limits : Limits := {}
  private lineRev : List UInt8 := []
  private lineBytes : Nat := 0
  private sawCR : Bool := false
  private headBytes : Nat := 0
  private trailerBytes : Nat := 0
  private wireBytes : Nat := 0
  private method : String := ""
  private target : ByteArray := ByteArray.empty
  private headers : Array Header := #[]
  private bodyBlocks : List ByteArray := []
  private bodyRev : List UInt8 := []
  private bodyBlockSize : Nat := 0
  private bodySize : Nat := 0
  private trailers : Array Header := #[]

inductive ParseResult where
  | needMore (parser : Parser)
  | complete (request : Request) (remaining : ByteArray)
  | error (message : String)
  | eof

def Parser.new (limits : Limits := {}) : Parser := { limits }

/-- Streaming variant reports the validated head once before reading a body. -/
inductive HeaderParseResult where
  | needMore (parser : Parser)
  | headers (head : RequestHead) (parser : Parser) (remaining : ByteArray)
  | complete (request : Request) (remaining : ByteArray)
  | error (message : String)

private inductive Advance where
  | more (parser : Parser)
  | headers (parser : Parser)
  | done (request : Request)
  | fail (message : String)

private def appendBody (p : Parser) (c : UInt8) : Parser :=
  let active := c :: p.bodyRev
  if p.bodyBlockSize + 1 == 4096 then
    { p with bodyBlocks := bytes active.reverse :: p.bodyBlocks,
             bodyRev := [], bodyBlockSize := 0, bodySize := p.bodySize + 1 }
  else
    { p with bodyRev := active, bodyBlockSize := p.bodyBlockSize + 1,
             bodySize := p.bodySize + 1 }

private def finishRequest (p : Parser) : Request := Id.run do
  let mut body := ByteArray.empty
  for block in p.bodyBlocks.reverse do
    body := body.append block
  body := body.append (bytes p.bodyRev.reverse)
  return { method := p.method, target := p.target, headers := p.headers,
           body := body, trailers := p.trailers }

private def handleLine (p : Parser) (line : List UInt8) : Advance :=
  let p := { p with lineRev := [], lineBytes := 0, sawCR := false }
  match p.stage with
  | .requestLine =>
    match parseRequestLine line with
    | .error e => .fail e
    | .ok (method, target) => .more { p with method := method, target := target, stage := .headers }
  | .headers =>
    if line.isEmpty then
      match framing p.headers p.limits with
      | .error e => .fail e
      | .ok (some 0) => .done (finishRequest p)
      | .ok (some n) => .headers { p with stage := .fixed n }
      | .ok none => .headers { p with stage := .chunkLine }
    else if p.headers.size >= p.limits.maxHeaderCount then .fail "too many headers"
    else match parseHeader line with
      | .error e => .fail e
      | .ok h => .more { p with headers := p.headers.push h }
  | .chunkLine =>
    match parseChunkSize line (p.limits.maxBodyBytes - p.bodySize) with
    | .error e => .fail e
    | .ok 0 => .more { p with stage := .trailers }
    | .ok n => .more { p with stage := .chunkData n }
  | .trailers =>
    if line.isEmpty then .done (finishRequest p)
    else if p.trailers.size >= p.limits.maxTrailerCount then .fail "too many trailers"
    else match parseHeader line with
      | .error e => .fail e
      | .ok h =>
        if ["content-length", "transfer-encoding", "host", "trailer"].contains h.name then
          .fail "forbidden trailer"
        else .more { p with trailers := p.trailers.push h }
  | _ => .fail "internal parser state"

private def advanceLine (p : Parser) (c : UInt8) : Advance :=
  let p := { p with lineBytes := p.lineBytes + 1 }
  let lineLimit := match p.stage with
    | .chunkLine => p.limits.maxChunkLineBytes
    | .trailers => p.limits.maxTrailerBytes
    | _ => p.limits.maxHeaderBytes
  if p.lineBytes > lineLimit then .fail "line limit exceeded"
  else if p.sawCR then
    if c != 10 then .fail "bare CR in line"
    else handleLine p p.lineRev.reverse
  else if c == 13 then .more { p with sawCR := true }
  else if c == 10 then .fail "bare LF in line"
  else .more { p with lineRev := c :: p.lineRev }

private def advance (p : Parser) (c : UInt8) : Advance :=
  let isHead := match p.stage with | .requestLine | .headers => true | _ => false
  let isTrailer := match p.stage with | .trailers => true | _ => false
  let isChunkWire := match p.stage with
    | .chunkLine | .chunkData _ | .chunkCR | .chunkLF | .trailers => true
    | _ => false
  let p := { p with
    headBytes := p.headBytes + if isHead then 1 else 0
    trailerBytes := p.trailerBytes + if isTrailer then 1 else 0
    wireBytes := p.wireBytes + if isChunkWire then 1 else 0 }
  if p.headBytes > p.limits.maxHeaderBytes then .fail "header limit exceeded"
  else if p.trailerBytes > p.limits.maxTrailerBytes then .fail "trailer limit exceeded"
  else if p.wireBytes > p.limits.maxBodyWireBytes then .fail "chunk wire limit exceeded"
  else match p.stage with
    | .requestLine | .headers | .chunkLine | .trailers => advanceLine p c
    | .fixed n =>
      let p := appendBody p c
      if n <= 1 then .done (finishRequest p)
      else .more { p with stage := .fixed (n - 1) }
    | .chunkData n =>
      let p := appendBody p c
      if n <= 1 then .more { p with stage := .chunkCR }
      else .more { p with stage := .chunkData (n - 1) }
    | .chunkCR => if c == 13 then .more { p with stage := .chunkLF } else .fail "missing chunk terminator"
    | .chunkLF => if c == 10 then .more { p with stage := .chunkLine } else .fail "missing chunk terminator"

/-- Feed wire bytes exactly once. Unconsumed bytes are returned for pipelining. -/
def Parser.feed (parser : Parser) (input : ByteArray) : ParseResult :=
  go parser 0 input.size
where
  go (p : Parser) (index remaining : Nat) : ParseResult :=
    match remaining with
    | 0 => .needMore p
    | n + 1 =>
      match advance p input[index]! with
      | .more next | .headers next => go next (index + 1) n
      | .fail message => .error message
      | .done request => .complete request (input.extract (index + 1) input.size)

/-- Like `feed`, but yields once immediately after a body-bearing head. The
    caller can handle `Expect: 100-continue` before reading the request body.
    Resume the returned parser with the returned, unconsumed bytes. -/
def Parser.feedWithHeaders (parser : Parser) (input : ByteArray) : HeaderParseResult :=
  go parser 0 input.size
where
  go (p : Parser) (index remaining : Nat) : HeaderParseResult :=
    match remaining with
    | 0 => .needMore p
    | n + 1 =>
      match advance p input[index]! with
      | .more next => go next (index + 1) n
      | .headers next =>
        let head : RequestHead := { method := next.method, target := next.target, headers := next.headers }
        .headers head next (input.extract (index + 1) input.size)
      | .fail message => .error message
      | .done request => .complete request (input.extract (index + 1) input.size)

/-- EOF before a complete message is an error, including a partial chunk. -/
def Parser.finish (parser : Parser) : ParseResult :=
  match parser.stage with
  | .requestLine =>
    if parser.headBytes == 0 then .eof else .error "unexpected EOF in request"
  | _ => .error "unexpected EOF in request"

end LeanNet.HTTP1
