import LeanNet.HTTP1.Protocol

namespace LeanNet.HTTP1

private def bytes (xs : List UInt8) : ByteArray := ByteArray.mk xs.toArray
private def tokenByte (b : UInt8) : Bool :=
  let n := b.toNat
  (n >= 48 && n <= 57) || (n >= 65 && n <= 90) || (n >= 97 && n <= 122) ||
    [33, 35, 36, 37, 38, 39, 42, 43, 45, 46, 94, 95, 96, 124, 126].contains n
private def whitespace (b : UInt8) : Bool := b == 32 || b == 9

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

private def isHex (c : UInt8) : Bool :=
  (c.toNat >= 48 && c.toNat <= 57) || (c.toNat >= 65 && c.toNat <= 70) ||
    (c.toNat >= 97 && c.toNat <= 102)

private def allSpan (input : ByteArray) (start stop : Nat) (test : UInt8 → Bool) : Bool := Id.run do
  for i in [start:stop] do
    if !test input[i]! then return false
  return true

private def findByte (input : ByteArray) (start stop : Nat) (test : UInt8 → Bool) : Nat := Id.run do
  for i in [start:stop] do
    if test input[i]! then return i
  return stop

private def trimSpan (input : ByteArray) (start stop : Nat) : Nat × Nat := Id.run do
  let left := findByte input start stop (!whitespace ·)
  let mut right := stop
  for delta in [:stop - left] do
    let i := stop - 1 - delta
    if !whitespace input[i]! then
      right := i + 1
      break
  return (left, if left == stop then stop else right)

private def percentSpan (input : ByteArray) (start stop : Nat) : Bool := Id.run do
  for i in [start:stop] do
    if input[i]! == 37 && (i + 2 >= stop || !isHex input[i + 1]! || !isHex input[i + 2]!) then
      return false
  return true

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

private def complexAuthority (value : ByteArray) : Bool :=
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

/-- Preserve generic URI authority grammar; HTTP routing applies any required
    nonempty-host constraint separately. Ordinary hostnames scan wire bytes. -/
def validAuthority (value : ByteArray) : Bool :=
  if !value.isEmpty && value[0]! == 91 then complexAuthority value
  else
    let colon := findByte value 0 value.size (· == 58)
    let regNameByte := fun c : UInt8 =>
      let n := c.toNat
      (n >= 65 && n <= 90) || (n >= 97 && n <= 122) || (n >= 48 && n <= 57) ||
        [33,36,37,38,39,40,41,42,43,44,45,46,59,61,95,126].contains n
    allSpan value 0 colon regNameByte && percentSpan value 0 colon &&
      (colon == value.size || allSpan value (colon + 1) value.size (fun c => c >= 48 && c <= 57))

private def validUserInfo (value : List UInt8) : Bool :=
  value.all (fun c =>
    let n := c.toNat
    (n >= 65 && n <= 90) || (n >= 97 && n <= 122) || (n >= 48 && n <= 57) ||
      [33,36,37,38,39,40,41,42,43,44,45,46,58,59,61,95,126].contains n)

private def parseRequestLine (line : List UInt8) : Except String (String × ByteArray × String) := do
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
  let digit := fun (c : UInt8) => c >= 48 && c <= 57
  match version with
  | [72, 84, 84, 80, 47, major, 46, minor] =>
    if !digit major || !digit minor then throw "invalid HTTP version"
    if major != 49 then throw "unsupported HTTP version"
  | _ => throw "invalid HTTP version"
  let some methodText := String.fromUTF8? (bytes method) | throw "invalid method"
  return (methodText, bytes target, if version == "HTTP/1.0".toUTF8.toList then "HTTP/1.0" else "HTTP/1.1")

private def hexDigit (c : UInt8) : Option Nat :=
  let n := c.toNat
  if n >= 48 && n <= 57 then some (n - 48)
  else if n >= 65 && n <= 70 then some (n - 55)
  else if n >= 97 && n <= 102 then some (n - 87)
  else none

private def quotedEnd (input : ByteArray) (start stop : Nat) : Option Nat :=
  go start (stop - start + 1)
where
  go (index fuel : Nat) : Option Nat :=
    match fuel with
    | 0 => none
    | fuel + 1 =>
      if index >= stop then none
      else
        let c := input[index]!
        if c == 34 then some (index + 1)
        else if c == 92 then
          if index + 1 >= stop then none
          else
            let escaped := input[index + 1]!
            if escaped == 9 || (escaped >= 32 && escaped != 127) then go (index + 2) fuel else none
        else if c == 9 || (c >= 32 && c != 127) then go (index + 1) fuel else none

private def extensionsSpan (input : ByteArray) (start stop : Nat) : Bool :=
  go start (stop - start + 1)
where
  go (index fuel : Nat) : Bool :=
    match fuel with
    | 0 => false
    | fuel + 1 =>
      let index := findByte input index stop (!whitespace ·)
      if index == stop then true
      else if input[index]! != 59 then false
      else
        let nameStart := findByte input (index + 1) stop (!whitespace ·)
        let nameEnd := findByte input nameStart stop (!tokenByte ·)
        if nameEnd == nameStart then false
        else
          let tail := findByte input nameEnd stop (!whitespace ·)
          if tail < stop && input[tail]! == 61 then
            let valueStart := findByte input (tail + 1) stop (!whitespace ·)
            if valueStart == stop then false
            else if input[valueStart]! == 34 then
              match quotedEnd input (valueStart + 1) stop with
              | none => false
              | some next => go next fuel
            else
              let valueEnd := findByte input valueStart stop (!tokenByte ·)
              valueEnd != valueStart && go valueEnd fuel
          else go tail fuel

private def parseChunkSizeSpan (input : ByteArray) (start stop bound : Nat) : Except String Nat := do
  let semicolon := findByte input start stop (· == 59)
  let sizeEnd := if semicolon < stop then (trimSpan input start semicolon).2 else stop
  if sizeEnd == start then throw "empty chunk size"
  let mut size := 0
  for index in [start:sizeEnd] do
    let some digit := hexDigit input[index]! | throw "invalid chunk size"
    size := size * 16 + digit
    if size > bound then throw "body limit exceeded"
  if semicolon < stop && !extensionsSpan input semicolon stop then throw "invalid chunk extension"
  return size

private def parseHeaderSpan (input : ByteArray) (start stop : Nat) : Except String Header := do
  let colon := findByte input start stop (· == 58)
  if colon == start || colon == stop || !allSpan input start colon tokenByte then throw "invalid header name"
  if !allSpan input (colon + 1) stop (fun c => c == 9 || (c.toNat >= 32 && c != 127)) then
    throw "invalid header value"
  let mut name := ByteArray.emptyWithCapacity (colon - start)
  for i in [start:colon] do
    let c := input[i]!
    name := name.push (if c >= 65 && c <= 90 then c + 32 else c)
  let some nameText := String.fromUTF8? name | throw "invalid header name"
  let (left, right) := trimSpan input (colon + 1) stop
  return { name := nameText, value := input.extract left right }

private def spanAscii (input : ByteArray) (start stop : Nat) (text : String) : Bool :=
  let expected := text.toUTF8
  stop - start == expected.size && Id.run do
    for i in [:expected.size] do
      if input[start + i]! != expected[i]! then return false
    return true

/-- Common origin/asterisk targets scan their original input directly. Complex
    absolute/CONNECT forms retain the established authority grammar. -/
private def requestLineSpan (input : ByteArray) (start stop : Nat) : Except String (String × ByteArray × String) := do
  let first := findByte input start stop (· == 32)
  let second := findByte input (first + 1) stop (· == 32)
  if first == start || first == stop || second == first + 1 || second == stop ||
      !allSpan input start first tokenByte then throw "invalid request line"
  let version := if spanAscii input (second + 1) stop "HTTP/1.1" then "HTTP/1.1"
    else if spanAscii input (second + 1) stop "HTTP/1.0" then "HTTP/1.0" else ""
  let version ← if !version.isEmpty then pure version else
    -- RFC 9112 §2.3: HTTP-version = "HTTP/" DIGIT "." DIGIT. A higher 1.x
    -- minor is served as HTTP/1.1; another major version receives 505.
    let digit := fun (c : UInt8) => c >= 48 && c <= 57
    let vs := second + 1
    if stop - vs == 8 && spanAscii input vs (vs + 5) "HTTP/" && digit input[vs + 5]! &&
        input[vs + 6]! == 46 && digit input[vs + 7]! then
      if input[vs + 5]! == 49 then pure "HTTP/1.1" else throw "unsupported HTTP version"
    else throw "invalid HTTP version"
  let some method := String.fromUTF8? (input.extract start first) | throw "invalid method"
  if method == "CONNECT" || (input[first + 1]! != 47 && input[first + 1]! != 42) then
    return ← parseRequestLine (input.extract start stop).toList
  let targetStart := first + 1
  if input[targetStart]! == 42 then
    if second != targetStart + 1 || method != "OPTIONS" then throw "invalid asterisk target"
  else
    let valid := fun c : UInt8 =>
      let n := c.toNat
      (n >= 65 && n <= 90) || (n >= 97 && n <= 122) || (n >= 48 && n <= 57) ||
        [33,36,37,38,39,40,41,42,43,44,45,46,47,58,59,61,63,64,95,126].contains n
    if !allSpan input targetStart second valid || !percentSpan input targetStart second then
      throw "invalid request target"
  return (method, input.extract targetStart second, version)

private def asciiLowerBytes (bytes : ByteArray) : ByteArray :=
  ⟨bytes.data.map fun c => if c >= 65 && c <= 90 then c + 32 else c⟩

private def expectsContinue (version : String) (headers : Array Header) : Bool :=
  version == "HTTP/1.1" && headers.any fun header =>
    header.name == "expect" && asciiLowerBytes header.value == "100-continue".toUTF8

/-- RFC 9110/9112 status for a request the parser rejected. Every rejection
    still closes the connection: the remaining bytes are never reinterpreted. -/
def Parser.errorStatus (message : String) : Nat :=
  match message with
  | "body limit exceeded" | "body wire limit exceeded" => 413
  | "expectation body limit exceeded" => 417
  | "request line limit exceeded" => 414
  | "header limit exceeded" | "trailer limit exceeded" | "too many headers" | "too many trailers" => 431
  | "unsupported transfer-encoding" => 501
  | "unsupported HTTP version" => 505
  | _ => 400

private def inferFraming (version : String) (headers : Array Header) (limits : Limits) : Except String BodyFraming := do
  let hosts := headers.filter (·.name == "host")
  if (version == "HTTP/1.1" && hosts.size != 1) || hosts.size > 1 ||
      hosts.any (fun h => !validAuthority h.value) then throw "exactly one valid host is required"
  let cls := headers.filter (·.name == "content-length")
  let tes := headers.filter (·.name == "transfer-encoding")
  if !cls.isEmpty && !tes.isEmpty then throw "content-length with transfer-encoding"
  if cls.size > 1 then throw "duplicate content-length"
  if tes.size > 1 then throw "duplicate transfer-encoding"
  if !tes.isEmpty then
    if version != "HTTP/1.1" then throw "transfer-encoding requires HTTP/1.1"
    let coding := tes[0]!.value
    if coding.size != 7 || !(Id.run do
      for i in [:7] do
        let c := coding[i]!
        if (if c >= 65 && c <= 90 then c + 32 else c) != ("chunked".toUTF8)[i]! then return false
      return true) then throw "unsupported transfer-encoding"
    return .chunked
  if cls.isEmpty then return .none
  let value := cls[0]!.value
  if value.isEmpty then throw "empty content length"
  let mut n := 0
  for c in value do
    if c < 48 || c > 57 then throw "invalid content length"
    n := n * 10 + c.toNat - 48
    if n > min limits.maxBodyBytes limits.maxBodyWireBytes then
      -- RFC 9110 §10.1.1: a client awaiting 100 Continue learns of the
      -- refusal with 417 before it transmits the body.
      throw (if expectsContinue version headers then "expectation body limit exceeded" else "body limit exceeded")
  return .contentLength n

private inductive Stage where
  | requestLine | headers | paused | done | fixed (remaining : Nat) | untilEof
  | chunkLine | chunkData (remaining : Nat) | chunkCR | chunkLF | trailers
  deriving Inhabited

structure Parser.Options where
  allowObsFold : Bool := false
  deriving Repr, Inhabited

/-- Owned partial lines and bounded body blocks allow the caller to release
    each reactor buffer after a feed, even with a pool smaller than a request. -/
structure Parser where
  private stage : Stage := .requestLine
  private limits : Limits := {}
  private options : Parser.Options := {}
  private line : ByteArray := ByteArray.empty
  private lineBytes : Nat := 0
  private sawCR : Bool := false
  private headBytes : Nat := 0
  private trailerBytes : Nat := 0
  private wireBytes : Nat := 0
  private method : String := ""
  private version : String := "HTTP/1.1"
  private target : ByteArray := ByteArray.empty
  private headers : Array Header := #[]
  private framing : BodyFraming := .none
  private body : ByteArray := ByteArray.empty
  private bodyBlocks : List ByteArray := []
  private bodySize : Nat := 0
  private trailers : Array Header := #[]

inductive ParseResult where
  | needMore (parser : Parser)
  | complete (request : Request) (remaining : ByteArray)
  | error (message : String)
  | eof

inductive HeaderParseResult where
  | needMore (parser : Parser)
  | headers (head : RequestHead) (parser : Parser) (remaining : ByteArray)
  | complete (request : Request) (remaining : ByteArray)
  | error (message : String)

/-- `consumed` is relative to the input window, including line terminators.
    A head pauses before every body, including a bodyless message. -/
inductive Parser.Progress where
  | needMore (parser : Parser) (consumed : Nat)
  | head (head : RequestHead) (framing : BodyFraming) (parser : Parser) (consumed : Nat)
  | complete (request : Request) (consumed : Nat)
  | error (message : String) (consumed : Nat)

def Parser.new (limits : Limits := {}) (options : Parser.Options := {}) : Parser := { limits, options }

private def finishRequest (p : Parser) : Request :=
  let body := if p.bodyBlocks.isEmpty then p.body else Id.run do
    let mut body := ByteArray.emptyWithCapacity p.bodySize
    for block in p.bodyBlocks.reverse do body := body.append block
    return body.append p.body
  { method := p.method, version := p.version, target := p.target,
    headers := p.headers, body, trailers := p.trailers }

/-- Tighten the decoded body bound for the paused request (never loosens). -/
def Parser.limitBody (p : Parser) (limit : Nat) : Parser :=
  { p with limits := { p.limits with maxBodyBytes := min p.limits.maxBodyBytes limit } }

/-- Only an unframed HTTP/1.0 head may opt into the explicit EOF-body extension. -/
def Parser.resumeBody (p : Parser) (chosen : BodyFraming) : Except String Parser := do
  if !(match p.stage with | .paused => true | _ => false) then throw "parser is not paused at a head"
  if chosen != p.framing && !(chosen == .closeDelimited && p.framing == .none && p.version == "HTTP/1.0") then
    throw "body framing decision disagrees with request headers"
  let stage := match chosen with
    | .none | .contentLength 0 => Stage.done
    | .contentLength n => .fixed n
    | .chunked => .chunkLine
    | .closeDelimited => .untilEof
  return { p with stage, framing := chosen }

private inductive Step where
  | more (parser : Parser) (consumed : Nat)
  | inputEnd (parser : Parser) (consumed : Nat)
  | head (head : RequestHead) (framing : BodyFraming) (parser : Parser) (consumed : Nat)
  | done (request : Request) (consumed : Nat)
  | fail (message : String) (consumed : Nat)

private def charge (p : Parser) (count : Nat) : Except String Parser := do
  let isHead := match p.stage with | .requestLine | .headers => true | _ => false
  let isTrailer := match p.stage with | .trailers => true | _ => false
  let isBody := !isHead
  let p := { p with
    headBytes := p.headBytes + (if isHead then count else 0)
    trailerBytes := p.trailerBytes + (if isTrailer then count else 0)
    wireBytes := p.wireBytes + (if isBody then count else 0) }
  if p.headBytes > p.limits.maxHeaderBytes then
    throw (match p.stage with | .requestLine => "request line limit exceeded" | _ => "header limit exceeded")
  if p.trailerBytes > p.limits.maxTrailerBytes then throw "trailer limit exceeded"
  if p.wireBytes > p.limits.maxBodyWireBytes then throw "body wire limit exceeded"
  return p

private def appendField (p : Parser) (input : ByteArray) (start stop : Nat) (trailer : Bool) : Except String Parser := do
  let fields := if trailer then p.trailers else p.headers
  let maximum := if trailer then p.limits.maxTrailerCount else p.limits.maxHeaderCount
  if whitespace input[start]! then
    if !p.options.allowObsFold || fields.isEmpty then throw "obsolete or orphan header folding"
    if !allSpan input start stop (fun c => c == 9 || (c.toNat >= 32 && c != 127)) then throw "invalid header value"
    let (left, right) := trimSpan input start stop
    let prior := fields.back!
    let value := input.extract left right
    let combined := if value.isEmpty then prior.value else if prior.value.isEmpty then value
      else (prior.value.push 32).append value
    let fields := fields.set! (fields.size - 1) { prior with value := combined }
    return if trailer then { p with trailers := fields } else { p with headers := fields }
  if fields.size >= maximum then throw (if trailer then "too many trailers" else "too many headers")
  let field ← parseHeaderSpan input start stop
  if trailer then
    if forbiddenTrailerName field.name then throw "forbidden trailer"
    match connectionTokens p.headers with
    | .error _ => throw "invalid Connection options before trailers"
    | .ok names => if names.contains field.name then throw "connection-nominated trailer"
  let fields := fields.push field
  return if trailer then { p with trailers := fields } else { p with headers := fields }

private def handleLine (p : Parser) (input : ByteArray) (start stop count : Nat) : Step :=
  let p := { p with line := ByteArray.empty, lineBytes := 0, sawCR := false }
  match p.stage with
  | .requestLine => match requestLineSpan input start stop with
    | .error e => .fail e count
    | .ok (method, target, version) => .more { p with method, target, version, stage := .headers } count
  | .headers =>
    if start == stop then
      match inferFraming p.version p.headers p.limits with
      | .error e => .fail e count
      | .ok framing =>
        let p := { p with stage := .paused, framing }
        .head { method := p.method, version := p.version, target := p.target, headers := p.headers } framing p count
    else match appendField p input start stop false with
      | .error e => .fail e count
      | .ok p => .more p count
  | .chunkLine => match parseChunkSizeSpan input start stop (p.limits.maxBodyBytes - p.bodySize) with
    | .error e => .fail e count
    | .ok 0 => .more { p with stage := .trailers } count
    | .ok n => .more { p with stage := .chunkData n } count
  | .trailers =>
    if start == stop then .done (finishRequest p) count
    else match appendField p input start stop true with
      | .error e => .fail e count
      | .ok p => .more p count
  | _ => .fail "internal parser line state" count

private def lineStep (p : Parser) (input : ByteArray) (start available : Nat) : Step := Id.run do
  let stop := start + available
  let newline := if p.sawCR then start else findByte input start stop (fun c => c == 13 || c == 10)
  let complete := p.sawCR || (newline < stop && newline + 1 < stop)
  let count := if p.sawCR then 1 else if complete then newline - start + 2 else available
  if p.sawCR && input[start]! != 10 then return .fail "bare CR in line" 1
  if !p.sawCR && newline < stop && input[newline]! == 10 then return .fail "bare LF in line" (newline - start + 1)
  if !p.sawCR && complete && input[newline + 1]! != 10 then return .fail "bare CR in line" (newline - start + 2)
  let p ← match charge p count with | .ok p => pure p | .error e => return .fail e count
  let lineLimit := match p.stage with
    | .chunkLine => p.limits.maxChunkLineBytes
    | .trailers => p.limits.maxTrailerBytes
    | _ => p.limits.maxHeaderBytes
  if p.lineBytes + count > lineLimit then
    return .fail (match p.stage with
      | .requestLine => "request line limit exceeded"
      | .chunkLine => "chunk line limit exceeded"
      | .trailers => "trailer limit exceeded"
      | _ => "header limit exceeded") count
  let contentStop := if newline < stop then newline else stop
  if complete then
    if p.sawCR then return handleLine p p.line 0 p.line.size count
    else if p.line.isEmpty then return handleLine p input start contentStop count
    else
      let line := input.copySlice start p.line p.line.size (contentStop - start) false
      return handleLine p line 0 line.size count
  else
    let line := input.copySlice start p.line p.line.size (contentStop - start) false
    return .inputEnd { p with line, lineBytes := p.lineBytes + count, sawCR := newline < stop } count

/-- Copy input spans in bulk into bounded blocks. Keeping an old immutable
    parser caps copy-on-write work at one block instead of the entire body. -/
private def appendBodySpans (input : ByteArray) (start count : Nat)
    (initialBlocks : List ByteArray) (initial : ByteArray) : List ByteArray × ByteArray := Id.run do
  let mut blocks := initialBlocks
  let mut active := initial
  let mut cursor := start
  let mut remaining := count
  for _ in [:count / 4096 + 2] do
    if remaining == 0 then break
    let amount := min remaining (4096 - active.size)
    active := input.copySlice cursor active active.size amount false
    cursor := cursor + amount
    remaining := remaining - amount
    if active.size == 4096 then
      blocks := active :: blocks
      active := ByteArray.empty
  return (blocks, active)

private def bodyStep (p : Parser) (input : ByteArray) (start count : Nat) : Except String Parser := do
  if p.bodySize + count > p.limits.maxBodyBytes then throw "body limit exceeded"
  let p ← charge p count
  let (bodyBlocks, body) := appendBodySpans input start count p.bodyBlocks p.body
  return { p with body, bodyBlocks, bodySize := p.bodySize + count }

/-- Scan an input window without allocating or copying its unconsumed suffix.
    The caller must resume the paused head before supplying any body bytes. -/
def Parser.feedSlice (parser : Parser) (input : ByteArray) (start length : Nat) : Parser.Progress :=
  if start > input.size || length > input.size - start then .error "invalid parser input slice" 0
  else go parser start length (length + 1)
where
  go (p : Parser) (index remaining fuel : Nat) : Parser.Progress :=
    match p.stage with
    | .paused => .error "body framing decision required" (index - start)
    | .done => .complete (finishRequest p) (index - start)
    | _ => match fuel with
      | 0 => .error "internal parser progress limit" (index - start)
      | fuel + 1 =>
        if remaining == 0 then .needMore p (index - start)
        else
          let step := match p.stage with
            | .requestLine | .headers | .chunkLine | .trailers => lineStep p input index remaining
            | .fixed n | .chunkData n =>
              let count := min n remaining
              if count == 0 then .fail "internal zero-length body stage" 0
              else match bodyStep p input index count with
                | .error e => .fail e count
                | .ok p => match p.stage with
                  | .fixed _ => if n == count then .done (finishRequest p) count else .more { p with stage := .fixed (n - count) } count
                  | _ => .more { p with stage := if n == count then .chunkCR else .chunkData (n - count) } count
            | .untilEof => match bodyStep p input index remaining with
              | .error e => .fail e remaining
              | .ok p => .inputEnd p remaining
            | .chunkCR | .chunkLF => match charge p 1 with
              | .error e => .fail e 1
              | .ok p => match p.stage with
                | .chunkCR => if input[index]! == 13 then .more { p with stage := .chunkLF } 1 else .fail "missing chunk terminator" 1
                | _ => if input[index]! == 10 then .more { p with stage := .chunkLine } 1 else .fail "missing chunk terminator" 1
            | _ => .fail "internal parser state" 0
          match step with
          | .more next count => go next (index + count) (remaining - count) fuel
          | .inputEnd next count => .needMore next (index + count - start)
          | .head head framing next count => .head head framing next (index + count - start)
          | .done request count => .complete request (index + count - start)
          | .fail message count => .error message (index + count - start)

private def automaticBody (parser : Parser) (framing : BodyFraming) (input : ByteArray) (start : Nat) : Parser.Progress :=
  match parser.resumeBody framing with
  | .error e => .error e start
  | .ok parser => match parser.feedSlice input start (input.size - start) with
    | .needMore next n => .needMore next (start + n)
    | .complete request n => .complete request (start + n)
    | .error e n => .error e (start + n)
    | .head _ _ _ n => .error "duplicate parser head" (start + n)

/-- Compatible complete-message interface; the explicit head decision is made
    automatically using ordinary HTTP request framing. -/
def Parser.feed (parser : Parser) (input : ByteArray) : ParseResult :=
  let result := match parser.feedSlice input 0 input.size with
    | .head _ framing next consumed => automaticBody next framing input consumed
    | result => result
  match result with
  | .needMore next _ => .needMore next
  | .complete request consumed => .complete request (input.extract consumed input.size)
  | .error message _ => .error message
  | .head .. => .error "internal duplicate parser head"

/-- Compatibility interface yields body-bearing heads only, as before. -/
def Parser.feedWithHeaders (parser : Parser) (input : ByteArray) : HeaderParseResult :=
  match parser.feedSlice input 0 input.size with
  | .head head framing next consumed =>
    match next.resumeBody framing with
    | .error e => .error e
    | .ok next =>
      let bodyBearing := match framing with | .chunked | .closeDelimited => true | .contentLength n => n > 0 | .none => false
      if bodyBearing then .headers head next (input.extract consumed input.size)
      else match next.feedSlice input consumed (input.size - consumed) with
        | .complete request used => .complete request (input.extract (consumed + used) input.size)
        | .needMore next _ => .needMore next
        | .error message _ => .error message
        | .head .. => .error "internal duplicate parser head"
  | .needMore next _ => .needMore next
  | .complete request used => .complete request (input.extract used input.size)
  | .error message _ => .error message

/-- Only explicit close-delimited mode completes at EOF. All incomplete framed
    bodies and partial request heads remain truncation errors. -/
def Parser.finish (parser : Parser) : ParseResult :=
  match parser.stage with
  | .untilEof | .done => .complete (finishRequest parser) ByteArray.empty
  | .requestLine => if parser.headBytes == 0 then .eof else .error "unexpected EOF in request"
  | .paused => .error "body framing decision required"
  | _ => .error "unexpected EOF in request"

end LeanNet.HTTP1
