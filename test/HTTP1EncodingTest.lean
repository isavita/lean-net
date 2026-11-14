import LeanNet.HTTP1.Encoding

open LeanNet.HTTP1

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do throw (IO.userError message)

private def field (name value : String) : Header := { name, value := value.toUTF8 }
private def flatten (encoded : EncodedResponse) : ByteArray :=
  encoded.parts.foldl ByteArray.append ByteArray.empty

private def encode (response : Response) (context : EncodeContext := {})
    (options : ResponseOptions := {}) : IO EncodedResponse := do
  match response.encodeFor context options with
  | .ok result => return result
  | .error message => throw (IO.userError s!"unexpected encoding failure: {message}")

private def wire (label : String) (response : Response) (context : EncodeContext)
    (options : ResponseOptions) (expected : ByteArray)
    (next : ResponseNext := .nextRequest .keepAlive) : IO Unit := do
  let encoded ← encode response context options
  check (flatten encoded == expected) s!"{label}: incorrect bytes"
  check (encoded.next == next) s!"{label}: incorrect next action"

private def rejected (label : String) (response : Response) (context : EncodeContext := {})
    (options : ResponseOptions := {}) : IO Unit := do
  match response.encodeFor context options with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError s!"{label}: invalid response was accepted")

private def rejectUpgrade (label : String) (response : Response) (context : EncodeContext)
    (options : ResponseOptions := {}) : IO Unit := do
  match response.encodeAcceptedUpgrade context options with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError s!"{label}: invalid upgrade was accepted")

private def crlfAt? (bytes : ByteArray) (start : Nat) : Option Nat := Id.run do
  for i in [start:bytes.size] do
    if i + 1 < bytes.size && bytes[i]! == 13 && bytes[i + 1]! == 10 then return some i
  return none

/-- Independent test-only decoder validates chunk boundaries and the terminal
    zero chunk for arbitrary binary bodies; it does not call encoder helpers. -/
private def decodeChunks (bytes : ByteArray) : Except String ByteArray := do
  let mut position := 0
  let mut result := ByteArray.empty
  for _ in [:bytes.size + 1] do
    let some finish := crlfAt? bytes position | throw "missing chunk line"
    if finish == position then throw "empty chunk size"
    let mut length := 0
    for i in [position:finish] do
      let c := bytes[i]!.toNat
      let digit ← if c >= 48 && c <= 57 then pure (c - 48)
        else if c >= 65 && c <= 70 then pure (c - 55)
        else if c >= 97 && c <= 102 then pure (c - 87)
        else throw "invalid chunk size"
      length := length * 16 + digit
    position := finish + 2
    if length == 0 then
      if position + 2 != bytes.size || bytes.extract position bytes.size != "\r\n".toUTF8 then
        throw "invalid terminal chunk"
      return result
    if position + length + 2 > bytes.size then throw "truncated chunk"
    result := result.append (bytes.extract position (position + length))
    position := position + length
    if bytes.extract position (position + 2) != "\r\n".toUTF8 then throw "missing chunk terminator"
    position := position + 2
  throw "missing final chunk"

private def protocolTests : IO Unit := do
  check (Version.parse? "HTTP/1.0" == some .http10 && Version.parse? "HTTP/1.1" == some .http11) "parse supported versions"
  for bad in ["HTTP/0.9", "HTTP/1.2", "HTTP/2", "http/1.1", "HTTP/1.1 "] do
    check ((Version.parse? bad).isNone) s!"reject version {bad}"
  check (Version.http10.wire == "HTTP/1.0" && Version.http11.wire == "HTTP/1.1") "version wire strings"
  let keep := #[field "cOnNeCtIoN" " \tKeEp-AlIvE\t "]
  let close := #[field "Connection" "keep-alive, ClOsE"]
  let repeated := #[field "Connection" "Keep-Alive", field "connection" "close"]
  check (connAction .http11 #[] (.contentLength 4) == .keepAlive) "HTTP/1.1 default persistence"
  check (connAction .http11 #[] .none == .keepAlive) "HTTP/1.1 bodyless persistence"
  check (connAction .http11 #[] .chunked == .keepAlive) "HTTP/1.1 chunked persistence"
  check (connAction .http10 #[] (.contentLength 4) == .close) "HTTP/1.0 default closure"
  check (connAction .http10 keep (.contentLength 4) == .keepAlive) "HTTP/1.0 explicit persistence"
  check (connAction .http10 keep .none == .close && connAction .http10 keep .chunked == .close) "HTTP/1.0 persistence requires explicit legal length"
  for version in [Version.http10, .http11] do
    for framing in [BodyFraming.none, .contentLength 0, .contentLength 10, .chunked, .closeDelimited] do
      check (connAction version close framing == .close && connAction version repeated framing == .close) "close token wins"
    check (connAction version keep .closeDelimited == .close) "close framing wins"
  for value in ["", "keep-alive,", ",keep-alive", "keep-alive,,upgrade", "\"close\"", "keep alive", "close;foo"] do
    check (connAction .http11 #[field "Connection" value] (.contentLength 1) == .close) "malformed Connection closes"
  check (connAction .http11 #[field "Connection" "something"] (.contentLength 1) == .keepAlive) "extension token preserves default"

private def framingTests : IO Unit := do
  let binary := ByteArray.mk #[0, 255, 13, 10]
  let response := Response.mk 200 #[field "Content-Type" "application/octet-stream"] binary
  let header := "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n\r\n".toUTF8
  wire "fixed binary" response {} {} (header.append binary)
  let segmented ← encode response
  check (segmented.parts.size == 2 && segmented.parts[1]! == binary) "fixed body remains a separate shallow segment"
  check (segmented.framing == .contentLength 4) "fixed framing metadata"
  wire "HEAD" response { requestMethod := "HEAD" } {} header
  wire "HEAD external representation length" {} { requestMethod := "HEAD" }
    { framing := some (.contentLength 12345) } "HTTP/1.1 200 OK\r\nContent-Length: 12345\r\n\r\n".toUTF8
  wire "HTTP/1.0 default" { body := "ok".toUTF8 } { version := .http10 } {}
    "HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".toUTF8 (.nextRequest .close)
  wire "HTTP/1.0 persistent" { body := "ok".toUTF8 }
    { version := .http10, requestHeaders := #[field "Connection" "Keep-Alive"] } {}
    "HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok".toUTF8
  for version in [Version.http10, .http11] do
    let expected := (((version.wire.toUTF8.append " 200 OK\r\nConnection: close\r\n\r\n".toUTF8).append binary))
    wire "close-delimited" { body := binary } { version } { framing := some .closeDelimited }
      expected (.nextRequest .close)
  wire "force close" { body := "ok".toUTF8 } {} { forceClose := true }
    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".toUTF8 (.nextRequest .close)
  rejected "length mismatch" response {} { framing := some (.contentLength 3) }
  rejected "bodyless ordinary response" {} {} { framing := some .none }
  rejected "HTTP/1.0 chunked" response { version := .http10 } { framing := some .chunked }
  rejected "HEAD chunked" response { requestMethod := "HEAD" } { framing := some .chunked }
  rejected "HEAD close" response { requestMethod := "HEAD" } { framing := some .closeDelimited }
  rejected "CONNECT success" {} { requestMethod := "CONNECT" }
  for length in [0, 1, 2, 15, 16, 255, 256, 4095, 4096, 65536] do
    let body := ByteArray.mk ((List.range length).map (fun i => UInt8.ofNat (i * 31 + i / 7))).toArray
    let encoded ← encode { body } {} { framing := some .chunked }
    check (encoded.framing == .chunked && encoded.next == .nextRequest .keepAlive) "chunked metadata"
    let chunkWire := encoded.parts.toList.drop 1 |>.foldl ByteArray.append ByteArray.empty
    match decodeChunks chunkWire with
    | .ok decoded => check (decoded == body) s!"binary chunk roundtrip length {length}"
    | .error message => throw (IO.userError s!"chunk decoding length {length}: {message}")
    if length > 0 then check (encoded.parts.size == 5 && encoded.parts[2]! == body) "chunked body stays a separate segment"
  wire "empty chunked" {} {} { framing := some .chunked }
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".toUTF8

private def statusTests : IO Unit := do
  for (status, reason) in [(204, "No Content"), (304, "Not Modified")] do
    let expected := ((("HTTP/1.1 ".toUTF8.append (toString status).toUTF8).append " ".toUTF8).append reason.toUTF8).append "\r\n\r\n".toUTF8
    wire "bodyless status" { status } {} {} expected
    wire "bodyless status overrides HEAD" { status } { requestMethod := "HEAD" } {} expected
    rejected "forbidden status content" { status, body := "x".toUTF8 }
    rejected "forbidden status Content-Length" { status } {} { framing := some (.contentLength 0) }
    rejected "forbidden status chunking" { status } {} { framing := some .chunked }
  wire "205" { status := 205 } {} {} "HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\n\r\n".toUTF8
  rejected "205 content" { status := 205, body := "x".toUTF8 }
  rejected "205 close framing" { status := 205 } {} { framing := some .closeDelimited }
  for (status, reason) in [(100, "Continue"), (102, "Processing"), (103, "Early Hints"), (199, "Response")] do
    let expected := ((("HTTP/1.1 ".toUTF8.append (toString status).toUTF8).append " ".toUTF8).append reason.toUTF8).append "\r\n\r\n".toUTF8
    wire "informational" { status } {} {} expected .informational
    rejected "HTTP/1.0 informational" { status } { version := .http10 }
    rejected "informational content" { status, body := "x".toUTF8 }
    rejected "informational framing" { status } {} { framing := some (.contentLength 0) }
    rejected "informational closure" { status } {} { forceClose := true }
  wire "custom reason" { status := 299 } {} { reason := some "Almost Ready" }
    "HTTP/1.1 299 Almost Ready\r\nContent-Length: 0\r\n\r\n".toUTF8
  wire "empty custom reason" {} {} { reason := some "" } "HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n".toUTF8
  for status in [0, 99, 600, 999, 1000] do rejected "status range" { status }
  for reason in ["ok\r\nInjected: yes", "bad\nreason", String.singleton (Char.ofNat 0), String.singleton (Char.ofNat 127)] do
    rejected "reason injection" {} {} { reason := some reason }
  for status in [201, 203, 206, 300, 301, 308, 400, 416, 417, 426, 451, 500, 503, 511, 599] do
    let _ ← encode { status }
    pure ()

private def fieldAndTrailerTests : IO Unit := do
  let date := "Sun, 06 Nov 1994 08:49:37 GMT".toUTF8
  wire "pure Date input" {} { date := some date } {}
    "HTTP/1.1 200 OK\r\nDate: Sun, 06 Nov 1994 08:49:37 GMT\r\nContent-Length: 0\r\n\r\n".toUTF8
  let supplied := "Thu, 01 Jan 1970 00:00:00 GMT"
  wire "supplied Date wins" { headers := #[field "dAtE" supplied] } { date := some date } {}
    "HTTP/1.1 200 OK\r\ndAtE: Thu, 01 Jan 1970 00:00:00 GMT\r\nContent-Length: 0\r\n\r\n".toUTF8
  wire "informational does not invent Date" { status := 100 } { date := some date } {}
    "HTTP/1.1 100 Continue\r\n\r\n".toUTF8 .informational
  rejected "duplicate Date" { headers := #[field "Date" supplied, field "date" supplied] }
  rejected "cached Date injection" {} { date := some "bad\r\nInjected: yes".toUTF8 }
  for name in ["", "Bad Name", "X\r\nInjected", "X:bad", "X\tBad"] do
    rejected "header name" { headers := #[field name "value"] }
  for name in ["Content-Length", "tRaNsFeR-EnCoDiNg", "Connection", "Trailer"] do
    rejected "managed header" { headers := #[field name "value"] }
  for byte in [0, 1, 10, 13, 31, 127] do
    rejected "header control byte" { headers := #[{ name := "X-Test", value := ByteArray.mk #[65, UInt8.ofNat byte, 66] }] }
  let wireValue := ByteArray.mk #[9, 65, 128, 255]
  let valid ← encode { headers := #[{ name := "X-Opaque", value := wireValue }] }
  check (valid.parts.size == 1) "wire header values can retain HTAB and obs-text bytes"
  let options : ResponseOptions := {
    framing := some .chunked
    trailers := #[field "X-Check" "one", field "Digest" "sha", field "x-check" "two"] }
  wire "chunked trailers" { body := "abc".toUTF8 } {} options
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: x-check, digest\r\n\r\n3\r\nabc\r\n0\r\nX-Check: one\r\nDigest: sha\r\nx-check: two\r\n\r\n".toUTF8
  rejected "trailers require chunking" {} {} { trailers := #[field "Digest" "sha"] }
  rejected "HEAD trailers" {} { requestMethod := "HEAD" } options
  for name in ["Content-Length", "Transfer-Encoding", "Host", "Trailer", "Connection", "Upgrade", "Content-Type", "Authorization"] do
    rejected "forbidden trailer" {} {} { framing := some .chunked, trailers := #[field name "value"] }
  rejected "connection-nominated trailer" {} { requestHeaders := #[field "Connection" "X-Check"] }
    { framing := some .chunked, trailers := #[field "X-Check" "value"] }
  rejected "trailer injection" {} {} { framing := some .chunked, trailers := #[field "X-Test" "ok\r\nInjected: yes"] }
  rejected "trailer name injection" {} {} { framing := some .chunked, trailers := #[field "X\r\nBad" "value"] }

private def upgradeTests : IO Unit := do
  let context : EncodeContext := { requestHeaders := #[field "Connection" "keep-alive, Upgrade", field "Upgrade" "websocket, Example/One"] }
  let response : Response := { status := 101, headers := #[field "Upgrade" "WebSocket"] }
  match response.encodeAcceptedUpgrade context with
  | .error message => throw (IO.userError s!"valid upgrade: {message}")
  | .ok encoded =>
    check (encoded.next == .upgrade && encoded.framing == .none && encoded.parts.size == 1) "explicit upgrade transition"
    check (flatten encoded == "HTTP/1.1 101 Switching Protocols\r\nUpgrade: WebSocket\r\nConnection: upgrade\r\n\r\n".toUTF8) "upgrade wire"
  let versioned : Response := { status := 101, headers := #[field "Upgrade" "example/One"] }
  match versioned.encodeAcceptedUpgrade context { reason := some "Welcome" } with
  | .ok result => check (result.next == .upgrade) "protocol name case-insensitive with exact version"
  | .error message => throw (IO.userError s!"versioned upgrade: {message}")
  rejected "101 must be explicit" response context
  rejectUpgrade "wrong status" {} context
  rejectUpgrade "HTTP/1.0 upgrade" response { context with version := .http10 }
  rejectUpgrade "missing Connection upgrade" response { requestHeaders := #[field "Upgrade" "websocket"] }
  rejectUpgrade "close conflicts with upgrade" response { context with requestHeaders := context.requestHeaders.push (field "Connection" "close") }
  rejectUpgrade "missing selected protocol" { status := 101 } context
  rejectUpgrade "unoffered selected protocol" { status := 101, headers := #[field "Upgrade" "other"] } context
  rejectUpgrade "multiple selected protocols" { status := 101, headers := #[field "Upgrade" "websocket, other"] } context
  rejectUpgrade "duplicate selected field" { response with headers := response.headers.push (field "Upgrade" "websocket") } context
  rejectUpgrade "protocol version is case-sensitive" { status := 101, headers := #[field "Upgrade" "example/one"] } context
  rejectUpgrade "upgrade content" { response with body := "raw".toUTF8 } context
  rejectUpgrade "upgrade trailers" response context { trailers := #[field "X-Trailer" "v"] }
  rejectUpgrade "upgrade framing" response context { framing := some .chunked }
  rejectUpgrade "upgrade closure" response context { forceClose := true }

private def legacyCompatibility : IO Unit := do
  let body := "legacy".toUTF8
  let response : Response := Response.mk 200 #[] body
  let reply : Reply := { response, informational := #[({ status := 103 }, {})] }
  check (reply.response.body == body && reply.informational.size == 1) "Reply wraps unchanged legacy Response"
  match response.serialize "GET", response.encodeFor {} with
  | .ok before, .ok after => check (before == flatten after) "legacy fixed response wire unchanged"
  | _, _ => throw (IO.userError "legacy serialization failed")
  match ({ status := 100 } : Response).validate "GET" with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError "legacy final validation was widened")

def main : IO Unit := do
  protocolTests
  framingTests
  statusTests
  fieldAndTrailerTests
  upgradeTests
  legacyCompatibility
  IO.println "HTTP/1 pure encoding tests passed"
