import LeanNet.HTTP1.ClientResponse

open LeanNet.HTTP1.ClientResponse

private def check (condition : Bool) (label : String) : IO Unit :=
  unless condition do throw (IO.userError label)

private def ok (result : Except Error α) (label : String) : IO α :=
  match result with
  | .ok value => pure value
  | .error error => throw (IO.userError s!"{label}: {repr error}")

private def rejected (expected : Error) (result : Except Error α) (label : String) : IO Unit :=
  match result with
  | .error actual => check (actual == expected) s!"{label}: {repr actual}"
  | .ok _ => throw (IO.userError label)

private def body (events : Array Event) : ByteArray := Id.run do
  let mut output := ByteArray.empty
  for event in events do
    if let .body view := event then output := output.append view.copy
  return output

private def statuses (events : Array Event) : Array (UInt16 × Bool) := Id.run do
  let mut output := #[]
  for event in events do
    match event with
    | .head head => output := output.push (head.status, head.reusable)
    | .informational head => output := output.push (head.status, false)
    | _ => pure ()
  return output

private def completed (events : Array Event) : Bool :=
  events.any fun event => match event with | .complete => true | _ => false

private def splitParse (wire : ByteArray) (method : ByteArray := "GET".toUTF8)
    (limits : Limits := {}) : IO Unit := do
  for split in [:wire.size + 1] do
    let parser ← ok (Parser.new method limits) "new parser"
    let first ← ok (parser.feed (wire.extract 0 split)) "first split"
    check (first.consumed == split) "first split not fully consumed"
    let second ← ok (first.parser.feed (wire.extract split wire.size)) "second split"
    check (second.consumed == wire.size - split) "second split not fully consumed"
    check (completed (first.events ++ second.events)) "split did not complete"

private def fixedTests : IO Unit := do
  let binary := ByteArray.mk #[0, 255, 13, 10, 1]
  let head := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\nX-Trace: abc\r\n\r\n".toUTF8
  let wire := head.append binary
  splitParse wire
  let parser ← ok (Parser.new "GET".toUTF8) "new fixed"
  let result ← ok (parser.feed wire) "fixed response"
  check (statuses result.events == #[(200, true)]) "fixed status/reuse"
  check (body result.events == binary && completed result.events) "fixed body changed"
  check (result.consumed == wire.size) "fixed consumed wrong length"
  let next ← ok (result.parser.feed "HTTP/1.1 999 nope\r\n".toUTF8) "done parser"
  check (next.consumed == 0 && next.events.isEmpty) "extra bytes mistaken for a new response"
  let truncatedParser ← ok (Parser.new "GET".toUTF8) "new truncated"
  let incomplete ← ok (truncatedParser.feed (head.append (binary.extract 0 4))) "partial fixed body"
  rejected .truncated incomplete.parser.eof "truncated fixed body"

private def chunkTests : IO Unit := do
  let wire := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;foo=bar\r\nabc\r\n2\r\nde\r\n0\r\nX-Checksum: yes\r\n\r\n".toUTF8
  splitParse wire
  let parser ← ok (Parser.new "GET".toUTF8) "new chunked"
  let result ← ok (parser.feed wire) "chunked response"
  check (statuses result.events == #[(200, true)]) "chunked status/reuse"
  check (body result.events == "abcde".toUTF8 && completed result.events) "chunked body"
  let trailers := result.events.filterMap fun event => match event with
    | .trailers fields => some fields
    | _ => none
  check (trailers.size == 1 && trailers[0]!.size == 1 &&
    trailers[0]![0]!.name == "x-checksum".toUTF8) "chunked trailers"
  let badWire := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nxyX".toUTF8
  let badParser ← ok (Parser.new "GET".toUTF8) "new bad chunk"
  rejected .invalidChunk (badParser.feed badWire) "bad chunk terminator accepted"
  let trailerWire := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 1\r\n\r\n".toUTF8
  let trailerParser ← ok (Parser.new "GET".toUTF8) "new trailer"
  rejected .forbiddenTrailer (trailerParser.feed trailerWire) "framing trailer accepted"
  let nominated := "HTTP/1.1 200 OK\r\nConnection: x-late\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Late: bad\r\n\r\n".toUTF8
  let nominatedParser ← ok (Parser.new "GET".toUTF8) "new nominated"
  rejected .forbiddenTrailer (nominatedParser.feed nominated) "connection-nominated trailer accepted"

private def informationalTests : IO Unit := do
  let wire := "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".toUTF8
  splitParse wire
  let parser ← ok (Parser.new "GET".toUTF8) "new interim"
  let result ← ok (parser.feed wire) "interim response"
  check (statuses result.events == #[(100, false), (103, false), (200, true)])
    "informational sequence"
  check (body result.events == "ok".toUTF8) "informational body"
  let many := "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".toUTF8
  let capped ← ok (Parser.new "GET".toUTF8 { maxInformational := 1 }) "new cap"
  rejected .informationalLimit (capped.feed many) "unbounded interim responses"
  let switching := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nraw".toUTF8
  let switchParser ← ok (Parser.new "GET".toUTF8) "new switch"
  let switched ← ok (switchParser.feed switching) "switching response"
  check (switched.consumed == switching.size - 3 &&
    switched.events.any (fun event => match event with | .tunnel _ => true | _ => false))
    "101 tunnel boundary"

private def specialBodies : IO Unit := do
  let headWire := "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nnext".toUTF8
  let headParser ← ok (Parser.new "HEAD".toUTF8) "new HEAD"
  let head ← ok (headParser.feed headWire) "HEAD response"
  check (head.consumed == headWire.size - 4 && completed head.events &&
    body head.events == ByteArray.empty) "HEAD interpreted representation as body"
  let noContent ← ok (Parser.new "GET".toUTF8) "new 204"
  rejected .invalidFraming (noContent.feed "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".toUTF8)
    "204 Content-Length accepted"
  let notModified ← ok (Parser.new "GET".toUTF8) "new 304"
  let result ← ok (notModified.feed "HTTP/1.1 304 Not Modified\r\nContent-Length: 500\r\n\r\n".toUTF8)
    "304 response"
  check (completed result.events && body result.events == ByteArray.empty) "304 got body"
  let resetParser ← ok (Parser.new "GET".toUTF8) "new 205"
  let reset ← ok (resetParser.feed "HTTP/1.1 205 Reset Content\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".toUTF8)
    "empty chunked 205"
  check (completed reset.events && reset.consumed ==
    "HTTP/1.1 205 Reset Content\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".toUTF8.size)
    "205 chunk terminator unconsumed"
  let badResetParser ← ok (Parser.new "GET".toUTF8) "new bad 205"
  rejected .invalidFraming
    (badResetParser.feed "HTTP/1.1 205 Reset Content\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n".toUTF8)
    "205 with body accepted"
  let unframedReset ← ok (Parser.new "GET".toUTF8) "new unframed 205"
  rejected .invalidFraming
    (unframedReset.feed "HTTP/1.1 205 Reset Content\r\n\r\nsmuggled".toUTF8)
    "unframed 205 consumed following bytes"
  let tunnelParser ← ok (Parser.new "CONNECT".toUTF8) "new CONNECT"
  let tunnelWire := "HTTP/1.1 200 Connection Established\r\n\r\nTLS".toUTF8
  let tunnel ← ok (tunnelParser.feed tunnelWire) "CONNECT tunnel"
  check (tunnel.consumed == tunnelWire.size - 3) "CONNECT consumed tunnel bytes"
  let closeParser ← ok (Parser.new "GET".toUTF8) "new close"
  let first ← ok (closeParser.feed "HTTP/1.0 200 OK\r\n\r\nabc".toUTF8) "close-delimited"
  check (statuses first.events == #[(200, false)] && !completed first.events &&
    body first.events == "abc".toUTF8) "close-delimited head/body"
  let second ← ok (first.parser.feed "de".toUTF8) "close body continuation"
  check (body second.events == "de".toUTF8 && !completed second.events) "close continuation"
  let ending ← ok second.parser.eof "close EOF"
  check (completed ending.events) "close-delimited EOF did not complete"

private def rejectionTests : IO Unit := do
  for wire in [
      "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n".toUTF8,
      "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n".toUTF8,
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n".toUTF8] do
    let parser ← ok (Parser.new "GET".toUTF8) "new ambiguous"
    rejected .invalidFraming (parser.feed wire) "ambiguous response framing accepted"
  let malformedStatus ← ok (Parser.new "GET".toUTF8) "new status"
  rejected .invalidStatus (malformedStatus.feed "HTTP/1.1 20 OK\r\n\r\n".toUTF8)
    "short status accepted"
  let folded ← ok (Parser.new "GET".toUTF8) "new folded"
  rejected .invalidHeader (folded.feed "HTTP/1.1 200 OK\r\nX: y\r\n folded\r\n\r\n".toUTF8)
    "obs-fold accepted"
  let bareLF ← ok (Parser.new "GET".toUTF8) "new bare LF"
  rejected .invalidHeader (bareLF.feed "HTTP/1.1 200 OK\n\n".toUTF8)
    "bare LF accepted"
  let tinyBody ← ok (Parser.new "GET".toUTF8 { maxBodyBytes := 2 }) "new tiny body"
  rejected .bodyLimit (tinyBody.feed "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc".toUTF8)
    "oversized declared body accepted"
  let tinyHead ← ok (Parser.new "GET".toUTF8 { maxHeaderCount := 1 }) "new tiny head"
  rejected .headerCount (tinyHead.feed "HTTP/1.1 200 OK\r\nA: b\r\nB: c\r\n\r\n".toUTF8)
    "too many headers accepted"
  let tinyWire ← ok (Parser.new "GET".toUTF8 { maxBodyWireBytes := 8 }) "new tiny wire"
  rejected .wireLimit (tinyWire.feed "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n".toUTF8)
    "chunk overhead exceeded wire cap"

def main : IO Unit := do
  fixedTests
  chunkTests
  informationalTests
  specialBodies
  rejectionTests
