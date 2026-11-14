import LeanNet.HTTP1.Parser

open LeanNet.HTTP1

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do throw (IO.userError message)

private def bytes (s : String) : ByteArray := s.toUTF8

private def inspect (label : String) (method : String) (target body remaining : ByteArray)
    (result : ParseResult) : IO Request := do
  match result with
  | .complete request rest =>
    check (request.method == method) s!"{label}: incorrect method"
    check (request.target == target) s!"{label}: incorrect target"
    check (request.body == body) s!"{label}: incorrect body"
    check (rest == remaining) s!"{label}: incorrect remaining bytes"
    return request
  | .eof => throw (IO.userError s!"{label}: unexpected EOF")
  | .needMore _ => throw (IO.userError s!"{label}: expected complete request")
  | .error message => throw (IO.userError s!"{label}: unexpected parser error: {message}")

private def expectError (label : String) (input : ByteArray) (limits : Limits := {}) : IO Unit := do
  match (Parser.new limits).feed input with
  | .error _ => pure ()
  | .eof => throw (IO.userError s!"{label}: expected rejection, got EOF")
  | .needMore _ => throw (IO.userError s!"{label}: expected rejection, got needMore")
  | .complete _ _ => throw (IO.userError s!"{label}: expected rejection, got complete")

private def expectTruncated (label : String) (input : ByteArray) : IO Unit := do
  match (Parser.new).feed input with
  | .needMore parser =>
    match parser.finish with
    | .error _ => pure ()
    | _ => throw (IO.userError s!"{label}: truncated input did not fail at EOF")
  | _ => throw (IO.userError s!"{label}: incomplete input did not request more bytes")

/-- Exercise every two-part boundary, including a request completed in part one. -/
private def allSplits (label : String) (wire : ByteArray) (method : String)
    (target body remainder : ByteArray) : IO Unit := do
  for split in [0:wire.size + 1] do
    let first := wire.extract 0 split
    let last := wire.extract split wire.size
    let result := (Parser.new).feed first
    let result := match result with
      | .needMore parser => parser.feed last
      | .complete request rest => .complete request (rest.append last)
      | .error message => .error message
      | .eof => .eof
    let _ ← inspect s!"{label}, split {split}" method target body remainder result

/-- Resume after each individual byte to exercise persistent parser state. -/
private def bytewise (label : String) (wire : ByteArray) (method : String)
    (target body : ByteArray) : IO Unit := do
  let mut parser := Parser.new
  let mut completed := false
  for i in [0:wire.size] do
    match parser.feed (wire.extract i (i + 1)) with
    | .needMore next => parser := next
    | .error message => throw (IO.userError s!"{label}, byte {i}: {message}")
    | .eof => throw (IO.userError s!"{label}: unexpected EOF")
    | result@(.complete _ _) =>
      check (i + 1 == wire.size) s!"{label}: completed early"
      let _ ← inspect label method target body ByteArray.empty result
      completed := true
  check completed s!"{label}: incomplete after final byte"

private def parserTests : IO Unit := do
  match (Parser.new).finish with
  | .eof => pure ()
  | _ => throw (IO.userError "empty parser did not report clean EOF")
  let body := ByteArray.mk #[0, 255, 13, 10]
  let head := bytes "POST /upload?q=1 HTTP/1.1\r\nhOsT: example.test\r\nContent-Length: 4\r\n\r\n"
  let pipeline := bytes "GET /next HTTP/1.1\r\nHost: example.test\r\n\r\n"
  let wire := (head.append body).append pipeline
  allSplits "content length and pipeline" wire "POST" (bytes "/upload?q=1") body pipeline
  bytewise "content length one byte at a time" (head.append body) "POST" (bytes "/upload?q=1") body
  let request ← inspect "case folding" "POST" (bytes "/upload?q=1") body pipeline ((Parser.new).feed wire)
  match request.headers.find? (fun header => header.name == "host") with
  | some header => check (header.value == bytes "example.test") "header value changed"
  | none => throw (IO.userError "header names were not case-folded")
  for i in [0:26] do
    let upper := String.singleton (Char.ofNat (65 + i))
    let lower := String.singleton (Char.ofNat (97 + i))
    let input := bytes s!"GET / HTTP/1.1\r\nHost: example.test\r\n{upper}: value\r\n\r\n"
    let parsed ← inspect s!"case-fold {upper}" "GET" (bytes "/") ByteArray.empty ByteArray.empty
      ((Parser.new).feed input)
    check (parsed.headers.any (fun header => header.name == lower && header.value == bytes "value"))
      s!"header {upper} not lowercased"
  let _ ← inspect "parse pipeline remainder" "GET" (bytes "/next") ByteArray.empty ByteArray.empty
    ((Parser.new).feed pipeline)

  let chunked := bytes "POST /chunks HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=bar\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trailer: yes\r\n\r\n"
  allSplits "chunked with extensions and trailers" (chunked.append pipeline) "POST"
    (bytes "/chunks") (bytes "Wikipedia") pipeline
  bytewise "chunked one byte at a time" chunked "POST" (bytes "/chunks") (bytes "Wikipedia")
  let chunkRequest ← inspect "chunk trailer" "POST" (bytes "/chunks") (bytes "Wikipedia")
    ByteArray.empty ((Parser.new).feed chunked)
  match chunkRequest.trailers.find? (fun header => header.name == "x-trailer") with
  | some header => check (header.value == bytes "yes") "trailer value changed"
  | none => throw (IO.userError "chunk trailer not preserved")

  let _ ← inspect "absolute-form target" "GET" (bytes "http://example.test/path?q=1") ByteArray.empty ByteArray.empty
    ((Parser.new).feed (bytes "GET http://example.test/path?q=1 HTTP/1.1\r\nHost: example.test\r\n\r\n"))
  let _ ← inspect "generic absolute-form URI" "GET" (bytes "urn:oasis:names:specification:docbook:dtd:xml:4.1.2") ByteArray.empty ByteArray.empty
    ((Parser.new).feed (bytes "GET urn:oasis:names:specification:docbook:dtd:xml:4.1.2 HTTP/1.1\r\nHost: example.test\r\n\r\n"))
  let _ ← inspect "IPv4-embedded IPv6 host" "GET" (bytes "/") ByteArray.empty ByteArray.empty
    ((Parser.new).feed (bytes "GET / HTTP/1.1\r\nHost: [::ffff:192.0.2.128]:8080\r\n\r\n"))
  let _ ← inspect "IPvFuture host" "GET" (bytes "/") ByteArray.empty ByteArray.empty
    ((Parser.new).feed (bytes "GET / HTTP/1.1\r\nHost: [v1.fe80]\r\n\r\n"))
  let _ ← inspect "absolute URI userinfo" "GET" (bytes "ftp://user:pass@example.com/path") ByteArray.empty ByteArray.empty
    ((Parser.new).feed (bytes "GET ftp://user:pass@example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n"))
  expectError "invalid URI userinfo" (bytes "GET ftp://bad[user]@example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
  expectError "invalid raw URI character" (bytes "GET /bad|path HTTP/1.1\r\nHost: example.test\r\n\r\n")
  expectError "invalid percent encoding" (bytes "GET /bad%2 HTTP/1.1\r\nHost: example.test\r\n\r\n")
  expectError "fragment in request target" (bytes "GET /path#frag HTTP/1.1\r\nHost: example.test\r\n\r\n")

  expectError "content-length plus transfer-encoding"
    (bytes "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\nTrAnSfEr-EnCoDiNg: chunked\r\n\r\n0\r\n\r\n")
  expectError "conflicting content-length" (bytes "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab")
  expectError "signed content-length" (bytes "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: +1\r\n\r\na")
  expectError "nonnumeric content-length" (bytes "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: nope\r\n\r\n")
  expectError "invalid chunk length" (bytes "POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n")
  expectError "invalid chunk extension" (bytes "POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n1;=bad\r\na\r\n0\r\n\r\n")
  expectError "framing trailer" (bytes "POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 3\r\n\r\n")
  expectError "invalid chunk terminator" (bytes "POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcX\r\n0\r\n\r\n")
  expectError "invalid field name" (bytes "GET / HTTP/1.1\r\nHost: example.test\r\nBad Header: value\r\n\r\n")
  expectError "missing host" (bytes "GET / HTTP/1.1\r\n\r\n")
  expectError "IPv4 before IPv6 compression" (bytes "GET / HTTP/1.1\r\nHost: [192.0.2.1::]\r\n\r\n")
  expectError "unclosed IP literal in host" (bytes "GET / HTTP/1.1\r\nHost: [::1\r\n\r\n")
  expectError "nonnumeric host port" (bytes "GET / HTTP/1.1\r\nHost: example.test:abc\r\n\r\n")
  expectError "invalid host" (bytes "GET / HTTP/1.1\r\nHost: bad host\r\n\r\n")
  expectError "duplicate host" (bytes "GET / HTTP/1.1\r\nHost: first.test\r\nHost: second.test\r\n\r\n")
  expectError "header without colon" (bytes "GET / HTTP/1.1\r\nHost: example.test\r\nMissingColon\r\n\r\n")
  expectError "oversized headers" (bytes "GET / HTTP/1.1\r\nHost: abcdefghijklmnopqrstuvwxyz\r\n\r\n") { maxHeaderBytes := 24 }
  expectError "fixed body exceeds wire limit" (bytes "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 9\r\n\r\n123456789") { maxBodyBytes := 16, maxBodyWireBytes := 8 }
  expectError "oversized body" (bytes "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 9\r\n\r\n123456789") { maxBodyBytes := 8 }
  expectTruncated "truncated header" (bytes "GET / HTTP/1.1\r\nHost: example.test\r\n")
  expectTruncated "truncated fixed body" (bytes "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\nabc")
  expectTruncated "truncated chunk body" (bytes "POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabc")
  expectError "too many headers" (bytes "GET / HTTP/1.1\r\nHost: example.test\r\nX: v\r\n\r\n") { maxHeaderCount := 1 }
  expectError "too many trailers" (bytes "POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: v\r\n\r\n") { maxTrailerCount := 0 }
  expectError "oversized chunk line" (bytes "POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n1;ext=value\r\na\r\n0\r\n\r\n") { maxChunkLineBytes := 4 }
  IO.println "HTTP/1 parser tests passed"

def main : IO Unit := parserTests
