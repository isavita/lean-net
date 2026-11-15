import LeanNet.Gateway.Wire

open LeanNet LeanNet.Gate LeanNet.HTTP LeanNet.HTTP1 LeanNet.Gateway

private def check (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError s!"gateway wire: {message}")

private def field (name value : String) : Header := { name, value := value.toUTF8 }

private def admitted : IO Admitted := do
  let text := "backend local { http 127.0.0.1:9000 ; serves example.com }\n" ++
    "host example.com { route POST /admin -> proxy local }"
  let spec ← match Spec.parse text with
    | .ok value => pure value
    | .error error => throw (IO.userError (toString error))
  let policy ← match Policy.compile spec with
    | .ok value => pure value
    | .error error => throw (IO.userError (toString error))
  let head : Admission.Head :=
    { protocol := .http11, method := "POST", target := "/%61dmin?x=1".toUTF8,
      authority := "example.com".toUTF8,
      headers := #[field "host" "example.com", field "connection" "x-secret",
        field "x-secret" "do-not-forward", field "x-forwarded-for" "1.2.3.4",
        field "forwarded" "for=1.2.3.4", field "x-forwarded-client-cert" "spoofed-cert",
        field "x-real-ip" "spoofed-ip", field "x-useful" "value"] }
  let facts := Transport.Facts.forTesting false (peer := ByteArray.mk #[10, 2, 3, 4])
  match admitHead policy facts head with
  | .ok value => pure value
  | .error rejection => throw (IO.userError s!"admission status {rejection.status}")

private def requestFor (a : Admitted) : Request :=
  { method := "GET", target := "/wrong".toUTF8, headers := a.head.headers,
    body := "payload".toUTF8 }

def main : IO Unit := do
  let a ← admitted
  let wire ← match encodeRequest a (requestFor a) with
    | .ok parts => pure parts
    | .error error => throw (IO.userError s!"serialization failed: {repr error}")
  check (wire.size == 2 && wire[1]! == "payload".toUTF8) "body changed"
  let head := (String.fromUTF8? wire[0]!).getD ""
  check (head.startsWith "POST /admin?x=1 HTTP/1.1\r\n") "request target or method not admission-bound"
  check (head.contains "Host: example.com\r\n") "Host not admission-bound"
  check (!head.contains "do-not-forward" && !head.contains "1.2.3.4" &&
    !head.contains "spoofed-cert" && !head.contains "spoofed-ip") "untrusted headers crossed hop"
  check (head.contains "Forwarded: for=\"10.2.3.4\";proto=http;host=\"example.com\"\r\n")
    "Forwarded was not rebuilt"
  check (head.contains "X-Forwarded-For: 10.2.3.4\r\n") "X-Forwarded-For was not rebuilt"
  check (head.contains "Via: 1.1 lean-net\r\n") "Via missing"
  check (head.contains "Content-Length: 7\r\n") "body length missing"
  let poisoned := { requestFor a with headers := (requestFor a).headers.push (field "x-bad" "evil\r\nX: injected") }
  check (match encodeRequest a poisoned with | .error .invalidHeader => true | _ => false)
    "CRLF header accepted"
  let trailer := { requestFor a with trailers := #[field "content-length" "1"] }
  check (match encodeRequest a trailer with | .error .invalidTrailer => true | _ => false)
    "framing trailer accepted"
  for name in #["forwarded", "x-forwarded-for", "x-forwarded-client-cert",
      "x-real-ip", "x-client-cert", "via", "x-ssl-client-cert"] do
    let spoofed := { requestFor a with trailers := #[field name "spoofed"] }
    check (match encodeRequest a spoofed with | .error .invalidTrailer => true | _ => false)
      s!"identity trailer {name} crossed hop"
  let emptyRequest := requestFor a
  let emptyBody : ByteArray := ByteArray.empty
  let emptyRequest := { emptyRequest with body := emptyBody }
  let emptyTrailers := { emptyRequest with trailers := #[field "x-checksum" "abc"] }
  let .ok emptyWire := encodeRequest a emptyTrailers
    | throw (IO.userError "empty chunked request rejected")
  check (emptyWire.size == 2 && emptyWire[1]! == "0\r\nx-checksum: abc\r\n\r\n".toUTF8)
    "empty body emitted a duplicate final chunk"
  let v6 := ByteArray.mk #[0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1]
  check (peerText v6 == some "2001:db8:0:0:0:0:0:1".toUTF8) "IPv6 address rendering"
  let parser ← match ClientResponse.Parser.new "POST".toUTF8 with
    | .ok value => pure value
    | .error error => throw (IO.userError s!"response parser: {repr error}")
  let parsed ← match parser.feed
      "HTTP/1.1 200 OK\r\nConnection: x-hop\r\nX-Hop: secret\r\nContent-Length: 2\r\nX-Useful: yes\r\n\r\nok".toUTF8 with
    | .ok value => pure value
    | .error error => throw (IO.userError s!"response parse: {repr error}")
  let some upstream := parsed.events.findSome? (fun event => match event with
    | .head value => some value | _ => none)
    | throw (IO.userError "response head missing")
  let goodTrailer : ClientResponse.Header :=
    { name := "trailer".toUTF8, value := "X-Checksum".toUTF8 }
  let advertised := { upstream with headers := upstream.headers.push goodTrailer }
  check (match declaredTrailers advertised with
    | .ok names => names == #["x-checksum"] | .error _ => false)
    "safe upstream trailer declaration was lost"
  let badTrailer : ClientResponse.Header :=
    { name := "trailer".toUTF8, value := "Content-Length".toUTF8 }
  let invalidDeclaration := { upstream with headers := upstream.headers.push badTrailer }
  check (match declaredTrailers invalidDeclaration with | .error .invalidTrailer => true | _ => false)
    "framing trailer declaration was accepted"
  let reply ← match decodeReply upstream "ok".toUTF8 with
    | .ok value => pure value
    | .error error => throw (IO.userError s!"response decode: {repr error}")
  check (reply.response.status == 200 && reply.response.body == "ok".toUTF8) "response payload changed"
  check (reply.response.headers.any (fun h => h.name == "x-useful" && h.value == "yes".toUTF8))
    "end-to-end response header lost"
  check (!reply.response.headers.any (fun h => ["connection", "content-length", "x-hop"].contains h.name))
    "hop-by-hop response header crossed hop"
