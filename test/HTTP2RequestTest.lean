import LeanNet.HTTP2.Request
open LeanNet.HTTP2

private def check (ok : Bool) (message : String) : IO Unit := do
  unless ok do throw (IO.userError message)
private def h (n v : String) : HPACK.Header := { name := n.toUTF8, value := v.toUTF8 }
private def base : Array HPACK.Header := #[h ":method" "GET", h ":scheme" "http", h ":authority" "localhost", h ":path" "/"]
private def reject (label : String) (headers : Array HPACK.Header) : IO Unit := do
  match validateRequestHead headers with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError s!"{label}: accepted malformed request")

def main : IO Unit := do
  match validateRequestHead base with
  | .error e => throw (IO.userError e)
  | .ok head =>
    let request ← match head.complete ByteArray.empty with
      | .ok request => pure request
      | .error e => throw (IO.userError e)
    check (request.method == "GET" && request.version == "HTTP/2" && request.target == "/".toUTF8)
      "valid request was not converted"
    check (request.headers.any (fun x => x.name == "host" && x.value == "localhost".toUTF8))
      "authority was not conveyed to the router"
  match validateRequestHead ((base.push (h "cookie" "a=1")).push (h "cookie" "b=2")) with
  | .error e => throw (IO.userError e)
  | .ok head => check (head.headers.any (fun field => field.name == "cookie" && field.value == "a=1; b=2".toUTF8)) "split cookies were not joined"
  match validateRequestHead (base.push (h "host" "LOCALHOST")) with
  | .error e => throw (IO.userError e)
  | .ok head => check (head.headers.any (fun field => field.name == "host" && field.value == "localhost".toUTF8)) "authority did not override Host"
  reject "CONNECT missing port" #[h ":method" "CONNECT", h ":authority" "example.test"]
  match validateRequestHead #[h ":method" "CONNECT", h ":authority" "example.test:443"] with
  | .ok _ => pure ()
  | .error e => throw (IO.userError s!"valid CONNECT rejected: {e}")
  reject "empty HTTP authority" #[h ":method" "GET", h ":scheme" "http", h ":path" "/"]
  reject "empty host with port" #[h ":method" "GET", h ":scheme" "http", h ":authority" ":80", h ":path" "/"]
  reject "missing method" #[h ":scheme" "http", h ":path" "/"]
  reject "pseudo-field after regular" #[h ":method" "GET", h "x" "a", h ":path" "/", h ":scheme" "http"]
  reject "uppercase name" (base.push (h "X-Test" "a"))
  reject "connection header" (base.push (h "connection" "close"))
  reject "transfer encoding" (base.push (h "transfer-encoding" "chunked"))
  reject "invalid TE" (base.push (h "te" "gzip"))
  reject "duplicate pseudo-field" (base.push (h ":method" "POST"))
  reject "mismatched host" (base.push (h "host" "other.example"))
  reject "invalid authority" #[h ":method" "GET", h ":scheme" "http", h ":authority" "bad host", h ":path" "/"]
  reject "invalid content length" (base.push (h "content-length" "+1"))
  reject "invalid path" #[h ":method" "GET", h ":scheme" "http", h ":path" "relative"]
  reject "invalid path escape" #[h ":method" "GET", h ":scheme" "http", h ":path" "/%xx"]
  reject "invalid path character" #[h ":method" "GET", h ":scheme" "http", h ":path" "/{bad}"]
  reject "invalid field control" (base.push { name := "x".toUTF8, value := ByteArray.mk #[1] })
  let bodyHead ← match validateRequestHead #[h ":method" "POST", h ":scheme" "http", h ":authority" "localhost", h ":path" "/", h "content-length" "2"] with
    | .ok head => pure head
    | .error e => throw (IO.userError e)
  match bodyHead.complete "x".toUTF8 with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError "short body was accepted")
  match validateTrailers #[h ":path" "/"] with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError "pseudo trailer was accepted")
  match validateTrailers #[h "content-length" "4"] with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError "framing trailer was accepted")
  IO.println "HTTP/2 request tests passed"
