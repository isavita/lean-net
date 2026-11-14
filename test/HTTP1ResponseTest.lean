import LeanNet.HTTP1.Response

open LeanNet.HTTP1

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do throw (IO.userError message)

private def encoded (label : String) (response : Response) (method : String)
    (close : Bool) (expected : ByteArray) : IO Unit := do
  match response.serialize method close with
  | .ok actual => check (actual == expected) s!"{label}: incorrect wire bytes"
  | .error message => throw (IO.userError s!"{label}: unexpected error: {message}")

private def rejected (label : String) (response : Response) (method : String := "GET") : IO Unit := do
  match response.serialize method with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError s!"{label}: invalid response was accepted")

def main : IO Unit := do
  check (formatDate (0 : Std.Time.Timestamp) == "Thu, 01 Jan 1970 00:00:00 GMT") "epoch Date format"
  check (formatDate (784111777 : Std.Time.Timestamp) == "Sun, 06 Nov 1994 08:49:37 GMT") "RFC example Date format"
  let supplied : Response := { headers := #[{ name := "dAtE", value := "Sun, 06 Nov 1994 08:49:37 GMT".toUTF8 }] }
  let preserved ← supplied.withCurrentDate
  check (preserved.headers.size == 1 && preserved.headers[0]!.value == "Sun, 06 Nov 1994 08:49:37 GMT".toUTF8) "supplied Date was not preserved exactly once"
  rejected "duplicate Date" { headers := #[{ name := "Date", value := "x".toUTF8 }, { name := "date", value := "y".toUTF8 }] }
  let binary := ByteArray.mk #[0, 255, 13, 10]
  let response : Response := { headers := #[{name := "Content-Type", value := "application/octet-stream".toUTF8}], body := binary }
  encoded "binary" response "GET" false
    ("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n\r\n".toUTF8.append binary)
  encoded "HEAD" response "HEAD" false
    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n\r\n".toUTF8
  encoded "close" { body := "ok".toUTF8 } "GET" true
    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".toUTF8
  encoded "204" { status := 204 } "GET" false "HTTP/1.1 204 No Content\r\n\r\n".toUTF8
  encoded "304" { status := 304 } "GET" false "HTTP/1.1 304 Not Modified\r\n\r\n".toUTF8
  encoded "205" { status := 205 } "GET" false "HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\n\r\n".toUTF8
  for status in [204, 205, 304] do
    rejected s!"content on {status}" { status, body := "x".toUTF8 }
  rejected "informational status" { status := 100 }
  rejected "status outside range" { status := 600 }
  rejected "successful CONNECT tunnel" {} "CONNECT"
  rejected "content-length override" { headers := #[{ name := "CoNtEnT-LeNgTh", value := "4".toUTF8 }] }
  rejected "transfer-encoding override" { headers := #[{ name := "Transfer-Encoding", value := "chunked".toUTF8 }] }
  rejected "connection override" { headers := #[{ name := "Connection", value := "keep-alive".toUTF8 }] }
  rejected "header name injection" { headers := #[{ name := "X-Test\r\nInjected", value := "value".toUTF8 }] }
  rejected "header value injection" { headers := #[{ name := "X-Test", value := "ok\r\nInjected: yes".toUTF8 }] }
  rejected "header NUL" { headers := #[{ name := "X-Test", value := ByteArray.mk #[65, 0, 66] }] }
  IO.println "HTTP/1 response tests passed"
