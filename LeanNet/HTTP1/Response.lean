import LeanNet.HTTP1.Request
import LeanNet.HTTP1.Date

namespace LeanNet.HTTP1

/-- A complete final HTTP/1.1 response. The serializer owns message framing;
    applications must not supply Content-Length, Transfer-Encoding, Connection,
    or Trailer headers. -/
structure Response where
  status : Nat := 200
  headers : Array Header := #[]
  body : ByteArray := ByteArray.empty

/-- Supply the current HTTP Date unless the application supplied one. -/
def Response.withCurrentDate (response : Response) : IO Response := do
  if response.headers.any (fun h => h.name.toLower == "date") then return response
  let date ← currentDate
  return { response with headers := response.headers.push { name := "Date", value := date } }

private def responseTokenByte (b : UInt8) : Bool :=
  let n := b.toNat
  (n >= 48 && n <= 57) || (n >= 65 && n <= 90) || (n >= 97 && n <= 122) ||
    [33, 35, 36, 37, 38, 39, 42, 43, 45, 46, 94, 95, 96, 124, 126].contains n

private def reasonPhrase (status : Nat) : String :=
  match status with
  | 200 => "OK"
  | 201 => "Created"
  | 202 => "Accepted"
  | 204 => "No Content"
  | 205 => "Reset Content"
  | 206 => "Partial Content"
  | 301 => "Moved Permanently"
  | 302 => "Found"
  | 303 => "See Other"
  | 304 => "Not Modified"
  | 307 => "Temporary Redirect"
  | 308 => "Permanent Redirect"
  | 400 => "Bad Request"
  | 401 => "Unauthorized"
  | 403 => "Forbidden"
  | 404 => "Not Found"
  | 405 => "Method Not Allowed"
  | 408 => "Request Timeout"
  | 409 => "Conflict"
  | 413 => "Content Too Large"
  | 414 => "URI Too Long"
  | 415 => "Unsupported Media Type"
  | 417 => "Expectation Failed"
  | 422 => "Unprocessable Content"
  | 429 => "Too Many Requests"
  | 431 => "Request Header Fields Too Large"
  | 500 => "Internal Server Error"
  | 501 => "Not Implemented"
  | 502 => "Bad Gateway"
  | 503 => "Service Unavailable"
  | 504 => "Gateway Timeout"
  | 505 => "HTTP Version Not Supported"
  | _ => "Response"

private def validateHeader (header : Header) : Except String Unit := do
  let name := header.name.toUTF8.toList
  if name.isEmpty || !name.all responseTokenByte then throw "invalid response header name"
  if ["content-length", "transfer-encoding", "connection", "trailer"].contains header.name.toLower then
    throw "response framing headers are managed by the serializer"
  if !header.value.toList.all (fun c => c == 9 || (c.toNat >= 32 && c.toNat != 127)) then
    throw "invalid response header value"

/-- Validate a final response without allocating its wire representation. -/
def Response.validate (response : Response) (requestMethod : String) : Except String Unit := do
  if response.status < 200 || response.status > 599 then
    throw "only final HTTP status codes from 200 to 599 are supported"
  if requestMethod == "CONNECT" && response.status < 300 then
    throw "successful CONNECT requires a tunnel"
  let noBodyStatus := response.status == 204 || response.status == 205 || response.status == 304
  if noBodyStatus && !response.body.isEmpty then
    throw "this response status forbids content"
  if (response.headers.filter (fun h => h.name.toLower == "date")).size > 1 then
    throw "multiple Date headers"
  for header in response.headers do validateHeader header

/-- Serialize a final response using explicit length framing. HEAD responses carry
    the representation length but no body. Statuses 204 and 304 have no framing
    header or body; 205 has Content-Length 0. `close` advertises connection
    closure. Informational responses and CONNECT tunnels are not supported. -/
def Response.serialize (response : Response) (requestMethod : String)
    (close : Bool := false) : Except String ByteArray := do
  response.validate requestMethod
  let noBodyStatus := response.status == 204 || response.status == 205 || response.status == 304
  let mut result := "HTTP/1.1 ".toUTF8
  result := result.append (toString response.status).toUTF8
  result := result.append " ".toUTF8
  result := result.append (reasonPhrase response.status).toUTF8
  result := result.append "\r\n".toUTF8
  for header in response.headers do
    result := result.append header.name.toUTF8
    result := result.append ": ".toUTF8
    result := result.append header.value
    result := result.append "\r\n".toUTF8
  if response.status != 204 && response.status != 304 then
    result := result.append "Content-Length: ".toUTF8
    result := result.append (toString response.body.size).toUTF8
    result := result.append "\r\n".toUTF8
  if close then result := result.append "Connection: close\r\n".toUTF8
  result := result.append "\r\n".toUTF8
  if requestMethod != "HEAD" && !noBodyStatus then
    result := result.append response.body
  return result

end LeanNet.HTTP1
