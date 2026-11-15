import LeanNet

open LeanNet
open LeanNet.HTTP1

private def parsePort : List String → Except String UInt16
  | [] => .ok 8081
  | [text] => do
    if text.isEmpty || !text.toUTF8.data.all (fun byte => byte >= 48 && byte <= 57) then
      throw "PORT must be an integer from 1 to 65535"
    let some value := text.toNat? | throw "invalid PORT"
    if value == 0 || value > 65535 then throw "PORT must be between 1 and 65535"
    return value.toUInt16
  | _ => .error "usage: api-server [PORT]"

private def json (status : Nat) (body : ByteArray) : Response := {
  status
  headers := #[{ name := "content-type", value := "application/json".toUTF8 }]
  body }

private def methodNotAllowed (allow : ByteArray) : Response :=
  let response := json 405 "{\"error\":\"method not allowed\"}\n".toUTF8
  { response with headers := response.headers.push { name := "allow", value := allow } }

private def itemId? (path : ByteArray) : Option Nat := do
  let bytes := path.toList
  if bytes.take 7 != "/items/".toUTF8.toList then none else do
    let digits := bytes.drop 7
    if digits.isEmpty || digits.length > 9 ||
        !digits.all (fun byte => byte >= 48 && byte <= 57) then none
    else some (digits.foldl (fun value byte => value * 10 + byte.toNat - 48) 0)

private def route (request : Request) : Response := Id.run do
  let path := ByteArray.mk (request.target.toList.takeWhile (· != 63)).toArray
  let read := request.method == "GET" || request.method == "HEAD"
  if path == "/".toUTF8 || path == "/health".toUTF8 then
    return if read then json 200 "{\"status\":\"ok\"}\n".toUTF8
      else methodNotAllowed "GET, HEAD".toUTF8
  if path == "/echo".toUTF8 then
    return if request.method == "POST" then {
      headers := #[{ name := "content-type", value := "application/octet-stream".toUTF8 }]
      body := request.body }
    else methodNotAllowed "POST".toUTF8
  if let some id := itemId? path then
    return if read then json 200 ("{\"id\":".toUTF8 ++ (toString id).toUTF8 ++ "}\n".toUTF8)
      else methodNotAllowed "GET, HEAD".toUTF8
  return json 404 "{\"error\":\"not found\"}\n".toUTF8

private def config : HTTP.ReactorServerConfig := {
  workers := 0
  server := { maxClients := 128, maxResponseBytes := 32768 }
  machine := { limits := {
    maxHeaderBytes := 8192, maxHeaderCount := 32,
    maxBodyBytes := 16384, maxBodyWireBytes := 32768 } }
  http2 := {
    maxConcurrentStreams := 64, maxHeaderListBytes := 16384, maxHeaderFields := 64,
    maxRequestBodyBytes := 32768, maxBufferedRequestBytes := 131072,
    maxResponseBodyBytes := 32768 }
  healthPaths := true
  metricsPath := some "/metrics".toUTF8 }

def main (args : List String) : IO Unit := do
  let port ← match parsePort args with
    | .ok port => pure port
    | .error message => throw (IO.userError message)
  HTTP.ReactorServer.serveFactory
    (fun _ => pure { onRequest := fun request => pure { response := route request } })
    config "127.0.0.1" port
