import LeanNet.HTTP1.Server
import LeanNet.WebSocket.Server

namespace LeanNet.HTTP2

/-- Serve HTTP/1.1 and prior-knowledge cleartext HTTP/2 on the same listener. -/
def serveWith (router : HTTP1.Router) (config : HTTP1.ServerConfig := {})
    (host : String := "127.0.0.1") (port : UInt16 := 8080) : IO Unit :=
  HTTP1.serveWithConfig router config host port

private def demoAsset : HTTP1.Response := {
  headers := #[{ name := "content-type", value := "text/plain; charset=utf-8".toUTF8 }]
  body := "Optional server push from lean-net.\n".toUTF8 }

/-- The demo route can promise a same-origin cacheable GET when push is enabled.
    Peers that disable push receive the ordinary parent response. -/
def demoHandlersWith (websocketOrigin : Option ByteArray := none) : HTTP1.Handlers := {
  onHeaders := fun head _ => do
    if head.target == "/ws".toUTF8 then
      if let some origin := websocketOrigin then
        return ← WebSocket.Server.acceptHTTP1 head
          { originAllowed := fun presented => presented == some origin }
          WebSocket.Server.echo
    return .accept none
  onWebSocket := fun head => do
    if head.target == "/ws".toUTF8 then
      if let some origin := websocketOrigin then
        let policy : WebSocket.Handshake.Policy :=
          { originAllowed := fun presented => presented == some origin }
        return some (policy, WebSocket.Server.echo)
    else return none
    return none
  onRequest := fun request => do
    if request.target == "/pushed.txt".toUTF8 && ["GET", "HEAD"].contains request.method then
      return { response := demoAsset }
    -- Demonstrates the mTLS identity exposed to applications.
    if request.target == "/client-certificate".toUTF8 && request.method == "GET" then
      let text := "text/plain; charset=utf-8".toUTF8
      match request.clientCertificate with
      | some certificate =>
        let body := s!"subject={certificate.subject}\n" ++
          String.join (certificate.subjectAltNames.toList.map fun name => s!"san={name}\n")
        return { response := { status := 200, headers := #[{ name := "content-type", value := text }], body := body.toUTF8 } }
      | none =>
        return { response := { status := 404, headers := #[{ name := "content-type", value := text }],
                               body := "no verified client certificate\n".toUTF8 } }
    return { response := ← HTTP1.defaultRouter request }
  onPush := fun request => pure <|
    if request.method == "GET" && request.target == "/".toUTF8 then
      #[{ target := "/pushed.txt".toUTF8, response := demoAsset }]
    else #[] }

def demoHandlers : HTTP1.Handlers := demoHandlersWith none

/-- Configure native HTTP/2 limits and optional push without sharing mutable
    application state between the per-core reactors. -/
def serveWithOptions (config : HTTP.ReactorServerConfig := {})
    (host : String := "127.0.0.1") (port : UInt16 := 8080) : IO Unit :=
  HTTP.ReactorServer.serveFactory (fun _ => pure (demoHandlersWith config.websocketOrigin)) config host port

/-- Run the shared demonstration router over HTTP/1.1 and h2c. -/
def serve (host : String := "127.0.0.1") (port : UInt16 := 8080) : IO Unit :=
  serveWithOptions {} host port

end LeanNet.HTTP2
