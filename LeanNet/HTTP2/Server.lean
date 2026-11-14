import LeanNet.HTTP1.Server

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
def demoHandlers : HTTP1.Handlers := {
  onRequest := fun request => do
    if request.target == "/pushed.txt".toUTF8 && ["GET", "HEAD"].contains request.method then
      return { response := demoAsset }
    return { response := ← HTTP1.defaultRouter request }
  onPush := fun request => pure <|
    if request.method == "GET" && request.target == "/".toUTF8 then
      #[{ target := "/pushed.txt".toUTF8, response := demoAsset }]
    else #[] }

/-- Configure native HTTP/2 limits and optional push without sharing mutable
    application state between the per-core reactors. -/
def serveWithOptions (config : HTTP.ReactorServerConfig := {})
    (host : String := "127.0.0.1") (port : UInt16 := 8080) : IO Unit :=
  HTTP.ReactorServer.serveFactory (fun _ => pure demoHandlers) config host port

/-- Run the shared demonstration router over HTTP/1.1 and h2c. -/
def serve (host : String := "127.0.0.1") (port : UInt16 := 8080) : IO Unit :=
  serveWithOptions {} host port

end LeanNet.HTTP2
