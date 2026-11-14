import LeanNet.HTTP1.Server

namespace LeanNet.HTTP2

/-- Serve HTTP/1.1 and prior-knowledge cleartext HTTP/2 on the same listener. -/
def serveWith (router : HTTP1.Router) (config : HTTP1.ServerConfig := {})
    (host : String := "127.0.0.1") (port : UInt16 := 8080) : IO Unit :=
  HTTP1.serveWithConfig router config host port

/-- Run the shared demonstration router over HTTP/1.1 and h2c. -/
def serve (host : String := "127.0.0.1") (port : UInt16 := 8080) : IO Unit :=
  HTTP1.serve host port

end LeanNet.HTTP2
