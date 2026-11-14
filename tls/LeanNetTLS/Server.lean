import LeanNet.HTTP1.Server
import LeanNetTLS.Session

namespace LeanNetTLS.Server

/-- Serve the shared HTTP/1.1 and HTTP/2 router over TLS with ALPN. -/
def serveWithConfig (router : LeanNet.HTTP1.Router) (config : LeanNet.HTTP1.ServerConfig)
    (certificate privateKey : String) (host : String := "127.0.0.1") (port : UInt16 := 8443) : IO Unit :=
  Context.withContext certificate privateKey fun context =>
    LeanNet.HTTP1.serveWithTransport router config
      (some fun connection => connection.installTransport context.transport) host port

/-- Serve an application router with default event-loop limits. -/
def serveWith (router : LeanNet.HTTP1.Router) (certificate privateKey : String)
    (host : String := "127.0.0.1") (port : UInt16 := 8443) : IO Unit :=
  serveWithConfig router {} certificate privateKey host port

/-- Serve the default route over TLS. -/
def serve (certificate privateKey : String) (host : String := "127.0.0.1")
    (port : UInt16 := 8443) : IO Unit :=
  serveWith LeanNet.HTTP1.defaultRouter certificate privateKey host port

end LeanNetTLS.Server
