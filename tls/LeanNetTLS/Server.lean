import LeanNet.HTTP1.Server
import LeanNetTLS.ReactorServer

namespace LeanNetTLS.Server

/-- Serve the shared router through the native reactor and dedicated TLS
    workers. Compatibility callbacks keep their single-worker ownership. -/
def serveWithConfig (router : LeanNet.HTTP1.Router) (config : LeanNet.HTTP1.ServerConfig)
    (certificate privateKey : String) (host : String := "127.0.0.1") (port : UInt16 := 8443) : IO Unit :=
  ReactorServer.serveWithHandlers (.ofRouter router)
    { certificateChain := certificate, privateKey,
      handshakeTimeoutMs := UInt64.ofNat config.requestTimeoutMs }
    { server := config } host port

/-- Serve an application router with default native reactor limits. -/
def serveWith (router : LeanNet.HTTP1.Router) (certificate privateKey : String)
    (host : String := "127.0.0.1") (port : UInt16 := 8443) : IO Unit :=
  serveWithConfig router {} certificate privateKey host port

/-- Serve the default route with one HTTP reactor per available core. -/
def serve (certificate privateKey : String) (host : String := "127.0.0.1")
    (port : UInt16 := 8443) : IO Unit :=
  ReactorServer.serveFactory (fun _ => pure .default)
    { certificateChain := certificate, privateKey } {} host port

end LeanNetTLS.Server
