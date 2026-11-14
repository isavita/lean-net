import LeanNet.HTTP.ReactorServer
import LeanNetTLS.Reactor

namespace LeanNetTLS.ReactorServer

/-- Build independent application handlers on each reactor owner, sharing only
    the sealed certificate bundle across the dedicated TLS workers. -/
def serveFactory (factory : Nat → IO LeanNet.HTTP1.Handlers)
    (tls : Reactor.Config) (http : LeanNet.HTTP.ReactorServerConfig := {})
    (host : String := "127.0.0.1") (port : UInt16 := 8443) : IO Unit :=
  Reactor.withBundle tls fun bundle =>
    LeanNet.HTTP.ReactorServer.serveFactoryWithTransport
      (fun _ maxClients reactor use => Reactor.withWorker bundle tls reactor maxClients use)
      factory http host port

/-- Diagnostics are scoped to the same owner as its application callbacks. -/
def serveFactoryWithDiagnostics (factory : Nat → IO Reactor.Stats → IO LeanNet.HTTP1.Handlers)
    (tls : Reactor.Config) (http : LeanNet.HTTP.ReactorServerConfig := {})
    (host : String := "127.0.0.1") (port : UInt16 := 8443) : IO Unit :=
  Reactor.withBundle tls fun bundle =>
    LeanNet.HTTP.ReactorServer.serveWorkerFactory
      (fun workerId maxClients reactor use =>
        Reactor.withWorkerStats bundle tls reactor maxClients fun transport diagnostics => do
          let handlers ← factory workerId diagnostics
          use transport handlers)
      http host port

/-- Compatibility callbacks retain one worker's ownership. -/
def serveWithHandlers (handlers : LeanNet.HTTP1.Handlers)
    (tls : Reactor.Config) (http : LeanNet.HTTP.ReactorServerConfig := {})
    (host : String := "127.0.0.1") (port : UInt16 := 8443) : IO Unit :=
  serveFactory (fun _ => pure handlers) tls { http with workers := 1 } host port

end LeanNetTLS.ReactorServer
