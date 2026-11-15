import LeanNet.HTTP.ReactorServer
import LeanNetTLS.Reactor
import LeanNetTLS.GatewayProvider
import LeanNet.HTTP.Static.Catalog

namespace LeanNetTLS.ReactorServer

/-- Each worker creates its own outbound TLS trust context. A caller that
    supplied a custom provider keeps it; otherwise HTTPS routes use verified
    OpenSSL roots, optionally from `upstreamCA`. -/
private def withUpstreamTLS (http : LeanNet.HTTP.ReactorServerConfig)
    (upstreamCA : Option String) : LeanNet.HTTP.ReactorServerConfig :=
  { http with gateway := http.gateway.map fun gateway =>
      if gateway.tlsProviderFactory.isSome then gateway
      else { gateway with tlsProviderFactory := some (fun reactor =>
        GatewayProvider.new reactor upstreamCA) } }

/-- When certificate reloading is configured (including interval zero), each
    SIGHUP asks the off-loop loader to publish a fresh certificate generation.
    Existing sessions keep their generation; failures keep the last valid one. -/
private def withReloadSignal (bundle : Reactor.Bundle) (tls : Reactor.Config)
    (http : LeanNet.HTTP.ReactorServerConfig) : LeanNet.HTTP.ReactorServerConfig :=
  if tls.reload.isNone then http
  else { http with onReload := do
    http.onReload
    let _ ← bundle.requestReload
    pure () }

/-- TLS encrypts file regions on its dedicated worker, using the catalog's
    resident immutable source while preserving normal ciphertext fences. -/
def serveStaticRoot (root : System.FilePath) (tls : Reactor.Config)
    (catalogConfig : LeanNet.HTTP.Static.Catalog.Config := {})
    (http : LeanNet.HTTP.ReactorServerConfig := {})
    (host : String := "127.0.0.1") (port : UInt16 := 8443)
    (upstreamCA : Option String := none) : IO Unit :=
  Reactor.withBundle tls fun bundle =>
    LeanNet.HTTP.Static.Catalog.withCatalog root catalogConfig fun catalog =>
      LeanNet.HTTP.ReactorServer.serveWorkerFactory
        (fun _ maxClients reactor use => do
          let bound ← catalog.bind reactor
          Reactor.withWorker bundle tls reactor maxClients fun transport => do
            use transport (← bound.handlers)) (withReloadSignal bundle tls (withUpstreamTLS http upstreamCA)) host port

/-- Build independent application handlers on each reactor owner, sharing only
    the sealed certificate bundle across the dedicated TLS workers. -/
def serveFactory (factory : Nat → IO LeanNet.HTTP1.Handlers)
    (tls : Reactor.Config) (http : LeanNet.HTTP.ReactorServerConfig := {})
    (host : String := "127.0.0.1") (port : UInt16 := 8443)
    (upstreamCA : Option String := none) : IO Unit :=
  Reactor.withBundle tls fun bundle =>
    LeanNet.HTTP.ReactorServer.serveFactoryWithTransport
      (fun _ maxClients reactor use => Reactor.withWorker bundle tls reactor maxClients use)
      factory (withReloadSignal bundle tls (withUpstreamTLS http upstreamCA)) host port

/-- Diagnostics are scoped to the same owner as its application callbacks. -/
def serveFactoryWithDiagnostics (factory : Nat → IO Reactor.Stats → IO LeanNet.HTTP1.Handlers)
    (tls : Reactor.Config) (http : LeanNet.HTTP.ReactorServerConfig := {})
    (host : String := "127.0.0.1") (port : UInt16 := 8443)
    (upstreamCA : Option String := none) : IO Unit :=
  Reactor.withBundle tls fun bundle =>
    LeanNet.HTTP.ReactorServer.serveWorkerFactory
      (fun workerId maxClients reactor use =>
        Reactor.withWorkerStats bundle tls reactor maxClients fun transport diagnostics => do
          let handlers ← factory workerId diagnostics
          use transport handlers)
      (withReloadSignal bundle tls (withUpstreamTLS http upstreamCA)) host port

/-- Compatibility callbacks retain one worker's ownership. -/
def serveWithHandlers (handlers : LeanNet.HTTP1.Handlers)
    (tls : Reactor.Config) (http : LeanNet.HTTP.ReactorServerConfig := {})
    (host : String := "127.0.0.1") (port : UInt16 := 8443)
    (upstreamCA : Option String := none) : IO Unit :=
  serveFactory (fun _ => pure handlers) tls { http with workers := 1 } host port upstreamCA

end LeanNetTLS.ReactorServer
