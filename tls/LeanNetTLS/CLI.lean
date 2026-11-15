import LeanNet.HTTP.CLI
import LeanNetTLS.ReactorServer

namespace LeanNetTLS.CLI

/-- Keep certificate, catalog and protocol ownership in the library. Reloading
    is opt-in and uses the same sealed-provider bracket as static TLS setup. -/
def serve (options : LeanNet.HTTP.CLI.Options) (certificate privateKey : String)
    (host : String := "127.0.0.1") (port : UInt16 := 8443) : IO Unit := do
  let http ← options.httpConfig
  let tls : Reactor.Config := {
    certificateChain := certificate
    privateKey
    -- Always start the off-loop loader so SIGHUP can reload certificates;
    -- without --reload-certs-ms it only acts on explicit (signal) requests.
    reload := some { intervalMs := (options.reloadCertsMs.getD 0).toUInt64 } }
  if let some root := options.staticRoot then
    let bytes := options.staticMemoryMiB * 1024 * 1024
    ReactorServer.serveStaticRoot root tls
      { builder := { maxFileBytes := bytes, maxPackBytes := bytes }, residentBytes := bytes }
      http host port
  else ReactorServer.serveFactory (fun _ => pure LeanNet.HTTP2.demoHandlers) tls http host port

end LeanNetTLS.CLI
