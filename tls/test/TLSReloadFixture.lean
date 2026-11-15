import LeanNetTLS.ReactorServer

open LeanNet

private def handlers (worker : Nat) (bundle : LeanNetTLS.Reactor.Bundle)
    (diagnostics : IO LeanNetTLS.Reactor.Stats) : HTTP1.Handlers := {
  onRequest := fun request => do
    let base : Array HTTP1.Header := #[{ name := "X-Worker", value := (toString worker).toUTF8 }]
    if request.target == "/reload".toUTF8 then
      let ticket ← bundle.requestReload
      return { response := { headers := base, body := (toString ticket).toUTF8 } }
    if request.target == "/status".toUTF8 then
      let status ← bundle.reloadStatus
      let stats ← diagnostics
      let text := String.intercalate "," [toString status.generation, toString status.attempts,
        toString status.publications, toString status.failures, toString status.lastError,
        toString status.liveVersions, toString status.loaderThreads,
        toString status.requested, toString status.completed]
      return { response := {
        headers := base.push { name := "X-Owner-Violations", value := (toString stats.ownerViolations).toUTF8 }
        body := text.toUTF8 } }
    return { response := { headers := base, body := "reload-ok".toUTF8 } } }

def main (args : List String) : IO UInt32 := do
  let some certA := args[0]? | throw (IO.userError "missing alpha certificate")
  let some keyA := args[1]? | throw (IO.userError "missing alpha key")
  let some certB := args[2]? | throw (IO.userError "missing beta certificate")
  let some keyB := args[3]? | throw (IO.userError "missing beta key")
  let some port := args[4]?.bind String.toNat? | throw (IO.userError "missing port")
  let some interval := args[5]?.bind String.toNat? | throw (IO.userError "missing reload interval")
  if port == 0 || port > 65535 || interval > 9223372036854775807 then throw (IO.userError "invalid fixture limits")
  let config : LeanNetTLS.Reactor.Config := {
    certificateChain := certA
    privateKey := keyA
    hosts := #[{ name := "alpha.test", certificateChain := certA, privateKey := keyA },
               { name := "beta.test", certificateChain := certB, privateKey := keyB }]
    reload := some { intervalMs := interval.toUInt64 }
    queueCapacity := 1
    handshakeTimeoutMs := 5000
    shutdownTimeoutMs := 500 }
  let http : HTTP.ReactorServerConfig := {
    workers := 4
    server := { maxClients := 32 }
    shutdownDrainMs := 1000 }
  LeanNetTLS.Reactor.withBundle config fun bundle =>
    HTTP.ReactorServer.serveWorkerFactory
      (fun worker maxClients reactor use =>
        LeanNetTLS.Reactor.withWorkerStats bundle config reactor maxClients fun transport diagnostics =>
          use transport (handlers worker bundle diagnostics)) http "127.0.0.1" port.toUInt16
  return 0
