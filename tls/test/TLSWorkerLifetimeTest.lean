import LeanNetTLS.Reactor

open LeanNet

private def expectClosed (label : String) (action : IO α) : IO Unit := do
  let rejected ← try
      let _ ← action
      pure false
    catch error =>
      pure ((error.toString.splitOn "TLS worker is closed").length > 1)
  unless rejected do throw (IO.userError s!"escaped TLS {label} did not reject its closed native owner")

def main (args : List String) : IO UInt32 := do
  let some certificate := args[0]? | throw (IO.userError "certificate required")
  let some key := args[1]? | throw (IO.userError "private key required")
  let config : LeanNetTLS.Reactor.Config := {
    certificateChain := certificate
    privateKey := key
    shutdownTimeoutMs := 50 }
  let native : Reactor.Config := {
    maxConnections := 1
    maxEvents := 8
    maxWrites := 1
    buffers4k := 3
    buffers16k := 0
    buffers64k := 0 }
  LeanNetTLS.Reactor.withBundle config fun bundle => do
    Reactor.withReactor native fun reactor => do
      let escaped ← IO.mkRef (none : Option HTTP.Transport.Worker)
      let diagnostics ← IO.mkRef (none : Option (IO LeanNetTLS.Reactor.Stats))
      LeanNetTLS.Reactor.withWorkerStats bundle config reactor 1 fun worker stats => do
        escaped.set (some worker)
        diagnostics.set (some stats)
      let some worker ← escaped.get | throw (IO.userError "missing escaped worker")
      expectClosed "poll" worker.poll
      expectClosed "event" (worker.event .wake)
      expectClosed "pending-work check" worker.hasWork
      expectClosed "shutdown cutoff" (worker.shutdownBefore 1)
      expectClosed "shutdown start" worker.beginShutdown
      expectClosed "shutdown completion" worker.shutdownComplete
      let some stats ← diagnostics.get | throw (IO.userError "missing escaped diagnostics")
      expectClosed "diagnostics" stats
  IO.println "TLS escaped worker callbacks reject closed native owners"
  return 0
