import LeanNet.HTTP.ReactorServer

open LeanNet LeanNet.HTTP1

private def handlers (_worker : Nat) : IO Handlers := do
  let cancelled ← IO.mkRef (#[] : Array String)
  let completed ← IO.mkRef (0 : Nat)
  let started ← IO.mkRef (0 : Nat)
  return {
    onRequest := fun _ => pure { response := { status := 500 } }
    onHeaders := fun head _ => do
      if head.target == "/refuse".toUTF8 then
        return .reject { response := {
          status := 403
          headers := #[{ name := "x-early", value := "checked".toUTF8 }]
          body := "refused".toUTF8 } }
      return .accept none
    onRequestDeferred := some fun request => do
      if request.target == "/stats".toUTF8 then
        return .immediate { response := { body :=
          (s!"completed={← completed.get};started={← started.get};" ++ String.intercalate "," (← cancelled.get).toList).toUTF8 } }
      if request.target == "/immediate".toUTF8 then
        return .immediate { response := { body := "immediate".toUTF8 } }
      started.modify (· + 1)
      let target := String.fromUTF8! request.target
      let delay := if target == "/slow" then 300 else if target == "/fast" then 0 else 10000
      let ready := (← Reactor.nowMs) + delay.toUInt64
      return .deferred {
        retainedBytes := if target == "/oversize" then 100000 else if target == "/big" then 5000 else 0
        timeoutMs := if target == "/timeout" then 60 else 30000
        poll := do
          if target == "/failed" then throw (IO.userError "injected adapter failure")
          if (← Reactor.nowMs) < ready then return none
          completed.modify (· + 1)
          return some { response := { body := target.toUTF8 } }
        cancel := fun reason => do
          cancelled.modify (·.push (reprStr reason))
          IO.eprintln s!"cancel={reprStr reason}" }
  }

def main (args : List String) : IO Unit := do
  let some port := args.head?.bind String.toNat? | throw (IO.userError "usage: fixture PORT")
  if port == 0 || port > 65535 then throw (IO.userError "invalid port")
  HTTP.ReactorServer.serveFactory handlers {
    workers := 1
    server := { maxClients := 16 }
    shutdownDrainMs := 100
    deferred := {
      maxPending := 3
      maxPendingPerClient := 2
      maxRetainedBytes := 8192
      maxTimeoutMs := 1000
      pollIntervalMs := 2 } }
    "127.0.0.1" port.toUInt16
