import LeanNet.HTTP.Observability

open LeanNet.HTTP.Observability

private def check (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

private partial def waitFor (condition : IO Bool) (deadline : Nat) : IO Unit := do
  if ← condition then return
  if (← IO.monoMsNow) >= deadline then throw (IO.userError "process sampler test deadline")
  IO.sleep 10
  waitFor condition deadline

def main : IO Unit := do
  let calls ← IO.mkRef (0 : Nat)
  let entered ← IO.mkRef false
  let release ← IO.mkRef false
  let sampler : IO ByteArray := do
    calls.modify (· + 1)
    if (← calls.get) == 1 then return "initial".toUTF8
    entered.set true
    waitFor release.get ((← IO.monoMsNow) + 3000)
    return "updated".toUTF8
  withHub (sampleProcessMetrics := some sampler) 1 none fun hub => do
    try
      waitFor entered.get ((← IO.monoMsNow) + 5000)
      -- A blocked collector cannot block a scrape or cause another collection.
      for _ in [:100] do
        check ((← hub.processMetrics) == "initial".toUTF8) "collector replaced its cache before completion"
      check ((← calls.get) == 2) "scrapes invoked process collection"
      release.set true
      waitFor (do return (← hub.processMetrics) == "updated".toUTF8) ((← IO.monoMsNow) + 3000)
    finally release.set true

  let calls ← IO.mkRef (0 : Nat)
  let failing : IO ByteArray := do
    calls.modify (· + 1)
    if (← calls.get) == 1 then return "initial".toUTF8
    throw (IO.userError "injected process sampler failure")
  let failed ← try
      withHub (sampleProcessMetrics := some failing) 1 none fun hub => do
        waitFor (do
          try hub.check; return false
          catch _ => return true) ((← IO.monoMsNow) + 5000)
        let rejected ← try let _ ← hub.processMetrics; pure false catch _ => pure true
        check rejected "failed collector continued serving stale gauges"
      pure false
    catch error => pure ((error.toString.splitOn "injected process sampler failure").length > 1)
  check failed "collector failure did not propagate through its lifetime bracket"
  withHub 1 none fun hub => do
    hub.check
    check (← hub.processMetrics).isEmpty "sampler state escaped its hub"
  IO.println "Process metrics cache, failure propagation and bounded collector lifetime passed"
