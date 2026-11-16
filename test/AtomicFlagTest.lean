import LeanNet.AtomicFlag

open LeanNet

@[extern "lean_net_atomic_flag_live"]
private opaque liveFlags : IO UInt64

private def check (ok : Bool) (message : String) : IO Unit :=
  unless ok do throw (IO.userError message)

private def transientFlags : IO Unit := do
  for _ in [:10000] do
    let flag ← AtomicFlag.new
    check (!(← flag.isSet)) "new flag must be unset"
    flag.set
    flag.set
    check (← flag.isSet) "set flag regressed"

private def sharedFlag : IO Unit := do
  let flag ← AtomicFlag.new
  let start ← IO.Promise.new
  let mut tasks : Array (Task (Except IO.Error Unit)) := #[]
  for worker in [:8] do
    let task ← IO.asTask do
      let _ ← IO.wait start.result?
      let mut observed := false
      for iteration in [:10000] do
        if worker % 2 == 0 && iteration >= 50 then flag.set
        let current ← flag.isSet
        check (!observed || current) "shared flag lost a published transition"
        observed := observed || current
      return ()
    tasks := tasks.push task
  start.resolve ()
  for task in tasks do
    match ← IO.wait task with
    | .ok () => pure ()
    | .error error => throw error
  check (← flag.isSet) "concurrent setters did not publish"

private def retainedAlias : IO Unit := do
  let aliases ← do
    let flag ← AtomicFlag.new
    flag.set
    pure #[flag, flag]
  let some first := aliases[0]? | throw (IO.userError "missing first alias")
  let some second := aliases[1]? | throw (IO.userError "missing second alias")
  check (← first.isSet) "alias lost storage after original reference dropped"
  check (← second.isSet) "second alias lost storage"

def main : IO Unit := do
  let before ← liveFlags
  transientFlags
  check ((← liveFlags) == before) "transient native flags leaked"
  retainedAlias
  check ((← liveFlags) == before) "aliased native flag leaked"
  for _ in [:16] do sharedFlag
  check ((← liveFlags) == before) "cross-thread native flags leaked"
  IO.println "atomic flag: fresh/idempotent, cross-thread monotonicity, alias lifetime and reclamation passed"
