import LeanNet.Reactor.Basic

/-- Startup-only native parallelism hint; no reactor, worker or socket starts. -/
def main : IO Unit := do
  let count ← LeanNet.Reactor.cpuCount
  IO.println ("{\"cpu_count\":" ++ toString count ++ "}")
