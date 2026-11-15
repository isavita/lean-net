import LeanNet.Gate.Gate

/-! Reproducible, single-thread gate microbenchmark. `IO.getNumHeartbeats`
counts the Lean runtime's small allocations on this thread; it does not count
large allocations or establish a zero-GC property for the server. -/

open LeanNet LeanNet.Gate LeanNet.HTTP

private def fail (message : String) : IO α := throw (IO.userError message)

private def policyFor (spec : Spec) : IO Policy :=
  match Policy.compile spec with
  | .ok policy => pure policy
  | .error error => fail (toString error)

private def sample (label : String) (count : Nat) (run : IO Bool) : IO Unit := do
  let warmup := min count 5000
  for _ in [:warmup] do
    unless ← run do fail s!"{label} warmup rejected a valid head"
  let beforeAlloc ← IO.getNumHeartbeats
  let beforeNs ← IO.monoNanosNow
  let mut admitted := 0
  for _ in [:count] do
    if ← run then admitted := admitted + 1
  let afterNs ← IO.monoNanosNow
  let afterAlloc ← IO.getNumHeartbeats
  if admitted != count then fail s!"{label} admitted only {admitted}/{count} heads"
  let smallAlloc := afterAlloc - beforeAlloc
  let elapsed := afterNs - beforeNs
  let perRequest := Float.ofNat smallAlloc / Float.ofNat count
  let nsPerRequest := Float.ofNat elapsed / Float.ofNat count
  IO.println s!"\{\"case\":\"{label}\",\"requests\":{count},\"small_allocations\":{smallAlloc},\"small_allocations_per_request\":{perRequest},\"elapsed_ns\":{elapsed},\"ns_per_request\":{nsPerRequest}}"

def main (args : List String) : IO Unit := do
  let count := (args.head?.bind String.toNat?).getD 100000
  if count < 1000 then fail "usage: lean-net-gate-perf [ITERATIONS >= 1000]"
  let head : Admission.Head := {
    protocol := .http11, method := "GET", target := "/health".toUTF8,
    authority := "example.com".toUTF8,
    headers := #[{ name := "host", value := "example.com".toUTF8 }]
  }
  let facts := Transport.Facts.forTesting false (peer := ByteArray.mk #[127, 0, 0, 1])
  let hostSpec := Spec.hostsOnly #["example.com"]
  let hostPolicy ← policyFor hostSpec
  let routeSpec ← match Spec.parse "host example.com { tls sni off ; route GET /health -> app }" with
    | .ok spec => pure spec
    | .error error => fail (toString error)
  let routePolicy ← policyFor routeSpec
  sample "disabled-reference" count (pure true)
  sample "host-only-gate" count do
    return (← Gate.decide { spec := hostSpec } hostPolicy 0 facts head).isOk
  sample "route-gate" count do
    return (← Gate.decide { spec := routeSpec } routePolicy 0 facts head).isOk
