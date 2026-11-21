import Std.Data.HashMap
import LeanNet.Gate.RateLimiter
import LeanNetSpec.RateLimit

/-! Differential test: the native GCRA limiter (`c/ratelimit.h`) against the
executable model in `LeanNetSpec.RateLimit`, whose properties are proved
there. Every acquire must return the same admission and the same retry delay.
It also replays `leases_exceed_burst` against the C code. -/

open LeanNet.Gate
open LeanNetSpec.RateLimit

private def fail (message : String) : IO α := throw (IO.userError message)

private def workers : Nat := 3

/-- Rule `i` of the spec; `(tokens, periodMs, burst, keyed, route)`. -/
private def rules : Array (Nat × Nat × Nat × Bool × Bool) := #[
  (100000, 1000, 50, false, false),  -- leased: 64-cell cap, burst 50
  (7, 1000, 3, false, false),        -- one-cell lease: strict GCRA
  (3001, 1000, 10, false, false),    -- the `leases_exceed_burst` parameters
  (5, 1000, 2, true, false),         -- keyed by client address
  (3, 2000, 4, false, true)]         -- one bucket per route

private def specText : String :=
  "ratelimit fast 100000/s burst 50 by global\n" ++
  "ratelimit slow 7/s burst 3 by global\n" ++
  "ratelimit odd 3001/s burst 10 by global\n" ++
  "ratelimit perkey 5/s burst 2 by client-ip\n" ++
  "ratelimit routed 3/2s burst 4 by route\n" ++
  "host a.example.com { route GET /x -> app { limit fast } }"

private def nativeRule (index : Nat) : NativeRule :=
  let (tokens, period, burst, keyed, _) := rules[index]!
  NativeRule.ofSpec tokens period burst workers keyed

/-- Small deterministic generator (64-bit LCG). -/
private structure Gen where
  state : UInt64

private def Gen.next (g : Gen) (bound : Nat) : Gen × Nat :=
  let state := g.state * 6364136223846793005 + 1442695040888963407
  ({ state }, ((state >>> 33).toNat) % bound)

private def keys : Array ByteArray := #["10.0.0.1".toUTF8, "10.0.0.2".toUTF8, "2001:db8::7".toUTF8]
private def deltas : Array Nat := #[0, 0, 0, 0, 1, 1, 2, 3, 5, 17, 60, 140, 333, 700, 1500]

private def replayLeaseTrace (limiter : Limiter) (start : Nat) : IO Unit := do
  let rule : UInt32 := 2
  for w in [0, 1] do
    let delay ← limiter.acquire w.toUInt32 rule 0 ByteArray.empty start.toUInt64
    if delay != 0 then fail s!"lease trace: worker {w} refused at t0"
  let mut admittedAtInstant := 0
  for w in [0, 1, 2] do
    for _ in [:4] do
      if (← limiter.acquire w.toUInt32 rule 0 ByteArray.empty (start + 1).toUInt64) == 0 then
        admittedAtInstant := admittedAtInstant + 1
  -- The model's `leases_exceed_burst` value: 11 cells in one instant, burst 10.
  if admittedAtInstant != 11 then
    fail s!"lease trace: native admitted {admittedAtInstant} at one instant, model proves 11"
  IO.println s!"lease trace: native limiter admitted {admittedAtInstant} cells at one instant (burst 10), as modeled"

private def differential (limiter : Limiter) (start events : Nat) (seed : UInt64) :
    IO Unit := do
  let mut gen : Gen := { state := seed }
  let mut now := start
  let mut buckets : Std.HashMap (Nat × Nat) NativeBucket := {}
  let mut admitted := 0
  let mut refused := 0
  let mut refusedByRule : Array Nat := Array.replicate rules.size 0
  for step in [:events] do
    let (g1, delta) := gen.next deltas.size
    let (g2, ruleIndex) := g1.next rules.size
    let (g3, worker) := g2.next workers
    let (g4, keyIndex) := g3.next keys.size
    let (g5, scopePick) := g4.next 2
    gen := g5
    -- Every fifth block of 400 acquires lands in one millisecond, so leased
    -- buckets also exhaust their burst and leases.
    let storm := (step / 400) % 5 == 0
    now := now + (if storm then 0 else deltas[delta]!)
    let (_, _, _, keyed, routed) := rules[ruleIndex]!
    let scope := if routed then scopePick else 0
    let key := if keyed then keys[keyIndex]! else ByteArray.empty
    let native ← limiter.acquire worker.toUInt32 ruleIndex.toUInt32 scope.toUInt32 key now.toUInt64
    let bucket := buckets.getD (ruleIndex, scope) {}
    let (bucket', model) := NativeModel.acquire (nativeRule ruleIndex) bucket worker key now
    buckets := buckets.insert (ruleIndex, scope) bucket'
    if native.toNat != model then
      fail s!"step {step}: rule {ruleIndex} worker {worker} scope {scope} key {keyIndex} t+{now - start}ms: native {native}, model {model}"
    if model == 0 then admitted := admitted + 1
    else
      refused := refused + 1
      refusedByRule := refusedByRule.modify ruleIndex (· + 1)
  if admitted == 0 || refusedByRule.any (· == 0) then
    fail s!"degenerate trace: {admitted} admitted, refusals per rule {refusedByRule}"
  IO.println s!"seed {seed}: {events} acquires agree ({admitted} admitted, refusals per rule {refusedByRule})"

def main (args : List String) : IO Unit := do
  let events := (args.head?.bind String.toNat?).getD 20000
  let spec ← match Spec.parse specText with
    | .ok spec => pure spec
    | .error error => fail s!"spec: {repr error}"
  -- Each run gets a fresh limiter: the model starts from empty buckets.
  for seed in [1, 2, 3, 0x5eed] do
    RateLimiter.withLimiter spec workers fun handle => do
      let start := (← IO.monoMsNow) + 10
      differential handle.limiter start events seed.toUInt64
  RateLimiter.withLimiter spec workers fun handle => do
    replayLeaseTrace handle.limiter ((← IO.monoMsNow) + 10)
  IO.println "rate limiter differential tests passed"
