import LeanNet.Gate.RateLimiter

/-! A reloadable gate for a running server.

`withLive` validates a policy, creates the native rate limiter (if the policy
declares rules) and process counters, and yields a `Live` handle:
`Live.factory` for `ReactorServerConfig.admission`, `Live.reloadFile` for
`onReload` (SIGHUP), and `Live.metrics` for Prometheus.

A reload compiles and validates the new text off the request path and
publishes it atomically. Invalid text keeps the current policy and counts a
failed reload. Each worker notices the new generation with one relaxed atomic
load and compiles its own private copy, so no policy object is shared across
cores. In-flight requests keep the snapshot they were admitted under. Rate
rules (`ratelimit` lines) are fixed for the limiter's lifetime: a reload that
changes them, or adds more routes than the limiter reserved, is refused. -/

namespace LeanNet.Gate

open LeanNet.HTTP

@[extern "lean_net_counters_new"] private opaque countersNew (count : UInt32) : IO UInt64
@[extern "lean_net_counters_add"] private opaque countersAdd (handle : UInt64) (index : UInt32) (amount : UInt64) : IO Unit
@[extern "lean_net_counters_get"] private opaque countersGet (handle : UInt64) (index : UInt32) : IO UInt64
@[extern "lean_net_counters_get32"] private opaque countersGet32 (handle : UInt64) (index : UInt32) : IO UInt32
@[extern "lean_net_counters_worker_add"] private opaque countersWorkerAdd (handle : UInt64) (worker : UInt32) : IO Unit
@[extern "lean_net_counters_worker_sum"] private opaque countersWorkerSum (handle : UInt64) : IO UInt64
@[extern "lean_net_counters_free"] private opaque countersFree (handle : UInt64) : IO Unit

/-- Counter layout: generation, reloads ok, reloads failed, admitted, then
    one per rejection reason. -/
private def counterGeneration : UInt32 := 0
private def counterReloads : UInt32 := 1
private def counterReloadFailures : UInt32 := 2
private def counterReason (reason : Reason) : UInt32 := (4 + reason.index).toUInt32

structure Live where
  private mk ::
  private counters : UInt64
  private current : IO.Ref Config
  private routeCapacity : Nat
  limiter : Option RateLimiter.Handle

private def sameRates (a b : Array RateSpec) : Bool :=
  a.size == b.size && (a.zip b).all fun (x, y) =>
    x.name == y.name && x.tokens == y.tokens && x.periodMs == y.periodMs && x.burst == y.burst && x.key == y.key

/-- The validated configuration currently published. -/
def Live.config (live : Live) : IO Config := live.current.get

def Live.generation (live : Live) : IO UInt64 := countersGet live.counters counterGeneration

/-- Validate and publish a new policy. Returns the error and keeps the
    current policy when the text is invalid. -/
def Live.reload (live : Live) (spec : Spec) : IO (Except String UInt64) := do
  let previous ← live.current.get
  let fail := fun (message : String) => do
    countersAdd live.counters counterReloadFailures 1
    return .error message
  if !sameRates previous.spec.rates spec.rates then
    return ← fail "ratelimit rules changed; restart the server to change them"
  let generation := (← live.generation) + 1
  let next := { previous with spec, generation }
  match next.validate with
  | .error error => fail (toString error)
  | .ok policy =>
    if !spec.rates.isEmpty && policy.routeCount > live.routeCapacity then
      return ← fail s!"policy has {policy.routeCount} routes; the rate limiter reserved {live.routeCapacity}"
    live.current.set next
    countersAdd live.counters counterGeneration 1
    countersAdd live.counters counterReloads 1
    return .ok generation

/-- Re-read and publish a policy file (for `ReactorServerConfig.onReload`). -/
def Live.reloadFile (live : Live) (path : System.FilePath) : IO Unit := do
  let text ← try IO.FS.readFile path catch error =>
    countersAdd live.counters counterReloadFailures 1
    IO.eprintln s!"lean-net: gate reload failed: {error}"
    return
  match Spec.parse text with
  | .error error =>
    countersAdd live.counters counterReloadFailures 1
    IO.eprintln s!"lean-net: gate reload failed: {error}"
  | .ok spec =>
    match ← live.reload spec with
    | .ok generation => IO.eprintln s!"lean-net: gate policy generation {generation} active"
    | .error message => IO.eprintln s!"lean-net: gate reload failed: {message}"

/-- Per-worker hook. The worker checks the generation counter on each head
    and recompiles its private policy only when it changed. -/
def Live.factory (live : Live) : Admission.Factory := fun worker => do
  let compile := fun (config : Config) => match Policy.compile config.spec config.generation with
    | .ok policy => pure policy
    | .error error => throw (IO.userError (toString error))
  let initial ← live.current.get
  let cache ← IO.mkRef ((← live.generation).toUInt32, initial, ← compile initial)
  let lane := worker.toUInt32
  return { decide := fun facts head => do
    let generation ← countersGet32 live.counters counterGeneration
    let (seen, config, policy) ← cache.get
    let (config, policy) ← if generation == seen then pure (config, policy) else do
      let config ← live.current.get
      let policy ← compile config
      cache.set (generation, config, policy)
      pure (config, policy)
    match ← decide config policy worker facts head with
    | .ok verdict =>
      countersWorkerAdd live.counters lane
      return verdict
    | .error rejection =>
      countersAdd live.counters (counterReason rejection.reason) 1
      config.app.onReject rejection head
      return .reject rejection.toAdmission }

/-- Prometheus exposition: policy generation, reloads, admissions,
    rejections by reason and rate-limiter outcomes. -/
def Live.metrics (live : Live) : IO ByteArray := do
  let get := countersGet live.counters
  let mut out := "# TYPE lean_net_gate_policy_generation gauge\n" ++
    s!"lean_net_gate_policy_generation {← get counterGeneration}\n" ++
    "# TYPE lean_net_gate_reloads_total counter\n" ++
    s!"lean_net_gate_reloads_total\{result=\"ok\"} {← get counterReloads}\n" ++
    s!"lean_net_gate_reloads_total\{result=\"failed\"} {← get counterReloadFailures}\n" ++
    "# TYPE lean_net_gate_admitted_total counter\n" ++
    s!"lean_net_gate_admitted_total {← countersWorkerSum live.counters}\n" ++
    "# TYPE lean_net_gate_rejections_total counter\n"
  for reason in Reason.all do
    out := out ++ s!"lean_net_gate_rejections_total\{reason=\"{reason.label}\"} {← get (counterReason reason)}\n"
  if let some limiter := live.limiter then
    let stats ← limiter.stats
    out := out ++ "# TYPE lean_net_rate_limit_decisions_total counter\n" ++
      s!"lean_net_rate_limit_decisions_total\{result=\"allowed\"} {stats.allowed}\n" ++
      s!"lean_net_rate_limit_decisions_total\{result=\"limited\"} {stats.limited}\n"
  return out.toUTF8

/-- Validate `config`, create the limiter (when the policy has rate rules)
    for `workers`, and bracket a reloadable gate. `routeHeadroom` reserves
    rate-limit buckets for routes added by later reloads. -/
def withLive (config : Config) (workers : Nat) (use : Live → IO α) (routeHeadroom : Nat := 1024) : IO α := do
  let policy ← match (if config.spec.rates.isEmpty then config else { config with limiter := some { acquire := fun _ _ _ _ _ => pure 0 } }).validate with
    | .ok policy => pure policy
    | .error error => throw (IO.userError (toString error))
  let raw ← countersNew (4 + Reason.all.size).toUInt32
  let code := Errno.decode raw
  if code <= 0 then throw (IO.userError "gate counters allocation failed")
  let counters := raw
  let routeCapacity := policy.routeCount + routeHeadroom
  try
    if config.spec.rates.isEmpty then
      use ⟨counters, ← IO.mkRef config, routeCapacity, none⟩
    else
      let spec := config.spec
      RateLimiter.withLimiter spec workers (routeCapacity := routeCapacity) fun handle => do
        let config := { config with limiter := some handle.limiter }
        use ⟨counters, ← IO.mkRef config, routeCapacity, some handle⟩
  finally
    countersFree counters

end LeanNet.Gate
