import LeanNet.Gate.Gate
import LeanNet.FFI.Errno

/-! Native lock-free GCRA rate limiter (`c/ratelimit.h`), shared by all
    workers. Unkeyed rules (`global`, per `route`) use per-worker leases
    reserved with one CAS; keyed rules (`client-ip`, `principal`,
    `header NAME`) use a fixed-size, SipHash-indexed table. Unused leased cells
    may expire.

    Guarantees (proved in `LeanNetSpec.RateLimit`, checked against this
    native code by `test/RateLimitDifferential.lean`): keyed rules, and
    unkeyed rules whose lease is one cell, admit at most `burst + ⌊w / T⌋`
    cells in any window of length `w`. A leased unkeyed rule reserves each
    lease through the same bucket, but spends it up to one lease lifetime
    (`lease × T`, about 5 ms) later, so a short window can see up to the
    outstanding leased cells above the burst (`leases_exceed_burst`). -/

namespace LeanNet.Gate.RateLimiter

@[extern "lean_net_rl_new"]
private opaque ffiNew (rules : @& ByteArray) (workers slots : UInt32) (random : @& ByteArray) (nowMs : UInt64) : IO UInt64
@[extern "lean_net_rl_acquire"]
private opaque ffiAcquire (handle : UInt64) (worker rule scope : UInt32) (key : @& ByteArray) (nowMs : UInt64) : IO UInt32
@[extern "lean_net_rl_stats"]
private opaque ffiStats (handle : UInt64) : IO (UInt64 × UInt64)
@[extern "lean_net_rl_free"]
private opaque ffiFree (handle : UInt64) : IO UInt64

private def le32 (n : Nat) : ByteArray :=
  ByteArray.mk #[n.toUInt8, (n >>> 8).toUInt8, (n >>> 16).toUInt8, (n >>> 24).toUInt8]

/-- Native rule table: tokens, period, burst, kind (0 global, 1 per route,
    2 keyed) and scope count (route rules get one bucket per route). -/
def encodeRules (rates : Array RateSpec) (routeCount : Nat) : ByteArray :=
  rates.foldl (init := ByteArray.empty) fun out rate =>
    let kind := match rate.key with | .global => 0 | .route => 1 | _ => 2
    out ++ le32 rate.tokens ++ le32 rate.periodMs ++ le32 rate.burst ++ le32 kind ++ le32 (routeCount + 1)

structure Stats where
  allowed : UInt64
  limited : UInt64

/-- A live limiter. Valid only inside `withLimiter`. -/
structure Handle where
  private mk ::
  private handle : UInt64
  limiter : Limiter
  stats : IO Stats

/-- Create the shared limiter for `spec` and `workers`, run `use`, then free
    it. Keep every worker inside this bracket. `keyedSlots` (a power of two)
    bounds the keyed table (8 bytes per slot). -/
def withLimiter (spec : Spec) (workers : Nat) (use : Handle → IO α) (keyedSlots : Nat := 65536)
    (routeCapacity : Option Nat := none) : IO α := do
  if spec.rates.isEmpty then throw (IO.userError "rate limiter needs at least one ratelimit rule")
  -- These values cross a UInt32 FFI boundary. Check them before conversion so
  -- an oversized configuration cannot wrap into a smaller, permissive limit.
  if workers == 0 || workers > 256 then
    throw (IO.userError "rate limiter workers must be between 1 and 256")
  if keyedSlots > 16777216 then
    throw (IO.userError "rate limiter keyed slots exceed the native maximum")
  let compiled ← match Policy.compile spec with
    | .ok policy => pure policy.routeCount
    | .error error => throw (IO.userError (toString error))
  -- Route-keyed rules reserve one bucket per route, plus headroom for reloads.
  let routeCount := max compiled (routeCapacity.getD compiled)
  if routeCount >= 65536 then
    throw (IO.userError "rate limiter route capacity exceeds 65535")
  let raw ← ffiNew (encodeRules spec.rates routeCount) workers.toUInt32 keyedSlots.toUInt32
    (← IO.getRandomBytes 16) (← IO.monoMsNow).toUInt64
  let code := Errno.decode raw
  if code <= 0 then throw (← Errno.error "rate limiter setup" (if code == 0 then -22 else code))
  let handle := raw
  let limiter : Limiter := { acquire := fun worker rule scope key now => ffiAcquire handle worker rule scope key now }
  try
    use { handle, limiter, stats := do let (allowed, limited) ← ffiStats handle; return { allowed, limited } }
  finally
    let _ ← ffiFree handle

end LeanNet.Gate.RateLimiter
