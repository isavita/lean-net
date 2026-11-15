import LeanNet.Gate.Gate
import LeanNet.FFI.Errno

/-! Native lock-free GCRA rate limiter (`c/ratelimit.h`), shared by all
    workers. Unkeyed rules (`global`, per `route`) use per-worker leases
    reserved with one CAS; keyed rules (`client-ip`, `principal`,
    `header NAME`) use a fixed-size, SipHash-indexed table. Admissions never
    exceed a rule's rate and burst; unused leased cells may expire. -/

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
def withLimiter (spec : Spec) (workers : Nat) (use : Handle → IO α) (keyedSlots : Nat := 65536) : IO α := do
  if spec.rates.isEmpty then throw (IO.userError "rate limiter needs at least one ratelimit rule")
  let routeCount ← match Policy.compile spec with
    | .ok policy => pure policy.routeCount
    | .error error => throw (IO.userError (toString error))
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
