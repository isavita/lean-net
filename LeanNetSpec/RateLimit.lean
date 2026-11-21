/-! # GCRA rate limiting: specification and proofs

A model of the native limiter in `c/ratelimit.h`. GCRA keeps one theoretical
arrival time (`tat`) per bucket. With emission interval `T` and burst `B` the
tolerance is `τ = B·T`; `k` cells are admitted at time `now` when
`max tat now + k·T ≤ now + τ`, and admission moves `tat` to that sum. The
native code writes the same test as `ahead + k·T ≤ τ` with
`ahead = max tat now - now`; in ℕ the two are equivalent.

Times are naturals in one fixed unit: nanoseconds for unkeyed buckets and
100 µs ticks for keyed buckets.

Proved here, for any history (any starting `tat`) and any arrival order:

* `admitted_window` — cells admitted at times in `[s, e]` satisfy
  `s + cells·T ≤ e + τ`, so `cells ≤ B + (e - s) / T`
  (`admitted_window_div`). This is the guarantee of keyed rules and of unkeyed
  rules whose lease is one cell (`leaseStep_one`).
* `reserve_of_drained`, `admitted_paced` — traffic within the rate is never
  refused.
* `retry_admits`, `retry_exact` — the delay sent with a refusal is exactly
  when the next cell becomes admissible (the `Retry-After` value).
* `keyed_stricter` — the keyed table's 100 µs quantization never loosens a
  rule.

Per-worker leases reserve several cells with one CAS and spend them later.
`leases_exceed_burst` is a checked trace with the native parameters of a
`3001/s burst 10` rule on three workers in which 11 cells are admitted at one
instant, so "admissions never exceed a rule's burst" does not hold for leased
buckets. `test/RateLimitDifferential.lean` replays the same trace against the
C implementation and compares random traces with `NativeModel`. -/

namespace LeanNetSpec.RateLimit

/-- A GCRA rule: emission interval `T` and tolerance `τ`. Configured rules
have `τ = B·T` for burst `B`; keyed rules round `τ` to 100 µs ticks. -/
structure Rule where
  interval : Nat
  tau : Nat
  deriving Repr, DecidableEq

/-- The rule of `B` cells per burst. -/
def Rule.ofBurst (interval burst : Nat) : Rule := { interval, tau := burst * interval }

/-- Reserve `k` cells at `now`. `some tat'` admits them; `none` refuses and
leaves the bucket unchanged. -/
def reserve (r : Rule) (tat now k : Nat) : Option Nat :=
  if max tat now + k * r.interval ≤ now + r.tau then some (max tat now + k * r.interval)
  else none

/-- Delay after which one cell becomes admissible, absent other traffic. -/
def retryAfter (r : Rule) (tat now : Nat) : Nat :=
  max tat now + r.interval - (now + r.tau)

/-- Process arrivals `(time, cells)` in order; return the final `tat` and the
number of cells admitted. Refused arrivals leave `tat` unchanged. -/
def run (r : Rule) : Nat → List (Nat × Nat) → Nat × Nat
  | tat, [] => (tat, 0)
  | tat, (t, k) :: rest =>
    match reserve r tat t k with
    | some tat' => ((run r tat' rest).1, k + (run r tat' rest).2)
    | none => run r tat rest

/-- Cells admitted by `run`. -/
def admitted (r : Rule) (tat : Nat) (events : List (Nat × Nat)) : Nat :=
  (run r tat events).2

theorem reserve_some {r : Rule} {tat now k tat' : Nat} (h : reserve r tat now k = some tat') :
    tat' = max tat now + k * r.interval ∧ max tat now + k * r.interval ≤ now + r.tau := by
  unfold reserve at h
  split at h
  · cases h; exact ⟨rfl, ‹_›⟩
  · cases h

theorem reserve_none {r : Rule} {tat now k : Nat} (h : reserve r tat now k = none) :
    now + r.tau < max tat now + k * r.interval := by
  unfold reserve at h
  split at h
  · cases h
  · omega

private theorem admitted_cons (r : Rule) (tat t k : Nat) (rest : List (Nat × Nat)) :
    admitted r tat ((t, k) :: rest) =
      match reserve r tat t k with
      | some tat' => k + admitted r tat' rest
      | none => admitted r tat rest := by
  simp only [admitted, run]
  split <;> rfl

/-- A nonempty admission by time `e` is bounded by `e + τ` from its start. -/
private theorem admitted_upper (r : Rule) (e : Nat) :
    ∀ (events : List (Nat × Nat)) (tat : Nat), (∀ p ∈ events, p.1 ≤ e) →
      0 < admitted r tat events → tat + admitted r tat events * r.interval ≤ e + r.tau
  | [], tat, _, h => by simp [admitted, run] at h
  | (t, k) :: rest, tat, hin, hpos => by
    have ht : t ≤ e := hin (t, k) (by simp)
    have hrest : ∀ p ∈ rest, p.1 ≤ e := fun p hp => hin p (by simp [hp])
    rw [admitted_cons] at hpos ⊢
    cases hres : reserve r tat t k with
    | none =>
      rw [hres] at hpos
      dsimp only at hpos ⊢
      exact admitted_upper r e rest tat hrest hpos
    | some tat' =>
      rw [hres] at hpos
      dsimp only at hpos ⊢
      obtain ⟨rfl, hfit⟩ := reserve_some hres
      have hmax : tat ≤ max tat t := Nat.le_max_left _ _
      have hmax' : t ≤ max tat t := Nat.le_max_right _ _
      rw [Nat.add_mul]
      by_cases hz : admitted r (max tat t + k * r.interval) rest = 0
      · rw [hz, Nat.zero_mul]; omega
      · have ih := admitted_upper r e rest _ hrest (Nat.pos_of_ne_zero hz)
        omega

/-- **Window bound.** Whatever happened before, the cells admitted at times
in `[s, e]` fit the burst plus the rate over the window. Arrivals need not be
sorted, and refused arrivals are included in `events`. -/
theorem admitted_window (r : Rule) (tat s e : Nat) (events : List (Nat × Nat))
    (hse : s ≤ e) (hin : ∀ p ∈ events, s ≤ p.1 ∧ p.1 ≤ e) :
    s + admitted r tat events * r.interval ≤ e + r.tau := by
  induction events generalizing tat with
  | nil => simp [admitted, run]; omega
  | cons p rest ih =>
    obtain ⟨t, k⟩ := p
    have ht := hin (t, k) (by simp)
    have hrest : ∀ p ∈ rest, s ≤ p.1 ∧ p.1 ≤ e := fun p hp => hin p (by simp [hp])
    rw [admitted_cons]
    cases hres : reserve r tat t k with
    | none => exact ih tat hrest
    | some tat' =>
      obtain ⟨rfl, hfit⟩ := reserve_some hres
      have hmax' : t ≤ max tat t := Nat.le_max_right _ _
      dsimp only
      rw [Nat.add_mul]
      by_cases hz : admitted r (max tat t + k * r.interval) rest = 0
      · rw [hz, Nat.zero_mul]; omega
      · have up := admitted_upper r e rest _ (fun p hp => (hrest p hp).2)
          (Nat.pos_of_ne_zero hz)
        omega

/-- The window bound as a count: at most `⌊(e - s + τ) / T⌋` cells. -/
theorem admitted_window_div (r : Rule) (hT : 0 < r.interval) (tat s e : Nat)
    (events : List (Nat × Nat)) (hse : s ≤ e) (hin : ∀ p ∈ events, s ≤ p.1 ∧ p.1 ≤ e) :
    admitted r tat events ≤ (e - s + r.tau) / r.interval := by
  have h := admitted_window r tat s e events hse hin
  exact (Nat.le_div_iff_mul_le hT).mpr (by omega)

/-- For a configured rule: at most `B + ⌊(e - s) / T⌋` cells in `[s, e]`. -/
theorem admitted_window_burst (interval burst : Nat) (hT : 0 < interval) (tat s e : Nat)
    (events : List (Nat × Nat)) (hse : s ≤ e) (hin : ∀ p ∈ events, s ≤ p.1 ∧ p.1 ≤ e) :
    admitted (Rule.ofBurst interval burst) tat events ≤ burst + (e - s) / interval := by
  have h := admitted_window_div (Rule.ofBurst interval burst) hT tat s e events hse hin
  simp only [Rule.ofBurst] at h ⊢
  rw [Nat.add_mul_div_right _ _ hT] at h
  omega

/-- **No false refusals (1).** A drained bucket admits up to a burst at once. -/
theorem reserve_of_drained (r : Rule) (tat now k : Nat) (hd : tat ≤ now)
    (hk : k * r.interval ≤ r.tau) :
    reserve r tat now k = some (now + k * r.interval) := by
  have hmax : max tat now = now := Nat.max_eq_right hd
  unfold reserve
  rw [hmax, ite_eq_left (by omega)]

/-- Single cells arriving at least one interval apart, starting from a
drained bucket. -/
def Paced (T : Nat) : Nat → List (Nat × Nat) → Prop
  | _, [] => True
  | tat, (t, k) :: rest => k = 1 ∧ tat ≤ t ∧ Paced T (t + T) rest

/-- **No false refusals (2).** Traffic paced at the configured rate is
always admitted, for any burst of at least one. -/
theorem admitted_paced (r : Rule) (hb : r.interval ≤ r.tau) :
    ∀ (tat : Nat) (events : List (Nat × Nat)), Paced r.interval tat events →
      admitted r tat events = events.length
  | _, [], _ => rfl
  | tat, (t, k) :: rest, ⟨hk, ht, hrest⟩ => by
    subst hk
    rw [admitted_cons, reserve_of_drained r tat t 1 ht (by omega), Nat.one_mul]
    dsimp only
    rw [admitted_paced r hb (t + r.interval) rest hrest]
    simp [Nat.add_comm]

/-- **Retry-After admits.** Retrying a refused cell after the returned delay
(or later) succeeds when no other traffic arrived. -/
theorem retry_admits (r : Rule) (hb : r.interval ≤ r.tau) (tat now d : Nat)
    (hd : retryAfter r tat now ≤ d) : reserve r tat (now + d) 1 ≠ none := by
  intro h
  have hn := reserve_none h
  unfold retryAfter at hd
  have h1 : tat ≤ max tat now := Nat.le_max_left _ _
  have h2 : now ≤ max tat now := Nat.le_max_right _ _
  rw [Nat.one_mul] at hn
  by_cases hc : tat ≤ now + d
  · rw [Nat.max_eq_right hc] at hn; omega
  · rw [Nat.max_eq_left (by omega)] at hn; omega

/-- **Retry-After is exact.** Any earlier retry is still refused. -/
theorem retry_exact (r : Rule) (hb : r.interval ≤ r.tau) (tat now d : Nat)
    (hd : d < retryAfter r tat now) : reserve r tat (now + d) 1 = none := by
  unfold retryAfter at hd
  unfold reserve
  rw [ite_eq_right]
  intro hfit
  rw [Nat.one_mul] at hfit
  have h1 : tat ≤ max tat (now + d) := Nat.le_max_left _ _
  by_cases hc : tat ≤ now
  · rw [Nat.max_eq_right hc] at hd; omega
  · rw [Nat.max_eq_left (by omega)] at hd; omega

/-! ## Native rule parameters -/

/-- Native keyed time unit: 100 µs, in nanoseconds. -/
def tickNs : Nat := 100000

/-- Keyed rules store `tat` in ticks: the interval rounds up and the tolerance
rounds down, but is at least one interval. -/
def keyedRule (r : Rule) : Rule :=
  let interval := (r.interval + tickNs - 1) / tickNs
  { interval, tau := max (r.tau / tickNs) interval }

/-- **Quantization never loosens a keyed rule.** Its interval is at least the
configured one, and its tolerance is at most `max B 1` of its intervals. -/
theorem keyed_stricter (interval burst : Nat) :
    interval ≤ (keyedRule (Rule.ofBurst interval burst)).interval * tickNs ∧
      (keyedRule (Rule.ofBurst interval burst)).tau ≤
        max burst 1 * (keyedRule (Rule.ofBurst interval burst)).interval := by
  have htick : 0 < tickNs := by decide
  simp only [keyedRule, Rule.ofBurst]
  generalize hi : (interval + tickNs - 1) / tickNs = i
  have hceil : interval ≤ i * tickNs := by
    have := Nat.div_add_mod (interval + tickNs - 1) tickNs
    have := Nat.mod_lt (interval + tickNs - 1) htick
    rw [hi] at *
    rw [Nat.mul_comm]
    omega
  refine ⟨hceil, ?_⟩
  have hfloor : burst * interval / tickNs ≤ burst * i := by
    apply Nat.div_le_of_le_mul
    calc burst * interval ≤ burst * (i * tickNs) := Nat.mul_le_mul_left _ hceil
      _ = tickNs * (burst * i) := by
        rw [Nat.mul_comm i tickNs, Nat.mul_left_comm]
  rcases Nat.le_total (burst * interval / tickNs) i with hle | hle
  · rw [Nat.max_eq_right hle]
    exact Nat.le_mul_of_pos_left _ (by omega)
  · rw [Nat.max_eq_left hle]
    exact Nat.le_trans hfloor (Nat.mul_le_mul_right _ (Nat.le_max_left _ _))

/-! ## Leases (`ln_rl_unkeyed`) -/

structure Lease where
  remaining : Nat := 0
  expires : Nat := 0
  deriving Repr, DecidableEq, Inhabited

/-- One worker's unkeyed acquire at `now`: spend a live leased cell, or
reserve up to `L` cells with one CAS. Returns the bucket `tat`, the worker's
lease, and `none` (admitted) or the refusal delay. -/
def leaseStep (r : Rule) (L tat : Nat) (lease : Lease) (now : Nat) :
    Nat × Lease × Option Nat :=
  if 0 < lease.remaining ∧ now < lease.expires then
    (tat, { lease with remaining := lease.remaining - 1 }, none)
  else
    let ahead := max tat now - now
    let cleared := { lease with remaining := 0 }
    if r.tau < ahead then (tat, cleared, some (ahead - r.tau + r.interval))
    else if r.tau - ahead < r.interval then (tat, cleared, some (r.interval - (r.tau - ahead)))
    else
      let take := min ((r.tau - ahead) / r.interval) L
      (max tat now + take * r.interval,
        { remaining := take - 1, expires := now + take * r.interval }, none)

/-- With a one-cell lease, an unkeyed bucket is exactly `reserve … 1`, so
`admitted_window` applies unchanged. -/
theorem leaseStep_one (r : Rule) (hT : 0 < r.interval) (tat now : Nat) (lease : Lease)
    (hl : lease.remaining = 0) :
    (leaseStep r 1 tat lease now).1 = (reserve r tat now 1).getD tat ∧
      ((leaseStep r 1 tat lease now).2.2.isNone ↔ reserve r tat now 1 ≠ none) ∧
      (leaseStep r 1 tat lease now).2.1.remaining = 0 := by
  have h1 : tat ≤ max tat now := Nat.le_max_left _ _
  have h2 : now ≤ max tat now := Nat.le_max_right _ _
  simp only [leaseStep, hl, Nat.lt_irrefl, false_and, ite_false, reserve, Nat.one_mul]
  by_cases ha : r.tau < max tat now - now
  · rw [ite_eq_left ha, ite_eq_right (by omega)]; simp
  · rw [ite_eq_right ha]
    by_cases hb : r.tau - (max tat now - now) < r.interval
    · rw [ite_eq_left hb, ite_eq_right (by omega)]; simp
    · rw [ite_eq_right hb, ite_eq_left (by omega)]
      have hfit : 1 ≤ (r.tau - (max tat now - now)) / r.interval :=
        (Nat.le_div_iff_mul_le hT).mpr (by omega)
      rw [Nat.min_eq_right hfit]
      simp

/-- Run unkeyed acquires `(worker, time)` against one bucket with per-worker
leases; return the admission flag of every event. -/
def leaseRun (r : Rule) (L : Nat) : Nat → List Lease → List (Nat × Nat) → List Bool
  | _, _, [] => []
  | tat, leases, (w, t) :: rest =>
    let (tat', lease', delay) := leaseStep r L tat (leases.getD w {}) t
    delay.isNone :: leaseRun r L tat' (leases.set w lease') rest

/-- Native parameters of `3001/s burst 10` on three workers: the interval is
`⌈10⁹ / 3001⌉ ns` and the lease is `min (3001·5 / (1000·3)) 10 = 5` cells. -/
def leasedRule : Rule := Rule.ofBurst 333223 10

/-- Two workers lease at time 0; at 1 ms each spends its four leftover cells
and a third worker reserves three more. -/
def leasedTrace : List (Nat × Nat) :=
  [(0, 0), (1, 0)] ++ List.replicate 4 (0, 1000000) ++ List.replicate 4 (1, 1000000) ++
    List.replicate 4 (2, 1000000)

/-- **Leases can exceed the burst.** Eleven cells are admitted at the single
instant `1 ms`, while `admitted_window` bounds a strict bucket by the burst
(10) in any zero-length window. -/
theorem leases_exceed_burst :
    ((leaseRun leasedRule 5 0 [{}, {}, {}] leasedTrace).drop 2).count true = 11 := by
  decide

/-! ## Executable model of the native limiter

`test/RateLimitDifferential.lean` runs random traces through `NativeModel`
and through `c/ratelimit.h` and requires identical results. -/

/-- `ln_rl_delay_ms`: round up to milliseconds, at least one. -/
def delayMs (ns : Nat) : Nat :=
  let ms := ns / 1000000 + (if ns % 1000000 == 0 then 0 else 1)
  if ms == 0 then 1 else min ms 0xFFFFFFFE

/-- Parameters derived by `ln_rl_create`. -/
structure NativeRule where
  rule : Rule
  lease : Nat
  keyed : Bool

def NativeRule.ofSpec (tokens periodMs burst workers : Nat) (keyed : Bool) : NativeRule :=
  let interval := (periodMs * 1000000 + tokens - 1) / tokens
  let per5 := tokens * 5 / (periodMs * workers)
  let lease := min (if per5 < 1 then 1 else if per5 > 64 then 64 else per5) burst
  { rule := Rule.ofBurst interval burst, lease, keyed }

/-- State of one bucket: unkeyed `tat` with per-worker leases, or one keyed
`tat` in ticks per key. -/
structure NativeBucket where
  tat : Nat := 0
  leases : List Lease := []
  keys : List (ByteArray × Nat) := []

private def keyTat (keys : List (ByteArray × Nat)) (key : ByteArray) : Nat :=
  ((keys.find? (·.1 == key)).map (·.2)).getD 0

private def setKeyTat (keys : List (ByteArray × Nat)) (key : ByteArray) (tat : Nat) :
    List (ByteArray × Nat) :=
  (key, tat) :: keys.filter (·.1 != key)

/-- One native acquire; `0` admits, otherwise the delay in milliseconds. -/
def NativeModel.acquire (rule : NativeRule) (bucket : NativeBucket) (worker : Nat)
    (key : ByteArray) (nowMs : Nat) : NativeBucket × Nat :=
  if rule.keyed then
    let r := keyedRule rule.rule
    let now := nowMs * 10
    let current := keyTat bucket.keys key
    let ahead := max current now - now
    if r.tau < ahead then (bucket, delayMs ((ahead - r.tau + r.interval) * tickNs))
    else if r.tau - ahead < r.interval then
      (bucket, delayMs ((r.interval - (r.tau - ahead)) * tickNs))
    else ({ bucket with keys := setKeyTat bucket.keys key (max current now + r.interval) }, 0)
  else
    let (tat, lease, delay) := leaseStep rule.rule rule.lease bucket.tat
      (bucket.leases.getD worker {}) (nowMs * 1000000)
    let leases := (List.replicate (worker + 1 - bucket.leases.length) {}).foldl
      (fun acc l => acc ++ [l]) bucket.leases
    ({ bucket with tat, leases := leases.set worker lease }, (delay.map delayMs).getD 0)

end LeanNetSpec.RateLimit
