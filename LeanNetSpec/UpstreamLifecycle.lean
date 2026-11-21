/-! # Upstream connection lifecycle

A model of one upstream socket as `Gateway.Pool` and `Gateway.Engine` drive
it, including the reactor's read interest, which the engine switches off while
a streamed response waits for downstream credit.

The model reproduces a bug fixed in `Pool.finishResponse` (commit "Re-enable
reads before returning plain upstream sockets to the pool"). A streamed
response paused reads; the reactor had already delivered the final bytes in
the same poll, the engine held them, and `Engine.resume` completed the
response from that held input. The pool put the socket back to idle with
reads still off. The next checkout then never read its response and ended in
a 504, and the idle socket could not notice an upstream close.

* `buggy_reaches_stuck` — with the old transition, a concrete four-event trace
  ends in an idle socket with reads off, and after the next checkout only a
  timeout can make progress (`stuck_until_timeout`).
* `fixed_preserves` — with the corrected transition, every event keeps
  `Healthy`: idle sockets and unpaused busy sockets always read.

The code enforces the corrected transition by construction: `Pool`'s idle
phases carry a `ReadArmed` token that only `armReads`/`armSecureReads`
create, and they create it only by re-enabling read interest. -/

namespace LeanNetSpec.UpstreamLifecycle

inductive Phase where
  | connecting | busy | idle | closed
  deriving DecidableEq, Repr

structure Conn where
  phase : Phase
  /-- Reactor read interest on the socket. -/
  reading : Bool
  /-- The engine paused this response for downstream backpressure. -/
  paused : Bool
  /-- A read already emitted in the poll that paused, held by the engine. It
  holds the response's final bytes. -/
  held : Bool
  deriving DecidableEq, Repr

inductive Event where
  /-- Nonblocking connect completed; the reactor arms reads. -/
  | connected
  /-- A body slice was forwarded downstream; the engine disables reads. -/
  | pause
  /-- The reactor delivers a read emitted before the pause took effect. -/
  | heldRead
  /-- Downstream credit returned: the engine resumes this response. -/
  | resume
  /-- The final response byte was read and parsed (requires reads). -/
  | complete (reusable : Bool)
  /-- The pool hands the idle socket to the next request. -/
  | acquire
  /-- Bytes or EOF on an idle socket (requires reads); the pool closes it. -/
  | idleInput
  /-- The response deadline fired. -/
  | timeout
  deriving DecidableEq, Repr

def allEvents : List Event :=
  [.connected, .pause, .heldRead, .resume, .complete true, .complete false, .acquire,
    .idleInput, .timeout]

/-- `Pool.finishResponse`: a reusable, completely read response returns the
socket to idle. The old code left read interest as it was; the fix arms it. -/
def toIdle (fixed : Bool) (c : Conn) : Conn :=
  { c with phase := .idle, reading := fixed || c.reading, paused := false, held := false }

/-- Abort or close: the engine drops its job, including any paused state. -/
def close (c : Conn) : Conn := { c with phase := .closed, paused := false, held := false }

def step (fixed : Bool) (c : Conn) : Event → Conn
  | .connected => if c.phase = .connecting then
      { phase := .busy, reading := true, paused := false, held := false } else c
  | .pause => if c.phase = .busy ∧ c.reading ∧ !c.paused then
      { c with paused := true, reading := false } else c
  | .heldRead => if c.phase = .busy ∧ c.paused ∧ !c.held then { c with held := true } else c
  | .resume =>
    if c.phase = .busy ∧ c.paused then
      -- The held input completes the response, so the engine's job is gone
      -- and `Engine.resume` never re-enables reads itself.
      if c.held then toIdle fixed c else { c with paused := false, reading := true }
    else c
  | .complete reusable =>
    if c.phase = .busy ∧ c.reading ∧ !c.paused then
      if reusable then toIdle fixed c else close c
    else c
  | .acquire => if c.phase = .idle then { c with phase := .busy, paused := false } else c
  | .idleInput => if c.phase = .idle ∧ c.reading then close c else c
  | .timeout => if c.phase = .busy then close c else c

def runTrace (fixed : Bool) (c : Conn) (events : List Event) : Conn :=
  events.foldl (step fixed) c

/-- Idle sockets observe upstream input, and a busy socket that is not paused
reads its response. -/
def Healthy (c : Conn) : Prop :=
  (c.phase = .idle → c.reading = true) ∧
  (c.phase = .busy → c.paused = false → c.reading = true) ∧
  (c.paused = true → c.phase = .busy) ∧
  (c.held = true → c.paused = true)

instance (c : Conn) : Decidable (Healthy c) := by unfold Healthy; infer_instance

def start : Conn := { phase := .connecting, reading := false, paused := false, held := false }

theorem start_healthy : Healthy start := by decide

/-- **The fix is sufficient.** Every transition keeps every connection
healthy. -/
theorem fixed_preserves (c : Conn) (e : Event) (h : Healthy c) : Healthy (step true c e) := by
  obtain ⟨phase, reading, paused, held⟩ := c
  cases phase <;> cases reading <;> cases paused <;> cases held <;> cases e <;>
    first
    | (rename_i reusable; cases reusable <;> revert h <;> decide)
    | (revert h; decide)

theorem fixed_run_healthy (events : List Event) : Healthy (runTrace true start events) := by
  unfold runTrace
  suffices ∀ c, Healthy c → Healthy (events.foldl (step true) c) from this start start_healthy
  induction events with
  | nil => intro c h; exact h
  | cons e rest ih => intro c h; exact ih _ (fixed_preserves c e h)

/-- Connect, stream one slice (pause), receive the final bytes in the same
poll (held), then resume. -/
def bugTrace : List Event := [.connected, .pause, .heldRead, .resume]

/-- **The bug.** The old transition returns an idle socket that cannot read. -/
theorem buggy_reaches_stuck :
    runTrace false start bugTrace =
      { phase := .idle, reading := false, paused := false, held := false } ∧
    ¬ Healthy (runTrace false start bugTrace) := by decide

/-- After the next checkout, nothing but the response timeout changes the
socket: its response is never read, so the request ends in a 504. -/
theorem stuck_until_timeout :
    let s := step false (runTrace false start bugTrace) .acquire
    s.phase = .busy ∧ s.reading = false ∧
      allEvents.all (fun e => e == .timeout || step false s e == s) = true ∧
      (step false s .timeout).phase = .closed := by decide

/-- The same trace is harmless with the fix. -/
theorem fixed_trace_reads :
    runTrace true start bugTrace =
      { phase := .idle, reading := true, paused := false, held := false } := by decide

end LeanNetSpec.UpstreamLifecycle
