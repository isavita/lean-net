import LeanNet.Gate.Policy
import LeanNet.Gateway.Wire

/-! Runtime gate: binds a compiled policy to application handlers, named
    checks, a rate limiter and an optional upstream forwarder, and turns it
    into a per-worker `HTTP.Admission.Factory`. -/

namespace LeanNet.Gate

open LeanNet.HTTP

/-- Business handler for `-> app NAME`, receiving the admitted request. -/
abbrev Handler := Admitted → HTTP1.Request → IO HTTP1.Reply

/-- Named head-stage validation for `check NAME`. Runs before any body is
    read, after the pure policy checks; must not block. -/
abbrev Check := Admitted → IO (Except Rejection Unit)

/-- Rate limiter boundary (see `LeanNet.Gate.RateLimiter` for the native
    implementation). `scope` is the route ID for route-keyed rules. Returns 0
    when allowed, otherwise the retry delay in milliseconds. -/
structure Limiter where
  acquire : (worker rule scope : UInt32) → (key : ByteArray) → (nowMs : UInt64) → IO UInt32

/-- Application side of a gate. Every name the policy references must be
    registered here; `Gate.factory` rejects missing ones at startup. -/
structure App where
  handlers : Array (String × Handler) := #[]
  checks : Array (String × Check) := #[]
  /-- Optional application override for `-> proxy`; the native gateway handles
      such routes when no override is registered. -/
  forwarder : Option Handler := none
  /-- Observe every rejection (metrics, logging). Must not block. -/
  onReject : Rejection → Admission.Head → IO Unit := fun _ _ => pure ()

structure Config where
  spec : Spec
  app : App := {}
  limiter : Option Limiter := none
  generation : UInt64 := 0
  /-- Monotonic milliseconds, injectable for tests. -/
  clock : IO UInt64 := IO.monoMsNow.map (·.toUInt64)

private def actionNames (spec : Spec) : Array (Nat × ActionSpec) :=
  spec.hosts.foldl (fun acc host =>
    let routes := host.routes.map (fun route => (route.line, route.action))
    acc ++ routes ++ (host.fallback.map (fun a => #[(host.line, a)])).getD #[]) #[]

private def checkNames (spec : Spec) : Array (Nat × String) :=
  spec.hosts.foldl (fun acc host =>
    acc ++ host.items.checks.map (host.line, ·) ++
      host.routes.foldl (fun acc route => acc ++ route.items.checks.map (route.line, ·)) #[]) #[]

/-- Compile the policy and check that every referenced handler, check,
    forwarder and limiter is available. -/
def Config.validate (config : Config) : Except ConfigError Policy := do
  let policy ← Policy.compile config.spec config.generation
  for (line, action) in actionNames config.spec do
    match action with
    | .app (some name) =>
      if !config.app.handlers.any (·.1 == name) then throw ⟨line, s!"no handler registered for 'app {name}'"⟩
    | .proxy _ => pure ()
    | _ => pure ()
  for (line, name) in checkNames config.spec do
    if !config.app.checks.any (·.1 == name) then throw ⟨line, s!"no check registered for 'check {name}'"⟩
  if !config.spec.rates.isEmpty && config.limiter.isNone then
    throw ⟨0, "rate limits need a limiter (Gate.RateLimiter.create)"⟩
  return policy

private def u32Bytes (n : Nat) : ByteArray :=
  ByteArray.mk #[(n >>> 24).toUInt8, (n >>> 16).toUInt8, (n >>> 8).toUInt8, n.toUInt8]

/-- Key bytes for a keyed rule; never derived from headers unless the rule
    explicitly says so (`by header NAME`). -/
private def principalKey (identity : HTTP1.ClientCertificate) : ByteArray := Id.run do
  let subject := identity.subject.toUTF8
  let sans := identity.subjectAltNames.qsort (fun a b => decide (a < b))
  let mut key := (u32Bytes subject.size).append subject
  key := key.append (u32Bytes sans.size)
  for san in sans do
    let value := san.toUTF8
    key := (key.append (u32Bytes value.size)).append value
  return key

private def rateKey (rate : RateSpec) (a : Admitted) : ByteArray :=
  match rate.key with
  | .global | .route => ByteArray.empty
  | .clientIp => a.facts.peer
  | .principal => match a.facts.principal with
    | some identity => principalKey identity
    | none => ByteArray.empty
  | .header name => ((a.head.headers.find? (·.name == name)).map (·.value)).getD ByteArray.empty

private def canonicalTarget (path : NormalPath) : ByteArray :=
  if path.query.isEmpty then path.path
  else (path.path.append "?".toUTF8).append path.query

/-- Route matching, application logic, and upstream forwarding must observe
    the same canonical path. In particular, a route for `/admin` must not hand
    `/%61dmin` to a backend that interprets escapes differently. -/
private def rewriter (a : Admitted) : Option (HTTP1.Request → HTTP1.Request) :=
  let target := canonicalTarget a.path
  let names := a.rules.headers.strip
  if target == a.head.target && names.isEmpty then none
  else some fun request => Id.run do
    let headers := if names.isEmpty then request.headers
      else request.headers.filter (fun h => !names.contains h.name)
    return { request with target := target, headers := headers }

private def retryAfter (ms : UInt32) : HTTP1.Header :=
  { name := "retry-after", value := (toString ((ms.toNat + 999) / 1000)).toUTF8 }

/-- Decide one head: pure policy, named checks, rate limits, then dispatch. -/
def decide (config : Config) (policy : Policy) (worker : Nat) (facts : Transport.Facts)
    (head : Admission.Head) : IO (Except Rejection Admission.Verdict) := do
  let a ← match admitHead policy facts head with
    | .ok a => pure a
    | .error rejection => return .error rejection
  for name in a.rules.checks do
    if let some (_, check) := config.app.checks.find? (·.1 == name) then
      if let .error rejection ← check a then return .error rejection
  if let some limiter := config.limiter then
    if !a.rules.limits.isEmpty then
      let now ← config.clock
      for rule in a.rules.limits do
        if let some rate := policy.rates[rule]? then
          if rate.key == .principal && a.facts.principal.isNone then
            return .error (.make .clientCertRequired 403)
          if let .header name := rate.key then
            let count := a.head.headers.foldl
              (fun found header => if header.name == name then found + 1 else found) 0
            if count == 0 then return .error (.make .missingHeader 400)
            if count != 1 then return .error (.make .duplicateHeader 400)
          let scope := if rate.key == .route then (a.routeId?.getD 0) + 1 else 0
          let delay ← limiter.acquire worker.toUInt32 rule.toUInt32 scope.toUInt32 (rateKey rate a) now
          if delay == UInt32.ofNat 4294967295 then
            return .error (.make .limiterUnavailable 503)
          if delay != 0 then return .error (.make .rateLimited 429 #[retryAfter delay])
  let dispatch : Option (HTTP1.Request → IO HTTP1.Reply) := match a.action? with
    | some (.app (some name)) => (config.app.handlers.find? (·.1 == name)).map fun (_, handler) => handler a
    | some (.proxy _ _) => config.app.forwarder.map (· a)
    | _ => none
  let proxy : Option Admission.ProxyPlan :=
    if config.app.forwarder.isSome then none
    else match a.backend? with
      | none => none
      | some index =>
        let backend := a.policy.backends[index]
        some {
          targets := backend.targets.map fun target =>
            { host := target.host, port := target.port,
              tls := target.scheme == .https,
              verifyName := backend.verify.getD target.host }
          serialize := fun request =>
            match Gateway.encodeRequest a request with
            | .ok wire => .ok wire
            | .error error => .error s!"{repr error}" }
  let label := match a.selection with
    | .route r => (a.policy.hosts[a.host]).routes[r].pattern
    | .fallback => "fallback"
    | .internal => "internal"
  -- Trailers arrive after head checks, including named checks and rate-key
  -- selection. Refuse them before dispatch and observe the typed rejection.
  let postBody : HTTP1.Request → IO (Except Admission.Rejection HTTP1.Request) :=
    fun request => do
      if request.trailers.isEmpty then return .ok request
      let rejection := Rejection.make .invalidTrailer 400
      config.app.onReject rejection head
      return .error rejection.toAdmission
  return .ok (.accept a.rules.body dispatch (rewriter a) (some label) proxy (some postBody))

/-- The per-worker admission factory. Each worker compiles its own copy of
    the policy on its own thread (no cross-core reference counting). -/
def factory (config : Config) : Except ConfigError Admission.Factory := do
  let _ ← config.validate
  return fun worker => do
    let policy ← match Policy.compile config.spec config.generation with
      | .ok policy => pure policy
      | .error error => throw (IO.userError (toString error))
    return { decide := fun facts head => do
      match ← decide config policy worker facts head with
      | .ok verdict => return verdict
      | .error rejection =>
        config.app.onReject rejection head
        return .reject rejection.toAdmission }

/-- Restrict a server to an allowlist of hosts and nothing else: every path
    and method on those hosts reaches the server's own handlers. -/
def Spec.hostsOnly (hosts : Array String) : Spec :=
  { hosts := #[{ patterns := hosts, sni := .strict, fallback := some (.app none) }] }

end LeanNet.Gate
