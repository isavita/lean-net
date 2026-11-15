import Std.Data.HashMap
import LeanNet.Gate.Spec
import LeanNet.HTTP.Admission

/-! Compiled, immutable gate policy and proof-carrying admitted requests.

`Policy.compile` validates a `Spec` and produces indexes: an exact host hash
table, a wildcard list, and per-host segment tries. Upstream bindings are
*dependently typed*: a route's `proxy` action stores the backend index
together with a proof that the backend's `serves` list covers every pattern
of the route's own virtual host. `Admitted` can only be built by `admitHead`
and carries erased proofs of its header and host invariants. Together these
give `Admitted.backend_serves`: the backend selected for an admitted request
always declares that it serves a host pattern matching that request's
authority, so `Host: example.com` cannot reach a backend that does not list it. -/

namespace LeanNet.Gate

open LeanNet.HTTP

structure Backend where
  name : String
  targets : Array Target
  verify : Option String
  serves : Array HostPattern
  deriving Inhabited

/-- Route actions. `proxy` carries its serving proof. -/
inductive Action (backends : Array Backend) (patterns : Array HostPattern) where
  | app (name : Option String)
  | proxy (backend : Fin backends.size)
      (serves : patterns.all (fun p => (backends[backend]).serves.contains p) = true)
  | deny (status : Nat)
  | websocket (name : Option String)
  | redirect (status : Nat) (location : ByteArray)

structure HeaderPolicy where
  require : Array String := #[]
  forbid : Array String := #[]
  forbidPrefix : Array String := #[]
  max : Array (String × Nat) := #[]
  single : Array String := #[]
  oneOf : Array (String × Array ByteArray) := #[]
  strip : Array String := #[]
  deriving Inhabited

/-- Effective rules after host inheritance. Rate limits are indices into
    `Policy.rates`. -/
structure Rules where
  body : Option Nat := none
  timeoutMs : Option Nat := none
  limits : Array Nat := #[]
  checks : Array String := #[]
  /-- Host allowlist. A matching route allowlist is checked separately. -/
  allow : Array Cidr := #[]
  /-- Route allowlist; both nonempty allowlists must admit the peer. -/
  routeAllow : Array Cidr := #[]
  deny : Array Cidr := #[]
  mtls : Array PrincipalRule := #[]
  headers : HeaderPolicy := {}
  deriving Inhabited

structure Route (backends : Array Backend) (patterns : Array HostPattern) where
  /-- Process-unique route ID (rate-limit key and metrics label). -/
  id : Nat
  pattern : String
  methods : Option (Array String)
  captureNames : Array String
  action : Action backends patterns
  rules : Rules

/-- Segment trie; leaves hold slot indices (one slot per distinct pattern). -/
inductive Node where
  | mk (literals : Array (ByteArray × Node)) (param : Option Node) (rest : Option Nat) (exact : Option Nat)
  deriving Inhabited

structure VHost (backends : Array Backend) where
  patterns : Array HostPattern
  sni : SniMode
  rules : Rules
  routes : Array (Route backends patterns)
  /-- Route indices sharing one path pattern, in declaration order. -/
  slots : Array (Array Nat)
  trie : Node
  fallback : Option (Action backends patterns)

structure Policy where
  private mk ::
  generation : UInt64
  limits : LimitsSpec
  rates : Array RateSpec
  backends : Array Backend
  hosts : Array (VHost backends)
  exactHosts : Std.HashMap ByteArray (Array (Option UInt16 × Nat))
  wildcardHosts : Array (ByteArray × Nat)
  catchAll : Option Nat
  unknownHost : UnknownHost
  routeCount : Nat

structure ConfigError where
  line : Nat
  message : String
  deriving Repr, Inhabited

instance : ToString ConfigError := ⟨fun e => s!"gate policy line {e.line}: {e.message}"⟩

/-! ## Compilation -/

private inductive Seg where
  | lit (bytes : ByteArray) | param (name : String) | rest
  deriving BEq, Inhabited

private def Seg.key : Seg → String
  | .lit bytes => "l:" ++ (String.fromUTF8? bytes).getD "" | .param _ => ":" | .rest => "*"

private def parsePattern (text : String) (line : Nat) : Except ConfigError (Array Seg) := do
  if !text.startsWith "/" then throw ⟨line, s!"path pattern '{text}' must start with '/'"⟩
  let parts := ((text.drop 1).toString.splitOn "/").filter (!·.isEmpty)
  let mut segs : Array Seg := #[]
  for h : i in [:parts.length] do
    let part := parts[i]
    if part == "*" then
      if i + 1 != parts.length then throw ⟨line, "'*' is only allowed as the final segment"⟩
      segs := segs.push .rest
    else if part.startsWith ":" then
      let name := (part.drop 1).toString
      if name.isEmpty || !name.toList.all (fun c => c.isLower || c.isDigit || c == '_') then
        throw ⟨line, s!"invalid capture name in '{part}'"⟩
      segs := segs.push (.param name)
    else
      match normalizePath ("/" ++ part).toUTF8 with
      | .ok normal =>
        if normal.segments.size != 1 || !normal.query.isEmpty || part.contains '?' then
          throw ⟨line, s!"invalid path segment '{part}'"⟩
        segs := segs.push (.lit normal.segments[0]!)
      | .error _ => throw ⟨line, s!"invalid path segment '{part}'"⟩
  return segs

private def compareBytes (a b : ByteArray) : Bool := Id.run do
  for i in [:min a.size b.size] do
    if a[i]! != b[i]! then return a[i]! < b[i]!
  return a.size < b.size

/-- Build a trie from (segments, slot) pairs. -/
private partial def build (entries : Array (Array Seg × Nat)) (depth : Nat) : Node := Id.run do
  let mut exact : Option Nat := none
  let mut rest : Option Nat := none
  let mut params : Array (Array Seg × Nat) := #[]
  let mut literalKeys : Array ByteArray := #[]
  for (segs, slot) in entries do
    match segs[depth]? with
    | none => exact := some slot
    | some .rest => rest := some slot
    | some (.param _) => params := params.push (segs, slot)
    | some (.lit bytes) => if !literalKeys.contains bytes then literalKeys := literalKeys.push bytes
  let sorted := literalKeys.qsort compareBytes
  let literals := sorted.map fun key =>
    (key, build (entries.filter fun (segs, _) => segs[depth]? == some (.lit key)) (depth + 1))
  let param := if params.isEmpty then none else some (build params (depth + 1))
  return .mk literals param rest exact

private def principalOk (rule : PrincipalRule) : Bool :=
  match rule with
  | .any => true
  | .san _ value => !value.isEmpty

private def compileHeaders (rules : Array HeaderRule) (line : Nat) : Except ConfigError HeaderPolicy := do
  let mut out : HeaderPolicy := {}
  let validName := fun (name : String) => !name.isEmpty && name.toUTF8.data.all tokenByte
  for rule in rules do
    match rule with
    | .require name => if !validName name then throw ⟨line, s!"invalid header name '{name}'"⟩
                       out := { out with require := out.require.push name }
    | .forbid name =>
      if name.endsWith "*" then
        let prefixName := (name.dropEnd 1).toString
        if !validName prefixName then throw ⟨line, s!"invalid header prefix '{name}'"⟩
        out := { out with forbidPrefix := out.forbidPrefix.push prefixName }
      else
        if !validName name then throw ⟨line, s!"invalid header name '{name}'"⟩
        out := { out with forbid := out.forbid.push name }
    | .max name bytes => if !validName name then throw ⟨line, s!"invalid header name '{name}'"⟩
                         out := { out with max := out.max.push (name, bytes) }
    | .single name => if !validName name then throw ⟨line, s!"invalid header name '{name}'"⟩
                      out := { out with single := out.single.push name }
    | .oneOf name values => if !validName name then throw ⟨line, s!"invalid header name '{name}'"⟩
                            let bytes := values.map fun value =>
                              (if name == "content-type" then value.toLower else value).toUTF8
                            out := { out with oneOf := out.oneOf.push (name, bytes) }
    | .strip name => if !validName name then throw ⟨line, s!"invalid header name '{name}'"⟩
                     out := { out with strip := out.strip.push name }
  return out

private def mergeHeaders (a b : HeaderPolicy) : HeaderPolicy :=
  { require := a.require ++ b.require, forbid := a.forbid ++ b.forbid,
    forbidPrefix := a.forbidPrefix ++ b.forbidPrefix, max := a.max ++ b.max,
    single := a.single ++ b.single, oneOf := a.oneOf ++ b.oneOf, strip := a.strip ++ b.strip }

private def compileRules (spec : Spec) (items : Items) (line : Nat) : Except ConfigError Rules := do
  let mut limits := #[]
  for name in items.limits do
    let some index := spec.rates.findIdx? (·.name == name) | throw ⟨line, s!"unknown rate limit '{name}'"⟩
    limits := limits.push index
  let cidrs := fun (texts : Array String) => texts.mapM fun text =>
    match Cidr.parse text with
    | some cidr => pure cidr
    | none => throw (⟨line, s!"invalid CIDR block '{text}'"⟩ : ConfigError)
  for rule in items.mtls do
    if !principalOk rule then throw ⟨line, "empty mTLS SAN value"⟩
  for name in items.checks do
    if name.isEmpty then throw ⟨line, "empty check name"⟩
  return { body := items.body, timeoutMs := items.timeoutMs, limits, checks := items.checks,
           allow := ← cidrs items.allow, deny := ← cidrs items.deny, mtls := items.mtls,
           headers := ← compileHeaders items.headers line }

private def inherit (host route : Rules) : Rules :=
  { body := route.body <|> host.body, timeoutMs := route.timeoutMs <|> host.timeoutMs,
    limits := host.limits ++ route.limits, checks := host.checks ++ route.checks,
    allow := host.allow, routeAllow := route.allow,
    deny := host.deny ++ route.deny, mtls := host.mtls ++ route.mtls,
    headers := mergeHeaders host.headers route.headers }

private def compileAction (backends : Array Backend) (patterns : Array HostPattern)
    (action : ActionSpec) (line : Nat) : Except ConfigError (Action backends patterns) := do
  match action with
  | .app name => return .app name
  | .websocket name => return .websocket name
  | .deny status => return .deny status
  | .redirect status location => return .redirect status location.toUTF8
  | .proxy name =>
    let some index := backends.findIdx? (·.name == name) | throw ⟨line, s!"unknown backend '{name}'"⟩
    if h : index < backends.size then
      let backend : Fin backends.size := ⟨index, h⟩
      if serves : patterns.all (fun p => (backends[backend]).serves.contains p) = true then
        return .proxy backend serves
      else
        -- The Bool equality is Decidable: the successful branch constructs
        -- the erased route proof automatically, including for `gate%`.
        let missing := patterns.find? (fun p => !((backends[backend]).serves.contains p))
        let host := (missing.map HostPattern.render).getD "<unknown>"
        throw ⟨line, s!"backend does not declare 'serves' for host (host='{host}', backend='{name}')"⟩
    else throw ⟨line, s!"unknown backend '{name}'"⟩

private def methodsOverlap (a b : Option (Array String)) : Bool :=
  match a, b with
  | none, _ | _, none => true
  | some x, some y => x.any y.contains

/-- Validate and index a policy. Rejects unknown names, invalid hosts, CIDRs
    or headers, duplicate host patterns, backends that do not serve a host
    routed to them, and routes with identical patterns and overlapping methods. -/
def Policy.compile (spec : Spec) (generation : UInt64 := 0) : Except ConfigError Policy := do
  let limits := spec.limits
  if limits.maxHeaders == 0 || limits.maxHeaders > 1000 || limits.maxHeaderBytes < 256 ||
      limits.maxHeaderBytes > 1048576 || limits.maxTargetBytes == 0 ||
      limits.maxTargetBytes > 1048576 || limits.maxPathDepth == 0 || limits.maxPathDepth > 256 then
    throw ⟨0, "limits out of range (headers 1-1000, header-bytes 256B-1MiB, target-bytes 1B-1MiB, path-depth 1-256)"⟩
  if spec.rates.size > 1024 then throw ⟨0, "too many rate limits (maximum 1024)"⟩
  for h : i in [:spec.rates.size] do
    let rate := spec.rates[i]
    if rate.tokens == 0 || rate.burst == 0 || rate.periodMs == 0 then throw ⟨0, s!"rate limit '{rate.name}' must be positive"⟩
    if rate.tokens > 4294967295 || rate.periodMs > 4294967295 || rate.burst > 4294967295 then
      throw ⟨0, s!"rate limit '{rate.name}' exceeds the native 32-bit range"⟩
    if let .header name := rate.key then
      if name.isEmpty || name != name.toLower || !name.toUTF8.data.all tokenByte then
        throw ⟨0, s!"rate limit '{rate.name}' has an invalid key header name"⟩
    if (spec.rates.extract 0 i).any (·.name == rate.name) then throw ⟨0, s!"duplicate rate limit '{rate.name}'"⟩
  let mut backends : Array Backend := #[]
  for b in spec.backends do
    if backends.any (·.name == b.name) then throw ⟨0, s!"duplicate backend '{b.name}'"⟩
    if b.targets.isEmpty then throw ⟨0, s!"backend '{b.name}' has no targets"⟩
    let mut serves := #[]
    for text in b.serves do
      let some pattern := HostPattern.parse text | throw ⟨0, s!"backend '{b.name}': invalid serves pattern '{text}'"⟩
      serves := serves.push pattern
    if serves.isEmpty then throw ⟨0, s!"backend '{b.name}' must declare the hosts it serves"⟩
    if let some name := b.verify then
      if !validHost name.toUTF8 && (parseAddress name).isNone then
        throw ⟨0, s!"backend '{b.name}': invalid TLS verify name '{name}'"⟩
      if b.targets.any (·.scheme == .http) then
        throw ⟨0, s!"backend '{b.name}': TLS verify requires HTTPS targets only"⟩
    for t in b.targets do
      if !validHost t.host.toUTF8 && (parseAddress t.host).isNone then
        throw ⟨0, s!"backend '{b.name}': invalid target host '{t.host}'"⟩
    backends := backends.push { name := b.name, targets := b.targets, verify := b.verify, serves }
  let mut hosts : Array (VHost backends) := #[]
  let mut seenPatterns : Array HostPattern := #[]
  let mut routeId := 0
  for host in spec.hosts do
    let mut patterns : Array HostPattern := #[]
    for text in host.patterns do
      let some pattern := HostPattern.parse text | throw ⟨host.line, s!"invalid host pattern '{text}'"⟩
      if seenPatterns.contains pattern then throw ⟨host.line, s!"duplicate host pattern '{text}'"⟩
      seenPatterns := seenPatterns.push pattern
      patterns := patterns.push pattern
    let hostRules ← compileRules spec host.items host.line
    let mut routes : Array (Route backends patterns) := #[]
    let mut slotKeys : Array String := #[]
    let mut slots : Array (Array Nat) := #[]
    let mut entries : Array (Array Seg × Nat) := #[]
    for route in host.routes do
      let segs ← parsePattern route.path route.line
      if segs.size > limits.maxPathDepth then throw ⟨route.line, "pattern deeper than path-depth"⟩
      let key := "/".intercalate (segs.map Seg.key).toList
      let names := segs.filterMap fun | .param name => some name | _ => none
      if names.size != (names.toList.eraseDups).length then throw ⟨route.line, "duplicate capture name"⟩
      let action ← compileAction backends patterns route.action route.line
      let rules := inherit hostRules (← compileRules spec route.items route.line)
      let index := routes.size
      routes := routes.push { id := routeId, pattern := route.path, methods := route.methods,
                              captureNames := names, action, rules }
      routeId := routeId + 1
      match slotKeys.findIdx? (· == key) with
      | some slot =>
        for other in slots[slot]! do
          if (routes[other]?.map (methodsOverlap ·.methods route.methods)).getD false then
            throw ⟨route.line, s!"route '{route.path}' overlaps an earlier route with the same pattern and methods"⟩
        slots := slots.modify slot (·.push index)
      | none =>
        slotKeys := slotKeys.push key
        entries := entries.push (segs, slots.size)
        slots := slots.push #[index]
    let fallback ← host.fallback.mapM (compileAction backends patterns · host.line)
    hosts := hosts.push { patterns, sni := host.sni, rules := hostRules, routes, slots,
                          trie := build entries 0, fallback }
  let mut exactHosts : Std.HashMap ByteArray (Array (Option UInt16 × Nat)) := {}
  let mut wildcardHosts := #[]
  let mut catchAll := none
  for h : i in [:hosts.size] do
    for pattern in hosts[i].patterns do
      match pattern with
      | .exact host port => exactHosts := exactHosts.insert host ((exactHosts.getD host #[]).push (port, i))
      | .wildcard suffix => wildcardHosts := wildcardHosts.push (suffix, i)
      | .any => catchAll := some i
  match spec.unknownHost with
  | .status code => if code < 400 || code > 599 then throw ⟨0, "on unknown-host needs a 4xx/5xx status"⟩
  | .close => pure ()
  return { generation, limits, rates := spec.rates, backends, hosts, exactHosts, wildcardHosts,
           catchAll, unknownHost := spec.unknownHost, routeCount := routeId }

/-! ## Typed rejections -/

inductive Reason where
  | headerLimit | badHeader | badAuthority | unknownHost | misdirected | badPath
  | notFound | methodNotAllowed | ipDenied | clientCertRequired | principalDenied
  | missingHeader | forbiddenHeader | headerTooLarge | duplicateHeader | unsupportedValue
  | upgradeRequired | denied | redirect | rateLimited | limiterUnavailable | checkFailed | bodyTooLarge
  | invalidTrailer
  deriving BEq, Repr, Inhabited

def Reason.label : Reason → String
  | .headerLimit => "header_limit" | .badHeader => "bad_header" | .badAuthority => "bad_authority"
  | .unknownHost => "unknown_host" | .misdirected => "misdirected" | .badPath => "bad_path"
  | .notFound => "not_found" | .methodNotAllowed => "method_not_allowed" | .ipDenied => "ip_denied"
  | .clientCertRequired => "client_cert_required" | .principalDenied => "principal_denied"
  | .missingHeader => "missing_header" | .forbiddenHeader => "forbidden_header"
  | .headerTooLarge => "header_too_large" | .duplicateHeader => "duplicate_header"
  | .unsupportedValue => "unsupported_value" | .upgradeRequired => "upgrade_required"
  | .denied => "denied" | .redirect => "redirect" | .rateLimited => "rate_limited"
  | .limiterUnavailable => "limiter_unavailable"
  | .checkFailed => "check_failed" | .bodyTooLarge => "body_too_large"
  | .invalidTrailer => "invalid_trailer"

def Reason.all : Array Reason := #[.headerLimit, .badHeader, .badAuthority, .unknownHost, .misdirected,
  .badPath, .notFound, .methodNotAllowed, .ipDenied, .clientCertRequired, .principalDenied,
  .missingHeader, .forbiddenHeader, .headerTooLarge, .duplicateHeader, .unsupportedValue,
  .upgradeRequired, .denied, .redirect, .rateLimited, .limiterUnavailable, .checkFailed, .bodyTooLarge,
  .invalidTrailer]

def Reason.index (reason : Reason) : Nat := (Reason.all.findIdx? (· == reason)).getD 0

/-- A typed refusal: never thrown, never echoing request bytes. -/
structure Rejection where
  reason : Reason
  status : Nat
  headers : Array HTTP1.Header := #[]
  /-- Close silently instead of answering (e.g. `on unknown-host close`). -/
  drop : Bool := false
  deriving Inhabited

def Rejection.make (reason : Reason) (status : Nat) (headers : Array HTTP1.Header := #[]) : Rejection :=
  { reason, status, headers }

def Rejection.toAdmission (rejection : Rejection) : Admission.Rejection :=
  { status := rejection.status, headers := rejection.headers,
    body := if rejection.status >= 300 && rejection.status < 400 then ByteArray.empty
      else s!"{rejection.reason.label}\n".toUTF8
    drop := rejection.drop
    label := rejection.reason.label }

/-! ## Admission -/

/-- Where an admitted request goes. -/
inductive Selection (v : VHost bs) where
  | route (index : Fin v.routes.size)
  | fallback
  /-- A server-owned endpoint (metrics, health) passing host and IP rules. -/
  | internal

/-- A request that passed every pure policy check. Only `admitHead` builds it. -/
structure Admitted where
  private mk ::
  policy : Policy
  facts : Transport.Facts
  head : Admission.Head
  authority : Authority
  path : NormalPath
  host : Fin policy.hosts.size
  selection : Selection (policy.hosts[host])
  /-- `:name` captures as normalised (still percent-encoded) segment bytes. -/
  captures : Array (String × ByteArray)
  private fieldsSafe : head.headers.all fieldOk = true
  private fieldsBounded : head.headers.size ≤ policy.limits.maxHeaders
  private hostMatches : (policy.hosts[host]).patterns.any (·.matches authority) = true

def Admitted.vhost (a : Admitted) : VHost a.policy.backends := a.policy.hosts[a.host]

def Admitted.action? (a : Admitted) : Option (Action a.policy.backends a.vhost.patterns) :=
  match a.selection with
  | .route r => some ((a.policy.hosts[a.host]).routes[r]).action
  | .fallback => a.vhost.fallback
  | .internal => none

def Admitted.rules (a : Admitted) : Rules :=
  match a.selection with
  | .route r => ((a.policy.hosts[a.host]).routes[r]).rules
  | _ => a.vhost.rules

def Admitted.routeId? (a : Admitted) : Option Nat :=
  match a.selection with
  | .route r => some ((a.policy.hosts[a.host]).routes[r]).id
  | _ => none

def Admitted.capture (a : Admitted) (name : String) : Option ByteArray :=
  (a.captures.find? (·.1 == name)).map (·.2)

/-- The upstream for this request: read only from the bound route. -/
def Admitted.backend? (a : Admitted) : Option (Fin a.policy.backends.size) :=
  match a.action? with
  | some (.proxy b _) => some b
  | _ => none

/-- Every admitted header value is free of CR and LF. -/
theorem Admitted.no_crlf (a : Admitted) :
    ∀ field ∈ a.head.headers, ∀ c ∈ field.value.data, c ≠ 13 ∧ c ≠ 10 := by
  intro field hf
  exact fieldOk_no_crlf ((Array.all_eq_true'.mp a.fieldsSafe) field hf)

theorem Admitted.header_count_bounded (a : Admitted) : a.head.headers.size ≤ a.policy.limits.maxHeaders :=
  a.fieldsBounded

/-- The virtual host was selected by a pattern that matches the authority. -/
theorem Admitted.host_matches (a : Admitted) : ∃ p ∈ a.vhost.patterns, p.matches a.authority = true :=
  Array.any_eq_true'.mp a.hostMatches

/-- **Routing safety.** A backend selected for an admitted request declares
    (in `serves`) a host pattern that matches the request's authority. -/
theorem Admitted.backend_serves (a : Admitted) (b : Fin a.policy.backends.size)
    (h : a.backend? = some b) :
    ∃ p ∈ (a.policy.backends[b]).serves, p.matches a.authority = true := by
  obtain ⟨p, hp, hm⟩ := a.host_matches
  refine ⟨p, ?_, hm⟩
  unfold Admitted.backend? at h
  split at h
  · rename_i b' serves _
    cases h
    exact Array.contains_iff_mem.mp ((Array.all_eq_true'.mp serves) p hp)
  · cases h

private def headerBytes (headers : Array HTTP1.Header) : Nat :=
  headers.foldl (fun n field => n + field.name.length + field.value.size + 4) 0

private def lookupLiteral (literals : Array (ByteArray × Node)) (key : ByteArray) : Option Node := Id.run do
  let mut lo := 0
  let mut hi := literals.size
  while lo < hi do
    let mid := (lo + hi) / 2
    let (k, node) := literals[mid]!
    if k == key then return some node
    if compareBytes k key then lo := mid + 1 else hi := mid
  return none

/-- Literal before `:param` before `*`, with backtracking over the depth. -/
private partial def Node.find (node : Node) (segments : Array ByteArray) (i : Nat) (captures : Array ByteArray) :
    Option (Nat × Array ByteArray) :=
  let .mk literals param rest exact := node
  if i >= segments.size then
    match exact with
    | some slot => some (slot, captures)
    | none => rest.map (·, captures)
  else
    let literal := (lookupLiteral literals segments[i]!).bind (·.find segments (i + 1) captures)
    match literal with
    | some found => some found
    | none =>
      let byParam := param.bind (·.find segments (i + 1) (captures.push segments[i]!))
      match byParam with
      | some found => some found
      | none => rest.map (·, captures)

private def Policy.lookupHost (policy : Policy) (authority : Authority) : Option Nat := Id.run do
  if let some candidates := policy.exactHosts[authority.host]? then
    for (port, index) in candidates do
      if port.isSome && port == authority.port then return some index
    for (port, index) in candidates do
      if port.isNone then return some index
  let host := authority.host
  for (suffix, index) in policy.wildcardHosts do
    if (HostPattern.wildcard suffix).matches authority then return some index
  let _ := host
  return policy.catchAll

private def sanMatches (rule : PrincipalRule) (principal : Option HTTP1.ClientCertificate) : Bool :=
  match rule, principal with
  | _, none => false
  | .any, some _ => true
  | .san kind value, some identity =>
    let wanted := kind ++ ":" ++ value
    if value.endsWith "*" then
      let prefixText := (wanted.dropEnd 1).toString
      identity.subjectAltNames.any (·.startsWith prefixText)
    else identity.subjectAltNames.contains wanted

private def mediaValue (value : ByteArray) : ByteArray :=
  let stop := (value.data.findIdx? (· == 59)).getD value.size
  let trimmed := (value.extract 0 stop).data.toList.dropWhile (· == 32) |>.reverse |>.dropWhile (fun c => c == 32 || c == 9) |>.reverse
  lowerBytes ⟨trimmed.toArray⟩

/-- Address, principal and header rules shared by routes and server endpoints. -/
def Rules.check (rules : Rules) (facts : Transport.Facts) (headers : Array HTTP1.Header) :
    Except Rejection Unit := do
  if !rules.allow.isEmpty && !rules.allow.any (·.contains facts.peer) then throw (.make .ipDenied 403)
  if !rules.routeAllow.isEmpty && !rules.routeAllow.any (·.contains facts.peer) then throw (.make .ipDenied 403)
  if rules.deny.any (·.contains facts.peer) then throw (.make .ipDenied 403)
  for rule in rules.mtls do
    if facts.principal.isNone then throw (.make .clientCertRequired 403)
    if !sanMatches rule facts.principal then throw (.make .principalDenied 403)
  let policy := rules.headers
  for name in policy.require do
    if !headers.any (·.name == name) then throw (.make .missingHeader 400)
  for field in headers do
    if policy.forbid.contains field.name || policy.forbidPrefix.any (fun p => field.name.startsWith p) then
      throw (.make .forbiddenHeader 400)
    for (name, limit) in policy.max do
      if field.name == name && field.value.size > limit then throw (.make .headerTooLarge 431)
  for name in policy.single do
    if (headers.filter (·.name == name)).size > 1 then throw (.make .duplicateHeader 400)
  for (name, values) in policy.oneOf do
    for field in headers do
      if field.name == name then
        let actual := if name == "content-type" then mediaValue field.value else field.value
        if !values.contains actual then
          throw (.make .unsupportedValue (if name == "content-type" then 415 else 400))

private def methodMatches (methods : Option (Array String)) (method : String) : Bool :=
  match methods with
  | none => true
  | some list => list.contains method || (method == "HEAD" && list.contains "GET")

/-- A WebSocket route must see the actual opening protocol. A mere Upgrade
    field does not authorize h2c or another raw protocol on that route. -/
private def websocketHead (head : Admission.Head) : Bool := Id.run do
  match head.kind with
  | .upgrade =>
    if head.protocol != .http11 || head.method != "GET" || !head.bodyless then return false
    let upgrades := head.headers.filter (·.name == "upgrade")
    if upgrades.size != 1 || !equalFold upgrades[0]!.value "websocket".toUTF8 then return false
    match HTTP1.connectionTokens head.headers with
    | .ok options => return options.contains "upgrade" && !options.contains "close"
    | .error _ => return false
  | .tunnel =>
    return head.protocol == .http2 && head.method == "CONNECT" &&
      head.requestedProtocol == some "websocket".toUTF8
  | _ => return false

/-- Pure head-stage admission: header invariants, authority, virtual host,
    TLS SNI agreement, path normalisation, routing and rules. Rate limits and
    named checks run afterwards in `LeanNet.Gate.Gate`. -/
def admitHead (policy : Policy) (facts : Transport.Facts) (head : Admission.Head) :
    Except Rejection Admitted := do
  if bounded : head.headers.size ≤ policy.limits.maxHeaders then
    if safe : head.headers.all fieldOk = true then
      if headerBytes head.headers > policy.limits.maxHeaderBytes then throw (.make .headerLimit 431)
      -- Defence in depth: the core parsers already enforce these.
      let hosts := head.headers.filter (·.name == "host")
      match head.protocol with
      | .http2 => if hosts.any (fun h => !equalFold h.value head.authority) then throw (.make .badAuthority 400)
      | _ => if hosts.size != 1 || !equalFold hosts[0]!.value head.authority then throw (.make .badAuthority 400)
      let some authority := Authority.parse head.authority | throw (.make .badAuthority 400)
      let unknown : Rejection := match policy.unknownHost with
        | .status code => .make .unknownHost code
        | .close => { reason := .unknownHost, status := 421, drop := true }
      let some index := policy.lookupHost authority | throw unknown
      if hi : index < policy.hosts.size then
        let host : Fin policy.hosts.size := ⟨index, hi⟩
        let vhost := policy.hosts[host]
        if hmatch : vhost.patterns.any (·.matches authority) = true then
          if facts.secure && vhost.sni == .strict && facts.sni != some authority.host then
            throw (.make .misdirected 421)
          if let some scheme := head.scheme then
            if scheme != (if facts.secure then "https".toUTF8 else "http".toUTF8) then throw (.make .misdirected 421)
          let build := fun (path : NormalPath) (selection : Selection vhost) captures =>
            (⟨policy, facts, head, authority, path, host, selection, captures, safe, bounded, hmatch⟩ : Admitted)
          if head.kind == .internal then
            vhost.rules.check facts head.headers
            return build default .internal #[]
          let path ← match normalizePath head.target policy.limits.maxPathDepth policy.limits.maxTargetBytes with
            | .ok path => pure path
            | .error _ => throw (.make .badPath 400)
          let method := if head.kind == .tunnel then "GET" else head.method
          match vhost.trie.find path.segments 0 #[] with
          | some (slot, values) =>
            let candidates := vhost.slots[slot]?.getD #[]
            let chosen := candidates.find? fun r => (vhost.routes[r]?.map (methodMatches ·.methods method)).getD false
            match chosen with
            | none =>
              let allowed := candidates.foldl (fun acc r =>
                acc ++ ((vhost.routes[r]?.bind (·.methods)).getD #["*"])) #[]
              throw (.make .methodNotAllowed 405 #[{ name := "allow", value := (", ".intercalate allowed.toList).toUTF8 }])
            | some r =>
              if hr : r < vhost.routes.size then
                let route := vhost.routes[r]
                route.rules.check facts head.headers
                match route.action, head.kind with
                | .websocket _, _ =>
                  if !websocketHead head then
                    throw (.make .upgradeRequired 426 #[{ name := "upgrade", value := "websocket".toUTF8 }])
                | _, .tunnel => throw (.make .notFound 404)
                | .deny status, _ => throw (.make .denied status)
                | .redirect status location, _ =>
                  throw (.make .redirect status #[{ name := "location", value := location }])
                | _, _ => pure ()
                let captures := (route.captureNames.zip values)
                return build path (.route ⟨r, hr⟩) captures
              else throw (.make .notFound 404)
          | none =>
            match vhost.fallback with
            | none => throw (.make .notFound 404)
            | some action =>
              vhost.rules.check facts head.headers
              match action, head.kind with
              | .websocket _, _ =>
                if !websocketHead head then
                  throw (.make .upgradeRequired 426 #[{ name := "upgrade", value := "websocket".toUTF8 }])
                return build path .fallback #[]
              | _, .tunnel => throw (.make .notFound 404)
              | .deny status, _ => throw (.make .denied status)
              | .redirect status location, _ => throw (.make .redirect status #[{ name := "location", value := location }])
              | _, _ => return build path .fallback #[]
        else throw unknown
      else throw unknown
    else throw (.make .badHeader 400)
  else throw (.make .headerLimit 431)

end LeanNet.Gate
