import LeanNet.Gate.Core

/-! The gate policy language.

```
# comments start with '#'; statements end at a newline or ';'
limits { headers 64 ; header-bytes 16KiB ; path-depth 16 }
ratelimit edge 2000/s burst 400 by client-ip      # by: route | client-ip | principal | header NAME | global
backend profiles { http 10.0.0.5:8080 10.0.0.6:8080 ; serves api.example.com }
host api.example.com, *.api.example.com {
  tls sni strict                                    # or: tls sni off
  allow 10.0.0.0/8 ; deny 10.9.0.0/16
  mtls require uri spiffe://corp/*                  # or: mtls require | dns NAME | email NAME
  limit edge ; check api-key ; body 1MiB ; timeout 30s
  headers { require x-api-key ; forbid x-internal-* ; max authorization 4KiB
            single authorization ; one-of content-type application/json ; strip x-debug }
  route GET,HEAD /profile/:id        -> proxy profiles { limit api }
  route PUT      /profile/:id/avatar -> app avatar     { body 5MiB }
  route *        /admin/*            -> deny 403
  route GET      /ws                 -> websocket chat
  route GET      /old/*              -> redirect 308 https://example.com/new
  fallback app
}
on unknown-host 421                                 # or: close
```

Paths: literal segments, `:name` (one segment, captured) and a final `*`
(the prefix itself and everything below it). `app` without a name is the
server's own handlers. Host items are inherited by every route: `body`,
`timeout` are overridden by the route; `limit`, `check`, `allow`, `deny`,
`mtls` and `headers` accumulate. -/

namespace LeanNet.Gate

inductive KeySource where
  | global | route | clientIp | principal | header (name : String)
  deriving BEq, Repr, Inhabited

structure RateSpec where
  name : String
  /-- Tokens per `periodMs`. -/
  tokens : Nat
  periodMs : Nat
  burst : Nat
  key : KeySource := .route
  deriving Repr, Inhabited

inductive Scheme where
  | http | https
  deriving BEq, Repr, Inhabited

structure Target where
  scheme : Scheme
  host : String
  port : UInt16
  deriving Repr, Inhabited

structure BackendSpec where
  name : String
  targets : Array Target := #[]
  verify : Option String := none
  serves : Array String := #[]
  deriving Repr, Inhabited

inductive HeaderRule where
  | require (name : String)
  /-- A trailing `*` forbids every name with that prefix. -/
  | forbid (name : String)
  | max (name : String) (bytes : Nat)
  | single (name : String)
  | oneOf (name : String) (values : Array String)
  | strip (name : String)
  deriving Repr, Inhabited

inductive PrincipalRule where
  /-- Any verified client certificate. -/
  | any
  /-- A SAN of this type (`URI`, `DNS`, `email`) equal to the value, or with
      its prefix when the value ends in `*`. -/
  | san (kind : String) (value : String)
  deriving Repr, Inhabited, BEq

inductive ActionSpec where
  | app (name : Option String)
  | proxy (backend : String)
  | deny (status : Nat)
  | websocket (name : Option String)
  | redirect (status : Nat) (location : String)
  deriving Repr, Inhabited

structure Items where
  body : Option Nat := none
  timeoutMs : Option Nat := none
  limits : Array String := #[]
  checks : Array String := #[]
  allow : Array String := #[]
  deny : Array String := #[]
  mtls : Array PrincipalRule := #[]
  headers : Array HeaderRule := #[]
  deriving Repr, Inhabited

structure RouteSpec where
  /-- `none` is `*` (every method). -/
  methods : Option (Array String)
  path : String
  action : ActionSpec
  items : Items := {}
  line : Nat := 0
  deriving Repr, Inhabited

inductive SniMode where
  | strict | off
  deriving BEq, Repr, Inhabited

structure HostSpec where
  patterns : Array String
  sni : SniMode := .strict
  items : Items := {}
  routes : Array RouteSpec := #[]
  fallback : Option ActionSpec := none
  line : Nat := 0
  deriving Repr, Inhabited

inductive UnknownHost where
  | status (code : Nat) | close
  deriving Repr, Inhabited

structure LimitsSpec where
  maxHeaders : Nat := 100
  maxHeaderBytes : Nat := 16384
  maxPathDepth : Nat := 32
  deriving Repr, Inhabited

/-- A parsed policy. Build it from text (`Spec.parse`), at compile time
    (`gate%`), or directly in Lean; all three compile through `Policy.compile`. -/
structure Spec where
  limits : LimitsSpec := {}
  rates : Array RateSpec := #[]
  backends : Array BackendSpec := #[]
  hosts : Array HostSpec := #[]
  unknownHost : UnknownHost := .status 421
  deriving Repr, Inhabited

structure ParseError where
  line : Nat
  message : String
  deriving Repr, Inhabited

instance : ToString ParseError := ⟨fun e => s!"gate policy line {e.line}: {e.message}"⟩

/-! ## Lexer -/

inductive Tok where
  | word (text : String)
  | lbrace | rbrace | semi | comma | arrow
  deriving BEq, Repr, Inhabited

private def Tok.describe : Tok → String
  | .word text => s!"'{text}'" | .lbrace => "'{'" | .rbrace => "'}'"
  | .semi => "end of statement" | .comma => "','" | .arrow => "'->'"

/-- Newlines become statement separators; comments run to end of line. -/
def lex (input : String) : Array (Tok × Nat) := Id.run do
  let mut out : Array (Tok × Nat) := #[]
  let mut line := 1
  let mut word := ""
  let mut comment := false
  let flush := fun (out : Array (Tok × Nat)) (word : String) (line : Nat) =>
    if word.isEmpty then out else if word == "->" then out.push (.arrow, line) else out.push (.word word, line)
  for c in input.toList do
    if comment then
      if c == '\n' then
        comment := false
        out := out.push (.semi, line)
        line := line + 1
      continue
    if c == '#' then
      out := flush out word line; word := ""; comment := true
    else if c == '\n' then
      out := flush out word line; word := ""
      out := out.push (.semi, line); line := line + 1
    else if c == ' ' || c == '\t' || c == '\r' then
      out := flush out word line; word := ""
    else if c == '{' || c == '}' || c == ';' || c == ',' then
      out := flush out word line; word := ""
      out := out.push (match c with | '{' => .lbrace | '}' => .rbrace | ';' => .semi | _ => .comma, line)
    else word := word.push c
  out := flush out word line
  return out.push (.semi, line)

/-! ## Parser -/

private structure P where
  toks : Array (Tok × Nat)
  pos : Nat := 0

private abbrev PM := StateT P (Except ParseError)

private def peek : PM Tok := do
  let p ← get
  return (p.toks[p.pos]?.map (·.1)).getD .semi
private def lineNow : PM Nat := do
  let p ← get
  return (p.toks[p.pos]?.map (·.2)).getD ((p.toks.back?.map (·.2)).getD 0)
private def fail (message : String) : PM α := do throw { line := ← lineNow, message }
private def advance : PM Unit := modify fun p => { p with pos := p.pos + 1 }
private def atEnd : PM Bool := do let p ← get; return p.pos >= p.toks.size
private def skipSemis : PM Unit := do
  while (← peek) == .semi && !(← atEnd) do advance
private def word (what : String) : PM String := do
  match ← peek with
  | .word text => advance; return text
  | other => fail s!"expected {what}, found {other.describe}"
private def expectTok (tok : Tok) : PM Unit := do
  let t ← peek
  if t == tok then advance else fail s!"expected {tok.describe}, found {t.describe}"
private def endStatement : PM Unit := do
  match ← peek with
  | .semi => advance
  | .rbrace => pure ()
  | other => fail s!"unexpected {other.describe}"
private def isWord : PM Bool := do return match ← peek with | .word _ => true | _ => false

/-- `N`, `NKiB`, `NMiB`, `NGiB`, `NB`. -/
def parseSize (text : String) : Option Nat :=
  let units := [("GiB", 1073741824), ("MiB", 1048576), ("KiB", 1024), ("B", 1)]
  match units.find? (fun (suffix, _) => text.endsWith suffix) with
  | some (suffix, factor) => ((text.dropEnd suffix.length).toString.toNat?).map (· * factor)
  | none => text.toNat?

/-- `Nms`, `Ns`, `Nm`. -/
def parseDuration (text : String) : Option Nat :=
  if text.endsWith "ms" then (text.dropEnd 2).toString.toNat?
  else if text.endsWith "s" then ((text.dropEnd 1).toString.toNat?).map (· * 1000)
  else if text.endsWith "m" then ((text.dropEnd 1).toString.toNat?).map (· * 60000)
  else none

private def size : PM Nat := do
  let text ← word "a size such as 16KiB"
  let some n := parseSize text | fail s!"invalid size '{text}'"
  return n

private def status : PM Nat := do
  let text ← word "an HTTP status"
  let some n := text.toNat? | fail s!"invalid status '{text}'"
  if n < 100 || n > 599 then fail s!"status {n} out of range"
  return n

/-- Words on the rest of the statement (stops before `;`, `}` or `{`). -/
private partial def restWords : PM (Array String) := do
  let mut out := #[]
  repeat
    match ← peek with
    | .word text => advance; out := out.push text
    | .comma => advance
    | _ => break
  return out

private def headerRule : PM HeaderRule := do
  let kind ← word "a header rule"
  let lower := fun (s : String) => s.toLower
  match kind with
  | "require" => return .require (lower (← word "a header name"))
  | "forbid" => return .forbid (lower (← word "a header name"))
  | "max" =>
    let name := lower (← word "a header name")
    return .max name (← size)
  | "single" => return .single (lower (← word "a header name"))
  | "strip" => return .strip (lower (← word "a header name"))
  | "one-of" =>
    let name := lower (← word "a header name")
    let values ← restWords
    if values.isEmpty then fail "one-of needs at least one value"
    return .oneOf name values
  | other => fail s!"unknown header rule '{other}'"

private partial def headerBlock : PM (Array HeaderRule) := do
  expectTok .lbrace
  let mut rules := #[]
  repeat
    skipSemis
    if (← peek) == .rbrace then advance; break
    if ← atEnd then fail "unterminated headers block"
    rules := rules.push (← headerRule)
    endStatement
  return rules

private def optionalName : PM (Option String) := do
  if ← isWord then return some (← word "an application name") else return none

private def action : PM ActionSpec := do
  let kind ← word "an action"
  match kind with
  | "app" => return .app (← optionalName)
  | "websocket" => return .websocket (← optionalName)
  | "proxy" => return .proxy (← word "a backend name")
  | "deny" => return .deny (← status)
  | "redirect" =>
    let code ← status
    if ![301, 302, 303, 307, 308].contains code then fail "redirect needs a 3xx status"
    return .redirect code (← word "a location")
  | other => fail s!"unknown action '{other}'"

/-- One shared item; `none` if the keyword is not an item. -/
private def item (items : Items) (keyword : String) : PM (Option Items) := do
  match keyword with
  | "body" => advance; return some { items with body := some (← size) }
  | "timeout" =>
    advance
    let text ← word "a duration"
    let some ms := parseDuration text | fail s!"invalid duration '{text}'"
    return some { items with timeoutMs := some ms }
  | "limit" => advance; return some { items with limits := items.limits.push (← word "a rate limit name") }
  | "check" => advance; return some { items with checks := items.checks.push (← word "a check name") }
  | "allow" =>
    advance
    let blocks ← restWords
    if blocks.isEmpty then fail "allow needs CIDR blocks"
    return some { items with allow := items.allow ++ blocks }
  | "deny" =>
    advance
    let blocks ← restWords
    if blocks.isEmpty then fail "deny needs CIDR blocks"
    return some { items with deny := items.deny ++ blocks }
  | "mtls" =>
    advance
    let verb ← word "'require'"
    if verb != "require" then fail "expected 'mtls require'"
    if !(← isWord) then return some { items with mtls := items.mtls.push .any }
    let kind := (← word "uri, dns or email").toLower
    let kindName ← match kind with
      | "uri" => pure "URI" | "dns" => pure "DNS" | "email" => pure "email"
      | other => fail s!"unknown SAN type '{other}'"
    return some { items with mtls := items.mtls.push (.san kindName (← word "a SAN value")) }
  | "headers" => advance; return some { items with headers := items.headers ++ (← headerBlock) }
  | _ => return none

private partial def itemBlock (items : Items) : PM Items := do
  expectTok .lbrace
  let mut items := items
  repeat
    skipSemis
    if (← peek) == .rbrace then advance; break
    if ← atEnd then fail "unterminated block"
    let keyword ← match ← peek with
      | .word text => pure text
      | other => fail s!"unexpected {other.describe}"
    match ← item items keyword with
    | some next => items := next; endStatement
    | none => fail s!"unknown setting '{keyword}'"
  return items

private def methods : PM (Option (Array String)) := do
  let first ← word "methods"
  if first == "*" then return none
  let mut out := #[first]
  while (← peek) == .comma do
    advance
    out := out.push (← word "a method")
  for m in out do
    if m.isEmpty || !m.toUTF8.data.all (fun c => c >= 65 && c <= 90) then fail s!"invalid method '{m}'"
  return some out

private partial def route : PM RouteSpec := do
  let line ← lineNow
  advance
  let methodSet ← methods
  let path ← word "a path pattern"
  expectTok .arrow
  let act ← action
  let items ← if (← peek) == .lbrace then itemBlock {} else pure {}
  return { methods := methodSet, path, action := act, items, line }

private partial def hostBlock : PM HostSpec := do
  let line ← lineNow
  advance
  let mut patterns := #[← word "a host pattern"]
  while (← peek) == .comma do
    advance
    patterns := patterns.push (← word "a host pattern")
  expectTok .lbrace
  let mut host : HostSpec := { patterns, line }
  repeat
    skipSemis
    if (← peek) == .rbrace then advance; break
    if ← atEnd then fail "unterminated host block"
    let keyword ← match ← peek with
      | .word text => pure text
      | other => fail s!"unexpected {other.describe}"
    match keyword with
    | "route" => host := { host with routes := host.routes.push (← route) }
    | "fallback" => advance; host := { host with fallback := some (← action) }
    | "tls" =>
      advance
      if (← word "'sni'") != "sni" then fail "expected 'tls sni strict|off'"
      match ← word "strict or off" with
      | "strict" => host := { host with sni := .strict }
      | "off" => host := { host with sni := .off }
      | other => fail s!"unknown SNI mode '{other}'"
    | _ =>
      match ← item host.items keyword with
      | some items => host := { host with items }
      | none => fail s!"unknown host setting '{keyword}'"
    endStatement
  return host

/-- `2000/s`, `100/m`, `10/h`, or `5/250ms`. -/
def parseRate (text : String) : Option (Nat × Nat) :=
  match text.splitOn "/" with
  | [count, unit] =>
    let period := match unit with
      | "s" => some 1000 | "m" => some 60000 | "h" => some 3600000 | other => parseDuration other
    match count.toNat?, period with
    | some n, some p => if n == 0 || p == 0 then none else some (n, p)
    | _, _ => none
  | _ => none

private def rateDecl : PM RateSpec := do
  advance
  let name ← word "a rate limit name"
  let rateText ← word "a rate such as 100/s"
  let some (tokens, periodMs) := parseRate rateText | fail s!"invalid rate '{rateText}'"
  let mut spec : RateSpec := { name, tokens, periodMs, burst := tokens }
  repeat
    match ← peek with
    | .word "burst" =>
      advance
      let text ← word "a burst size"
      let some n := text.toNat? | fail s!"invalid burst '{text}'"
      spec := { spec with burst := n }
    | .word "by" =>
      advance
      let key ← match ← word "a key source" with
        | "route" => pure KeySource.route
        | "global" => pure .global
        | "client-ip" => pure .clientIp
        | "principal" => pure .principal
        | "header" => pure (.header (← word "a header name").toLower)
        | other => fail s!"unknown key source '{other}'"
      spec := { spec with key }
    | _ => break
  return spec

private def target (scheme : Scheme) (text : String) : PM Target := do
  let parts := text.splitOn ":"
  let (host, portText) ← match parts with
    | [host, port] => pure (host, port)
    | _ => fail s!"backend target '{text}' must be host:port"
  let some port := portText.toNat? | fail s!"invalid port in '{text}'"
  if port == 0 || port > 65535 || host.isEmpty then fail s!"invalid backend target '{text}'"
  return { scheme, host, port := port.toUInt16 }

private partial def backendDecl : PM BackendSpec := do
  advance
  let name ← word "a backend name"
  expectTok .lbrace
  let mut spec : BackendSpec := { name }
  repeat
    skipSemis
    if (← peek) == .rbrace then advance; break
    if ← atEnd then fail "unterminated backend block"
    match ← word "a backend setting" with
    | "http" => for t in ← restWords do spec := { spec with targets := spec.targets.push (← target .http t) }
    | "https" => for t in ← restWords do spec := { spec with targets := spec.targets.push (← target .https t) }
    | "verify" => spec := { spec with verify := some (← word "a TLS name") }
    | "serves" => spec := { spec with serves := spec.serves ++ (← restWords) }
    | other => fail s!"unknown backend setting '{other}'"
    endStatement
  return spec

private partial def limitsBlock (limits : LimitsSpec) : PM LimitsSpec := do
  advance
  expectTok .lbrace
  let mut limits := limits
  repeat
    skipSemis
    if (← peek) == .rbrace then advance; break
    if ← atEnd then fail "unterminated limits block"
    match ← word "a limit" with
    | "headers" =>
      let text ← word "a count"
      let some n := text.toNat? | fail s!"invalid count '{text}'"
      limits := { limits with maxHeaders := n }
    | "header-bytes" => limits := { limits with maxHeaderBytes := ← size }
    | "path-depth" =>
      let text ← word "a depth"
      let some n := text.toNat? | fail s!"invalid depth '{text}'"
      limits := { limits with maxPathDepth := n }
    | other => fail s!"unknown limit '{other}'"
    endStatement
  return limits

private partial def file : PM Spec := do
  let mut spec : Spec := {}
  repeat
    skipSemis
    if ← atEnd then break
    match ← peek with
    | .word "host" => spec := { spec with hosts := spec.hosts.push (← hostBlock) }
    | .word "backend" => spec := { spec with backends := spec.backends.push (← backendDecl) }
    | .word "ratelimit" => spec := { spec with rates := spec.rates.push (← rateDecl) }
    | .word "limits" => spec := { spec with limits := ← limitsBlock spec.limits }
    | .word "on" =>
      advance
      if (← word "'unknown-host'") != "unknown-host" then fail "expected 'on unknown-host'"
      match ← peek with
      | .word "close" => advance; spec := { spec with unknownHost := .close }
      | _ => spec := { spec with unknownHost := .status (← status) }
    | .word other => fail s!"unknown statement '{other}'"
    | other => fail s!"unexpected {other.describe}"
    endStatement
  return spec

/-- Parse the policy language. Semantic checks (unknown names, duplicate or
    shadowed routes, invalid hosts or CIDRs) happen in `Policy.compile`. -/
def Spec.parse (input : String) : Except ParseError Spec :=
  (file.run { toks := lex input }).map (·.1)

end LeanNet.Gate
