import LeanNet.Gate
import LeanNet.Gate.Literal

open LeanNet LeanNet.Gate LeanNet.HTTP

private def check (condition : Bool) (label : String) : IO Unit :=
  unless condition do throw (IO.userError s!"gate test: {label}")

private def policyOf (text : String) : IO Policy := do
  match Spec.parse text with
  | .error e => throw (IO.userError s!"parse failed: {e}")
  | .ok spec => match Policy.compile spec with
    | .error e => throw (IO.userError s!"compile failed: {e}")
    | .ok policy => pure policy

private def compileError (text : String) (fragment : String) : IO Unit := do
  match Spec.parse text with
  | .error e => check ((toString e).contains fragment) s!"expected '{fragment}', got parse error {e}"
  | .ok spec => match Policy.compile spec with
    | .ok _ => throw (IO.userError s!"gate test: policy accepted, expected '{fragment}'")
    | .error e => check ((toString e).contains fragment) s!"expected '{fragment}', got {e}"

private def hdr (name value : String) : HTTP1.Header := { name, value := value.toUTF8 }

private def head (authority : String) (method target : String) (extra : Array HTTP1.Header := #[])
    (kind : Admission.Kind := .request) : Admission.Head :=
  { protocol := .http11, method, target := target.toUTF8, authority := authority.toUTF8, headers := #[hdr "host" authority] ++ extra, kind }

private def plain := Transport.Facts.forTesting false (peer := ByteArray.mk #[10, 2, 3, 4])
private def tls (sni : String) := Transport.Facts.forTesting true (sni := some sni.toUTF8) (peer := ByteArray.mk #[10, 2, 3, 4])

private def statusOf (result : Except Rejection Admitted) : Nat :=
  match result with | .ok _ => 0 | .error r => r.status

private def reasonOf (result : Except Rejection Admitted) : Option Reason :=
  match result with | .ok _ => none | .error r => some r.reason

private def policyText := "
limits { headers 20 ; header-bytes 4KiB ; path-depth 8 }
ratelimit api 100/s burst 10 by client-ip
backend profiles { http 10.0.0.5:8080 10.0.0.6:8080 ; serves api.example.com }
backend tenants  { https tenants.internal:443 ; verify tenants.internal ; serves *.tenant.example.com }

host api.example.com {
  tls sni strict
  headers { forbid x-internal-* ; max authorization 64 ; single authorization }
  route GET,HEAD /profile/:id        -> proxy profiles { limit api }
  route PUT      /profile/:id/avatar -> app avatar     { body 5MiB ; headers { one-of content-type image/png image/jpeg } }
  route GET      /profile/me         -> app me
  route *        /admin/*            -> deny 403
  route GET      /static/*           -> app
  route GET      /ws                 -> websocket chat
  route GET      /old/*              -> redirect 308 https://example.com/new
  route GET      /internal           -> app { allow 10.0.0.0/8 ; deny 10.1.0.0/16 }
  route GET      /keyed              -> app { headers { require x-api-key ; strip x-debug } }
}
host *.tenant.example.com {
  mtls require uri spiffe://corp/tenant/*
  route * /* -> proxy tenants
}
host plain.example.com:8080, plain.example.com { tls sni off ; fallback app }
on unknown-host 421
"

private def parsing : IO Unit := do
  let policy ← policyOf policyText
  check (policy.hosts.size == 3 && policy.backends.size == 2 && policy.rates.size == 1) "policy shape"
  check (policy.rates[0]!.tokens == 100 && policy.rates[0]!.burst == 10 && policy.rates[0]!.key == .clientIp) "rate parse"
  compileError "host a.com { route GET /x -> proxy nowhere }" "unknown backend"
  compileError "backend b { http 1.2.3.4:80 ; serves other.com }\nhost a.com { route GET /x -> proxy b }"
    "does not declare 'serves'"
  compileError "host a.com { route GET /x -> app }\nhost A.com { route GET /y -> app }" "duplicate host pattern"
  compileError "host a.com { route GET /x/:id -> app\n route GET /x/:other -> app }" "overlaps"
  compileError "host a.com { route GET /a/*/b -> app }" "final segment"
  compileError "host a.com { route GET /x -> app { limit nope } }" "unknown rate limit"
  compileError "host a.com { allow 10.0.0.300/8 ; route GET /x -> app }" "invalid CIDR"
  compileError "host bad_host { route GET /x -> app }" "invalid host pattern"
  compileError "host a.com { route get /x -> app }" "invalid method"
  compileError "host a.com { route GET /x -> nothing }" "unknown action"
  compileError "host a.com {\n route GET /x -> app {\n" "unterminated"
  compileError "backend b { https 1.2.3.4:443 ; verify bad_name ; serves a.com }" "verify name"
  -- Same methods on different patterns, and disjoint methods on one pattern, are fine.
  let _ ← policyOf "host a.com { route GET /x/:id -> app\n route POST /x/:other -> app }"
  -- The compile-time literal is a plain Spec.
  let literal : Spec := gate% "host lit.example.com { route GET /hello -> app }"
  check (literal.hosts.size == 1) "gate% literal"

private def hosts : IO Unit := do
  let policy ← policyOf policyText
  check (statusOf (admitHead policy plain (head "nope.example.com" "GET" "/")) == 421) "unknown host 421"
  check ((admitHead policy plain (head "plain.example.com:8080" "GET" "/anything")).toBool) "exact host with port"
  check ((admitHead policy plain (head "PLAIN.example.com" "GET" "/x")).toBool) "case-insensitive host"
  check (statusOf (admitHead policy plain (head "plain.example.com:9090" "GET" "/x")) == 0) "port-less pattern covers other ports"
  check (reasonOf (admitHead policy plain (head "example.com." "GET" "/")) == some .badAuthority) "trailing dot rejected"
  check (reasonOf (admitHead policy plain (head "a.b.tenant.example.com" "GET" "/")) == some .unknownHost) "wildcard spans one label"
  check (reasonOf (admitHead policy plain (head "tenant.example.com" "GET" "/")) == some .unknownHost) "wildcard excludes apex"
  -- SNI must equal the Host on strict hosts; it is ignored where sni is off.
  check ((admitHead policy (tls "api.example.com") (head "api.example.com" "GET" "/profile/me")).toBool) "matching SNI"
  check (reasonOf (admitHead policy (tls "other.example.com") (head "api.example.com" "GET" "/profile/me")) == some .misdirected) "SNI mismatch 421"
  check (reasonOf (admitHead policy (Transport.Facts.forTesting true) (head "api.example.com" "GET" "/profile/me")) == some .misdirected) "missing SNI 421"
  check ((admitHead policy (tls "other.example.com") (head "plain.example.com" "GET" "/x")).toBool) "sni off"
  -- Host/:authority disagreement and duplicate Host are refused.
  check (reasonOf (admitHead policy plain { head "api.example.com" "GET" "/profile/me" with authority := "plain.example.com".toUTF8 }) == some .badAuthority) "authority/Host mismatch"
  check (reasonOf (admitHead policy plain (head "api.example.com" "GET" "/profile/me" #[hdr "host" "x.com"])) == some .badAuthority) "duplicate Host"
  let h2 : Admission.Head :=
    { protocol := .http2, method := "GET", target := "/profile/me".toUTF8, authority := "api.example.com".toUTF8, scheme := some "https".toUTF8, headers := #[] }
  check ((admitHead policy (tls "api.example.com") h2).toBool) "HTTP/2 authority"
  check (reasonOf (admitHead policy (tls "api.example.com") { h2 with scheme := some "http".toUTF8 }) == some .misdirected) "h2 scheme mismatch"
  check (reasonOf (admitHead policy (tls "api.example.com") { h2 with headers := #[hdr "host" "other.com"] }) == some .badAuthority) "h2 host disagreement"

private def paths : IO Unit := do
  let policy ← policyOf policyText
  let api := fun method target => admitHead policy (tls "api.example.com") (head "api.example.com" method target)
  match api "GET" "/profile/42?x=1" with
  | .ok a =>
    check (a.capture "id" == some "42".toUTF8) "capture"
    check (a.path.query == "x=1".toUTF8) "query split"
    match a.backend? with
    | some b => check (a.policy.backends[b].name == "profiles") "proxy route bound to its backend"
    | none => throw (IO.userError "proxy route lost its backend")
  | .error _ => throw (IO.userError "profile route rejected")
  -- Literal beats :param; HEAD follows GET.
  match api "HEAD" "/profile/me" with
  | .ok a => check (a.backend?.isNone && a.routeId?.isSome) "literal precedence"
  | .error _ => throw (IO.userError "literal route rejected")
  -- Encoded and dotted bypasses of /admin/* are normalised or refused.
  for target in ["/admin", "/admin/x", "/%61dmin/x", "/%41DMIN"] do
    let expected := if target == "/%41DMIN" then 404 else 403
    check (statusOf (api "GET" target) == expected) s!"admin bypass {target}"
  for target in ["/a/../admin", "/./admin", "/admin%2Fx", "/a//b", "/x\\y", "/bad%0Z"] do
    check (reasonOf (api "GET" target) == some .badPath) s!"ambiguous path {target}"
  check (reasonOf (api "GET" "http://other.com/x") == some .badPath) "absolute-form refused"
  check (reasonOf (api "GET" "/a/b/c/d/e/f/g/h/i") == some .badPath) "path depth bound"
  -- /static/* covers the prefix itself and everything below.
  for target in ["/static", "/static/", "/static/css/site.css"] do
    check ((api "GET" target).toBool) s!"subtree {target}"
  match api "DELETE" "/profile/me" with
  | .error r =>
    check (r.status == 405 && r.headers.any (fun h => h.name == "allow" && h.value == "GET".toUTF8)) "405 with Allow"
  | .ok _ => throw (IO.userError "wrong method accepted")
  check (reasonOf (api "GET" "/missing") == some .notFound) "404"
  match api "GET" "/old/page" with
  | .error r => check (r.status == 308 && r.headers.any (·.name == "location")) "redirect"
  | .ok _ => throw (IO.userError "redirect route admitted")
  -- WebSocket routes need an upgrade; tunnels need a websocket route.
  check (statusOf (api "GET" "/ws") == 426) "websocket route without upgrade"
  check ((admitHead policy (tls "api.example.com") (head "api.example.com" "GET" "/ws" #[] .upgrade)).toBool) "websocket upgrade"
  check (statusOf (admitHead policy (tls "api.example.com") (head "api.example.com" "CONNECT" "/profile/me" #[] .tunnel)) == 404) "tunnel off a websocket route"
  -- Fallback serves unmatched paths on hosts without routes.
  check ((admitHead policy plain (head "plain.example.com" "POST" "/deep/path")).toBool) "fallback"

private def rules : IO Unit := do
  let policy ← policyOf policyText
  let api := fun (facts : Transport.Facts) method target extra =>
    admitHead policy facts (head "api.example.com" method target extra)
  let facts := tls "api.example.com"
  check (reasonOf (api facts "GET" "/profile/1" #[hdr "x-internal-trace" "1"]) == some .forbiddenHeader) "forbidden prefix"
  check (reasonOf (api facts "GET" "/profile/1" #[hdr "authorization" (String.ofList (List.replicate 100 'a'))]) == some .headerTooLarge) "max header"
  check (reasonOf (api facts "GET" "/profile/1" #[hdr "authorization" "a", hdr "authorization" "b"]) == some .duplicateHeader) "single header"
  check ((api facts "PUT" "/profile/1/avatar" #[hdr "content-type" "Image/PNG; q=1"]).toBool) "one-of media type"
  check (statusOf (api facts "PUT" "/profile/1/avatar" #[hdr "content-type" "text/html"]) == 415) "unsupported media type 415"
  check (reasonOf (api facts "GET" "/keyed" #[]) == some .missingHeader) "required header"
  -- Address rules: allow 10/8, deny 10.1/16.
  check ((api facts "GET" "/internal" #[]).toBool) "allowed peer"
  let denied := Transport.Facts.forTesting true (sni := some "api.example.com".toUTF8) (peer := ByteArray.mk #[10, 1, 9, 9])
  check (reasonOf (api denied "GET" "/internal" #[]) == some .ipDenied) "denied subnet"
  let outside := Transport.Facts.forTesting true (sni := some "api.example.com".toUTF8) (peer := ByteArray.mk #[192, 168, 0, 1])
  check (reasonOf (api outside "GET" "/internal" #[]) == some .ipDenied) "outside allow list"
  -- Header-level safety (CRLF injection, names, counts, bytes).
  check (reasonOf (api facts "GET" "/profile/1" #[hdr "x-a" "1\r\nX-Injected: yes"]) == some .badHeader) "CRLF value"
  check (reasonOf (api facts "GET" "/profile/1" #[hdr "x a" "1"]) == some .badHeader) "invalid name"
  check (reasonOf (api facts "GET" "/profile/1" #[hdr "x-a" " padded"]) == some .badHeader) "surrounding whitespace"
  check (reasonOf (api facts "GET" "/profile/1" (Array.replicate 25 (hdr "x-a" "1"))) == some .headerLimit) "header count"
  check (reasonOf (api facts "GET" "/profile/1" #[hdr "x-a" (String.ofList (List.replicate 5000 'a'))]) == some .headerLimit) "header bytes"
  -- mTLS principals on the tenant wildcard host.
  let tenant := fun (principal : Option HTTP1.ClientCertificate) =>
    admitHead policy (Transport.Facts.forTesting true (sni := some "acme.tenant.example.com".toUTF8) (principal := principal))
      (head "acme.tenant.example.com" "GET" "/x")
  check (reasonOf (tenant none) == some .clientCertRequired) "client certificate required"
  check (reasonOf (tenant (some { subject := "CN=x", subjectAltNames := #["URI:spiffe://corp/other/a"] })) == some .principalDenied) "principal prefix"
  match tenant (some { subject := "CN=x", subjectAltNames := #["DNS:x", "URI:spiffe://corp/tenant/acme"] }) with
  | .ok a =>
    match a.backend? with
    | some b => check (a.policy.backends[b].name == "tenants") "tenant backend"
    | none => throw (IO.userError "tenant proxy lost backend")
  | .error _ => throw (IO.userError "verified tenant rejected")

private def runtime : IO Unit := do
  let spec ← match Spec.parse policyText with | .ok s => pure s | .error e => throw (IO.userError (toString e))
  -- Every name must be supplied by the application.
  match (({ spec } : Config).validate) with
  | .error e => check ((toString e).contains "forwarder" || (toString e).contains "no handler registered") "missing handler detected"
  | .ok _ => throw (IO.userError "missing handlers accepted")
  let echo : Handler := fun a _ => pure { response := { body := ((a.capture "id").getD "none".toUTF8) } }
  let app : App := { handlers := #[("avatar", echo), ("me", echo)], forwarder := some echo }
  match (({ spec, app } : Config).validate) with
  | .error e => check ((toString e).contains "limiter") "missing limiter detected"
  | .ok _ => throw (IO.userError "missing limiter accepted")
  let calls ← IO.mkRef (0 : Nat)
  let limiter : Limiter := { acquire := fun _ _ _ _ _ => do
    calls.modify (· + 1)
    return if (← calls.get) > 2 then 1500 else 0 }
  let config : Config := { spec, app, limiter := some limiter }
  let factory ← match factory config with | .ok f => pure f | .error e => throw (IO.userError (toString e))
  let hook ← factory 0
  let facts := tls "api.example.com"
  let decide := fun target extra => hook.decide facts (head "api.example.com" "GET" target extra)
  for _ in [:2] do
    match ← decide "/profile/7" #[] with
    | .accept _ (some handler) _ _ =>
      let reply ← handler { method := "GET", target := "/profile/7".toUTF8, headers := #[], body := .empty }
      check (reply.response.body == "7".toUTF8) "forwarder receives the admitted request"
    | _ => throw (IO.userError "rate-limited route rejected early")
  match ← decide "/profile/7" #[] with
  | .reject r => check (r.status == 429 && r.headers.any (fun h => h.name == "retry-after" && h.value == "2".toUTF8)) "429 Retry-After"
  | .accept .. => throw (IO.userError "limit not enforced")
  match ← decide "/keyed" #[hdr "x-api-key" "k", hdr "x-debug" "1"] with
  | .accept _ none (some rewrite) _ =>
    let request := rewrite { method := "GET", target := "/keyed".toUTF8, headers := #[hdr "x-debug" "1", hdr "x-api-key" "k"], body := .empty }
    check (!request.headers.any (·.name == "x-debug") && request.headers.any (·.name == "x-api-key")) "strip rewrite"
  | _ => throw (IO.userError "strip rewrite missing")
  match ← hook.decide facts (head "api.example.com" "PUT" "/profile/1/avatar" #[hdr "content-type" "image/png"]) with
  | .accept bodyLimit .. => check (bodyLimit == some (5 * 1048576)) "route body bound"
  | .reject _ => throw (IO.userError "avatar rejected")
  -- hostsOnly: a strict host allowlist in front of the server's handlers.
  let only ← match Policy.compile (Spec.hostsOnly #["only.example.com"]) with
    | .ok p => pure p | .error e => throw (IO.userError (toString e))
  check ((admitHead only plain (head "only.example.com" "POST" "/any/path")).toBool) "hostsOnly admits its host"
  check (reasonOf (admitHead only plain (head "evil.example.com" "GET" "/")) == some .unknownHost) "hostsOnly refuses others"

private def cidrs : IO Unit := do
  let some v6 := Cidr.parse "2001:db8::/32" | throw (IO.userError "IPv6 CIDR")
  let inside := ByteArray.mk #[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
  check (v6.contains inside && !v6.contains (ByteArray.mk #[10, 0, 0, 1])) "IPv6 CIDR match"
  let some odd := Cidr.parse "192.168.0.0/23" | throw (IO.userError "odd prefix")
  check (odd.contains (ByteArray.mk #[192, 168, 1, 7]) && !odd.contains (ByteArray.mk #[192, 168, 2, 1])) "non-octet prefix"
  check ((Cidr.parse "1.2.3.4/33").isNone && (Cidr.parse "01.2.3.4").isNone && (Cidr.parse "::1::").isNone) "invalid CIDRs"

def main : IO Unit := do
  parsing
  hosts
  paths
  rules
  runtime
  cidrs
  IO.println "Gate policy, routing, rules and runtime tests passed"
