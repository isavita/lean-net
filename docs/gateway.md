# Optional request gate and gateway

lean-net works in tiers. The **core** server (spec-compliant HTTP/1.x,
HTTP/2, TLS) is always on and unchanged. The **gate** is an opt-in,
head-stage policy layer for hosts, routes, header rules, address and mTLS
rules, rate limits and typed rejections. The **gateway** adds upstream
forwarding behind `-> proxy` routes. With no gate configured the server pays
one `Option` branch per request.

## Request flow

1. The transport establishes sealed `Transport.Facts`: TLS, ClientHello SNI,
   ALPN, binary peer IP and verified mTLS identity. These never come from
   request bytes.
2. The core HTTP/1 parser or HTTP/2 HPACK decoder validates framing and
   syntax. HTTP/2 streams pause at their validated head; no further frames
   are read until the decision.
3. `Gate.decide` runs before any body intake, `100 Continue`, h2c upgrade,
   WebSocket or tunnel selection, metrics or health endpoint, or handler:
   - header count, size and safety;
   - authority and virtual host;
   - SNI agreement (`421` on mismatch);
   - strict path normalisation;
   - route and method (`404`, or `405` with `Allow`);
   - address, mTLS and header rules;
   - named checks;
   - rate limits (`429` with `Retry-After`).
4. Accepted requests carry the route's body bound (`413` while streaming).
   They go to the bound action: an `app NAME` handler, the server's own
   handlers (`app`), a WebSocket selection, or the upstream `forwarder`.
   `strip` rules remove headers before any handler sees them.
5. Rejections are typed values (`Gate.Rejection`), never exceptions. HTTP/1
   rejections close the connection. HTTP/2 rejections refuse that stream
   only. Bodies are fixed reason labels and never echo request bytes.

## Using it

```lean
import LeanNet
import LeanNet.Gate.Literal   -- only for `gate%`
open LeanNet LeanNet.Gate

def policy : Spec := gate% "
host api.example.com {
  tls sni strict
  headers { forbid x-internal-* ; strip x-debug }
  route GET /items/:id -> app item
  route * /admin/*     -> deny 403
  fallback app
}"

def app : App := { handlers := #[("item", fun admitted request => do
  let id := admitted.capture \"id\"  -- normalised segment bytes
  ...)] }

def main : IO Unit := do
  let factory ← IO.ofExcept ((Gate.factory { spec := policy, app }).mapError toString)
  HTTP.ReactorServer.serveWithHandlers handlers { admission := some factory }
```

Use `Spec.parse text` for a runtime file, `gate% "…"` to check a policy at
build time (a malformed policy fails the build), or build a `Spec` directly.
All three go through `Policy.compile`. `Gate.factory` additionally verifies
that every `app NAME`, `check NAME`, `proxy` and rate limit the policy uses
is provided. Each worker compiles its own copy of the policy, so no policy
object is shared across cores. `Spec.hostsOnly #["api.example.com"]` is the
smallest useful gate: a strict host allowlist in front of the existing
handlers.

## From the command line

Both public executables accept `--gate POLICY`:

```sh
.lake/build/bin/lean-net-http1 --host 0.0.0.0 --metrics --gate ./gate.policy 8080
tls/.lake/build/bin/lean-net-tls chain.pem key.pem --metrics --gate ./gate.policy 8443
```

- **Startup.** The policy is validated at startup; an invalid file stops the
  server.
- **Reload.** `SIGHUP` re-reads and atomically publishes it. On the TLS
  server it also reloads certificates. Invalid text keeps the current policy
  and increments `lean_net_gate_reloads_total{result="failed"}`. Each worker
  picks up a new generation with one relaxed atomic load and compiles a
  private copy. In-flight requests keep their snapshot. Changing `ratelimit`
  lines requires a restart.
- **Actions.** CLI policies can use `app` (the server's handlers or static
  files), `deny`, `redirect` and `websocket`. Named handlers (`app NAME`),
  named checks and `proxy` need a library program that registers them.
- **Metrics.** Gate counters appear on `/metrics` and on the admin port:
  - `lean_net_gate_policy_generation`
  - `lean_net_gate_reloads_total{result}`
  - `lean_net_gate_admitted_total`
  - `lean_net_gate_rejections_total{reason}`
  - `lean_net_rate_limit_decisions_total{result}`
- **Access logs.** Records gain `route` (the matched pattern, `fallback` or
  `internal`) and `reject_reason` (the fixed reason label). Both come from
  configuration, never from request bytes.

The library equivalent is `Gate.withLive config workers fun live => …`, then
set `admission := some live.factory`, `onReload := live.reloadFile path` and
`extraMetrics := live.metrics`.

### Overhead

h2load on a shared 4-vCPU Linux VM: `-n 100000 -c 10 -m 100 -t 2`,
4 workers, six alternating rounds per mode. The gated policy has a
header-rule block, three routes and a fallback.

| Mode | Mean (req/s) | Rounds (req/s) |
| --- | --- | --- |
| No gate | 84,930 | 101,654 / 81,181 / 102,372 / 81,656 / 69,667 / 72,703 |
| `--gate` | 76,894 | 79,920 / 93,604 / 73,182 / 70,931 / 63,798 / 79,928 |

That is about 9% overhead. All 1.2 million requests succeeded, and RSS
stayed flat at about 152 MB. h2load ran on the same VM, so these numbers
are indicative only; measure on your target hardware.

What keeps the overhead low:
- The hot path has no shared atomic writes: admissions count on per-worker
  cache lines, and the generation check is a relaxed load.
- Bodyless HTTP/2 heads are decided in batches. The frame loop pauses only
  for heads that may carry a body.
- Paths without escapes are normalised as one slice.
- Header-name checks do not allocate.

## Policy language

```
# comments start with '#'; statements end at a newline or ';'
limits { headers 64 ; header-bytes 16KiB ; path-depth 16 }
ratelimit edge 2000/s burst 400 by client-ip      # route | global | client-ip | principal | header NAME
backend profiles { http 10.0.0.5:8080 10.0.0.6:8080 ; serves api.example.com }
backend tenants  { https tenants.internal:443 ; verify tenants.internal ; serves *.tenant.example.com }

host api.example.com, api.example.org {
  tls sni strict                                   # or: tls sni off
  allow 10.0.0.0/8 ; deny 10.9.0.0/16              # IPv4 and IPv6 CIDRs
  mtls require uri spiffe://corp/*                 # or: mtls require | dns NAME | email NAME
  limit edge ; check api-key ; body 1MiB ; timeout 30s
  headers { require x-api-key ; forbid x-internal-* ; max authorization 4KiB
            single authorization ; one-of content-type application/json ; strip x-debug }

  route GET,HEAD /profile/:id        -> proxy profiles { limit api }
  route PUT      /profile/:id/avatar -> app avatar     { body 5MiB }
  route *        /admin/*            -> deny 403
  route GET      /ws                 -> websocket chat
  route GET      /old/*              -> redirect 308 https://example.com/new
  fallback app                                     # unmatched paths go to the server's handlers
}
host *.tenant.example.com { route * /* -> proxy tenants }
on unknown-host 421                                # or: close (drop silently)
```

- **Hosts.** Exact names (optionally with a port, else any port), one-label
  wildcards (`*.x.com` matches `a.x.com`, not `x.com` or `a.b.x.com`), and
  `_` as a catch-all. Matching is case-insensitive. Host and HTTP/2
  `:authority` must agree.
- **Paths.** A pattern is made of literal segments, `:name` captures (one
  segment) and a final `*`. `/a/*` matches `/a`, `/a/` and everything below.
  Literal segments win over captures, and captures win over `*`, with
  backtracking. `HEAD` also matches `GET` routes. Identical patterns with
  overlapping methods are compile errors.
- **Normalisation is strict.** Unreserved escapes are decoded (`/%61dmin` is
  `/admin`). Encoded `/`, `\` or NUL, raw `\`, dot segments and empty inner
  segments return 400. The router, the application and an upstream all see
  the same normalised path. A gated server therefore rejects
  absolute-form and `*` targets, and HTTP/1.0 requests without `Host`.
- **Inheritance.** Host items apply to every route. A route overrides `body`
  and `timeout`, and adds to `limit`, `check`, `allow`, `deny`, `mtls` and
  `headers`.
- **Actions.** `websocket` routes require an upgrade (426 otherwise).
  HTTP/2 extended CONNECT requires a `websocket` route.

## Rate limits

`ratelimit NAME RATE [burst N] [by KEY]` declares a rule, and `limit NAME`
applies it to a host or route. RATE is `N/s`, `N/m`, `N/h` or `N/<duration>`.
Keys:
- `route` (the default) gives each route its own bucket;
- `global` shares one bucket across everything that uses the rule;
- `client-ip`, `principal` (verified mTLS SAN) and `header NAME` key per
  client.

Wrap the workers in `Gate.RateLimiter.withLimiter spec workers` and pass
`handle.limiter` to `Gate.Config`.

The native limiter (`c/ratelimit.h`) implements GCRA. That is a token bucket
stored as one 64-bit theoretical arrival time, so there are no
window-boundary bursts and `Retry-After` is exact.
- **`global` and `route` rules** reserve leases of up to about 5 ms of
  traffic per worker with one compare-and-swap, then spend them without
  atomics. Reservation precedes spending, so admissions never exceed rate ×
  time + burst. Leased cells that expire unused are lost: at most workers ×
  lease per lease period.
- **Keyed rules** use one fixed table of 64-bit words (a 24-bit tag and a
  40-bit TAT in 100 µs units). The table is indexed by SipHash-2-4 under a
  random per-process key and probed over four slots. A new key evicts the
  slot with the oldest arrival time. Tag collisions share a budget, which is
  stricter, never looser. Memory is `keyedSlots × 8` bytes (default 64Ki
  slots = 512 KiB).
- Limits are per process. A fleet-wide quota needs an external coordinator.
- `test/ratelimit_test.c` checks under AddressSanitizer/UBSan and
  ThreadSanitizer that 8 contending threads never exceed the burst, that
  sustained throughput stays within rate × time + burst, that route scopes
  are independent, and that eviction never over-admits.

## Guarantees and their limits

`Admitted` has a private constructor; only `admitHead` creates it. It
carries erased proofs:

- `Admitted.no_crlf`: no admitted header value contains CR or LF.
- `Admitted.header_count_bounded`: the policy's header-count bound holds.
- `Admitted.host_matches`: the selected virtual host has a pattern matching
  the request authority.
- `Admitted.backend_serves`: the backend selected for a request declares
  (`serves`) a pattern matching that request's authority. A `proxy` action
  stores its backend together with a proof that the backend serves every
  pattern of the route's own host. A policy that routes `example.com` to a
  backend that does not list it is rejected at compile time, and forwarding
  code can only read the backend from the admitted route.

These hold by construction and are checked by Lean. They do not cover the
trie's matching order or the parser, which are covered by tests. The sealed
types protect library code from accidental misuse, not from hostile code in
the same process. Proof values are erased at runtime, but the validation
pass itself still runs once per request.

## Rejections

| Status | Reasons |
| --- | --- |
| 400 | bad header, bad authority, bad path, missing/forbidden/duplicate header, unsupported value |
| 401–403 | checks (application-chosen), IP rules, mTLS requirements, `deny` |
| 404 / 405 | no route / wrong method (`Allow` lists the route's methods) |
| 413 | route body bound exceeded (also mid-stream) |
| 415 | `content-type` outside a `one-of` rule |
| 421 | unknown host (configurable) or SNI / scheme mismatch |
| 426 | WebSocket route without an upgrade |
| 429 | rate limit, with `Retry-After` |
| 431 | header count, bytes or `max` rule |

`App.onReject` observes every rejection, for example for metrics.
