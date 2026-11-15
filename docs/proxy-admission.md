# Opt-in proxy admission design

`LeanNet.Proxy.Admission` is a first slice of a reverse-proxy boundary. It
compiles an allowlist of exact authorities and returns a sealed
`ValidatedRequest` that contains the selected route. The module is not yet
wired into the listeners and does not forward traffic. Existing server behavior
is unchanged until an application chooses the gateway path.

## Current type boundary

```lean
Policy.compile : Array Route → Limits → UInt64 → Except ConfigError Policy
admit : Policy → TransportFacts → ParsedHead → Except ProxyError ValidatedRequest
ValidatedRequest.backend : ValidatedRequest → Backend
ValidatedRequest.policyGeneration : ValidatedRequest → UInt64
ValidatedRequest.checkBodySize : ValidatedRequest → Nat → Except ProxyError Unit
```

The `Policy` and `ValidatedRequest` constructors are private. Application code
cannot replace a validated request's route with another backend. The route is
selected by exact, ASCII case-insensitive authority lookup and carried with the
request. `ValidatedRequest.countBound` proves that at most 100 headers reached
the wrapper; the proof is in `Prop` and is erased by Lean's compiler. Other
invariants rely on the sealed constructor's checked control flow, not separate
machine-checked theorems. Given the supplied transport facts, the constructor
checks header names and values, the configured count and byte limits, the
method and origin-form target, unique `Host`, HTTP/2 `:authority`/`Host`
agreement, scheme/transport agreement, exact Host/SNI agreement for TLS, the
route's method allowlist, and required headers. It
rejects absolute-form and CONNECT targets in this initial reverse-proxy
profile. The future body stream must check its cumulative byte count against
the selected route before forwarding each chunk. The present
`checkBodySize` helper does not make that check mandatory.

The current parser already applies framing, header syntax, and size limits.
This module rechecks the public `ParsedHead` because ordinary Lean structures
can be constructed by application code. The final integrated path should let
the parser create a sealed head witness directly, avoiding a second scan.
`Prop` erasure removes proof *values*, not validation work or Lean's reference
counting and allocations. The present module has not been benchmarked against
the 100k RPS/core target.

The strict authority profile accepts ASCII DNS-style names (including exact
dotted IPv4 text) and an optional explicit decimal port. It rejects bracketed
IPv6 literals, percent-encoded hostnames, userinfo, trailing dots, empty/zero
ports, and wildcard routing. An allowed
`example.com` and an allowed `example.com:443` are separate entries. This
conservative profile can be extended with separately specified canonical
forms, without silently changing existing route keys.

## Required ingress flow

1. The socket and TLS layer establish the transport. TLS must preserve the
   ClientHello SNI and the verified client-certificate identity as transport
   metadata; request headers cannot provide either fact.
2. The HTTP/1 parser or HTTP/2 HPACK decoder validates syntax and framing and
   emits a bounded head. HTTP/1 must pass its unique `Host`; HTTP/2 must pass
   `:authority` and `:scheme` and reject a disagreeing `Host` field.
3. A common **head-stage** gate runs before body intake, `100 Continue`, h2c
   upgrade, WebSocket selection, health/metrics, or an application callback.
   It calls `admit`, then the route limiter, returning `Except ProxyError`.
4. On success the request retains an immutable policy snapshot and its bound
   route. A business handler receives the validated type. A forwarding API
   derives the upstream solely from that route, never from `Host`, a forwarded
   header, or a separate backend argument. It creates fresh upstream framing,
   strips hop-by-hop and untrusted forwarding headers, verifies the upstream
   TLS name specified by `UpstreamTransport.tls`, and applies response limits
   before returning bytes to the client.
5. On failure the reactor translates `ProxyError.status` to a bounded response
   and stops or cancels upload intake. This path returns typed errors rather
   than throwing exceptions.

The current `HTTP1.Handlers.onHeaders` runs before an HTTP/1 body, but the
reactor currently handles h2c upgrade first and bypasses application handlers
for health and metrics. HTTP/2 has no equivalent policy pause: its frame loop
can consume HEADERS and DATA from one read before the application sees the
head. A safe integration therefore adds a server-level gate before those
special paths. The HTTP/2 parser must stop at the first validated head, mark
that stream awaiting a decision, and resume buffered DATA only after accept.
Reject sends a final status and cancels the stream without buffering the body.
The existing early `417` response path is a useful model. Admission must run
for every HTTP/2 stream, because one TLS connection may carry several
authorities.

`TransportFacts.secure` and `TransportFacts.sni` are public fields in this pure
prototype. They establish agreement with caller-supplied transport facts, not
provenance from a socket. An integrated gate must replace them with sealed
transport evidence minted by the reactor/TLS provider before claiming Host/SNI
security.
The TLS worker currently uses SNI for certificate selection but does not
expose it to `HTTP.Transport.Endpoint`. Until that metadata is plumbed through,
the server cannot claim strict Host/SNI matching. A TLS gateway must fail
closed on absent or mismatched SNI, including when certificate selection falls
back to a default certificate. Verified mTLS identity must likewise be passed
from the transport's trusted state for any principal-specific rule.

The integrated signature should replace the public prototype facts with an
opaque value constructed by the transport provider:

```lean
opaque VerifiedTransport : Type
admitHead : Policy → VerifiedTransport → ParsedHead → Except ProxyError ValidatedRequest
```

Only the reactor receives `VerifiedTransport`; an application cannot mint it
from request bytes. The provider records whether TLS was negotiated, the
ClientHello SNI, and the verified mTLS identity separately from HTTP fields.

## Rate limits

The first useful rule is per **configured route ID**, not per a client-supplied
`X-Forwarded-For` or identity header. For a process-wide fixed-window cap, keep
one native atomic `(epoch, remaining)` budget per route and a small tagged
credit lease on each reactor owner. A worker checks monotonic time on every
admission, discards old-epoch credits, decrements a local credit for the common
case, and reserves another bounded batch with CAS when empty. A single atomic
reservation transfers credits from the shared budget to that worker, so the
sum of spent and outstanding credits never exceeds the configured window cap.
The epoch may only move forward. Exhaustion returns a retry delay for a `429`.
Small leases reduce atomic contention but can leave some quota unused when
workers are idle; fixed windows also permit boundary bursts. A token-bucket
variant can be added behind the same interface if smoother traffic is needed.

The per-request admission call should remain native, adjacent to the reactor,
if a no-allocation hot path is a hard requirement:

```c
/* allowed, retry delay, or internal failure; route_id comes from Policy. */
ln_rate_result ln_rate_try_acquire(ln_limiter *limiter,
    uint32_t route_id, uint16_t worker_id, uint64_t monotonic_ns);
```

Lean owns setup/reload and typed results, rather than allocating a Lean `IO`
object for every rate check. Reconfiguration publishes a new generation;
workers discard old leases before admitting under it. A process-local limit
does not enforce a quota across container replicas. A fleet-wide hard limit
requires a coordinator that grants bounded quotas to replicas (or a deliberately
partitioned static quota), with an explicit behavior when it is unavailable.
The Lean-facing management boundary can use setup-only signatures such as
`create : Array RateLimitSpec → IO LimiterHandle` and
`reload : LimiterHandle → UInt64 → Array RateLimitSpec → IO Unit`; the native
reactor calls `ln_rate_try_acquire` for each admitted head.

## Configuration and extension

Routes and limits should be runtime data so they can hot-reload without a
rebuild, while the *schema of the configuration* and admission states remain
compile-time Lean types. Parse JSON or another control-plane format off the
request path, validate it, compile exact route keys and stable route IDs, and
publish an immutable generation to each worker. In-flight requests retain
their original generation. Reject a new generation atomically if any entry is
invalid or ambiguous. A small static deployment can define the same typed
`Array Route` in Lean; both sources go through `Policy.compile`.

The current route lookup is linear and is suitable only for a small allowlist.
Before a large virtual-host deployment, compile a prehashed immutable table
and benchmark lookups, parser handoff, and allocations on the target Linux
container and load balancer. The current `requiredHeaders` rule checks
presence only, not values. Later route schemas can add typed method/path
matchers, required mTLS principals, content type and body decoders, and
upstream pool policies without changing the sealed admission/forwarding
boundary. Body schema checks occur as a separate typed stage after bounded
stream decoding; a head-only witness must never assert that arbitrary body
bytes satisfy a schema.

## Rejection mapping

`badHeaders`, `badTarget`, `badAuthority`, and missing required fields map to
400; header limits map to 431; an unknown host or disallowed method maps to
403; TLS/SNI or HTTP/2 scheme mismatch maps to 421; body limit maps to 413;
rate exhaustion maps to 429. Reject responses must not echo untrusted host or
header bytes.

This design follows HTTP authority and misdirected-request semantics in
[RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html) and HTTP/2
`:authority` rules in [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.html).
