# Request gate and gateway

`LeanNet.Gate` validates a request head before its body reaches an application handler. A policy selects a host and route, applies header, address, mTLS and rate rules, then dispatches to an application handler, redirect, denial, WebSocket handler or HTTP/1.1 upstream. Enable it through `HTTP.ReactorServerConfig.admission`; set `gateway := some {}` for the built-in proxy transport.

## Policy

Save a policy as `gate.policy` and pass `--gate gate.policy` to either supplied executable:

```text
limits { headers 64 ; header-bytes 16KiB ; target-bytes 16KiB ; path-depth 16 }
ratelimit clients 1000/s burst 200 by client-ip
backend api { http 127.0.0.1:9000 ; serves api.example.com }

host api.example.com {
  tls sni strict
  limit clients
  headers { forbid x-internal-* ; strip x-debug }
  route GET /items/:id -> proxy api
  route * /admin/* -> deny 403
  fallback app
}
on unknown-host 421
```

```sh
.lake/build/bin/lean-net-http1 --gate ./gate.policy 8080
tls/.lake/build/bin/lean-net-tls ./chain.pem ./key.pem --gate ./gate.policy 8443
```

The file is validated at startup. SIGHUP reloads it on POSIX; invalid replacement text keeps the current policy. Rate declarations require a restart. A `gate% "..."` literal in Lean checks policy syntax and host/backend compatibility at build time. `Gate.Spec.parse` accepts runtime text, and `Gate.Spec.hostsOnly #["api.example.com"]` creates a host allowlist.

| Policy item | Form |
| --- | --- |
| Host | `host api.example.com, *.example.com { ... }`; exact, one-label wildcard, or `_` catch-all |
| Route | `route GET,HEAD /items/:id -> app item`; literal segments, `:name` capture, final `*` wildcard |
| Action | `app [NAME]`, `proxy BACKEND`, `websocket [NAME]`, `deny STATUS`, `redirect STATUS URL` |
| Host/route controls | `body SIZE`, `timeout DURATION`, `allow CIDR`, `deny CIDR`, `mtls require [uri|dns|email VALUE]`, `check NAME`, `limit NAME` |
| Header rules | `require NAME`, `forbid NAME`, `single NAME`, `max NAME SIZE`, `one-of NAME VALUES`, `strip NAME` inside `headers { ... }` |
| Rate declaration | `ratelimit NAME RATE burst N by route|global|client-ip|principal|header NAME`; `RATE` is `N/s`, `N/m`, `N/h` or `N/DURATION` |
| Backend | `backend NAME { http|https HOST:PORT ... ; serves HOST_PATTERN ; verify CERT_NAME }` |

The `serves` patterns must cover every host that can select the backend. `verify` selects the HTTPS certificate identity; without it, the target host is used. `host` and TLS SNI must agree when `tls sni strict` is set. Named `app` and `check` entries require a library program that registers their callbacks. The plain server rejects HTTPS backends; the TLS package supplies verified upstream TLS.

## Library setup

For a policy without rates, construct an admission factory with `Gate.factory { spec, app }`. For rates and runtime reload, use `Gate.withLive`:

```lean
import LeanNet

open LeanNet

def serve (spec : Gate.Spec) : IO Unit :=
  Gate.withLive { spec } 4 fun live =>
    HTTP.ReactorServer.serveFactory
      (fun _ => pure HTTP1.Handlers.default)
      { workers := 4, admission := some live.factory, gateway := some {} }
      "127.0.0.1" 8080
```

`Gate.App.handlers` registers `(name, handler)` pairs for `app NAME`; each handler receives an `Admitted` value and `HTTP1.Request`. `Gate.App.checks` registers head-stage checks returning `Except Gate.Rejection Unit`. Use `Gate.App.onReject` to observe rejections. `Gate.withLive` owns the shared limiter; set `onReload := live.reloadFile path` and `extraMetrics := live.metrics` when loading a policy file in a library application. Rejections become 400/403/404/405/413/415/421/426/429/431 as applicable; upstream failures become 502/503/504.

Rate limits are per process. `route` and `global` share a budget across workers; keyed limits use a fixed-size table. `by principal` requires a verified client certificate and keys on its subject and SANs. `by header NAME` requires exactly one such header. The separate `connectionRate := some { tokens := 20, periodMs := 1000, burst := 10 }` setting limits completed TCP accepts per peer IP before TLS. It defaults to off and sees the load balancer's source address unless client source IP is preserved.

## Upstream settings

`HTTP.ReactorServerConfig.gateway` accepts `LeanNet.Gateway.Config`. Its defaults include a per-worker pool of 64 total and 16 per target, a 30-second response timeout, a 5-second DNS timeout, and a 60-second resolution cache. Configure `pool.maxTotal`, `pool.maxPerTarget`, `pool.idleTimeoutMs`, `pool.connectTimeoutMs`, `response`, `responseTimeoutMs`, `resolveTimeoutMs`, and `resolveCacheMs` as needed. The gateway forwards requests and responses to HTTP/1.1 backends with bounded streaming and reuses only complete, idle connections. It does not proxy WebSocket upgrades or CONNECT tunnels.

For HTTPS backends in the supplied TLS executable, add `--upstream-ca roots.pem` for private trust roots. Library callers pass `upstreamCA := some "roots.pem"` to `LeanNetTLS.ReactorServer.serveFactory`. This is separate from inbound `clientCA`. Client `Connection` fields and their nominated hop-by-hop headers are removed; nominations of routing, framing, forwarding identity or `Upgrade` fields are rejected.
