# Server configuration

`LeanNet.HTTP.ReactorServer.serveFactory factory config host port` serves HTTP/1.0, HTTP/1.1 and h2c on one cleartext listener. `factory : Nat → IO HTTP1.Handlers` runs once for each worker. Use `LeanNetTLS.ReactorServer.serveFactory` for TLS and ALPN. All servers bind `127.0.0.1` unless given another address.

## HTTP/1 and HTTP/2 on one listener

Set HTTP/1 options in `machine`, HTTP/2 options in `http2`, and shared connection budgets and deadlines in `server`. Each client selects its protocol; both protocols call the same handlers.

```lean
import LeanNet

open LeanNet

def config : HTTP.ReactorServerConfig := {
  workers := 0
  server := { maxClients := 128, requestTimeoutMs := 15000 }
  machine := { limits := { maxHeaderBytes := 16384, maxBodyBytes := 1048576 } }
  http2 := {
    maxConcurrentStreams := 128
    maxHeaderListBytes := 32768
    maxRequestBodyBytes := 2097152
    pingIntervalMs := 10000
  }
  cleartextProtocol := .detect
  h2cUpgrade := true
  healthPaths := true
  metricsPath := some "/metrics".toUTF8
}

def app (_ : Nat) : IO HTTP1.Handlers := pure {
  onRequest := fun _ => pure { response := { body := "ok\n".toUTF8 } }
}

def main : IO Unit :=
  HTTP.ReactorServer.serveFactory app config "127.0.0.1" 8080
```

This configuration allows a 1 MiB HTTP/1 body and a 2 MiB HTTP/2 body. For HTTPS, import `LeanNetTLS` and pass the same `app` and `config` to:

```lean
LeanNetTLS.ReactorServer.serveFactory app
  { certificateChain := "./chain.pem", privateKey := "./key.pem" }
  config "127.0.0.1" 8443
```

| Client connection | Selected protocol |
| --- | --- |
| TLS with `h2` offered through ALPN | HTTP/2 (preferred when both are offered) |
| TLS with only `http/1.1`, or without ALPN | HTTP/1.1 |
| Cleartext HTTP/2 preface | HTTP/2 (h2c) |
| Cleartext HTTP/1 request | HTTP/1.0 or HTTP/1.1 |
| Cleartext HTTP/1.1 h2c upgrade | HTTP/2 after a successful upgrade |

Ordinary browser HTTP/2 uses HTTPS and ALPN. `cleartextProtocol` applies only to cleartext connections; TLS always follows its negotiated protocol. For a cleartext HTTP/1-only listener, set `cleartextProtocol := .http1` and `h2cUpgrade := false`. A client offering only unsupported ALPN protocols is rejected during the handshake.

Check one running cleartext listener with `curl --http1.1 http://127.0.0.1:8080/` and `curl --http2-prior-knowledge http://127.0.0.1:8080/`. For TLS, use `curl --cacert roots.pem --http1.1 https://HOST:8443/` and `curl --cacert roots.pem --http2 https://HOST:8443/`.

`workers := 0` uses the available CPU count, capped by `server.maxClients`. `maxClients` is the total inbound client budget. The worker factory must create separate mutable application state per worker. Callbacks are synchronous on the worker.

Reserve at least one `outputBuffers` credit per client assigned to a worker. Higher connection limits also require enough `native` buffer and write credits; TLS reserves two additional native buffers per client.

| Config field | Default | Use |
| --- | ---: | --- |
| `server.maxClients` | 32 | Total inbound connections |
| `server.idleTimeoutMs`, `requestTimeoutMs`, `writeTimeoutMs` | 30,000 each | Connection deadlines |
| `machine.limits`, `machine.parserOptions` | See `HTTP1.Machine.Config` | HTTP/1 parser and body limits |
| `native`, `outputBuffers`, `maxInputBytes`, `maxOutputBytes` | Reactor defaults; 128; 2 MiB + 64 KiB; 16 MiB | Native capacity and per-client buffers |
| `http2.maxConcurrentStreams` | 128 | HTTP/2 concurrent streams per connection |
| `http2.maxHeaderListBytes`, `maxRequestBodyBytes` | 65,536; 1 MiB | HTTP/2 request bounds |
| `http2.pingIntervalMs`, `pingTimeoutMs` | 0; 10,000 | Active PING interval (0 disables) and ACK deadline |
| `http2.enablePush`, `enableConnectProtocol` | `false` | Server push and WebSocket extended CONNECT |
| `h2cUpgrade` | `true` | Cleartext HTTP/1.1 `Upgrade: h2c` |
| `cleartextProtocol` | `.detect` | Detect HTTP/1 or h2c, or force `.http1` / `.http2` |
| `connectionRate` | `none` | Per-peer-IP completed TCP accept budget before TLS, `{ tokens, periodMs, burst }` |
| `admission`, `gateway` | `none` | [Request gate and upstream forwarding](gateway.md) |
| `shutdownDrainMs` | 2,000 | SIGINT/SIGTERM application drain deadline |
| `pinWorkers` | `false` | Pin native workers to allowed CPUs |

`HTTP1.Handlers.onRequest` receives a validated request and returns a `Reply`. `onHeaders` can reject before receiving the body or transfer an HTTP/1.1 upgrade to a `RawPipe`. `onPush` supplies optional HTTP/2 pushes. `onWebSocket` selects an HTTP/2 WebSocket callback and Origin policy. The [WebSocket API](../LeanNet/WebSocket/Server.lean) accepts HTTP/1.1 upgrades through `WebSocket.Server.acceptHTTP1` and HTTP/2 extended CONNECT through `Handlers.onWebSocket`.

`onHeaders` runs on both protocols after server admission and before body
intake or `100 Continue`. HTTP/2 supplies version `HTTP/2` and the validated
Host header; framing is `.contentLength n` when known, otherwise `.chunked`
for an unknown-length stream body (there is no HTTP/1 chunk encoding). HTTP/2
ignores framing overrides, returns bodyless header rejections, and rejects raw
upgrades with 501. Use `onWebSocket` for HTTP/2 extended CONNECT. Server-owned
health and metrics endpoints bypass application header callbacks.

`Request.transport` contains owned, socket-free `TransportInfo`: `secure`,
binary `peer` IP (4/16 bytes), optional SNI, and ALPN. ReactorServer fills these
from the accepted socket or completed TLS handshake before post-body validators,
admission rewrites and synchronous/deferred application callbacks. Incoming
Forwarded or X-Forwarded-* headers cannot alter the facts. Applications can use
the actual peer to decide which proxies are trusted before interpreting those
headers. `clientCertificate` continues to hold verified mTLS identity separately.

## Deferred application replies

`Handlers.onRequestDeferred` opts the reactor server into deferred application
responses and takes precedence over `onRequest`. Return
`HTTP.Deferred.Result.immediate reply` or `.deferred job`. Existing synchronous
handlers and the blocking reference servers keep their current behavior; use
`ReactorServer.serveFactory` for this API.

A `HTTP.Deferred.Job` supplies `poll : IO (Option HTTP1.Reply)` and
`cancel : CancelReason → IO Unit`, plus `timeoutMs` and `retainedBytes`.
The owner worker invokes both callbacks synchronously. They must perform only
bounded, nonblocking work. A nonblocking adapter can retain its own completion
state in the worker factory and return `none` until it is ready. This API does
not turn arbitrary blocking `IO` into asynchronous work. Any external producer
must use its own bounded owned-byte completion queue and observe cancellation;
never share reactor sockets, transport endpoints, or borrowed native buffers.

The `deferred` server configuration bounds each worker independently:

| Field | Default | Meaning |
| --- | ---: | --- |
| `maxPending` | 1,024 | Concurrent unfinished jobs on one worker |
| `maxPendingPerClient` | 64 | Concurrent jobs for one connection |
| `maxRetainedBytes` | 16 MiB | Request snapshot bytes plus adapter-declared buffers |
| `maxTimeoutMs` | 30,000 | Absolute lifetime cap, independent of upload/write deadlines |
| `pollIntervalMs` | 5 | Maximum idle native poll delay while jobs remain (1–100 ms) |

The server charges body, target, method, headers and trailers automatically;
`retainedBytes` must include additional buffers captured by the adapter. A job
that exceeds a budget is cancelled with `overloaded` and receives 503. A job
whose deadline expires is cancelled with `timeout` and receives 504. A throwing
poll is cancelled with `failed` and receives 500. Cancellation callbacks are
called once, after the job is removed, and their exceptions cannot retain work.
Successful completion removes the job without calling `cancel`.

HTTP/1 keeps its parser paused at the pending request, so pipelined responses
remain ordered. Transport reads stay armed to detect resets; any received
pipeline tail stays on its worker under `maxInputBytes`. A TCP half-close still
allows the outstanding response. HTTP/2 keeps reading other streams and can
complete them in any order. RST_STREAM cancels only that stream (`streamReset`);
connection loss cancels all its jobs (`disconnected`). Graceful shutdown polls
accepted jobs through the existing drain budget and then cancels unfinished
jobs (`shutdown`). Deferred replies pass through the existing response bounds,
security headers, protocol encoding and output flow control. Deferred HTTP/2
responses do not call `onPush`.

Run the native acceptance fixture with `lake build lean-net-deferred-reply-fixture`
and `python3 test/test_deferred_replies.py -v`. It covers HTTP/1 ordering,
HTTP/2 independent completion, timeout/failure parity, per-client and worker
count limits, retained byte budgets, disconnect/reset cancellation, capacity
recovery and graceful shutdown. These checks are included in the Linux,
macOS and Windows TLS/reactor CI matrix.

## Static and operational options

Use [`HTTP.Static.serveRoot`](static-files.md) to serve an immutable directory. These `ReactorServerConfig` fields configure observability and controls:

| Field | Effect |
| --- | --- |
| `metricsPath := some "/metrics".toUTF8` | Prometheus endpoint |
| `healthPaths := true` | `/healthz` and `/readyz` |
| `adminPort := some 9000` | Loopback-only `/stats`, `/metrics`, `/healthz`, `/readyz` |
| `accessLog := some { path, helperBinary, ... }` | JSON access log through the sibling helper binary |
| `securityHeaders.enabled := false` | Disable default response security headers |
| `tracing := false` | Disable automatic W3C `traceparent` generation |
| `onReload := action` | Run nonblocking application reload action on SIGHUP (POSIX) |

The access-log queue defaults to 1,024 records per worker. `queueCapacity` accepts powers of two from 1 to 65,536. Put `lean-net-access-log-helper` beside the server executable or set `helperBinary` explicitly. A full queue drops records and increments `lean_net_access_log_dropped_total`.

`AccessConfig.startupTimeoutMs` defaults to 10,000 ms for helper readiness; `shutdownTimeoutMs` defaults to 2,000 ms.

## Supplied executables

```sh
lake build lean-net-http1
.lake/build/bin/lean-net-http1 --host 0.0.0.0 --workers 4 --max-clients 512 \
  --health --metrics --admin-port 9000 --access-log ./access.jsonl 8080
```

Common flags are `--host ADDR`, `--workers N`, `--max-clients N`, `--connection-rate TOKENS/PERIOD_MS/BURST`, `--http2-ping-ms MS`, `--http2-ping-timeout-ms MS`, `--enable-push`, `--static DIR`, `--static-memory MiB`, `--health`, `--metrics`, `--admin-port PORT`, `--access-log PATH`, `--access-log-queue-capacity RECORDS`, `--log-helper PATH`, `--pin-workers`, `--no-security-headers`, and `--gate POLICY`. The TLS executable takes the same flags plus [TLS options](../tls/README.md).
