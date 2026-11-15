# Server configuration

`LeanNet.HTTP.ReactorServer.serveFactory factory config host port` serves HTTP/1.0, HTTP/1.1 and h2c on one cleartext listener. `factory : Nat → IO HTTP1.Handlers` runs once for each worker. Use `LeanNetTLS.ReactorServer.serveFactory` for TLS and ALPN. All servers bind `127.0.0.1` unless given another address.

```lean
import LeanNet

open LeanNet

def config : HTTP.ReactorServerConfig := {
  workers := 0
  server := { maxClients := 128, requestTimeoutMs := 15000 }
  http2 := { maxConcurrentStreams := 128, pingIntervalMs := 10000 }
  healthPaths := true
  metricsPath := some "/metrics".toUTF8
}
```

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
