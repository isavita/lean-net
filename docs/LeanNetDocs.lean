import LeanNet
import LeanNetTLS

/-!
# lean-net API

Lean 4 libraries for TCP, HTTP/1.x, HTTP/2, WebSocket, and reverse proxies.
Import `LeanNet` for the [core API](LeanNet.html), or `LeanNetTLS` for the
[TLS and mTLS API](LeanNetTLS.html).

## Start a server

The [runnable examples](https://github.com/isavita/lean-net/blob/main/examples/README.md)
progress from basic HTTP to a routed API, TLS static files, and a rate-limited gateway.

- [LeanNet.HTTP.ReactorServer.serveFactory](LeanNet/HTTP/ReactorServer.html#LeanNet.HTTP.ReactorServer.serveFactory)
  creates application handlers once per reactor worker.
- [LeanNet.HTTP1.Handlers](LeanNet/HTTP1/Handlers.html#LeanNet.HTTP1.Handlers)
  supplies request and head-stage callbacks shared by HTTP/1 and HTTP/2.
  HTTP/1 WebSocket upgrades use `onHeaders`; HTTP/2 uses `onWebSocket`.
- [LeanNet.HTTP.ReactorServerConfig](LeanNet/HTTP/ReactorServer.html#LeanNet.HTTP.ReactorServerConfig)
  configures workers, connection and buffer limits, protocol settings, admission,
  upstream forwarding, metrics, and graceful shutdown.
- [LeanNetTLS.ReactorServer.serveFactory](LeanNetTLS/ReactorServer.html#LeanNetTLS.ReactorServer.serveFactory)
  adds certificate and client-authentication settings through
  [LeanNetTLS.Reactor.Config](LeanNetTLS/ReactorConfig.html#LeanNetTLS.Reactor.Config).

## HTTP protocol selection

One listener serves HTTP/1 and HTTP/2 clients concurrently. Cleartext connections
default to `cleartextProtocol := .detect`: the HTTP/2 preface selects h2c, and
other connections use HTTP/1. `h2cUpgrade := true` also accepts an HTTP/1.1 h2c
upgrade. TLS connections select `h2` or `http/1.1` through ALPN; clients without
ALPN use HTTP/1.1. Protocol selection belongs to each connection.

## Feature APIs

- [Deferred replies](LeanNet/HTTP/Deferred.html): bounded owner-worker
  application completions, deadlines and cancellation.
- [Static files](LeanNet/HTTP/Static.html): immutable catalogs, compression,
  ranges, and validators.
- [Request gate](LeanNet/Gate.html): host routing, validation, mTLS identity,
  and rate limits.
- [Gateway engine](LeanNet/Gateway/Engine.html): HTTP/1.1 upstream pools and
  bounded request and response streaming.
- [WebSocket server](LeanNet/WebSocket/Server.html): HTTP/1.1 upgrades and
  HTTP/2 extended CONNECT.

See the [server configuration guide](https://github.com/isavita/lean-net/blob/main/docs/server.md)
for runnable examples and configuration defaults.
-/
