# Runnable servers

These examples use the repository's Lean toolchain and the [core](../README.md#install) and [TLS](../tls/README.md#install) native dependencies. Run commands from the repository root. Every listener binds to `127.0.0.1`; edit the bind address to expose it. Server commands run in the foreground; run `curl` in another terminal.

Use a curl build that lists `HTTP2` in `curl --version` for the HTTP/2 commands. On Windows the executable files have an `.exe` suffix.

```sh
lake -d examples build
```

| Level | Source | What it configures | Default port |
| --- | --- | --- | ---: |
| 1 | [Hello.lean](Hello.lean) | One handler, HTTP/1 and HTTP/2 detection | 8080 |
| 2 | [Api.lean](Api.lean) | Routes, JSON, binary uploads, separate protocol limits, health and metrics | 8081 |
| 3 | [TlsStatic.lean](TlsStatic.lean) | TLS/ALPN, static files, compression, ranges and validators | 8443 |
| 4 | [Gateway.lean](Gateway.lean) | Host policy, header validation, rate limits and upstream pools | 8083 |
| 5 | [Cooperative.lean](Cooperative.lean) | Deferred replies and budgeted response streaming | 8084 |

For a separate Lake project, follow the [quickstart](../README.md#start-a-lean-project) and copy the chosen source to `Main.lean`. `TlsStatic.lean` uses the [TLS dependency](../tls/README.md#install). `Cooperative.lean` needs the newer revision described in the quickstart. Each source file is self-contained.

## 1. Basic HTTP server

```sh
examples/.lake/build/bin/hello-server 8080
curl --http1.1 http://127.0.0.1:8080/
curl --http2-prior-knowledge http://127.0.0.1:8080/
```

Both clients receive `Hello from lean-net!`. `PORT` is optional.

## 2. Routed API

```sh
examples/.lake/build/bin/api-server 8081
curl http://127.0.0.1:8081/items/42
curl --data-binary 'hello' http://127.0.0.1:8081/echo
curl http://127.0.0.1:8081/metrics
```

`GET` and `HEAD` support `/`, `/health`, and `/items/ID` (one to nine decimal digits). `POST /echo` returns the request bytes. Unknown routes return 404; unsupported methods on known routes return 405 with `Allow`. Query parameters are ignored. `/healthz`, `/readyz`, and `/metrics` are server endpoints.

The HTTP/1 body limit is 16 KiB; HTTP/2 permits 32 KiB and 64 concurrent streams per connection. Configure these independently through `machine` and `http2` in the source. `PORT` is optional.

## 3. TLS static server

Supply a PEM certificate chain and its matching unencrypted private key:

```sh
examples/.lake/build/bin/tls-static-server examples/public ./chain.pem ./key.pem 8443
curl --cacert ./roots.pem --http1.1 https://localhost:8443/index.html
curl --cacert ./roots.pem --http2 https://localhost:8443/index.html
```

Use a hostname covered by the certificate. `roots.pem` is the trusted issuing CA bundle. For local testing, generate a short-lived certificate without changing system trust:

```sh
mkdir -p examples/certs
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout examples/certs/key.pem -out examples/certs/chain.pem -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost
examples/.lake/build/bin/tls-static-server examples/public \
  examples/certs/chain.pem examples/certs/key.pem 8443
curl --cacert examples/certs/chain.pem --http2 https://localhost:8443/index.html
```

ALPN selects HTTP/2 or HTTP/1.1 on the same port. The catalog uses a 1 MiB resident budget; the directory must fit that budget and the operating system's locked-memory limit. The catalog is a startup snapshot: restart after changing files. `PORT` is optional; the directory and certificate paths are required.

## 4. Rate-limited reverse proxy

Start the basic server as the upstream, then run the gateway in another terminal:

```sh
examples/.lake/build/bin/hello-server 8080
```

```sh
examples/.lake/build/bin/gateway-server 8083 8080
curl --header 'Host: localhost' http://127.0.0.1:8083/
curl --header 'Host: localhost' http://127.0.0.1:8083/about
curl --http2-prior-knowledge --header 'Host: localhost' http://127.0.0.1:8083/
```

The gateway accepts `Host: localhost` with an optional port. Other hosts receive 421. `/about` is handled locally; other paths are forwarded to the loopback upstream. `x-internal-*` headers are rejected with 400; `x-debug` is removed before forwarding. The process budget is 200 requests/s with burst 100; each peer IP gets 20 requests/s with burst 10. Excess requests receive 429. Budgets are shared across the two workers within this process. The upstream pool allows 16 total connections and eight per target per worker. Health and metrics endpoints are subject to the same host policy and rate limits.

Both `PORT` and `UPSTREAM_PORT` are optional. This example uses plain HTTP to its loopback upstream; [TLS configuration](../tls/README.md) covers verified HTTPS targets.

## 5. Cooperative replies and streaming

```sh
examples/.lake/build/bin/cooperative-server 8084
```

In another terminal, fetch the report with unbuffered output.

```sh
curl --no-buffer --http1.1 http://127.0.0.1:8084/report
curl --no-buffer --http2-prior-knowledge http://127.0.0.1:8084/report
curl --head http://127.0.0.1:8084/report
```

`/report` defers the response briefly, then writes `first line` and `second line` separately. While a report is pending, another connection or HTTP/2 stream can fetch `/` immediately. HEAD reports the complete body length and sends no body. The timer stands in for a nonblocking backend. The [streaming guide](../docs/application-streams.md) describes output credits, deadlines, and cancellation.

Stop servers with Ctrl-C. The [live example tests](../test/test_examples.py) check both protocols, TLS verification, API limits, static files, proxying, rate limits, and cooperative replies.
