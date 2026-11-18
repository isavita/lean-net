# lean-net

Lean 4 libraries for TCP, HTTP/1.0, HTTP/1.1, HTTP/2, and WebSocket servers. The optional [`lean-net-tls`](tls/README.md) package adds TLS, mTLS, SNI, and ALPN. Both packages use the same HTTP handlers and native reactor on Linux, macOS, and Windows.

[API reference](https://isavita.github.io/lean-net/).

[Runnable servers](examples/README.md) cover basic HTTP, a routed API, cooperative replies and streaming, TLS static files, and a rate-limited gateway.

## Install

Install Lean through Elan and use the version in [`lean-toolchain`](lean-toolchain). Lake builds the native transport and links the codecs into your executable.

| Platform | Native dependencies |
| --- | --- |
| Debian / Ubuntu | `sudo apt-get install build-essential pkg-config zlib1g-dev libbrotli-dev libgmp-dev libuv1-dev libssl-dev`, then `export LEAN_CC=cc` |
| macOS | Xcode Command Line Tools and `brew install pkgconf zlib brotli`. Before running Lake, `export PKG_CONFIG_PATH="$(brew --prefix zlib)/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"` |
| Windows | In an MSYS2 MINGW64 shell, `pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-pkgconf mingw-w64-x86_64-zlib mingw-w64-x86_64-brotli`. Keep the MINGW64 `bin` directory on `PATH` for Lake and the codec DLLs. |

For TLS, also install OpenSSL 1.1.1 or newer and use the [TLS dependency](tls/README.md#install).

## Start a Lean project

Create an executable package, or use an existing project with the matching toolchain.

```sh
lake +leanprover/lean4:v4.35.0 new hello-net exe.lean
cd hello-net
```

Add this dependency to `lakefile.lean`.

```lean
require «lean-net» from git "https://github.com/isavita/lean-net" @ "v0.1.2"
```

If your existing project uses `lakefile.toml`, append the dependency there.

```sh
cat >> lakefile.toml <<'TOML'

[[require]]
name = "lean-net"
git = "https://github.com/isavita/lean-net"
rev = "v0.1.2"
TOML
```

Replace `Main.lean` with the following program.

```lean
import LeanNet

open LeanNet

def main : IO Unit :=
  HTTP.ReactorServer.serveFactory
    (fun _ => pure {
      onRequest := fun _ =>
        pure { response := { status := 200, body := "ok\n".toUTF8 } }
    })
    { workers := 0, server := { maxClients := 128 } }
    "127.0.0.1" 8080
```

```sh
lake update
lake exe hello-net
```

Use your executable target name in place of `hello-net` if adding lean-net to an existing project. In another terminal, run `curl http://127.0.0.1:8080/` and expect `ok`. Press Ctrl-C to stop the server. `serveFactory` creates handlers once per worker. Set `workers := 0` for the available CPU count. Callbacks run on their owning worker and must return promptly. `serveWithHandlers` and `serveWithConfig` are single-worker entry points. `LeanNet.withListener` and `LeanNet.withConnection` provide bracketed socket ownership for lower-level applications.

The quickstart uses the `v0.1.2` release. Deferred replies and application streaming in the guides below require a newer repository revision. For those APIs, pin `b1bca92a38ec3fbba7e8edbd5cde2360045e1956` or a newer commit and run `lake update` again. If you use `lean-net-tls`, pin it to the same commit.

```mermaid
flowchart LR
  A[TCP accept] --> B[Reactor worker]
  B --> C[TLS and ALPN when enabled]
  C --> D[HTTP/1 or HTTP/2 parser]
  D --> E[Optional admission gate]
  E --> F[Application handler]
  E --> G[Static catalog]
  E --> H[Upstream gateway]
```

## Features and configuration

| Feature | Library configuration | Guide |
| --- | --- | --- |
| HTTP/1.x, HTTP/2, h2c, keep-alive, WebSocket | `HTTP.ReactorServerConfig`, `HTTP1.Handlers`; HTTP/2 uses `http2`, `h2cUpgrade` | [Server options](docs/server.md) |
| Deferred replies, streaming bodies, worker lifecycle | `HTTP.Deferred.Job`, `HTTP.Stream.Body`, `HTTP1.Handlers` | [Cooperative streaming](docs/application-streams.md) |
| TLS, mTLS, SNI, certificate reload | `LeanNetTLS.Reactor.Config` and `LeanNetTLS.ReactorServer.serveFactory` | [TLS](tls/README.md) |
| Static files, compression, ranges, validators | `HTTP.Static.serveRoot` and `HTTP.Static.Catalog.Config` | [Static files](docs/static-files.md) |
| Host routing, validation, rate limits, reverse proxy | `Gate.Spec`, `Gate.factory`, `ReactorServerConfig.admission` and `gateway` | [Gate and gateway](docs/gateway.md) |
| Metrics, access logs, health, tracing, graceful drain | `HTTP.ReactorServerConfig` | [Server options](docs/server.md) |
| Benchmarks | Reproducible commands and results | [Benchmarks](docs/benchmarks.md) |

The default listener is `127.0.0.1`; pass an explicit bind address to expose it. One listener serves HTTP/1 and HTTP/2 clients using the same handlers. Configure HTTP/1 through `machine` and HTTP/2 through `http2`; protocol selection uses the cleartext preface or h2c upgrade, and ALPN on TLS. See [combined protocol configuration](docs/server.md). The gateway forwards to HTTP/1.1 backends over HTTP or verified HTTPS.

## Build and test

```sh
lake build
lake -d tls build lean-net-tls
python3 test/soak.py --count 10000
```

Run the focused suites in [test/README.md](test/README.md). The executable entry points `lean-net-http1` and `lean-net-tls` use the same library APIs; their flags are listed in the [server](docs/server.md) and [TLS](tls/README.md) guides.

Generate the API reference with `python3 docs/build.py`. Serve `docs/.lake/build/doc` over HTTP to browse it locally.

## License

[Apache-2.0](LICENSE).
