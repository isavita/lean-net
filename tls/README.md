# lean-net-tls

TLS transport for [lean-net](../README.md). It serves HTTP/1.1 and HTTP/2 on the same listener using ALPN, with SNI certificates, mTLS client identity, certificate reload, and verified HTTPS upstream connections.

[API reference](https://isavita.github.io/lean-net/LeanNetTLS.html).

## Install

Use the repository's Lean toolchain. Install a C compiler, `pkg-config`, OpenSSL 1.1.1 or newer, zlib, and Brotli development libraries. On Linux, install the [core build dependencies](../README.md#install) and set `export LEAN_CC=cc` before running Lake. On macOS with Homebrew:

```sh
brew install openssl@3 zlib brotli pkgconf
export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig:$(brew --prefix zlib)/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
```

In a consumer `lakefile.lean`:

```lean
require «lean-net-tls» from git "https://github.com/isavita/lean-net" @ "v0.1.1" / "tls"
```

The TLS package depends on the core package. Build it in this repository with `lake -d tls build lean-net-tls`.

## Use

```lean
import LeanNetTLS

open LeanNet LeanNetTLS

def main : IO Unit :=
  ReactorServer.serveFactory
    (fun _ => pure {
      onRequest := fun _ =>
        pure { response := { status := 200, body := "ok\n".toUTF8 } }
    })
    { certificateChain := "./chain.pem", privateKey := "./key.pem" }
    { workers := 0, server := { maxClients := 128 } }
    "127.0.0.1" 8443
```

`certificateChain` is a PEM certificate chain and `privateKey` is its matching unencrypted PEM key. The default minimum protocol is TLS 1.2. TLS ALPN selects `h2` or `http/1.1`; clients without ALPN use HTTP/1.1.

One TLS listener serves both protocols with the same handlers. Pass HTTP/1 settings in `http.machine` and HTTP/2 settings in `http.http2`, where `http` is the HTTP configuration argument. See the [combined configuration example](../docs/server.md#http1-and-http2-on-one-listener).

| `LeanNetTLS.Reactor.Config` field | Use |
| --- | --- |
| `hosts := #[{ name, certificateChain, privateKey, ocspResponse }]` | Exact SNI host certificates; the default certificate serves absent or unknown SNI |
| `clientCA := some "roots.pem"` | Verify client certificates against PEM roots |
| `requireClientCert := true` | Require a verified client certificate (`clientCA` required) |
| `ocspResponse := some "response.der"` | Staple a current GOOD OCSP response for the default certificate |
| `reload := some { intervalMs := 1000 }` | Check certificate files periodically; zero permits explicit reload only |
| `handshakeTimeoutMs`, `shutdownTimeoutMs` | TLS handshake and close deadlines (10,000 and 2,000 ms defaults) |

Verified client identity is available as `HTTP1.Request.clientCertificate` (`subject` and tagged `subjectAltNames`, such as `DNS:example.com` or `URI:spiffe://example/app`). Absent or unverified certificates yield `none`. Use `Gate` mTLS rules for admission; see the [gate policy](../docs/gateway.md). `Bundle.requestReload` initiates an explicit reload and `Bundle.reloadStatus` reports its result. SIGHUP also requests reload when `reload` is enabled. An invalid replacement retains the last valid certificate snapshot.

For HTTPS proxy targets, pass `upstreamCA := some "roots.pem"` as the final `serveFactory` argument when private trust roots are needed. Without it, the package uses OpenSSL's configured default roots. The backend certificate is checked against the target's configured `verify` name.

## Supplied executable

```sh
lake -d tls build lean-net-tls
tls/.lake/build/bin/lean-net-tls ./chain.pem ./key.pem --host 0.0.0.0 \
  --client-ca ./clients.pem --require-client-cert --metrics --health 8443
```

TLS-specific flags are `--client-ca PEM`, `--require-client-cert`, `--ocsp-response DER`, `--reload-certs-ms MS`, and `--upstream-ca PEM` (with `--gate`). Common HTTP flags are listed in [server configuration](../docs/server.md). `--reload-certs-ms` accepts 1–3,600,000 ms; SIGHUP requests a reload even without a periodic interval in this executable.

## License

[Apache-2.0](../LICENSE).
