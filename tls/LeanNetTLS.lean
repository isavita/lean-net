/- Public TLS API; raw OpenSSL FFI stays internal. -/
import LeanNetTLS.Session
import LeanNetTLS.Server
import LeanNetTLS.CLI
import LeanNetTLS.ReactorServer
import LeanNetTLS.Gateway
import LeanNetTLS.GatewayProvider

/-!
# lean-net-tls

Import `LeanNetTLS` for TLS, mTLS, SNI, ALPN, certificate reload and HTTPS upstreams.
[`ReactorServer.serveFactory`](LeanNetTLS/ReactorServer.html#LeanNetTLS.ReactorServer.serveFactory)
accepts the same HTTP configuration and application handlers as the core server.
Each connection selects HTTP/2 (`h2`) or HTTP/1.1 through ALPN; clients without
ALPN use HTTP/1.1.

See the [TLS configuration guide](https://github.com/isavita/lean-net/blob/main/tls/README.md)
and [API overview](LeanNetDocs.html).
-/
