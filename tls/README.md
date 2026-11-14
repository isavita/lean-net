# lean-net-tls

The optional package serves HTTPS through lean-net's native epoll/kqueue/IOCP
reactors. Each HTTP reactor has a dedicated native TLS thread. That thread owns
every `SSL` and both halves of each bounded BIO pair; the loop owns sockets,
pooled buffers, protocol machines and application callbacks. Fixed SPSC byte
queues connect them. OpenSSL context setup happens before listeners start.

ALPN prefers `h2`, then `http/1.1`; clients without ALPN use HTTP/1.1. An offered
list without either protocol fails negotiation. TLS 1.2 is the minimum, server
cipher preference is enabled, and compression and renegotiation are disabled.
The negotiated protocol selects its parser; an h2 connection must still send
its HTTP/2 preface. The pure HTTP/2 machine is integrated with this transport;
phase 4 acceptance and the later production gates remain open.

Install OpenSSL development headers/libraries (1.1.1 or newer) and `pkg-config`.
Windows builds use MinGW GCC and matching OpenSSL import libraries/DLLs. On
macOS, select the intended OpenSSL package explicitly:

```sh
PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@3/lib/pkgconfig \
  lake -d tls build lean-net-tls lean-net-tls-fixture lean-net-tls-interruptible-test lean-net-tls-reactor-fixture
python3 tls/test/test_tls.py -v
python3 tls/test/test_tls_reactor.py -v
```

Serve the default route with a PEM chain and matching unencrypted PEM key:

```sh
./tls/.lake/build/bin/lean-net-tls /path/to/cert-chain.pem /path/to/private-key.pem 8443
curl --cacert /path/to/ca.pem --http2 https://localhost:8443/
# To enable the optional demo push when the peer permits it:
# ./tls/.lake/build/bin/lean-net-tls /path/to/cert-chain.pem /path/to/private-key.pem --enable-push 8443
```

The executable binds `127.0.0.1` and starts one HTTP reactor per available core.
`Server.serveWithConfig` preserves single-worker ownership of a supplied Router.
`ReactorServer.serveFactory` builds independent advanced HTTP handlers on each
worker and accepts `Reactor.Config` plus `HTTP.ReactorServerConfig`. Configure
SNI hosts with `hosts := #[{ name := "example.test", certificateChain := ..., privateKey := ... }]`.
The default certificate handles absent or unknown SNI. Early ClientHello
selection isolates each host's resumption namespace before session lookup.
The sealed contexts are shared across TLS threads, with bounded server session
caches and tickets; TLS 1.2 cache-only and TLS 1.2/1.3 ticket resumption are tested
across actual workers. Private keys are loaded at startup; encrypted PEM keys
are rejected without an interactive password prompt.

The transport claims a connected socket into a private handshaking capability,
then transitions its embedded socket to `tls_ready`. Native guards reject raw
writes and other plain operations through old connected aliases. HTTP sees
plaintext write completion only after the corresponding encrypted bytes reach
the socket. Handshake readiness also waits for its outbound wire fence.

Each session permanently reserves separate native 4 KiB ciphertext-output and
plaintext-input buffers. HTTP output credits and wire receive credits are
additional: a one-client, one-output-slot configuration needs at least four
cells. Plaintext consumption explicitly returns its reserved credit. Native
views remain on the loop; retained views prevent mutation. Per-session queued
ciphertext is bounded and pauses native reads when its byte lane is full.

Handshake and TLS shutdown have absolute deadlines. Orderly closes send
`close_notify`, await peer notification within the bound, then close the native
connection. Fatal alerts drain before peer-error cleanup. SIGINT stops admission
and attempts bounded TLS notification before joining all native TLS threads and
freeing reactor resources. The HTTP/2 machine performs a bounded GOAWAY and
stream drain before TLS shutdown. Remaining graceful shutdown and production
acceptance gates are tracked in the roadmap.

The older explicit `Context`/`Session` API remains available for compatibility;
public server entry points use the native worker transport. The legacy Windows
adapter borrows checked generation-table sockets without truncating `SOCKET`.
See [test/README.md](test/README.md) for verified clients, SNI/resumption,
sanitizers, full testssl grading and the separate final soak gates.
