# lean-net-tls

This separate package adds OpenSSL server-side TLS to lean-net's shared
single-threaded HTTP event loop. ALPN selects HTTP/2 (`h2`) or HTTP/1.1; when
the client sends no ALPN extension, HTTP/1.1 is used. The client supplies the
HTTP/2 connection preface after negotiating `h2`. HTTP/1.1 Upgrade to h2c is
not implemented.

Install OpenSSL development headers and libraries plus `pkg-config`. On macOS,
if OpenSSL is installed outside pkg-config's default search path, set
`PKG_CONFIG_PATH` to its `lib/pkgconfig` directory. From the repository root:

```sh
lake -d tls build lean-net-tls lean-net-tls-fixture lean-net-tls-interruptible-test
python3 tls/test/test_tls.py -v
```

Run the default route with a PEM certificate chain and matching unencrypted PEM
private key. The server supports TLS 1.2 and newer:

```sh
./tls/.lake/build/bin/lean-net-tls /path/to/cert-chain.pem /path/to/private-key.pem 8443
```

The server binds `127.0.0.1`; embedders can choose a host and router with
`LeanNetTLS.Server.serveWithConfig`. For browser use, the certificate must be
trusted by the browser and valid for the requested host. For a private test CA,
use `curl --cacert /path/to/ca.pem --http2 https://localhost:8443/` with a curl
build that supports HTTP/2.

A connection owns its TLS session but borrows the underlying socket; explicit
brackets release the session before closing the socket. Handshakes and I/O are
nonblocking, including TLS operations that require readiness in the opposite
direction. The server attempts close_notify on orderly close with a bounded
write deadline. On SIGINT it makes one nonblocking close_notify attempt per
established session when there is no pending incompatible TLS operation; blocked
or incomplete sessions may be closed abruptly so shutdown cannot hang. The
process-wide signal handler and OpenSSL session use are single-threaded.
