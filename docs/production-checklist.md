# Production readiness checklist status

Audit of the lean-net production checklist on 2026-11-15. Each item is
marked **Done** (implemented and exercised by a test or tool run),
**Partial** (implemented with a stated limitation) or **Open** (not yet
implemented). Evidence refers to tests in this repository unless stated
otherwise. Local tool runs were on a 4-vCPU Linux VM; macOS and Windows
coverage comes from the CI matrices.

## 1. Networking and reactor

| Item | Status | Evidence / notes |
| --- | --- | --- |
| Linux per-core `SO_REUSEPORT` listeners, one epoll loop per worker, `EPOLLEXCLUSIVE` | Done | `c/reactor_posix.c`. Listener registrations add `EPOLLEXCLUSIVE` (with fallback for kernels older than 4.5). Each per-core listener already has its own epoll set, so the flag guards applications that share a listener. |
| macOS single acceptor handing off to per-core kqueue workers | Done | `docs/reactor.md`, `test/test_reactor_dispatch.py` (macOS CI). |
| Windows `AcceptEx` acceptor handing off to per-core IOCP workers | Done | `c/reactor_windows.c`, `test/test_windows_native.py` (Windows CI). |
| All sockets `O_NONBLOCK`, no blocking syscalls in worker loops | Done | `rn_nonblocking` on every accepted socket. The new admin port runs on its own control thread, never on a worker. |
| `TCP_NODELAY`, `SO_REUSEADDR`, backlog 4096 | Done | `rn_accept_ready`, `rn_bind`, `rn_listen`. |
| Graceful degradation on `EMFILE` | Done (fixed) | Previously `EMFILE` **crashed the server**. Listeners now pause and retry after 100 ms on `EMFILE`/`ENFILE`/`ENOBUFS`/`ENOMEM` (epoll, kqueue and IOCP). Waiting clients stay in the kernel backlog. Covered by `test/test_resilience.py::DescriptorExhaustion`, which floods the server under `RLIMIT_NOFILE=64` and checks that it keeps serving. |
| Hierarchical/hashed timer wheel, no per-connection `timerfd` | Done | 1024-slot hashed wheel in the reactor (`docs/reactor.md`). |
| Explicit byte ordering at the FFI boundary | Done | Addresses go through `getaddrinfo`/`inet_ntop`. HTTP/2 framing uses explicit big-endian helpers. |
| Bind address | Done (added) | `--host ADDR` on both executables. The default stays `127.0.0.1`. |

## 2. HTTP/1.0 and HTTP/1.1

| Item | Status | Evidence / notes |
| --- | --- | --- |
| Strict Content-Length / chunked framing | Done | `HTTP1/Parser.lean`, `HTTP1ParserV2Test`. |
| Reject CL+TE, conflicting CL (400) | Done | 17 differential probes (CL.TE, TE.CL, TE.TE variants, obs-fold, bare LF, CL lists/signs/hex, chunk overflow). Each probe gets exactly one response and a closed connection, and the smuggled suffix is never served: `test_resilience.py::test_smuggling_probes_are_rejected_without_desync`. |
| Chunk extensions and trailers | Done | Parser suites. |
| Keep-alive defaults (1.1 persistent, 1.0 close unless keep-alive) | Done | `HTTP1MachineTest`, `test_http1_reactor.py`. |
| Pipelining with ordered responses | Done | `test_valid_pipeline_keeps_order` and the reactor suites. |
| `Expect: 100-continue`, 417 on oversized payload | Done (fixed) | An oversized Content-Length with `Expect: 100-continue` now gets **417** before the body is sent; without the expectation it gets **413**. All parser errors used to return 400. Requests now also get 414, 431, 501 and 505 where these apply. |
| Host enforcement and virtual hosting | Done | Exactly one valid Host is required in HTTP/1.1. Routing by Host/SNI is left to the application and the TLS SNI table. |
| Upgrade hand-off (`websocket`, `h2c`) | Done (h2c added) | Raw-socket `RawPipe` hand-off for application protocols. HTTP/1.1 `Upgrade: h2c` now switches to HTTP/2 after the 101 (`test_resilience.py::H2CUpgrade`, curl `--http2` on `http://`). |
| 408 on slow headers/body | Done | Verified live: a stalled request head receives `408 Request Timeout` at the 30 s default. |
| HTTP/1.x minor versions | Done (fixed) | `HTTP/1.2` and later minors are served as HTTP/1.1 (RFC 9110 §6.2). Other major versions get 505. |

## 3. HTTP/2

| Item | Status | Evidence / notes |
| --- | --- | --- |
| Framing, `SETTINGS_MAX_FRAME_SIZE` | Done | h2spec strict **147/147** (h2-only cleartext profile and the public TLS binary, run 2026-11-15). |
| Preface; h2c prior knowledge and HTTP/1.1 Upgrade | Done (Upgrade added) | On the shared HTTP/1+h2c port, a corrupt `PRI * HTTP/2.0` preface now gets `GOAWAY(PROTOCOL_ERROR)`. A non-HTTP/2 line such as h2spec's `INVALID CONNECTION PREFACE` is still an HTTP/1 request and gets 400, so h2spec reports 146/147 against the auto-detecting port. This is inherent to sharing one port. |
| HPACK (Huffman, dynamic table, size updates) | Done | `HPACKTest`, h2spec section 4/HPACK. |
| Multiplexing, `MAX_CONCURRENT_STREAMS` | Done | `test_http2_reactor.py` limits suite. |
| Flow control | Done | h2spec 6.9, reactor suites. |
| RST_STREAM / GOAWAY error handling | Done | h2spec, isolation tests. |
| RFC 9218 priorities (no RFC 7540 tree) | Done | `PriorityTest`, priority wire cases. |
| Server push behind `--enable-push` (off by default) | Done | `test_http2_cli.py`. |
| RFC 8441 extended CONNECT (WebSockets over h2) | **Open** | Needs streaming bidirectional stream tunnels in the HTTP/2 connection. The current machine buffers whole request and response bodies. `SETTINGS_ENABLE_CONNECT_PROTOCOL` is therefore not advertised, and `:protocol` requests are rejected as malformed. WebSockets work over HTTP/1.1 Upgrade. |
| Load: `h2load -n 100000 -c 10 -m 100` | Done | Three local rounds on 4 workers: 300,000/300,000 succeeded, 0 failed/errored/timed out. RSS stayed flat at 152,024 → 151,456 → 151,400 KiB and descriptors at 28. These runs used a shared 4-vCPU VM, so the >100k req/s gate rests on the recorded M2 results (`docs/production-roadmap.md`). |

## 4. TLS and security

| Item | Status | Evidence / notes |
| --- | --- | --- |
| TLS 1.2/1.3 only, no weak ciphers | Done (fixed) | The production context did **not** restrict TLS 1.2 suites, so OpenSSL defaults (static-RSA and CBC suites) were accepted. TLS 1.2 is now limited to ECDHE with AES-GCM or ChaCha20-Poly1305. sslyze 2026-11-15: SSL 2/3 and TLS 1.0/1.1 rejected; TLS 1.2 offers 3 ECDHE AEAD suites and TLS 1.3 offers 3 AEAD suites; forward secrecy OK; ROBOT not vulnerable (no RSA key exchange); Heartbleed and CCS OK; compression disabled; secure renegotiation only; `TLS_FALLBACK_SCSV` supported. `test_tls_production.py::test_cipher_and_protocol_policy`. |
| ALPN `h2`/`http/1.1`, HTTP/2 only via ALPN on TLS | Done | s_client ALPN cases. h2c Upgrade is never offered over TLS. |
| SNI certificate selection | Done | Existing two-host suites. |
| mTLS with subject DN/SANs exposed | Done (added) | `--client-ca PEM [--require-client-cert]`. Verified identities appear as `Request.clientCertificate` (RFC 2253 subject; `DNS:`, `URI:`, `email:` and `IP:` SANs). Tests cover acceptance, missing-certificate and foreign-CA rejection, optional mode, and curl with and without `--cert`. |
| Session tickets and session IDs | Done | Tickets and session IDs both resume (`-sess_in` with and without `-no_ticket`). sslyze reports session-ID resumption as unsupported because its probe offers the ticket extension, in which case OpenSSL issues tickets instead. |
| TLS 1.3 0-RTT with replay protection | **Open (deliberately disabled)** | Early data would have to be read through `SSL_read_early_data` before the handshake fence, and requests would have to be marked replayable (RFC 8470 `Early-Data`/425). OpenSSL's `max_early_data` stays 0, so no request can be replayed. |
| OCSP stapling | Done (added) | `--ocsp-response DER` (and `HostConfig.ocspResponse`). The response is accepted only if it is successful, GOOD and currently valid for the leaf. It is re-read with certificates on reload or SIGHUP. Tests use `s_client -status`, and an invalid response fails startup. |
| HSTS | Done (added) | `strict-transport-security: max-age=31536000; includeSubDomains` on TLS responses only. |
| OWASP secure headers | Done (added) | `x-content-type-options: nosniff`, `x-frame-options: SAMEORIGIN`, a strict `content-security-policy` and `referrer-policy` by default (`SecurityHeaders`, `--no-security-headers`). Application-set values win. |
| Path traversal defense | Done | Verified live: `..`, `.`, encoded `%2e%2e`, encoded slashes and backslashes all return 400. The static catalog is anchored and no-follow. |
| testssl.sh A+ | Partial | The previous pinned testssl v3.2.5 runs recorded A+ (`tls/test/reports`). testssl could not be downloaded in this session (blocked host), so the new cipher policy was verified with sslyze. Rerun testssl in CI before release. |

## 5. Performance

| Item | Status | Evidence / notes |
| --- | --- | --- |
| Zero-copy static files (`sendfile`/`TransmitFile`) | Done (plaintext) / Partial (TLS) | TLS uses memory BIOs on off-loop workers, which rules out kTLS. File bytes are spliced and then copied once into OpenSSL. kTLS/`SSL_sendfile` would require moving to socket BIOs. |
| Buffer pooling | Partial | Native 4/16/64 KiB pools with no native allocation during established I/O. Lean-side parser metadata and application values still allocate (documented in `docs/reactor.md`). |
| `writev` batching | Done | POSIX vectored writes, `WSASend` vectors on Windows. |
| TLS off the reactor thread | Done | Dedicated native TLS workers per reactor. |
| CPU affinity | Done (added) | `--pin-workers` / `pinWorkers`: Linux `sched_setaffinity` within the allowed cpuset, Windows `SetThreadAffinityMask`, macOS affinity tags. Default worker counts now respect Linux cpusets (containers). |
| In-place header parsing | Partial | Request heads are scanned in place over `ByteArray` spans. Header names become lowercase `String`s for the application API. |

## 6. Observability and operations

| Item | Status | Evidence / notes |
| --- | --- | --- |
| Structured JSON access logs | Done (extended) | `timestamp` (RFC 3339), `remote_ip`, `method`, `path`, `status`, `bytes_sent`, `duration_ms`, `trace_id`, plus the existing fields. Query strings are never logged. |
| Prometheus RED metrics | Done (extended) | Existing request/latency/connection metrics, plus process RSS and open-fd gauges and TLS handshake, resumption and client-certificate counters. |
| W3C `traceparent` | Done (added) | A valid incoming context is kept. Otherwise a new one is generated (per-worker splitmix64 seeded from the OS) and injected into the application request. Its `trace_id` is logged. |
| Graceful shutdown on SIGTERM/SIGINT | Done (fixed) | Only SIGINT was handled, so a SIGTERM (Kubernetes, systemd) **killed the process without draining**. Both signals now drain: GOAWAY on HTTP/2, in-flight requests finish within `shutdownDrainMs`. |
| Hot reload on SIGHUP | Done (added) | SIGHUP used to terminate the process. It now runs `ReactorServerConfig.onReload` on worker 0. The TLS executable always starts its loader, so SIGHUP republishes certificates, keys, OCSP responses and the client CA without dropping connections. Applications can swap routing tables or rate limits in this hook. |
| `/healthz` and `/readyz` | Done (added) | `--health`. Readiness returns 503 once draining begins. |
| Local-only admin API | Done (added) | `--admin-port PORT` on 127.0.0.1: `/stats` (JSON connection, request and memory statistics), `/metrics`, `/healthz`, `/readyz`. |

## 7. Testing and conformance

| Item | Status | Evidence / notes |
| --- | --- | --- |
| h2spec 100% | Done | 147/147 strict (h2-only cleartext and TLS); see section 3 for the auto-detecting port. |
| h2load zero errors, flat RSS | Done | See section 3. |
| curl four-mode matrix | Done | `test_tls_production.py::test_curl_four_mode_matrix_serves_one_route` (`--http1.0`, `--http1.1`, `--http2-prior-knowledge`, `--http2` over verified TLS/ALPN). |
| Smuggling probes | Done | `test_resilience.py` (custom differential probes; Burp Suite was not used). |
| 24-hour soak at 10k RPS | **Open** | Needs dedicated hardware and a full day. `test/soak24.py` provides the harness and acceptance thresholds. |
| TLS testing with s_client and curl mTLS | Done | `tls/test/test_tls_production.py`. |
