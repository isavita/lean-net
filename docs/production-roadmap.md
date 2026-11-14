# Production acceptance ledger

This ledger tracks the complete production brief supplied on 2026-11-14. It does
not replace or relax that brief. Existing TCP/HTTP/2/TLS tests are regression
coverage, not evidence that the new architecture or performance gates pass.

## Required sequence

1. Native reactor: epoll on Linux, kqueue on macOS, IOCP on Windows; owned
   connections and pooled buffers; nonblocking completion operations; hashed
   timer wheel; one dedicated loop per core; shared-nothing Unix listeners with
   SO_REUSEPORT; phantom socket lifecycle states; echo above 50k requests/s.
2. Pure HTTP/1.0 and HTTP/1.1 protocol/action machines, all specified framing,
   persistence, status/response, expectation, trailer and upgrade semantics;
   property tests and reactor integration.
3. Dedicated TLS workers and lock-free reactor queues; ALPN, SNI, tickets and
   resumption; certificate verification and two-certificate tests.
4. Pure HTTP/2 machine with RFC 9113/9218 scheduling, bounded flow control,
   configurable push disabled by default, peer SETTINGS limits, GOAWAY/drain;
   full h2spec pass before starting static-file phase.
5. Static files: platform sendfile, single ranges, conditional requests, ETags,
   Last-Modified, gzip/brotli and directory indexes.
6. Production hardening: fuzzing, Prometheus metrics, nonblocking structured
   logs, hot certificate reload, graceful drain and sustained load validation.

## Final gates (all required)

- Full h2spec pass plus explicit RFC 9113/9218 tests.
- h2load -n 100000 -c 10 -m 100: zero errors and over 100k requests/s.
- One route served by curl --http1.0, --http1.1,
  --http2-prior-knowledge, and --http2 over verified TLS/ALPN.
- testssl.sh/sslyze security assessment meeting the requested A-grade gate.
- Actual 24-hour soak at 10k requests/s: under 1% RSS growth, flat descriptor
  count, zero connection resets. A short run cannot satisfy this gate.
- Random-input parser fuzzing without panic, unbounded memory, or nontermination.
- Server push behind --enable-push and off by default; RFC 9218 priorities honored.
- No Std.Async in accept/read/write and no undeclared native FFI symbols.

## Evidence so far

- Starting revision: 9e5e0bd; macOS and Ubuntu tests from the previous design pass.
- The existing HTTP/TLS architecture uses poll and in-loop nonblocking OpenSSL. These do not
  satisfy the new reactor and off-loop TLS requirements.
- Reactor work remains in progress. No new phase gate has
  been declared complete.
- Windows listener sharding requires a platform-specific acceptor design;
  Windows lacks Unix SO_REUSEPORT listener semantics. A user decision is pending.

## Reactor progress (not a completed phase)

- macOS kqueue echo passes all nine existing acceptance tests, native buffer/
  generation/timer tests, and signal lifecycle tests under ASan/UBSan.
- Three-round loopback measurements exceed 50k RPS with one and eight workers;
  the latest acceptance repetition is recorded below.
- The original blocking echo baseline at concurrency100 was approximately
  17.3k RPS and only one client progressed in the first second.
- Native reactor CI on Linux epoll and macOS kqueue passed on d0d0a83,
  including lifecycle/allocation sanitizers and echo acceptance. The previous
  HTTP/1.1/h2c/TLS regression workflow also passed on that revision.
- Latest local completion-history echo gate: 191,923 verified RPS at
  concurrency100 with eight workers, 200,000 requests, all clients progressing;
  report: test/benchmarks/echo-reactor-completion-gate-macos-m2.json.
- Windows IOCP runtime CI and the Windows multi-core acceptor design remain
  open. Windows echo currently requires an explicit single worker.
- macOS listener tracing found all connections assigned to the last-created
  SO_REUSEPORT listener, including with four independent load processes and
  1,000 concurrent connections. Multi-core scaling remains unproven; the raw
  accept-distribution report is in test/benchmarks. No HTTP/TLS/static-file
  phase substitutes for these gates.
