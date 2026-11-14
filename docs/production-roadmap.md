# Production acceptance ledger

This ledger tracks the complete production brief supplied on 2026-11-14. It does
not replace or relax that brief. Existing TCP/HTTP/2/TLS tests are regression
coverage, not evidence that the new architecture or performance gates pass.

## Required sequence

1. Native reactor: epoll on Linux, kqueue on macOS, IOCP on Windows; owned
   connections and pooled buffers; nonblocking completion operations; hashed
   timer wheel; one dedicated loop per core; Linux SO_REUSEPORT listeners and
   approved macOS/Windows acceptor handoff; phantom socket lifecycle states;
   echo above 50k requests/s.
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

## Current phase status

Phase 1 reactor acceptance passed at d3ccc2e. Phase 2 HTTP/1 protocol-machine
acceptance passed at 8be5466 on Linux, macOS and Windows. Phases 3–6 and all final
gates remain open. The TLS worker implementation is under acceptance: dedicated
native threads, bounded byte lanes, SNI/resumption and native transport sharing
are implemented. Full matrix/scanner acceptance must pass before Phase 3 is
marked complete. h2c preserves the previous pure HTTP/2 implementation pending
its full phase-four migration.

## HTTP/1 machine acceptance evidence

- Pure Protocol/Parser/Encoding/Machine suites pass, including every-split and
  bytewise framing, HTTP/1.0 and 1.1, configured obs-fold, body/trailer bounds,
  explicit legacy EOF bodies, persistence, statuses, reason/header validation,
  Date input, Expect refusal/100 barriers, pipeline ordering, timeout and EOF
  transitions, and accepted-upgrade raw-tail preservation.
- The [native matrix](https://github.com/isavita/lean-net/actions/runs/43617051125)
  passes on all three platforms. Real one/four-worker HTTP acceptance exercises
  37 cases: binary/trailer traffic, ten pipelines then EOF, early raw bytes/FIN
  around 101, blocked-reader fairness, tiny two-cell pools, admission-credit
  failure cleanup, absolute deadlines and 1,000 connection cycles in both modes.
- Public cleartext APIs now use the new reactor. Compatibility Router callbacks
  retain one-worker ownership; default serving and the factory API use independent
  per-core handlers with the global client cap partitioned exactly. Existing h2c
  behavior is preserved through its previous pure connection implementation.
- Native vectors, read-pause/pool-pressure independence, retained leases,
  cancellation, historical write liveness and nonwrapping token exhaustion pass
  focused lifecycle tests. Native allocation counters cover the backend; parser
  metadata, owned body blocks and application values still allocate in Lean.
- The full [HTTP/TLS regression workflow](https://github.com/isavita/lean-net/actions/runs/43617051112)
  passes. Local regression also passed 16 HTTP server, 15 event/backpressure,
  20 h2c, 7 injected-fault and 28 legacy TLS tests.
- Actual curl --http1.0, --http1.1 and --http2-prior-knowledge requests served
  the same default route. The TLS curl leg must be repeated after phase three;
  this is not the final four-protocol acceptance gate.
- Controlled HTTP/1 characterization uses 128 clients of capacity, 512 requested
  output credits, concurrency 100 and three 200,000-request rounds. Verified-body
  median RPS: 40,555 with one worker, 93,328 with eight. Separate h2load --h1
  medians: 37,094 and 96,701, with zero reported errors. All 1.2 million native
  client response bodies matched; h2load additionally checked aggregate bytes.
  Reports: `test/benchmarks/http1-reactor-macos-m2-*.json` and methodology README.
  These are HTTP/1 measurements, not the final HTTP/2 >100k gate.

## Reactor acceptance evidence

- Linux epoll, macOS kqueue, and Windows IOCP passed the
  [native matrix](https://github.com/isavita/lean-net/actions/runs/43606979876).
  Strict native compilation, phantom states, pooled immutable buffers,
  generations, timer backlogs, and real Lean echo modes 1/4/default all pass.
- Linux retains one SO_REUSEPORT listener per worker. The user approved one
  acceptor with dedicated per-core workers on Windows and macOS. Windows has no
  equivalent listener option; macOS duplicate TCP bindings routed all observed
  traffic to the last listener. Those platform adaptations are now implemented.
- macOS native stress verifies 50 accepts on each of eight real threads,
  capacity-one retention/backpressure, saturated blocking polls, interrupted
  cross-loop notifications, both teardown orders, descriptor reuse, and zero
  backend native/buffer allocations during active I/O under ASan/UBSan.
- Windows native stress verifies actual IOCP socket adoption, bounded queues,
  round-robin distribution, cancellation lifetime, both teardown orders, flat
  handle counts, no active-I/O native allocations, and console shutdown.
- The real Lean echo checks concurrent binary traffic, half-close, resets, and
  clean shutdown in direct and multi-worker modes. Unix acceptance also checks
  all nine original cases, including 1,000 connections with flat descriptors.
- Fault regressions preserve committed completions across EINTR/EIO, prevent a
  Linux half-close busy loop, reject late drain-close writes without losing
  leases, and verify borrowed FFI handle arrays do not leak references.
- Fresh M2 loopback gates use 200,000 verified round trips at concurrency 100,
  three rounds each: one worker median 191,688 RPS; eight workers median
  188,213 RPS. Every round exceeds 50k and all clients progress. Reports are
  `test/benchmarks/echo-reactor-handoff-macos-m2-{1worker,8workers}.json`.
  These measurements do not establish linear multicore throughput scaling.
- Separate instrumentation of the actual Lean executable confirms all eight
  worker threads register and read their own sockets: 401 adoptions including
  the startup probe, and 800,000 positive reads matching 800,000 verified echoes.
  See `test/benchmarks/echo-reactor-handoff-macos-m2-worker-distribution.json`.
  Instrumented timing is diagnostic rather than a throughput acceptance result.
- Existing TCP/HTTP/1.1/h2c/TLS
  [regression CI](https://github.com/isavita/lean-net/actions/runs/43606979883)
  also passes on d3ccc2e. This remains coverage for the previous protocol design.
