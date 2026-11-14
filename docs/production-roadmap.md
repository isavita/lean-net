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
acceptance passed at 8be5466 on Linux, macOS and Windows. Phase 3 TLS acceptance
passed at e2dbbf0 on all three platforms, including matching-artifact full scans
of both SNI fixture hosts. Phases 4–6 and the remaining final gates stay open. h2c and negotiated h2 retain the previous pure HTTP/2
implementation pending its phase-four migration.

## TLS worker acceptance evidence

- The [TLS matrix](https://github.com/isavita/lean-net/actions/runs/43625971927)
  passes on Linux, macOS and Windows. All four public TLS executables build.
  Each platform passes 34 real cases with 1,000 verified connection cycles,
  malformed/reset peers, capacity-one and capacity-three queues, slow readers,
  fragmented records, raw upgrades, absolute deadlines and bounded shutdown.
  Windows performs the full suite through actual IOCP and native OpenSSL.
- The [native matrix](https://github.com/isavita/lean-net/actions/runs/43625971883)
  passes on all three platforms, including permanent buffer ownership,
  cancellation and generations, the claimed transport capability, stale plain
  aliases, Socket/Wire phantom states, and retained wake-handle lifetime.
  POSIX bounds each peer's read batch by 16 reads and 64 KiB; IOCP defers another
  positive receive until its next poll. Burst tests exercise fallback 64 KiB
  cells and owner pause/resume without exceeding transport input bounds.
- One dedicated native TLS worker serves each HTTP reactor through fixed SPSC
  byte lanes. Every session SSL/BIO operation runs on that worker; sealed context
  setup occurs before listeners start. The reactor owns sockets and Lean values.
  Instrumented verified connections observe all four real workers, zero SSL
  owner-thread violations and one native TLS thread per worker.
- Ciphertext output and plaintext input have independent permanent native buffer
  credits. HTTP output and wire receive credits are additional: four cells are
  the one-client minimum, and three-cell startup is rejected with endpoint reuse.
  Returned plaintext credit waits for retained ByteArray views before mutation.
  Unique-block binary payloads and blocked raw-view traffic verify exact bytes
  while another connection on the same worker progresses.
- Plaintext completion is fenced by actual encrypted socket completion. Initial
  readiness waits for outbound handshake bytes; 100 Continue and 101 Upgrade
  retain their wire barriers. Native CLOSED acknowledges canceled IOCP buffer
  ownership before a TLS slot can be reused. Fatal alerts drain within a bound.
- Verified TLS 1.2/1.3, h2-preferred ALPN, no-ALPN HTTP/1 fallback, current-protocol
  dispatch after resumption and two SNI certificate chains pass. TLS 1.2 cache-only
  resumption and TLS 1.2/1.3 tickets resume across actual workers; host changes do
  not resume another host's identity. Obsolete TLS clients receive a protocol
  version alert rather than being mistaken for a client-side unsupported option.
- SIGINT allows already-accepted handshakes to finish within the stop bound,
  sends close_notify and joins every native worker before reactor destruction.
  The shutdown regression passed 20 old-SIGINT repeats, 10 immediate verified
  handshake stops and the full 34-case/1,000-cycle suite. Full HTTP/2 GOAWAY and
  application stream draining remain part of phase six.
- Focused native ASan/UBSan fixtures check context-table borrowing and partial
  setup failures, byte-lane wrap, write fences, retained plaintext credit,
  failed-join storage lifetime and exact SSL/BIO allocation/free balance.
  The [full regression](https://github.com/isavita/lean-net/actions/runs/43625971933)
  also passes, including all 28 public TLS compatibility tests.
- The [accepted report](../tls/test/reports/2026-11-14-native-tls-e2dbbf0/README.md)
  records the exact source, executable SHA-256, library versions, commands, CI
  results, 34-case/1,000-cycle run and ownership diagnostics. Both full pinned
  testssl v3.2.5 scans report **A+, score 93** (150/159 seconds). This is the
  two-host private-CA fixture with its explicit HSTS application header, not a
  hosted Qualys assessment or a default-public-route A+ claim. Raw LOW/MEDIUM
  findings and the scoped missing-GOST client warning and test-certificate
  revocation-metadata HIGH finding are retained. No private keys are committed.
- A separate official h2spec v2.6.0 strict TLS/ALPN baseline passes all 147 tests
  with zero skips ([baseline artifacts](../tls/test/reports/2026-11-14-native-tls-e2dbbf0/h2spec-baseline/metadata.json)).
  Its IP-based conformance client uses --insecure; a separate
  hostname/CA-verified preflight and the verified curl suite check certificate
  trust. This old RFC 7540/7541 tool does not establish RFC 9113/9218 priority,
  push or stream-error isolation, so phase four remains open.

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
