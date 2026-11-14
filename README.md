# lean-net

A Lean 4 TCP and HTTP library under development. The first milestone is a
single-threaded TCP echo and HTTP/1.1 servers with an incremental request parser.
The HTTP server uses a non-blocking poll loop and supports HTTP/1.1 and
prior-knowledge HTTP/2 over cleartext (h2c) on the same listener. The
separate `tls/` package adds OpenSSL TLS and ALPN for HTTP/2 and HTTP/1.1.

The expanded production brief is being implemented phase by phase on the
reactor work branch. [The acceptance ledger](docs/production-roadmap.md) retains
all pending gates, including h2spec, sustained throughput, and the actual
24-hour soak. The new native-reactor echo and its ownership model are described
in [docs/reactor.md](docs/reactor.md); the HTTP/TLS paths still use the previous
event-loop design until their scheduled migration phases.

## Build and test

Install the Lean toolchain selected by `lean-toolchain`, then run:

```sh
lake build
lake build lean-net-http1-fixture lean-net-http2-fixture lean-net-event-ffi-test lean-net-transport-test lean-net-ffi-live lean-net-pool-lifetime-test
lake env lean test/LeanNetTest.lean
lake env lean --run test/HTTP1Test.lean
lake env lean --run test/HTTP1HeaderEventTest.lean
lake env lean --run test/HTTP1ResponseTest.lean
lake env lean --run test/HTTP2PrefaceTest.lean
lake env lean --run test/HTTP2FrameTest.lean
lake env lean --run test/HPACKTest.lean
lake env lean --run test/HTTP2RequestTest.lean
lake env lean --run test/HTTP2StreamTest.lean
lake env lean --run test/HTTP2ConnectionTest.lean
python3 test/test_echo.py -v
python3 test/test_http1_server.py -v
.lake/build/bin/lean-net-event-ffi-test
python3 test/test_ffi_live.py -v
python3 test/test_pool_lifetime.py -v
python3 test/test_http1_event.py -v
python3 test/test_transport_scheduler.py -v
python3 test/test_http1_faults.py -v
python3 test/test_http2_e2e.py -v
```

The build compiles the POSIX shim with `-Wall -Wextra -Wpedantic -Werror`.
The acceptance suite uses loopback sockets and checks descriptor counts using
`/proc` on Linux or `lsof` on macOS. The echo server takes a port argument:

```sh
.lake/build/bin/lean-net-echo 8080
# Or run the HTTP server and request its default route:
.lake/build/bin/lean-net-http1 8080
# In another terminal:
# curl -v --http1.1 http://localhost:8080/
# curl -v --http2-prior-knowledge http://localhost:8080/
```

The optional stdlib-only connection soak starts its own loopback server,
validates alternating HTTP/1.1 and prior-knowledge h2c responses, and samples
quiescent RSS and descriptor counts after each batch:

```sh
python3 test/soak.py
# Adjust workload or resource thresholds; see all options with --help:
python3 test/soak.py --count 10000 --warmup 500 --batch 1000 --concurrency 16
```

By default it allows no descriptor growth over baseline and at most 8192 KiB
RSS growth over the warmup sample. Use `--max-fd-growth` and
`--max-rss-growth-kib` to set thresholds for a different environment. RSS is
sampled with `ps`; descriptor counts use `/proc` or `lsof`. The check measures
connection churn over the run, not long-duration sustained-load performance.

## FFI and resource ownership

The C functions return Lean `IO` objects. Socket syscall results encode
non-negative descriptors and byte counts or negative `-errno` values; the
listener encodes `getaddrinfo` failures as `-(100000 + EAI_code)` (the native
EAI code may itself be negative). The Lean layer interprets results and owns
retry policy; C does not retry interrupted syscalls. `close` is called once,
never retried, and `EBADF` indicates a library defect. Socket resources are
managed with explicit brackets rather than finalizers.

The server executables have a scoped SIGINT handler with a self-pipe to wake its
blocking socket waits and permit the Lean brackets to unwind. This facility is
process-wide and assumes single-threaded use. The socket shim uses `SO_REUSEADDR`, `TCP_NODELAY`, and
platform SIGPIPE suppression by default.

`lakefile.lean` supplies the native build recipe: Lake cannot express this
custom C compilation step in the static TOML manifest. Socket handles are
borrowed for the lifetime of their bracket callback; callers must not retain
or close them again after the callback returns.

The HTTP/1.1 parser retains its progress across input fragments, enforces
configurable size limits, and returns unconsumed bytes for pipelined requests.
Parsing errors must close the connection; a caller must not resume parsing the
remaining bytes as a new request after a framing error.

The HTTP/1.1 server multiplexes connections on one thread. `ServerConfig`
bounds clients, response sizes and idle, request and write times. Router
callbacks execute synchronously and should not block. Responses have explicit
framing and a Date header. The default router serves `/`; applications can
provide a `LeanNet.HTTP1.Router`.

HTTP/2 supports request multiplexing, HPACK with static and dynamic tables
and Huffman coding, and stream and connection flow control. It does not
implement HTTP/1.1 Upgrade to h2c; use prior knowledge for cleartext. For
TLS setup, certificate requirements, and verified-client tests, see
[tls/README.md](tls/README.md).
