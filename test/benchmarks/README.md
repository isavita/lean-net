# Echo benchmark

Build `lean-net-echo`, then run the native-client benchmark from the repository
root:

```sh
lake build lean-net-echo
python3 test/bench_echo.py --output /tmp/echo-current.json
# Reactor acceptance throughput gate at useful concurrent load:
python3 test/bench_echo.py --connections 16 100 --require-rps 50000 --output /tmp/echo-reactor.json
```

The Python driver snapshots the server executable before the run and compiles a
C load generator with `-O3 -Wall -Wextra -Wpedantic -Werror`. The measured work is
200,000 completed 16-byte payload round trips per round, with one outstanding
request on each persistent connection. Connection setup is excluded. Every echo
byte is validated, and all server exits must be clean after SIGINT. The JSON
records the original binary's SHA-256, compiler, host, request and connection
counts, round-trip latency, throughput, and the count of clients that complete a
request in the first second. Use `--server-arg` to pass repeatable extra server
arguments after its port.

`echo-baseline-macos-m2.json` records the original blocking echo implementation
at commit `9e5e0bd` on an Apple M2 (8 logical CPUs, 16 GiB RAM), Darwin 27.2, Lean
4.35.0. Three-round medians were 43,793 completed requests/s at c=1, 36,941 at
c=16, and 17,332 at c=100. At c=16 and c=100, only one connection completed any
request in the first second. The largest c=100 latency was 11.84 seconds. These
results expose the original serial connection handling; they are not reactor
acceptance evidence.

A separate disposable concurrent C echo server calibrated load-client headroom
on the same host: 272,736 requests/s at c=16 and 256,006 at c=100, with all
connections progressing in the first second. It was only a generator capacity
check, not part of lean-net or a production implementation. Single-connection
round-trip throughput is bounded by loopback latency, so the >50k reactor gate
uses c=16 and c=100 and must be accompanied by concurrency/fairness tests.

A passing throughput run does not prove the reactor's other gates. Acceptance
also requires concurrent short and partial reads, blocked-reader fairness,
partial writes, abrupt/reset disconnects, no descriptor growth, timer expiry and
cancellation under load, safe descriptor reuse, cross-thread wakeups, and
multi-worker port sharing. Run native reactor tests on Linux epoll, macOS
kqueue, and Windows IOCP; a backend compiling elsewhere is not runtime evidence.

The broader production gates remain distinct:

- [h2spec](https://github.com/summerwind/h2spec) tests RFC 7540 and HPACK; keep
  explicit RFC 9113 and RFC 9218 tests in addition to its required full pass.
- [h2load](https://nghttp2.org/documentation/h2load.1.html) uses `-n` for total
  requests, `-c` for client connections, and `-m` for streams per connection.
- A brief connection churn run is not the required 24-hour, 10k-RPS soak.

## Native reactor measurement

`echo-reactor-macos-m2-1worker.json` and
`echo-reactor-macos-m2-8workers.json` record the same 3-round workload after the
reactor echo migration, with the server's worker count explicitly set to 1 or 8.
Both reports snapshot executable SHA-256
`ffbac50140b0bed2844fea3fe19af93973224625e54a15620899895f9a28aa0f`.
The implementation was measured before its feature commit, so the JSON's
`git_head` is the previous committed baseline; the executable hash identifies
what actually ran.

| Workers | Connections | Median completed requests/s | Round range |
| --- | --- | ---: | ---: |
| 1 | 16 | 167,290 | 155,456–171,085 |
| 1 | 100 | 193,721 | 172,018–194,852 |
| 8 | 16 | 185,574 | 148,524–185,713 |
| 8 | 100 | 187,583 | 170,056–190,704 |

Every round passed `--require-rps 50000`, and every client completed a request
in the first second. This validates the loopback echo throughput gate on this
Mac. It does not establish linear multi-core scaling: this workload did not
show a reliable advantage for eight workers. The accept-distribution diagnosis
below identifies a macOS listener-dispatch limitation in that snapshot.
HTTP/2, TLS, Windows runtime, and long-duration production gates remain separate.

Separate observational runs in `echo-reactor-macos-m2-resource-samples.json`
used 2,000,000 requests at c=100 while sampling `ps` every 250 ms. Their
throughput was 193,317 requests/s with one worker and 187,987 with eight.
After the first second, sampled process CPU medians were 98.5% and 97.8%
respectively (100% represents one logical CPU on this host). Startup RSS
peaked at 31,760 KiB and 223,888 KiB; later resident samples fell to
4,448–4,480 KiB and 4,672–7,984 KiB. macOS page residency/reclamation can
change these values independently of the reactor's reserved pool capacity;
this short sample is not leak or 24-hour-soak proof. These observations are
separate from the uninstrumented throughput acceptance runs above.

The later `echo-reactor-final-gate-macos-m2.json` records the post-backpressure-
validation build (`9df6575a62eef309e0e9874a82351880305ff6b780258bffdc094f32ea3bcf4c`):
three rounds at c=100 with eight workers achieved 186,806, 192,757, and 196,143
completed requests/s. All 100 clients progressed in the first second and every
round exceeded the explicit 50,000-RPS gate. Any later correctness build needs
its own executable-hash acceptance record; the historical reports remain useful
comparisons rather than claims about a different executable.

After the historical-completion/SocketId correctness change, the final single
acceptance repetition in `echo-reactor-completion-gate-macos-m2.json` measured
191,923 completed requests/s at c=100 and eight workers (200,000 verified
round trips), with all 100 clients progressing in the first second. Executable
SHA-256 `41e7439d2e6baa62f7a86f9108a579d911d8592f25180a4308115d53cfdb4b8d`
matched before and after the run; SIGINT exited normally. This is the latest
local echo throughput gate before acceptor handoff; later evidence follows below.

## macOS worker-distribution diagnosis

`echo-reactor-macos-m2-accept-distribution.json` records a disposable
`DYLD_INSERT_LIBRARIES` trace of successful `listen`/`accept` calls on the same
`41e7439d...` executable. It includes the full trace/driver source, hashes, raw
CPU samples, and listener fd/thread IDs. The production binary was unchanged;
only successful connection setup was instrumented, with no per-echo tracing.
Accept counts include one startup probe.

| Native client processes | Total load connections | Successful accepts by listeners 1–8 | Server CPU median / max |
| ---: | ---: | --- | ---: |
| 1 | 100 | 0, 0, 0, 0, 0, 0, 0, 101 | 95.5% / 100.0% |
| 4 | 400 | 0, 0, 0, 0, 0, 0, 0, 401 | 97.9% / 99.0% |
| 1 | 1,000 | 0, 0, 0, 0, 0, 0, 0, 1,001 | 95.2% / 95.2% |

Every connection reached the last-created listener and its one worker thread;
the other seven workers received no connections. Four independent native load
processes did not change this distribution. Thus the measured one-core server
use is explained by listener selection before Lean processing. These runs do
not test Lean contention under balanced load, and do not establish Linux or
Windows distribution. Instrumented timing is diagnostic, not a new acceptance
gate. The 1,000-connection CPU summary contains only one sample after the first
second, so the longer 100/400-connection runs provide the stronger CPU evidence.

[Apple's socket-option manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/setsockopt.2.html)
describes `SO_REUSEPORT` as allowing duplicate bindings, without promising load
balancing. In the published Apple XNU source,
[TCP input calls PCB lookup](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/tcp_input.c#L3020-L3032),
[IPv4 lookup returns the first matching address-specific PCB](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/in_pcb.c#L2558-L2665),
and [new PCBs enter at the list head](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/in_pcb.c#L2810-L2811).
That is consistent with the observed last-created-listener selection. This
source is `xnu-12377.1.9`, older than the running `xnu-13432.41.4`; the measured
accept distribution is the direct evidence for this host. This historical
listener-starvation defect is resolved by the acceptor handoff measured below.

## Acceptor handoff acceptance

The user-approved macOS/Windows design uses one acceptor and bounded native
channels to per-core workers. Each worker creates its own connection identity
and registers its socket before receiving `ACCEPTED` or performing reads.
Linux retains independent `SO_REUSEPORT` listeners.

`echo-reactor-handoff-macos-m2-1worker.json` and
`echo-reactor-handoff-macos-m2-8workers.json` record the final uninstrumented
c=100 gate at source commit `d3ccc2ebb3d0cb4cee188eca5832181c7fed5caa`,
executable SHA-256
`96b5c28c01e85a24dd595b3de826e3a890bd731e580068c080514a1f5f00dbe9`.
Both reports include source hashes and used 200,000 verified 16-byte echoes per
round, three rounds, with the explicit `--require-rps 50000` threshold.

| Workers | Completed requests/s by round | Median |
| ---: | --- | ---: |
| 1 | 185,657 / 191,688 / 193,948 | 191,688 |
| 8 | 188,213 / 191,608 / 179,073 | 188,213 |

All six rounds passed. All 100 clients progressed in the first second of every
round, and all server SIGINT exits were zero. These short single-client-process
measurements do not establish a throughput advantage for eight workers.

The separate `echo-reactor-handoff-macos-m2-worker-distribution.json` records a
disposable DYLD interposer against the same executable, using four independent
native client processes with 100 connections and 200,000 requests each. The
tracer joins connected-socket read registration to positive `recv` calls and
records owning thread IDs; its full source, driver, hashes and raw CPU samples
are embedded in the report. Timing from this instrumented run is diagnostic.

All eight distinct Lean worker threads registered and read their own sockets.
Their adoption counts were **51 / 50 / 50 / 50 / 50 / 50 / 50 / 50**, including
one startup probe. Every worker performed positive reads (93,501–105,288 calls
each), and each worker's registration thread matched its read thread. The
800,000 positive reads and 12,800,000 bytes match the clients' 800,000 verified
16-byte echoes. Server CPU after the first second had median 271.75% and maximum
309.5%, showing activity across multiple logical CPUs on this host. SIGINT
exited zero. This directly resolves the earlier last-listener starvation; it
does not establish linear throughput scaling or later protocol/soak gates.

`test/test_reactor_dispatch.py` additionally exercises eight real native worker
threads with exactly 50 accepts each, bounded capacity-one queues, retained
accepted sockets, saturated infinite waits, interrupted wake delivery,
completion preservation, both endpoint destruction orders, descriptor reuse,
and zero backend heap allocations during handoff/established I/O. It passes
with ASan/UBSan on macOS; other platform runtime gates remain separately tracked.

## HTTP/1.1 production-driver characterization

The HTTP/1 native driver was measured through the fixture's `/binary` route at
source commit `407c604e424344ad0dfb657a758815c5f6b90849`, executable SHA-256
`ed39f08e1dc3c41dd96f69d048f9256f487f91f90c19039b958a7ab0f998d436`.
All four reports below contain matching source-file hashes, a source-manifest
hash, compiler/tool versions, commands, configuration and per-round results.
The executable was snapshotted and its original hash rechecked after each run.
Measurements ran sequentially on the Apple M2 after other local builds/tests
finished.

The controlled `bench` fixture mode admits 128 clients and requests 512 output
buffers, preserving four outstanding write credits per admitted client with
both one and eight workers. Native pool/parser settings use their defaults.
The admission override permits c=100; the library's default admission limit is
32. The fixture serves the five exact bytes `00 ff 0d 0a 41`, with Date caching
and the production parser/encoder/reactor path enabled. Each round completes
200,000 HTTP/1.1 GET requests over 100 persistent connections, with one request
outstanding per connection and no pipelining.

| Client | Server workers | Completed requests/s by round | Median |
| --- | ---: | --- | ---: |
| Verified native client | 1 | 40,137 / 40,903 / 40,555 | 40,555 |
| Verified native client | 8 | 87,818 / 93,892 / 93,328 | 93,328 |
| h2load HTTP/1, four client threads | 1 | 37,186 / 37,094 / 37,058 | 37,094 |
| h2load HTTP/1, four client threads | 8 | 96,701 / 96,861 / 93,484 | 96,701 |

`http1-reactor-macos-m2-{1worker,8workers}-verified.json` uses
`test/bench_http1.c`, compiled with `-O3` and strict C11 warnings. It checks every
response's 200 status, explicit Content-Length, and all body bytes before
counting completion. Connection setup is excluded. All 1.2 million responses
were verified, and every round had all 100 clients progressing in the first
second. The eight-worker median was 2.30 times the one-worker median in this
workload. Tail latency was less consistent with eight workers: native-client
p99 ranged from 5.18–6.41 ms, versus 2.72–3.51 ms with one worker; full latency
statistics remain in the reports.

`http1-reactor-macos-m2-{1worker,8workers}-h2load.json` records nghttp2/h2load
1.71.0. Its [official options](https://nghttp2.org/documentation/h2load.1.html)
define `--h1` to force HTTP/1.1, `-n` as total requests, `-c` as client count,
`-t` as native client threads, and `-m 1` as one pipelined request in flight per
HTTP/1 connection. All 1.2 million requests completed as 2xx, with zero failures,
network errors, or timeouts and exactly 6,000,000 response-body bytes. h2load
checks status/traffic counts rather than inspecting each body; exact content
verification comes from the native-client reports. Its elapsed time includes
connection setup, so the two client methods should be assessed separately.

Reproduction:

```sh
lake build lean-net-http1-reactor-fixture
python3 test/bench_http1.py --server-arg bench --server-arg 1 --output /tmp/http1-1worker.json
python3 test/bench_http1.py --server-arg bench --server-arg 8 --output /tmp/http1-8workers.json
python3 test/bench_http1.py --client h2load --threads 4 --server-arg bench --server-arg 8 --output /tmp/http1-h2load.json
```

Neither wrk nor h2load was initially installed. nghttp2 1.71.0 was installed
through Homebrew with auto-update and cleanup disabled. Its dependency install
selected OpenSSL 4.1.0 for the global CLI while retaining the versioned OpenSSL
3.6.3 installation; plain HTTP was measured throughout. These are short HTTP/1
characterization runs. The final HTTP/2 100k-RPS, TLS and 24-hour-soak gates
remain separately required.
