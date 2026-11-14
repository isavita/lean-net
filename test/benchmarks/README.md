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
show a reliable advantage for eight workers, and its single load-generator
thread can itself constrain aggregate throughput. HTTP/2, TLS, Windows runtime,
and long-duration production gates remain separate.

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
