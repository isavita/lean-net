# Native HTTP/2 machine benchmark

The shutdown-corrected candidate at source
`2a015829682986d9f4bbf2c84188e9129bd293bb` passes the declared Phase 4 throughput,
protocol conformance and short RSS gates. Its three eight-worker rounds reach
279,326 / 283,681 / 300,794 requests/s. The full Linux regression and native/TLS
matrices pass on Linux, macOS and Windows; Phase 4 is accepted. The final
24-hour soak remains a separate Phase 6 gate.

The earlier `2a9e415` candidate passed its local benchmark and both native/TLS
CI matrices on all three platforms, but the
[full Linux regression](https://github.com/isavita/lean-net/actions/runs/43636942939)
exposed a blocked TLS shutdown exceeding its unchanged four-second bound.
Those measurements and the failure are retained as historical evidence. The
current fix aborts remaining HTTP/2 transports when the configured drain budget
expires, preventing a further full TLS shutdown interval from extending that
deadline. The unchanged focused case timed out in all three before-fix trials
and passed all five after-fix trials; the complete 28-case legacy TLS suite also
passed. [Raw logs and timing metadata](http2-conformance-macos-m2-2a01582/shutdown-deadline/after.json)
record total case durations, including setup/cleanup, separately from the
test's original four-second shutdown assertion.

The benchmark uses the native HTTP/2 fixture's `bench` profile: a global
128-client limit, 512 requested HTTP output buffers, four HTTP output flights
per admitted client, and native pool defaults. One persistent server process
runs three rounds for each worker count, with a fresh process between the
one-worker and eight-worker profiles. Each executable is copied before load;
its SHA-256 and the source snapshot are recorded.

The workload and acceptance rules were fixed before candidate timing:

```sh
python test/bench_http2.py --workers 1 8 --rounds 3 \
  --requests 100000 --connections 10 --streams 100 --threads 1 \
  --require-rps 100000 --throughput-gate-workers 8 \
  --output NEW_REPORT.json
```

Every round invokes the same h2load workload:

```sh
h2load -n 100000 -c 10 -m 100 -t 1 -N 10s -T 120s \
  http://127.0.0.1:PORT/binary
```

All three eight-worker rounds must each exceed **100,000 requests/s**. The
one-worker profile is characterization. All six rounds must complete exactly
100,000 started, completed, successful 2xx requests, with zero failed requests,
errors or timeouts and exactly 500,000 response DATA bytes. Before and after
each round, an independent HPACK client verifies the binary body `00ff0d0a41`.
h2load checks aggregate DATA byte counts; it does not verify each body's
contents. The independent codec is pinned to `hpack==4.2.0` with package hashes
in [requirements-http2.txt](../requirements-http2.txt).

The first measured round warms caches for a separate RSS assessment; its
correctness and throughput still count. For **both** worker profiles, RSS
immediately after round three must grow no more than **1%** relative to RSS
immediately after round one. The report retains raw KiB and percentages,
including decreases caused by page reclamation. This short observation does
not establish the final 24-hour soak. `ps` supplies process RSS and CPU samples;
its CPU observations are not function-level profiler attribution.

The local benchmark box is an Apple M2 with eight logical CPUs, macOS 27.2.1,
Lean 4.35.0 and h2load 1.71.0. Reports record the actual versions, complete
commands, source hashes, binary hash, raw h2load output and process samples.
The predeclared workload, thresholds and client thread count are retained when
measuring a changed implementation; failed measurements are preserved.

| Artifact | One-worker requests/s, rounds 1–3 | Eight-worker requests/s, rounds 1–3 | Result |
| --- | --- | --- | --- |
| Pre-machine `e2dbbf0` | 40,635 / 38,190 / 40,970 | 136,652 / 122,984 / 93,328 | All rounds had 680 failed/errored streams |
| Initial machine `768b4e0` | 41,830 / 42,547 / 42,853 | 130,748 / **90,994** / 136,458 | Throughput gate failed in eight-worker round 2 |
| Optimized `2a9e415` | 75,886 / 80,592 / 78,679 | 227,503 / 220,693 / 211,131 | Benchmark passed; later Linux shutdown failure |
| Bounded shutdown `2a01582` | 90,598 / 79,616 / 88,230 | **279,326 / 283,681 / 300,794** | All local and CI gates passed |

The pre-machine rates count successful responses rather than h2load's total
completion rate. That server advertised only 32 concurrent streams. Each
100,000-request round completed 99,320 successful 2xx responses and 680
failed/errored streams, with no timeout. See the
[baseline report](http2-baseline.md) and
[raw baseline JSON](http2-baseline-macos-m2-e2dbbf0.json).

The initial machine candidate completed all **600,000 requests** successfully,
with zero errors or timeouts and exact aggregate DATA counts. Its short RSS
assessments passed: one worker decreased from 34,352 to 11,136 KiB; eight
workers grew from 20,704 to 20,832 KiB, or **128 KiB / 0.6182%**. The failed
throughput result is preserved in
[http2-machine-macos-m2-768b4e0-failed.json](http2-machine-macos-m2-768b4e0-failed.json).
The executable SHA-256 was
`cde25651ff13d20f6dc4cea0a8fdc1755b5ab7191323d6b42e1aadea54cc0994`.

A separate diagnostic ran the unchanged initial candidate at one million
requests with the same ten connections, 100 streams and one client thread,
while `/usr/bin/sample` captured three seconds of native stacks. This was not
an acceptance rerun or a throughput rescore. All eight worker threads showed
active HTTP/2 and TCP-write stacks. Across 9,800 worker wall-stack observations,
`syncWriteTimer` appeared in 957, `flushOne` in 613, HPACK in 3,175 and `writev`
in 287. These inclusive categories overlap and are **not CPU percentages**.
Allocation/refcount operations, Huffman decoding and stream-table updates also
appeared prominently. The retained
[diagnostic summary](http2-conformance-macos-m2-2a9e415/profile-768b4e0-summary.json)
identifies the unchanged binary, command and raw sample hash.

The optimized candidate uses the output queue head when finding the earliest
write deadline, avoids recalculating that unchanged deadline when newer output
is appended or moved into a native lease, and combines small HTTP/2 header and
control parts into bounded 4 KiB groups while preserving wire order and large
DATA references. Huffman byte-bit extraction uses a shift and mask rather than
computing a power for every bit. Correctness validation is separate from the
throughput result. Validation also identified a deterministic TLS
queue-index liveness defect and a timing-sensitive premature close after an
empty-stream peer GOAWAY. Native and wire regressions cover both fixes;
peer-only GOAWAY keeps PING/control frames serviceable and refuses new requests.
The final artifacts passed all **48 wire cases**, **147/147 strict h2spec cases
on each transport**, and both public CLI tests. The wire suite includes
verified TLS coverage of the new GOAWAY policy, the mandatory TLS 1.2/h2 cipher
with P-256, exact binary responses on all four curl protocol modes, strict
stream-error isolation, priority scheduling, opt-in push and 1,000 native
connection cycles. The
[conformance summary and raw logs](http2-conformance-macos-m2-2a01582/summary.json)
retain source-file hashes validated against the committed candidate. TLS
h2spec uses `--insecure` for the generated private PKI; independent Python and
curl clients verify its CA and exact hostnames.

The optimized benchmark completed all **600,000 successful 2xx requests** with
zero errors or timeouts, exact DATA totals and passing binary pre/post checks.
The median rates were **88,230 requests/s** for one worker and **283,681
requests/s** for eight. Its RSS assessments passed: one worker decreased from
33,552 to 7,568 KiB; eight workers grew from 227,152 to 227,296 KiB, or
**144 KiB / 0.06339%**. Page residency differs between short runs; these values
establish the declared growth check and do not claim a reduction in the
server's absolute memory requirement.

The passing
[raw benchmark report](http2-machine-macos-m2-2a01582.json) records a clean
source tree and unchanged executable SHA-256
`3d865555e9abb4ade00e97cfc722c39b0ee3e05c515e764f94668c38ba1a641e`.
The [extended source snapshot](http2-machine-macos-m2-2a01582-source.json)
also verifies all recorded runtime Lean, C and header files against the
committed bytes. Each candidate used one six-round acceptance attempt; no
candidate's rounds were retried or rescored. No client-thread/workload change
was used, and the earlier results remain preserved:
[passing `2a9e415` measurement](http2-machine-macos-m2-2a9e415.json) and
[failed `768b4e0` measurement](http2-machine-macos-m2-768b4e0-failed.json).
