# Native HTTP/2 machine benchmark

The Phase 4 throughput gate remains open pending measurement of the optimized
candidate. The initial machine candidate passed correctness and the short RSS
gate, but one of its three eight-worker rounds missed the declared throughput
threshold. Its complete failed result is retained below.

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
| Optimized candidate | Pending | Pending | Not yet measured |

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
appeared prominently.

The optimized candidate uses the output queue head when finding the earliest
write deadline, avoids recalculating that unchanged deadline when newer output
is appended or moved into a native lease, and combines small HTTP/2 header and
control parts into bounded 4 KiB groups while preserving wire order and large
DATA references. Huffman byte-bit extraction uses a shift and mask rather than
computing a power for every bit. Correctness validation is separate from the
pending throughput result. Validation also identified a deterministic TLS
queue-index liveness defect and a timing-sensitive premature close after an
empty-stream peer GOAWAY. Native and wire regressions cover both fixes;
peer-only GOAWAY keeps PING/control frames serviceable and refuses new requests.
Final artifact validation and measurements will be recorded after these fixes
are rebuilt. The wire suite now has 48 cases, including verified TLS coverage
of the new GOAWAY policy.
