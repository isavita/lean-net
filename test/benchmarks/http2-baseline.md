# HTTP/2 pre-machine baseline — macOS M2

The six fixed-count runs in
[http2-baseline-macos-m2-e2dbbf0.json](http2-baseline-macos-m2-e2dbbf0.json)
use the immutable native HTTP/1 reactor fixture's existing `bench` profile at
source `e2dbbf08b5057e8c24af2e7bc0a5d73f0cd3221f`. Its legacy HTTP/2 path was
measured before building the new protocol machine. Executable SHA-256:

```text
ffad9418a6966ff1593a505822c28a2fa80ebe9107c4436e8a917997de1a6fc6
```

Every round used the required workload, with one native h2load client thread:

```sh
h2load -n 100000 -c 10 -m 100 -t 1 -N 10s -T 120s http://127.0.0.1:PORT/binary
```

The server profile has a global 128-client limit, 512 requested output buffers,
four HTTP output flights per admitted client, and native pool defaults. Worker
count was explicitly one or eight. The old server advertises only **32** streams
per connection. All six runs produced **99,320 successful 2xx responses and 680
failed/errored streams**, with no timeout. This baseline therefore **fails the
zero-error acceptance gate**. The exact 680 count is consistent with an initial
100-stream burst preceding the 32-stream server setting on ten connections;
that cause is an inference, not a captured h2load frame trace.

| Workers | Successful 2xx requests/s by round | Median |
| ---: | --- | ---: |
| 1 | 40,635 / 38,190 / 40,970 | 40,635 |
| 8 | 136,652 / 122,984 / 93,328 | 122,984 |

These rates exclude the errored streams from h2load's reported completion rate.
The raw tool output is retained. Before and after each load, an independent
official HPACK decoder verified the five binary body bytes `00ff0d0a41`.
Aggregate load data was exactly `99,320 × 5 = 496,600` bytes. h2load does not
validate each individual body's content.

Process sampling observed server CPU maxima of 96–100% for one worker and
374–475% for eight workers; sampled client CPU maxima were 12–28%. These are
`ps` observations, not profiler attribution. RSS round deltas were
−26,976/+192/−96 KiB for one worker and +2,320/−207,056/+224 KiB for eight.
Startup page residency/reclamation dominates those short observations; this is
not the final memory soak or a linear-scaling claim.

The JSON records immutable historical source hashes separately from the changing
Phase 4 working tree, complete commands, raw summaries, CPU/RSS samples, and tool
versions. h2load 1.71.0 reports cleartext HTTP/2 as `h2c`; the summary parser
accepts that label without accepting failed streams. No timing run was repeated
to correct that label classification.
