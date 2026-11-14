# Static-file throughput regression check

Source `7404295a8a3025b67a4d70d2f33a10a2c04bbbf2` passes the unchanged
macOS M2 six-round HTTP/2 benchmark. The candidate is **not accepted**: Linux
CI reaches Brotli but its shared library needs `log2@GLIBC_2.29`, unavailable
from Lean's bundled math-library link environment. Raw failed-job logs are
preserved in `ci/`. The next build selects static Brotli archives.

The [raw report](http2-benchmark.json) records a clean committed source tree,
immutable binary SHA-256, exact h2load commands, all raw output, binary-body
checks before and after each round, and process samples. The
[extended snapshot](source.json) covers every runtime Lean/C/header source.

The workload and gates are those declared for
[Phase 4](../http2-machine.md): three rounds per persistent process with one
and eight workers, `h2load -n 100000 -c 10 -m 100 -t 1`, binary route, and
fresh processes between worker profiles. All eight-worker rounds must exceed
100k RPS; one worker is characterization. Both RSS assessments compare after
round three against after round one and require at most 1% growth.

| Workers | RPS, rounds 1–3 | RSS growth after round one |
| --- | --- | --- |
| 1 | 86,892 / 90,603 / 84,768 | 48 KiB / 0.37547% |
| 8 | 290,476 / 302,097 / 284,045 | 512 KiB / 0.22513% |

All 600,000 requests are successful 2xx responses, with zero failures, errors
or timeouts and exact aggregate DATA counts. Independent samples verify exact
binary bytes; h2load does not verify every individual response body. No round
was retried or rescored. This is a short regression check, not the required
24-hour soak or a static-file-specific throughput measurement.
