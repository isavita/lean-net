# Benchmarks

## HTTP/1.1 loopback

Apple M2 (8 logical CPUs), macOS 27.2.1, Lean 4.35.0, Go 1.22.2; lean-net source commit `62a0b15`. The harness checked that both servers returned the same 337-byte `GET /binary` response: a five-byte body, explicit `Content-Length`, `Content-Type`, Date, and four security headers. The [Go reference](https://pkg.go.dev/net/http) used the standard `net/http` server.

One verified C client sent 200,000 requests per round over 100 persistent connections, with one request in flight per connection and no pipelining. Each server received 10,000 warmup requests before each measured round. Lean used 8 workers, `maxClients=128`, and 512 output buffers; Go used `GOMAXPROCS=8`. The paired order alternated across three rounds. Every measured response passed status, length, and body-byte checks; all 100 connections made progress in the first second.

| Server | Requests/s by round | Median requests/s | Median p99 latency | Approx. server CPU cores |
| --- | ---: | ---: | ---: | ---: |
| lean-net | 40,215 / 58,434 / 54,924 | 54,924 | 11.81 ms | 3.44 |
| Go `net/http` | 83,876 / 92,577 / 99,652 | 92,577 | 4.56 ms | 2.48 |

CPU cores are estimated from process CPU-time deltas divided by each round's wall time. The host had competing macOS and application load. An earlier paired pass with the same response and configuration measured 81–89k requests/s for lean-net and 144–166k for Go, showing material run-to-run variation on this host. These numbers characterize this loopback endpoint under contention, not TLS, proxying, fleet capacity, or a 100k requests/s/core result. The common client sustained at least the Go result, above the lean-net result.

Reproduce from the repository root:

```sh
lake build lean-net-http1-reactor-fixture
python3 test/benchmarks/compare_http1.py --rounds 3 --output /tmp/http1-comparison.json
```

[Raw results](../test/benchmarks/http1-comparison-macos-m2-62a0b15.json) include the executable/source hashes, tool versions, configuration, all rounds, and verification counts. [Benchmark commands](../test/benchmarks/README.md) cover HTTP/2, TCP echo, and gate allocations separately.
