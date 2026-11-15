# Benchmarks

## HTTP/1.1 versus Go `net/http`

The [comparison harness](../test/benchmarks/compare_http1.py) runs the same verified C client against both servers. It checks a 337-byte HTTP/1.1 response with the same status, five-byte body, and header values (normalizing the Date timestamp), then sends 200,000 requests per round over 100 persistent connections, one outstanding request per connection. Each server gets 10,000 warmup requests before each of three alternating rounds. All 1.2 million measured responses passed status, length, and body checks.

| Linux hosted runner, 4 CPUs | Requests/s by round | Median | Median p99 latency |
| --- | ---: | ---: | ---: |
| lean-net, 4 workers | 36,605 / 35,709 / 36,712 | 36,605 | 5.43 ms |
| Go `net/http`, `GOMAXPROCS=4` | 80,747 / 82,007 / 79,007 | 80,747 | 3.96 ms |

The run used Lean 4.35.0, Go 1.27.4, Linux x86-64, and source commit `a5bd7ac`. [Raw results](../test/benchmarks/http1-comparison-linux-a5bd7ac.json) record the binary and source hashes, tool versions, CPU-time estimates, response signature, and every round. These loopback results cover neither TLS nor proxying and do not establish a 100,000 requests/s per-core capacity. A separate [macOS sample](../test/benchmarks/http1-comparison-macos-m2-62a0b15.json) predates the write-timer optimization and had substantial host contention.

Reproduce on Linux with Go and a C compiler installed:

```sh
lake build lean-net-http1-reactor-fixture
python3 test/benchmarks/compare_http1.py --workers 4 --rounds 3 --output /tmp/http1-comparison.json
```

The [benchmark index](../test/benchmarks/README.md) lists the HTTP/2, TCP echo, and gate allocation commands.
