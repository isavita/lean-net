# Benchmarks

Run from the repository root after building the relevant target. HTTP/2 requires `h2load` and `python3 -m pip install -r test/requirements-http2.txt`. Reports record their source version, configuration, workload, and raw results; use the current [comparison](../../docs/benchmarks.md) for the published HTTP/1.1 results.

| Workload | Command |
| --- | --- |
| HTTP/1.1 vs Go `net/http` | `lake build lean-net-http1-reactor-fixture && python3 test/benchmarks/compare_http1.py --output /tmp/http1-comparison.json` |
| HTTP/1.1 vs Go, Python Uvicorn, Ruby Puma | Run the `Native reactor` workflow with `compare_http1=true`; it installs pinned references and uploads the four-server JSON report. |
| HTTP/1.1 only | `lake build lean-net-http1-reactor-fixture && python3 test/bench_http1.py --server-arg bench --server-arg 8 --output /tmp/http1.json` |
| HTTP/2 | `lake build lean-net-http2-reactor-fixture && python3 test/bench_http2.py --output /tmp/http2.json` |
| TCP echo | `lake build lean-net-echo && python3 test/bench_echo.py --output /tmp/echo.json` |
| Gateway gate allocations | `lake build lean-net-gate-perf && python3 test/bench_gate.py --output /tmp/gate.json` |

The HTTP/1.1 comparison uses the same C client for every server and verifies every response body. It measures a five-byte endpoint over persistent loopback connections, without TLS or proxying.
