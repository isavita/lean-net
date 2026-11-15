# Benchmarks

## HTTP/1.1 comparison

The [comparison harness](../test/benchmarks/compare_http1.py) runs one verified C client against lean-net, Ruby Puma, Python Uvicorn, and Go `net/http`. Each server uses four workers or four available CPU threads and returns a matching 337-byte response apart from the Date timestamp. The workload is 100 persistent loopback connections, 10,000 warmup requests per server, then three rounds of 200,000 requests per server. Every measured response's status, length, and body was checked.

| Linux hosted runner, 4 available CPUs | Requests/s by round | Median | Median p99 latency |
| --- | ---: | ---: | ---: |
| Ruby Puma | 20,667 / 21,084 / 20,907 | 20,907 | 10.88 ms |
| lean-net | 35,488 / 36,115 / 36,128 | 36,115 | 5.16 ms |
| Python Uvicorn | 38,822 / 39,247 / 39,010 | 39,010 | 6.36 ms |
| Go `net/http` | 77,722 / 75,778 / 78,084 | 77,722 | 4.52 ms |

On this workload, Puma is lower, Uvicorn is close to lean-net, and Go is higher. The run used Lean 4.35.0, Ruby 4.0.9 with Puma 8.0.3, Python 3.14.10 with Uvicorn 0.54.0, and Go 1.27.4 at source commit `0987bd3`. The [raw report](../test/benchmarks/http1-comparison-linux-four-way-0987bd3.json) contains versions, source and binary hashes, configuration, response signature, and all 12 runs.

Reproduce on Linux through the optional `Native reactor` workflow:

```sh
gh workflow run reactor.yml --ref main -f compare_http1=true
```

These loopback results cover neither TLS nor proxying and do not establish 100,000 requests/s per-core capacity. The [benchmark index](../test/benchmarks/README.md) lists the HTTP/2, TCP echo, and gate allocation commands.
