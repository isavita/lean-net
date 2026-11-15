# Production controls

The public plain and TLS servers share optional metrics, structured access
logging, worker limits and graceful shutdown. Phase 6 acceptance, including
the actual 24-hour soak, is tracked in the [acceptance ledger](production-roadmap.md).

```sh
.lake/build/bin/lean-net-http1 8080 --workers 8 --max-clients 128 \
  --metrics --access-log ./access.jsonl
tls/.lake/build/bin/lean-net-tls chain.pem key.pem 8443 \
  --workers 8 --max-clients 128 --metrics --access-log ./tls-access.jsonl \
  --reload-certs-ms 1000
```

Both commands also accept `--static DIRECTORY`, `--static-memory MIB` and
`--enable-push`. `--workers 0` selects the active CPU count; the global client
limit is divided across workers. Keep `lean-net-access-log-helper` (with `.exe`
on Windows) beside each installed server, or pass its absolute path with
`--log-helper`. Lake builds the helper with the public executable.

## Metrics and completion

`--metrics` reserves `/metrics` for Prometheus text exposition, including on
static servers. GET returns the snapshot, HEAD returns its headers, and other
methods receive 405. Library users set `ReactorServerConfig.metricsPath` to
choose another origin path. Snapshots aggregate counters published by their
owning workers; an idle worker's publication may lag by up to one second.

Application counters, latency and access logs exclude the metrics endpoint.
Labels contain only fixed method, protocol and status classes. A successful
request requires status 101 or 2xx/3xx and completed output. Handler return or
queued output alone does not complete a request. TLS completion waits for the
corresponding encrypted output to complete on the socket. Fulfilled historical
write completions retain their request metadata through transport retirement.
Stream resets, timeouts, errors and shutdown cancellation remain observable.

The transport byte counters include plaintext HTTP framing, control frames,
metrics scrapes and upgraded raw traffic. An access record's `bytes_sent`
counts completed response-body payload, excluding framing. HEAD, 204 and 304
therefore record zero payload bytes. An aborted physical write contributes no
partial-byte estimate. See the [observability contracts](../test/observability.md)
for the complete schema, resource bounds and native error behavior.

## Structured access logs

Each worker emits into its own bounded queue; one native helper formats JSON
and writes logs outside the reactor loops. A full queue drops the record and
increments `lean_net_access_log_dropped_total`. Writer errors surface to the
server. `lean_net_access_log_pending_records` exposes accepted records still
awaiting completion. A metrics-only configuration starts no helper.

Records contain timestamp, duration, worker, protocol, status, outcome, payload
bytes, method and sanitized target. Query strings, fragments and non-origin
URI details are removed. Headers are never passed to the logger. Target and
method truncation are explicit fields. Regular files append and rotate between
complete records; defaults are four managed files of at most 16 MiB each.
Oversized existing managed files cause startup failure while preserving their
contents. Null sinks do not rotate.

Library users set `ReactorServerConfig.accessLog` with an
`HTTP.Observability.AccessConfig`, including an explicit helper executable.
The server brackets the hub outside all worker lifetimes. Producers finish
before the helper drains and joins; its configured shutdown deadline bounds
waiting for a stalled writer.

## Graceful shutdown and certificate reload

SIGINT/console stop ends admission and starts one shared application drain
deadline (two seconds by default, `shutdownDrainMs` in the library). HTTP/1
finishes the current request and queued response with connection closure.
HTTP/2 sends GOAWAY and continues accepted streams and their flow-control
traffic. Remaining work is cancelled at the deadline. TLS close-notify and
worker teardown share that deadline; native workers join before their reactor
resources are freed.

Certificate reload is opt-in on the TLS server. The loader reads and validates
a bounded certificate/key snapshot outside reactor loops. Successful changes
publish a fresh immutable certificate generation; existing sessions retain
their original generation until cleanup. Invalid or incomplete replacements
leave the last valid generation active. Replace files atomically where
possible. The [TLS guide](../tls/README.md) describes explicit library reload
requests, status, SNI bundles and certificate-storage assumptions.

Build and run the focused tests listed in
[production validation](../test/production-hardening.md). Short wire, fuzz and
resource tests have separate evidence from the required full-duration soak.
