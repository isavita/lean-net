# Production controls

The public plain and TLS servers share optional metrics, structured access
logging, worker limits and graceful shutdown. Phase 6 acceptance, including
the actual 24-hour soak, is tracked in the [acceptance ledger](production-roadmap.md).
The soak requires each tested public server instance to sustain at least
10,000 successful requests/s independently, with metrics and logging enabled.

```sh
.lake/build/bin/lean-net-http1 8080 --workers 8 --max-clients 128 \
  --metrics --access-log ./access.jsonl \
  --http2-ping-ms 10000 --http2-ping-timeout-ms 10000
tls/.lake/build/bin/lean-net-tls chain.pem key.pem 8443 \
  --workers 8 --max-clients 128 --metrics --access-log ./tls-access.jsonl \
  --reload-certs-ms 1000 --http2-ping-ms 10000 --http2-ping-timeout-ms 10000
```

Both commands also accept `--static DIRECTORY`, `--static-memory MIB`,
`--enable-push`, `--host ADDR` (default `127.0.0.1`; use `0.0.0.0` or `::`
to serve external clients), `--health`, `--admin-port PORT`,
`--pin-workers` and `--no-security-headers`. The TLS server adds
`--client-ca PEM`, `--require-client-cert` and `--ocsp-response DER`. `--workers 0` selects the active CPU count; the global client
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

## Active HTTP/2 keepalive

Active server PINGs are opt-in. Both public CLIs accept `--http2-ping-ms N`
and `--http2-ping-timeout-ms N`, with decimal values from 1 to 3600000
milliseconds. The timeout flag requires the interval flag. The interval is
disabled by default; an enabled interval uses a 10000-millisecond ACK timeout
unless specified. Library users set `ReactorServerConfig.http2.pingIntervalMs`
and `pingTimeoutMs`; interval zero disables probes.

After the client preface and first SETTINGS, the pure HTTP/2 machine schedules
one periodic probe independently of application traffic. At most one probe is
queued or awaiting its matching eight-byte nonce ACK. The driver uses one
per-connection slot in the native timer wheel. It queues the PING in output
order, preserving complete header/CONTINUATION blocks and file DATA framing.

The absolute ACK timeout starts when the PING's physical write completes,
including its encrypted socket-write fence under TLS. A probe awaiting output
credit has no ACK timeout yet; the ordinary write deadline still bounds it.
A matching early ACK can clear a probe before its write notification arrives.
Wrong, stale or duplicate ACKs, duplicate write notifications, peer non-ACK
PINGs and ordinary requests cannot extend the active ACK deadline. A matching
ACK schedules the next interval from the time that ACK is processed.

An expired ACK deadline sends PROTOCOL_ERROR GOAWAY and drains/closes that
connection; other connections remain serviceable. Active observed requests
on that connection receive timeout outcomes. EOF and either side's GOAWAY
stop new probes. HTTP/1 receives no PING frames. PINGs create no application
request counters or access records, while transport byte counters include
their framing. The [pure and real-wire tests](../test/production-hardening.md#http2-active-keepalive)
exercise these distinctions; enabling the options alone is not acceptance.

## Structured access logs

Each worker emits into its own bounded queue; one native helper formats JSON
and writes logs outside the reactor loops. A full queue drops the record and
increments `lean_net_access_log_dropped_total`. Writer errors surface to the
server. `lean_net_access_log_pending_records` exposes accepted records still
awaiting completion. A metrics-only configuration starts no helper.

Both public CLIs accept `--access-log-queue-capacity RECORDS` alongside
`--access-log PATH`. The value is a power of two from 1 to 65536 and counts
records per worker; omission preserves the default of 1024. For example,
`--access-log /dev/null --access-log-queue-capacity 4096` allows bounded
scheduling bursts without changing the helper's write behavior. Larger queues
increase the shared mapping, which remains capped at 64 MiB across all workers;
configurations exceeding that bound fail startup. Capacity does not suppress
the dropped-record counter or retry dropped records. The option may appear
once and requires an access-log sink.

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
traffic. TLS reserves the smaller of its configured shutdown timeout and one
quarter of the shared budget for transport closure: the defaults allow up to
1.5 seconds of HTTP draining followed by up to 0.5 seconds for close-notify.
At that transition, remaining application work is cancelled while fulfilled
write completions retain their accounting. Handshakes completing during
transport closure send close-notify without admitting a new HTTP endpoint.
Blocked connections are aborted at the original deadline; teardown never
starts a fresh TLS timeout. Plain HTTP uses the full application drain budget.
Native workers join before their reactor resources are freed.

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

## Signals

SIGINT and SIGTERM both start the graceful drain described above, so
orchestrators that send SIGTERM (Kubernetes, systemd) drain instead of
killing in-flight requests. SIGHUP never terminates the server. It runs
`ReactorServerConfig.onReload` on worker 0's loop. The TLS server uses it to
request a certificate reload, so a SIGHUP republishes the certificates, keys,
OCSP responses and client CA, with or without `--reload-certs-ms`.
Applications can use the hook to swap routing tables or rate limits held in
thread-safe references. It must not block. Windows has no SIGHUP; use
`--reload-certs-ms` or `Bundle.requestReload` there.

## Descriptor exhaustion

When `accept` fails with `EMFILE`, `ENFILE`, `ENOBUFS` or `ENOMEM`, the
listener pauses for 100 ms instead of failing the worker. Queued
connections wait in the kernel backlog. Size `ulimit -n` to cover
`--max-clients` plus listeners, static files and the log helper.

## Health, admin and process metrics

`--health` serves `/healthz` (liveness, always 200) and `/readyz`
(readiness, 503 once draining starts) on the public listener. Like
`/metrics`, these bypass application callbacks and are excluded from
request metrics and access logs. `--admin-port PORT` binds a separate
loopback-only listener on a dedicated control thread. It serves `/stats`
(JSON: workers, uptime, draining, resident memory, open descriptors,
connection and request totals), `/metrics`, `/healthz` and `/readyz`. Both
metrics endpoints include `lean_net_process_resident_memory_bytes`,
`lean_net_process_open_fds` and, on TLS, `lean_net_tls_handshakes_total`,
`lean_net_tls_resumed_handshakes_total` and
`lean_net_tls_client_certificates_total`.

## Security headers

Application responses without these headers get secure defaults:
`x-content-type-options: nosniff`, `x-frame-options: SAMEORIGIN`,
`content-security-policy: default-src 'self'; frame-ancestors 'self';
object-src 'none'; base-uri 'self'` and
`referrer-policy: strict-origin-when-cross-origin`. TLS responses also get
`strict-transport-security: max-age=31536000; includeSubDomains`. An
application-supplied header always wins. Configure
`ReactorServerConfig.securityHeaders` or disable the defaults with
`--no-security-headers`.

## Tracing and access-log fields

Every application request carries a W3C `traceparent`. A valid incoming
value is kept. Otherwise a new trace is generated and injected into the
request headers, so handlers can forward it to downstream calls
(`ReactorServerConfig.tracing`). Access records add `timestamp` (RFC 3339
UTC), `remote_ip`, `path` (sanitized, no query), `duration_ms` and
`trace_id` to the existing fields.

## Mutual TLS and OCSP stapling

`--client-ca PEM` asks clients for a certificate and verifies it against the
bundle. Add `--require-client-cert` to reject handshakes without one. The
verified identity reaches handlers as `Request.clientCertificate`, with an
RFC 2253 `subject` and typed `subjectAltNames` such as
`URI:spiffe://...`. Unverified or absent certificates leave it `none`.
The entries remain separate, including URI values containing commas. The
verified subject and supported SAN text have a 64 KiB combined limit and at
most 256 SAN entries. A certificate whose identity cannot be represented
within these limits fails the handshake; applications never receive a
truncated name. Authorize on the typed SAN entries, with an explicit policy
for which types and trust anchors are accepted.
`--websocket-origin ORIGIN` enables the demo `/ws` echo endpoint for exactly
that Origin over HTTP/1.1 Upgrade and HTTP/2 extended CONNECT. Applications
register their own WebSocket callbacks through `HTTP1.Handlers` and must choose
their own Origin and authentication policy. Messages and frames have bounded
input/output budgets; extension compression is not negotiated.
`--ocsp-response DER` staples a pre-fetched OCSP response. It must be
successful, GOOD and currently valid for the leaf, or startup and reload
reject it. Refresh it by replacing the file and sending SIGHUP. TLS 1.2 is
limited to ECDHE with AES-GCM or ChaCha20-Poly1305. TLS 1.3 0-RTT stays
disabled because early data could be replayed.

## CPU pinning

`--pin-workers` pins worker *n* to the *n*-th CPU (modulo) of the process's
allowed set: `sched_setaffinity` on Linux, `SetThreadAffinityMask` on
Windows, affinity tags on macOS (unsupported on Apple silicon). Automatic
worker counts on Linux honour the cpuset, for example in containers.
