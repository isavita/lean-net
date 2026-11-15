# Observability resource and error contracts

`LeanNet.HTTP.Observability` is optional. A metrics-only Hub starts no process
and allocates no log queues. Bracket a Hub outside every worker lifetime;
each worker exclusively owns one Lane and its Counters value. Publish counters
cold. Snapshots aggregate fixed numeric slots with saturating arithmetic and
coherent per-worker publication. Labels are fixed protocol, method class and
status class values, never arbitrary paths. The histogram includes a cumulative
`+Inf` bucket equal to its count. The driver excludes the metrics route itself.

Request counts, completion/status/latency metrics and access records exclude
the metrics route. Successful completion includes status 101 upgrades and
2xx/3xx responses; completed error statuses and error/timeout outcomes count as
request errors. Cancellation/shutdown outcomes have their own counter.
`lean_net_request_bytes_total` and
`lean_net_response_bytes_total` instead count all plaintext transport traffic,
including HTTP framing, control frames, raw upgraded traffic and metrics
scrapes. Response bytes are credited only for fully completed native write
operations; an aborted partially written operation contributes no bytes.
For TLS these are plaintext bytes, not encrypted record sizes. Access-record
`bytes_sent` has a different meaning: completed application-body payload only,
excluding response headers, chunk framing, trailers and HTTP/2 frame headers.
HEAD, 204 and 304 therefore have zero access-record payload bytes. A canceled
response can contain the payload of earlier fully completed writes.

Access logging uses one native helper process and one bounded SPSC lane per
worker. Emit copies at most 32 method bytes and 256 target bytes and does no
allocation, formatting, clock lookup, file I/O or wake syscall in native producer
code. Full queues reject records and increment
`lean_net_access_log_dropped_total`. JSON formatting and all log file operations
run in the helper. Records contain no request headers; query strings and
fragments are removed, non-origin targets are replaced to avoid logging URI
userinfo, and truncation/redaction flags are explicit. Arbitrary non-ASCII or
control octets use byte-preserving JSON `\u00NN` escapes.

The helper path is explicit in library AccessConfig; CLI integration resolves
its installed sibling executable. Its startup handshake must complete before
serving. Missing helpers, invalid sinks and writer I/O failures surface as
errors. Capacity is a power of two up to 65536, workers are capped at 256, and
the entire mapping is capped at 64 MiB. The helper inherits only its mapping on
Windows. On POSIX it has a separate process group, an empty signal mask, and
closes unrelated descriptors using `/dev/fd` or `/proc/self/fd` (one view must
be available), preserving standard descriptors 0, 1, 2.

Regular logs append without truncating prior content. Rotation occurs between
complete records; managed paths are the active path and suffixes `.1` through
`.(fileCount-1)`. Startup fails with `EFBIG` if an existing managed regular
file exceeds maxFileBytes. Nonregular managed archives are rejected. These
checks preserve historical bytes while bounding this managed set; unrelated
paths and older suffixes outside the configured set are neither touched nor
claimed bounded. NUL, `/dev/null`, character devices and FIFOs never rotate.
FIFO would-block errors are visible writer failures, rather than reactor stalls.
The configured managed paths belong exclusively to this logger while it runs;
external writers or renames are outside this storage contract.

After producers join, shutdown requests a drain and polls for process exit.
At the configured deadline it terminates a stalled helper, then allows 100 ms
for reaping. The child owns an independent mapping, so releasing the parent
mapping cannot cause a use-after-free even during a blocked kernel write.
A killed but not yet reapable process reserves the single helper slot;
reopening logs returns `EBUSY` until it can be reaped. This bounds exceptional
orphan resources. Interrupted control operations are retried explicitly in Lean;
close slots clear before close and the same descriptor is never closed twice.

`lean_net_access_log_pending_records` is the approximate accepted-minus-written
gauge. A timed-out kernel write may still have an externally visible side effect;
the parent never edits the consumer cursor or invents a dropped-and-written
completion. Pending records and shutdown errors expose this distinction.

Run `python3 test/test_access_log.py` for actual helper/SPSC JSON, rotation,
append, capacity, FIFO/null, process-group SIGINT, interrupted writer, failed
startup/stop, inherited-descriptor and resource checks. POSIX runs ASan/UBSan.
`lake env lean --run test/ObservabilityMetricsTest.lean` checks the pure fixed
schema and Prometheus exposition. Windows runtime acceptance comes from CI;
cross-compilation alone is not runtime evidence.

Build `lean-net-observability-fixture`, the public plain/TLS CLIs and the log
helper, then run `python test/test_observability.py -v` with
`test/requirements-http2.txt` installed. Its 28 wire cases cover completed
ByteArray and resident-file output, HTTP/1 chunking/trailers/informational
responses, HEAD/204/304, actual fallback status, pipeline ordering, metric-route
exclusion, byte-level target privacy, four-worker aggregation, 1000 connection
cycles and process-group shutdown. Controlled HTTP/2 windows distinguish
handler return from completed output and check partial/canceled streams.
An accepted 101 upgrade counts as a successful request while subsequent raw
bytes remain transport traffic; a TCP reset after 100 Continue must produce
one reset counter and one terminal request record.
Six cases use verified TLS and the public static-file CLI. A separately compiled
test-only helper stalls after READY to force observable queue overflow without
slowing request progress. Production helpers do not read this test stall flag.
These bounded tests do not establish the separate 24-hour soak or throughput
acceptance gates.
