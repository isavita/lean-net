# Cooperative application streaming

`HTTP1.Reply.stream` owns an `HTTP.Stream.Body`. All callbacks run synchronously
on the reactor worker that created them. Producers must return promptly and
retain at most their declared `retainedBytes`. They never receive sockets,
transport endpoints or borrowed receive views.

`poll budget` returns pending, owned `data` (1..budget bytes), or `finish trailers`.
The server pulls at most one event per stream per turn, under output and HTTP/2
flow credits, and retains at most one 64KiB chunk. A zero budget allows only
pending/finish. Declare trailer names before headers. Optional knownLength is
checked against the exact emitted byte count. HEAD keeps GET length metadata
while suppressing/closing the producer. HTTP/1 chunks and pipelines stay ordered;
HTTP/2 streams complete independently. Idle and total lifetime deadlines cancel
stalled producers. `close none` is normal completion into the bounded output
queue (not remote acknowledgement); `close (some reason)` is terminal cancellation.
Close runs exactly once after removal, including errors, resets and disconnects.

Opt into incremental HTTP/2 uploads with `Handlers.streamRequests` at headers,
after early `onHeaders` checks. `Request.incoming` exposes an owned bounded
`IncomingBody`: poll returns data, finish with request trailers, or cancellation.
Receive-window credit is returned only as the application consumes/discards
bytes. Existing body/count/header/worker budgets still apply. Normal early
responses discard the remaining upload without resetting the response stream;
calling incoming.cancel explicitly resets the exchange. HTTP/1 request bodies
remain bounded buffered requests. Client/bidirectional streaming uses HTTP/2.
An admission policy with a `postBody` validator, including `LeanNet.Gate`,
uses the bounded buffered HTTP/2 request path instead. The validator sees the
complete body and trailers before any application handler or proxy dispatch.
Use a route without that post-body policy when early bidirectional upload
handling is required.

WebSocket `Callbacks.onPoll` supplies unsolicited server messages without an
inbound browser event, using the same bounded physical-write tickets.

`Handlers.onTick` runs at most once per worker turn, including idle/draining
periods. `onDrain deadline` runs once before HTTP drain begins; `isDrained` may
keep the bounded loop alive for application flush work. Application timestamps
and deadlines use **IO.monoMsNow** milliseconds. Native socket timers can have a
different epoch; the server translates the remaining shutdown budget at this
boundary. `onShutdown` runs after native transport cleanup. All hooks must be
nonblocking and use the one supplied deadline, without starting another timeout.

Validation: `lake build lean-net-stream-fixture` followed by
`python test/test_application_streams.py -v` (install test/requirements-http2.txt).
The real wire suite covers chunk timing, trailers, pipeline order, HEAD metadata,
HTTP/2 independent completion/window backpressure, two-way upload before END,
request trailers, early response discard, large bodies with small output budgets,
reset cleanup, idle deadlines, unsolicited WebSocket push on HTTP/1 and HTTP/2,
and idle/drain lifecycle hooks.
