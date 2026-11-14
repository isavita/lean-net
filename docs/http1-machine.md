# HTTP/1 protocol machine and reactor adapter

`LeanNet.HTTP1.Machine.step input state` returns the next pure state, a consumed
byte count, and a list of actions. It never performs IO. `Parser.feedSlice`
scans a bounded ByteArray range; complete lines are parsed in place, split
lines are retained as owned bytes, and bodies use bounded bulk-copy blocks.
The driver owns unread pipeline slices and releases their receive leases as
soon as they are consumed. The parser does not retain native receive storage.

Every request pauses after its head. The handler can accept its inferred
framing, reject it with a final response, or accept an explicit protocol
upgrade. HTTP/1.1 expectations are decided before body consumption. A successful
100 Continue waits for actual write completion before the body resumes; refusal
does not send 100. Unsupported expectations produce 417. Ordinary HTTP/1.0
requests without CL/TE are bodyless. The requested legacy EOF-body behavior is
available by explicitly choosing `.closeDelimited` for a body-intended HTTP/1.0
request in `onHeaders`; it cannot override CL/TE and always forces closure.

The pure encoder returns separate header/body/trailer byte arrays. It supports
length, HTTP/1.1 chunked, and close framing; HEAD representation lengths;
informational responses; custom reasons; and the stricter required omission of
both body and Content-Length on 204/304. A `Reply` carries encoding options and
optional informational responses without changing the original `Response.mk`
API used by existing applications and HTTP/2.

`LeanNet.HTTP.ReactorServer.serveFactory` creates handlers inside each dedicated
worker. Each owns its connection map, protocol state, Date cache, input leases
and output credits. The server-wide client limit is partitioned exactly.
Compatibility `HTTP1.serveWithConfig` uses one worker so existing callbacks can
retain their original mutable-state ownership. `HTTP1.serve` and `HTTP2.serve`
use the independent default-router factory and choose the active core count.

Reserved output leases remain available when input is retained at an
application or write barrier. Startup requires at least one output credit per
admitted client plus a receive credit. Per-connection flight quotas prevent a
blocked reader from taking the entire output pool. Native writev/scatter-gather
writes coalesce queued segments while preserving each logical completion.
Linux uses sendmsg with MSG_NOSIGNAL for equivalent vector writes and SIGPIPE
suppression. Partial writes and cancellation keep every referenced buffer alive.

Final responses advance the HTTP machine once all their parts enter the ordered
transport FIFO. Continue and upgrade barriers advance only after their last write
completes. The driver checks historical completion liveness, releases orphaned
read leases, and ignores obsolete timer records after rearming. Request and
write deadlines remain absolute; timers are not extended by trickle progress.

An accepted 101 switches to `RawPipe` on the same reactor-owned socket after
the handshake drains. Its `onBytes` receives a `ByteSlice`; its output can reuse
that immutable view. Unread tail bytes and a previously observed EOF are passed
to the new owner exactly once. `onClose` runs when that connection is released.

Cleartext h2c currently reuses the existing pure `HTTP2.Connection` through the
new reactor adapter, preserving existing behavior. Its full RFC 9113/9218,
priority, push and h2spec work remains phase four. The native TLS provider shares
this controller, selects HTTP/1 or HTTP/2 from ALPN, and acknowledges plaintext
writes after their encrypted wire fences. Its permanently reserved plaintext
buffer returns credit through an explicit consumption callback; ciphertext
output, HTTP output, and native wire receive have independent credits. The
older `serveWithTransport` scheduler remains an explicit compatibility API;
public TLS server entry points use the native provider.

Run the pure suites and real transport fixtures with:

```sh
lake build lean-net-http1-reactor-fixture lean-net-reactor-native-test
lake env lean --run test/HTTP1ParserV2Test.lean
lake env lean --run test/HTTP1EncodingTest.lean
lake env lean --run test/HTTP1MachineTest.lean
python3 test/test_http1_reactor.py -v
```

On Windows use `lake env python` for Python fixtures. The native matrix includes
the pure suites, real one/four-worker HTTP flows, IOCP vectors/read pause,
buffer ownership, bounded queues and teardown tests.
