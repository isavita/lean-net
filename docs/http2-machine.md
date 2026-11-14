# HTTP/2 machine

The native HTTP controller runs the pure `LeanNet.HTTP2.Machine` for both
prior-knowledge cleartext HTTP/2 and TLS connections negotiated with ALPN `h2`.
HTTP/1.1 Upgrade to h2c is not implemented. The machine owns protocol state,
not sockets or timers; the reactor driver owns transport I/O and executes the
application callbacks on its worker. Callbacks must not block. Each worker can
construct its own handlers with `LeanNet.HTTP.ReactorServer.serveFactory`;
TLS provides the corresponding transport-backed factory.

## Pure interface

`Machine.State.new` accepts `HTTP2.Connection.Config`. `Machine.step` takes an
`Input` and state and returns a `Step` containing the next state, the number of
input bytes consumed, and actions. `start` emits server SETTINGS; `bytes` takes
an input array, offset and length. The caller must preserve and resubmit any
unconsumed input. Actions are `write` (owned byte arrays), `request` (a complete
request and stream ID), or `drainClose`. Respond with the matching stream ID
using `respond`; `drain` schedules pending output. `clock`, `date`, `finish`,
and `goAway` supply time, the Date value, peer EOF, and shutdown respectively.
The reactor manages these calls for server applications.

The connection validates frames and HPACK, keeps independent stream and
connection flow-control windows, and scopes protocol errors to a stream or the
connection. Stream errors emit RST_STREAM; fatal connection errors emit GOAWAY.
Requests are delivered after their bodies have been collected, so the request
body and aggregate buffering limits matter even for applications that promptly
respond. Outbound DATA waits for both peer flow-control windows.

## Limits and scheduling

`HTTP.ReactorServerConfig.http2` is a `HTTP2.Connection.Config`. Its per-connection
defaults include:

| Limit | Default |
| --- | ---: |
| Concurrent streams | 128 |
| Incoming frame size | 16 KiB |
| Decoded header list / encoded header block | 64 KiB each |
| Header fields / CONTINUATION frames | 100 / 1,024 |
| Request body / buffered request bodies | 1 MiB / 8 MiB |
| Response body / queued response bodies | 8 MiB / 8 MiB |
| DATA per drain / output per batch | 64 KiB / 1 MiB |
| Pushes | 128, with push disabled by default |

Other limits include the initial stream window, frame and request work per
step, and reset history. `Config.validate` checks compatible ranges; machine
startup validates the configuration. The outer reactor has independent input,
output, worker and native buffer budgets. Peer SETTINGS also constrain the
server's outgoing frames, streams and windows.

RFC 9218 `Priority` fields and HTTP/2 PRIORITY_UPDATE frames select urgency
0–7 (default 3) and the incremental flag (default false). Malformed priority
values are ignored. The scheduler selects the lowest urgency among eligible
streams. At equal urgency, non-incremental output is sent serially; after a
64 KiB burst it yields a frame to an incremental peer, and incremental peers
take turns. Flow-controlled streams are ineligible until credit returns. Lower
urgencies do not receive a fairness guarantee while higher-priority streams
remain eligible. Legacy dependency-tree priorities are not used.

## Optional push and shutdown

Set `http2.enablePush := true` in the server configuration and supply
`HTTP1.Handlers.onPush` to propose `HTTP2.Push` values. Push is disabled by
default, and a peer's `SETTINGS_ENABLE_PUSH = 0` disables it even when the
server enables it. The handler hook proposes same-origin GET paths. The lower
level connection API also accepts validated, bodyless same-origin HEAD
promises on eligible parent streams. The machine limits proposals; an invalid
optional proposal does not fail the parent response. Push also respects
peer and configured stream limits. The demo binaries expose this through
`--enable-push`: a request for `/` may promise `/pushed.txt`.

On shutdown the driver stops admission, sends GOAWAY and continues servicing
accepted streams, including window updates, until they drain or the configured
`shutdownDrainMs` deadline (default 2,000 ms) expires. TLS then performs its
separately bounded transport shutdown. A peer EOF cancels incomplete requests;
completed requests and queued responses may drain. A deadline is a bound, not
a guarantee that a blocked client receives all pending data.

A peer's GOAWAY stops new pushes and puts request admission into draining
mode. It does not by itself close the transport: existing streams and control
frames such as PING can still progress until peer EOF, local shutdown or the
idle deadline. This avoids resetting a valid control frame arriving just after
GOAWAY.

## Validation

The pure tests include `test/HTTP2FrameV2Test.lean`, `test/PriorityTest.lean`,
`test/HTTP2ConnectionV2Test.lean` and `test/HTTP2MachineTest.lean`. The wire
tests use the independent pinned HPACK dependency in
`test/requirements-http2.txt`; `test/test_http2_reactor.py` exercises protocol
behavior on the native reactor and verified TLS, and `test/test_http2_cli.py`
checks the public executables' push flag over both transports. Build the native
fixtures and executables before running these tests. Phase 4 acceptance remains
pending its gates; phase 5 static files and phase 6 production hardening remain
open. See the [acceptance ledger](production-roadmap.md) for the full gates.
