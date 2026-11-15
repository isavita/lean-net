# Gateway hardening verification

This records what the gate and gateway currently enforce and which checks
exercise each claim. It is a source and test review, not a production capacity
or 24-hour soak result.

| Check | Result and evidence |
| --- | --- |
| HTTP/2 early rejection | A complete HPACK block is decoded before the head gate decides. The assembly and exchange are removed before the terminal `HEADERS` (`END_STREAM`) and `RST_STREAM(NO_ERROR)` are queued. No physical write acknowledgment is awaited. Fragmented rejection, late peer reset, peer GOAWAY, and sibling drain are covered in `test/HTTP2HeadGateTest.lean`. |
| Reset flood | `HTTP2.Connection.Config` defaults to 256 peer and 256 locally generated resets per 1,000 ms per connection. Exceeding either budget queues `GOAWAY(ENHANCE_YOUR_CALM)`; accepted sibling streams remain serviceable. New post-GOAWAY header blocks are bounded, HPACK-decoded, and discarded without exchanges or further resets. Continued peer reset abuse closes the connection. `test/HTTP2ConnectionV2Test.lean` and `test/HTTP2HeadGateTest.lean` cover both directions and window expiry. |
| Graceful GOAWAY | Normal GOAWAY stops new requests while allowing accepted streams to finish. The reset-budget tests verify a sibling can respond and complete the drain. Continued over-budget peer resets are treated as abuse and can terminate that drain. |
| GCRA admission | Global and route leases are spent only after the shared TAT reservation CAS succeeds; unused reservations can lower throughput but cannot create extra tokens. `test/ratelimit_test.c` exercises eight contending lanes and sustained bounds under sanitizers. `test/GateTest.lean` verifies that one monotonic timestamp is read for a head with two rate rules and passed unchanged to both. The default clock is `IO.monoMsNow`. This is code review plus testing, not a formal theorem about the C implementation. |
| `Connection` fields | The HTTP/1.1 serializer parses every client `Connection` option, strips nominated hop fields, and replaces the client's `Connection` field. It rejects nominations of routing, forwarding identity, framing, or `Upgrade` fields. `test/GatewayWireTest.lean` covers `X-Forwarded-For`, `X-Real-IP`, `Host`, framing fields, and an unsupported upgrade. This follows [RFC 9110 §7.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1). |
| Proof erasure | `gate%` already compiles the policy at elaboration and constructs the serving proof through a decidable Boolean check. A bad host/backend pair now appears in the compile error. `test/test_gate_erasure.py` checks generated C for eight runtime fields and no slots for `Admitted`'s three `Prop` proofs, and checks that the header and backend theorems have no `sorryAx`. `Admission.Head` has no proof fields; `Admitted` and route selection remain heap objects. A Lean `#eval sizeof Admitted` would not measure this dynamic runtime representation. |
| Gate allocation | `test/bench_gate.py` records per-request `IO.getNumHeartbeats` small allocations and monotonic time. The [macOS ARM64 report](../test/benchmarks/gate-allocations-macos-4eeaa6b.json) measured 48 small allocations for host-only admission and 59 for a routed decision. The Linux CI run uploads its own report. Large allocations and GC pauses are outside this metric, so zero GC is not established. |
| Pre-TLS connection limit | The opt-in per-peer-IP keyed GCRA table is shared by Linux listener lanes or attached to the macOS/Windows acceptor. Excess completed TCP accepts close before worker handoff and TLS. `test/test_connection_rate.py`, `tls/test/test_tls_connection_rate.py`, and the native limiter tests cover the budget. SYN packets before TCP acceptance remain a kernel or load-balancer concern. |

The reset handling is guided by [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.html),
including its requirement to maintain header compression state after a stream
is reset. The budget specifically covers locally generated resets from invalid
heads as well as peer resets; [CVE-2019-9514](https://github.com/netflix/security-bulletins/blob/master/advisories/third-party/2019-002.md)
concerned peers that provoke repeated server resets.
