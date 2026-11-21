# Verification

Parts of lean-net carry machine-checked proofs. They use three methods:

1. **Proofs about production code.** The theorem sits in the module that
   defines the function the server runs, so `lake build` checks it on every
   build. Changing the function in a way that breaks the property fails the
   build.
2. **Proofs about a model, plus a differential test.** Native C code and
   effectful reactor code are modeled in `LeanNetSpec/`. The model's
   properties are proved there, and an executable compares the model with the
   real implementation on generated traces.
3. **Typestate.** A type the code cannot construct without performing the
   step a proof depends on.

`test/ProofAudit.lean` lists every theorem below and fails unless each exists
and depends only on Lean's standard axioms (`propext`, `Classical.choice`,
`Quot.sound`), so no listed theorem uses `sorry` or `native_decide`.

```bash
lake build LeanNet LeanNetSpec
lake env lean test/ProofAudit.lean
lake build lean-net-ratelimit-differential
.lake/build/bin/lean-net-ratelimit-differential
```

## Gate admission

`LeanNet/Gate/Core.lean` and `LeanNet/Gate/Policy.lean`. An `Admitted`
request can only be built by `Policy.admit`, and it carries these facts.

| Theorem | Property |
| --- | --- |
| `fieldOk_no_crlf`, `Admitted.no_crlf` | No admitted header value contains CR or LF |
| `Admitted.header_count_bounded` | The header count is within the policy limit |
| `Admitted.host_matches` | The selected virtual host has a pattern matching the authority |
| `Admitted.backend_serves` | A selected backend declares a host pattern matching the authority |

## Upstream response framing (RFC 9112 §6.3)

`LeanNet/HTTP1/ClientResponse.lean`. The gateway's response parser frames
every final head with `frameHead` (`scanFraming`, then `selectFraming` and
`framingViolation`) and reads chunk sizes with `parseChunkSize`. These are
the defences against an upstream that tries to desynchronize a pooled
connection.

| Theorem | Property |
| --- | --- |
| `frameHead_rejects_duplicate_contentLength` | Two Content-Length fields are rejected, even with equal values |
| `frameHead_rejects_transferEncoding_with_contentLength` | Transfer-Encoding together with Content-Length is rejected |
| `frameHead_rejects_transferEncoding_http10` | An HTTP/1.0 response with Transfer-Encoding is rejected |
| `frameHead_rejects_framed_bodyless_status` | A 1xx or 204 head declaring a length is rejected |
| `frameHead_bodyless` | Responses to HEAD, and 1xx, 204 and 304 responses, read no body |
| `frameHead_tunnel` | After 101 or a successful CONNECT nothing is parsed as HTTP, and the socket is not reusable |
| `frameHead_reusable` | A reusable connection is never close-delimited, never a tunnel, and had no `Connection: close` |
| `frameHead_contentLength_bounded` | A declared length never exceeds the body limit |
| `parseChunkSize_bounded` | A chunk size never exceeds the remaining body budget |

## Upstream request forwarding

`LeanNet/Gateway/Wire.lean`. `encodeRequest` writes the route's Host, then
the client fields returned by `forwardedFields`, then the forwarding and
framing fields it builds itself.

| Theorem | Property |
| --- | --- |
| `forwardedFields_safe` | Every forwarded field is one of the client's fields, valid, not hop-by-hop, framing, Host or identity metadata, and not nominated by the client's Connection field |
| `forwardedFields_drops` | No client field named Host, Content-Length, Transfer-Encoding, Connection, TE, Upgrade, Expect, Forwarded, X-Forwarded-For/Host/Proto, X-Real-IP, Client-Cert and others in `neverForwarded` (any case) reaches the upstream |
| `forwardedFields_no_crlf` | No forwarded value contains CR or LF |

## Streamed HTTP/1 responses

`LeanNet/HTTP1/Machine.lean`. A streamed response commits its head before the
body exists. Writing more or fewer bytes than its Content-Length would let
the client read the surplus as a second response.

| Theorem | Property |
| --- | --- |
| `State.new_within`, `State.beginStream_within`, `State.streamChunk_within` | The committed body never exceeds the declared Content-Length or `maxStreamResponseBytes`; an overrunning slice aborts the connection |
| `State.endStream_rejects_mismatch` | Ending a Content-Length stream with a different byte count aborts the connection |

Only the stream operations assign the two fields that the invariant covers.

## Rate limiting

`LeanNetSpec/RateLimit.lean` models the GCRA limiter in `c/ratelimit.h`.
`test/RateLimitDifferential.lean` runs 80,000 generated acquires through the
C limiter and the model and requires identical admissions and retry delays.
The rules cover a leased global bucket, a one-cell lease, keyed and
per-route buckets, and three workers.

| Theorem | Property |
| --- | --- |
| `admitted_window`, `admitted_window_div`, `admitted_window_burst` | From any history, a bucket admits at most `burst + ⌊w / T⌋` cells in any window of length `w` |
| `reserve_of_drained`, `admitted_paced` | A drained bucket admits a full burst, and traffic paced at the rate is never refused |
| `retry_admits`, `retry_exact` | The `Retry-After` delay is exactly when the next cell becomes admissible |
| `keyed_stricter` | The keyed table's 100 µs quantization never loosens a rule |
| `leaseStep_one` | With a one-cell lease an unkeyed bucket is exact GCRA |
| `leases_exceed_burst` | A three-worker trace admits 11 cells in one instant under burst 10 |

The window bound covers keyed rules and global or route rules whose lease is
one cell. Faster global and route rules lease up to 64 cells per worker, and
`leases_exceed_burst` shows that a short window can then exceed the burst.
The differential test replays that trace against the C code.

## Upstream connection lifecycle

`LeanNetSpec/UpstreamLifecycle.lean` models one upstream socket, including
the reactor read interest that the engine disables while a streamed response
waits for downstream credit. `Gateway.Pool` enforces the verified transition
with a `ReadArmed` token: idle phases require one, and only the helpers that
re-enable reads create it.

| Theorem | Property |
| --- | --- |
| `fixed_preserves`, `fixed_run_healthy` | Idle sockets and unpaused busy sockets always read |
| `buggy_reaches_stuck`, `stuck_until_timeout` | The previous transition leaves an idle socket unable to read, and its next request can only time out |
| `fixed_trace_reads` | The same trace is harmless with the fix |

## Findings

- **Pooled upstream sockets could stay read-disabled.** A streamed response
  that finished from input held during a pause returned its socket to the
  pool with reads off, and the next request on it timed out with 504. The
  fix is in `Pool.finishResponse`; `test/GatewayEngineTest.lean` reproduces
  the trace, `UpstreamLifecycle` proves the corrected transition sufficient,
  and `ReadArmed` makes the old transition impossible to write.
- **The rate limiter's documented guarantee was too strong.** The comments
  said admissions never exceed a rule's burst. That holds for keyed and
  one-cell-lease buckets (`admitted_window`). Leased buckets can exceed the
  burst within one lease lifetime (`leases_exceed_burst`, reproduced against
  the C code). The documentation in `c/ratelimit.h`,
  `LeanNet/Gate/RateLimiter.lean` and [gateway](gateway.md) now states the
  proved bounds; behavior is unchanged.

## What is not covered

- The Lean kernel, compiler and runtime, the C reactor, OpenSSL and the
  operating system are trusted.
- A model proves properties of the model. The differential test checks the C
  limiter against it on generated traces, which is evidence, not proof.
- Byte-level serialization (`encodeRequest`'s final byte layout), the HTTP/2
  machine, HPACK and the reactor driver carry tests but no proofs yet.
