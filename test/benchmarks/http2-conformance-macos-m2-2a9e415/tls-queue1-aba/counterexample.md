# Deterministic queue-one TLS wake counterexample

The red/green log files contain the exact combined outputs captured in the completed tool calls, transcribed here afterward. No test was rerun to create these files.

The pre-fix production source is retained as `tls_worker-before.c`. The final source, fixture, and harness snapshots are adjacent; manifest.json records hashes and exact commands. The first-draft red fixture used the same injection and assertion, before changing its producer notifications to the new per-session helper and adding the partial-record/unrelated-wake checks.

1. Complete a real TLS handshake with client memory BIOs and a one-cell worker lane.
2. Force `SSL_read_ex` to return WANT_READ on the otherwise quiescent connection.
3. Interpose after `SSL_get_error` classified that result. Publish the first byte of an actual encrypted application record into cipher_in and consume it into the server BIO.
4. Publish the rest of that encrypted record. The lane's two-position cursor wraps back to the head value captured at drive entry, but the lane still contains ciphertext.
5. The original drive returns with no local input/output progress and `more=0`. Its next invocation compares equal head snapshots and never processes the queued record.
6. The regression requires that next drive to consume the pending ciphertext and emit the exact original binary plaintext. Before the fix it fails with: `TLS worker native: notification drives queued ciphertext after queue1 cursor ABA`.

The fixed fixture also wraps the notification counter across UINT32_MAX, leaves a real partial TLS record pending and verifies 100 idle drives perform no further SSL calls, and verifies an engine-only wake for another session causes no SSL retry. Existing threaded queue capacities 1 and 3, binary echo, wire fences, retained views, abort classification and failed-join ownership checks remain in the same passing sanitizer run.
