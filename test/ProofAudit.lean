import Lean
import LeanNet
import LeanNetSpec

/-! Proof audit for docs/verification.md. Every listed theorem must exist and
depend only on Lean's standard axioms: no `sorry`, no `native_decide`
(`Lean.ofReduceBool`) and no project axioms. Elaborating this file is the
check; renaming or weakening a listed theorem fails it. -/

open Lean Elab Command

elab "#audit_proofs " ids:ident* : command => do
  let allowed := #[``propext, ``Classical.choice, ``Quot.sound]
  for id in ids do
    let name ← liftCoreM <| realizeGlobalConstNoOverloadWithInfo id
    let info ← getConstInfo name
    unless info matches .thmInfo _ do
      throwErrorAt id m!"{name} is not a theorem"
    for axiom_ in ← collectAxioms name do
      unless allowed.contains axiom_ do
        throwErrorAt id m!"{name} depends on {axiom_}"
  logInfo m!"{ids.size} theorems use only the standard axioms"

-- Gate: admitted requests (LeanNet/Gate/Core.lean, Policy.lean).
#audit_proofs
  LeanNet.Gate.valueByte_not_crlf
  LeanNet.Gate.fieldOk_no_crlf
  LeanNet.Gate.Admitted.no_crlf
  LeanNet.Gate.Admitted.header_count_bounded
  LeanNet.Gate.Admitted.host_matches
  LeanNet.Gate.Admitted.backend_serves

-- Upstream response framing (LeanNet/HTTP1/ClientResponse.lean).
#audit_proofs
  LeanNet.HTTP1.ClientResponse.frameHead_rejects_duplicate_contentLength
  LeanNet.HTTP1.ClientResponse.frameHead_rejects_transferEncoding_with_contentLength
  LeanNet.HTTP1.ClientResponse.frameHead_rejects_transferEncoding_http10
  LeanNet.HTTP1.ClientResponse.frameHead_rejects_framed_bodyless_status
  LeanNet.HTTP1.ClientResponse.frameHead_bodyless
  LeanNet.HTTP1.ClientResponse.frameHead_tunnel
  LeanNet.HTTP1.ClientResponse.frameHead_reusable
  LeanNet.HTTP1.ClientResponse.frameHead_contentLength_bounded
  LeanNet.HTTP1.ClientResponse.parseChunkSize_bounded

-- Upstream request forwarding (LeanNet/Gateway/Wire.lean).
#audit_proofs
  LeanNet.Gateway.forwardedFields_safe
  LeanNet.Gateway.forwardedFields_drops
  LeanNet.Gateway.forwardedFields_no_crlf

-- Streamed HTTP/1 responses (LeanNet/HTTP1/Machine.lean).
#audit_proofs
  LeanNet.HTTP1.Machine.State.new_within
  LeanNet.HTTP1.Machine.State.beginStream_within
  LeanNet.HTTP1.Machine.State.streamChunk_within
  LeanNet.HTTP1.Machine.State.endStream_rejects_mismatch

-- GCRA rate limiting model (LeanNetSpec/RateLimit.lean).
#audit_proofs
  LeanNetSpec.RateLimit.admitted_window
  LeanNetSpec.RateLimit.admitted_window_div
  LeanNetSpec.RateLimit.admitted_window_burst
  LeanNetSpec.RateLimit.reserve_of_drained
  LeanNetSpec.RateLimit.admitted_paced
  LeanNetSpec.RateLimit.retry_admits
  LeanNetSpec.RateLimit.retry_exact
  LeanNetSpec.RateLimit.keyed_stricter
  LeanNetSpec.RateLimit.leaseStep_one
  LeanNetSpec.RateLimit.leases_exceed_burst

-- Upstream connection lifecycle model (LeanNetSpec/UpstreamLifecycle.lean).
#audit_proofs
  LeanNetSpec.UpstreamLifecycle.fixed_preserves
  LeanNetSpec.UpstreamLifecycle.fixed_run_healthy
  LeanNetSpec.UpstreamLifecycle.buggy_reaches_stuck
  LeanNetSpec.UpstreamLifecycle.stuck_until_timeout
  LeanNetSpec.UpstreamLifecycle.fixed_trace_reads
