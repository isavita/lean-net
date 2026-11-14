# Static-file acceptance evidence

Source `5e7a99f5e4af07ccb13fb419fe550fb14c8a60f9` passes the full Linux
regression, Native matrix and TLS matrix on Linux, macOS and Windows. The
`ci/` directory retains every job/step conclusion and the successful Windows
native log. Final test-instrumentation follow-up
`cfa4e700f47ea1d52028add8ff7bdf16a1784549` also passes all seven CI jobs;
its separate records and identical strict Windows proof are retained under
`final-ci-cfa4e70/`. Phase 6 and its actual 24-hour soak remain open.

Windows security initialization creates seven non-File runtime handles once.
After warming precisely that API, **1,000 injected unsupported-disposition
startup failures hold the process at 64 handles**. Every cycle creates and
closes four owned file handles, for **4,000/4,000** total and zero open. The
separate 1,000 publication lifetimes and real IOCP file/cancellation tests also
pass. The SDK initialization and each strict post-initialization measurement
are recorded in `ci/windows-failure-lifetime-proof.json`.

The [artifact identity report](artifact-identity.json) verifies six freshly
built macOS executables against the exact binaries that passed the preserved
[32 static wire cases](../static-files-macos-m2-9f59986/static-wire/full.log),
[48 HTTP/2 wire cases and 147 strict h2spec cases per transport](../static-files-macos-m2-9f59986/http2-conformance/summary.json),
and [six-round throughput/RSS check](../static-files-macos-m2-7404295/README.md).
All runtime Lean/C implementation files are unchanged from that tested source;
subsequent changes fix Linux library selection and native test instrumentation.
The report covers every runtime source file, the current build configuration,
and exact binary SHA-256 identities. The independent FFI review also verified
all 21 new native entrypoints have matching Lean declarations.

The unchanged benchmark completes 600,000 successful requests, zero failures,
errors or timeouts, with eight-worker rounds of 290,476 / 302,097 / 284,045 RPS.
Both short RSS assessments pass (one worker +0.37547%, eight workers +0.22513%).
This establishes the declared regression gate; it is neither static-file
throughput characterization nor the final sustained-load acceptance.

Pure and native sanitizer results, legacy regressions and failed earlier CI
candidates remain in the sibling evidence directories. No failed result was
rescored or hidden. h2spec uses `-k` for private test PKI; separate Python/curl
clients verify its CA and hostnames.
