# Initial static-file candidate

Source `9f59986f8773b1e4193d717418eec4c7199013cf` passed the local macOS
checks below, but **was not accepted**: all three Linux CI jobs failed to link
Brotli because pkg-config suppressed the system multiarch library directory.
The follow-up selects explicit shared-library paths in both Lake packages.
Raw failed-job logs are retained under `ci/`.

Both macOS jobs and Windows TLS passed, including all static wire cases.
Windows Native separately failed its injected unsupported-disposition cleanup
process-handle assertion before directory enumeration. This resource failure
also prevents acceptance and is being investigated separately from linking.

- Static wire: 32 cases, verified TLS, four curl modes, two 1,000-cycle
  resource checks, compression, validators, ranges and file cancellation.
- HTTP/2: 48 wire cases and 147 strict h2spec cases on each transport, with
  zero failures, errors or skips. h2spec trusts the private test PKI with `-k`;
  separate wire clients verify its CA and hostname.
- Pure/native: 15 Lean suites and three ASan/UBSan runners.
- Regressions: 38 HTTP/1, 34 native TLS, 28 legacy TLS, 20 legacy HTTP/2,
  two native TLS sanitizer runners and two public push CLI cases.

The JSON manifests retain immutable executable identities and exact committed
runtime source hashes. These are short correctness/resource checks, not the
required 24-hour soak or a throughput measurement.
