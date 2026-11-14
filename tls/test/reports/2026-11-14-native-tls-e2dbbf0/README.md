# Accepted native TLS evidence — 2026-11-14

The accepted source passed native reactor and native TLS CI on Linux, macOS,
and Windows. The final immutable macOS fixture passed **34 cases with 1,000
successful connection cycles plus 100 malformed/reset peers** in **11.001 s**.
Both complete testssl scans reported **A+**, score **93**, with tool exit zero.

| Evidence | Result |
| --- | --- |
| [Native reactor CI](https://github.com/isavita/lean-net/actions/runs/43625971883) | All three OS jobs passed |
| [Native TLS CI](https://github.com/isavita/lean-net/actions/runs/43625971927) | All three OS jobs passed |
| [Full regression CI](https://github.com/isavita/lean-net/actions/runs/43625971933) | Passed |
| [Final local TLS log](acceptance.log) | 34 passed; includes immediate handshake shutdown, raw-view backpressure, unique-block queue1/queue3 pipelines, SNI, resumption and strict binary bodies |
| [Worker diagnostics](worker-diagnostics.json) | Four real owners; one active TLS thread each; zero recorded SSL owner violations |
| [POSIX sanitizer log](validation/posix-asan.log) | ASan/UBSan fixture passed, 3.824 s |
| [TLS worker sanitizer log](validation/tls-worker-asan.log) | Queue/fence/lifetime fixture passed, 3.776 s |
| [TLS context sanitizer log](validation/tls-context-asan.log) | Borrowed ownership/policy fixture passed, 3.662 s |
| [State-check receipt](validation/receipt.json) | Phantom-state compile exit 0; silent compiler log retained |
| [Local HTTP log](validation/mac-http37.log) | 37 passed, 3.140 s |
| [Independent local TLS log](validation/mac-tls34.log) | 34/1,000 passed, 11.420 s |
| [alpha.test scan](testssl/alpha.test.json) / [log](testssl/alpha.test.log) | A+, 93, full scan 150 s |
| [beta.test scan](testssl/beta.test.json) / [log](testssl/beta.test.log) | A+, 93, full scan 159 s |

[ci.json](ci.json) independently records the completed successful workflow/job
results and verifies their exact head SHA. [acceptance.json](acceptance.json)
contains commands, environment, source hashes, linked libraries, and binary
provenance. Source was clean when the final acceptance run started:

```text
source: e2dbbf08b5057e8c24af2e7bc0a5d73f0cd3221f
fixture SHA-256: 26c01df14c714947c1bfa96da4d5f820110877e52c7946a86b77b4ee6c183cfd
```

The executable links versioned `libssl.3`/`libcrypto.3`; the installed library
is OpenSSL 3.6.3. Runtime and compile checks exercise actual native backends.
The sanitizer receipt records root-run
exit codes and unchanged logs, with reproduction commands. The CI source also
contains the actual native Lean pool/timer/generation and typed-wire tests.

The scanner is official testssl.sh v3.2.5 at peeled commit
`4f17be931a9d60f3f987975aea8221f1a8eaf7aa`. Both scans are full default runs,
including vulnerabilities and rating, with explicit SNI/IP and `--add-ca` for
an ephemeral private root. Its experimental SSL Labs-specification rating is
the tool's actual result, not a hosted Qualys assessment. The scanned fixture's
`/` handler adds HSTS; the public CLI default route without that header was not
independently graded here.

The grade does not mean an absence of findings. Full raw JSON/logs remain
available, and [nonblocking-findings.json](nonblocking-findings.json) separately
lists all 12 LOW/MEDIUM findings per host: offered obsolete CBC suites and the
tool's heuristic potential-LUCKY13 warning, a short deterministic test-certificate
serial, and absent optional application security headers. The CBC heuristic is
not a confirmed side-channel exploit result.

[testssl/summary.json](testssl/summary.json) additionally retains two exact scoped
findings without changing their original severity:

- `scanner_limitations`: optional GOST engine unavailable in the scanner client
  (`engine_problem`, WARN).
- `fixture_certificate_limitations`: the generated private-PKI leaf has no CRL
  or OCSP URI (`cert_revocation`, HIGH). Public deployment and revocation
  coverage are not established by this fixture.

These are narrowly classified findings, not blanket warning exceptions. Missing
or incomplete ratings, scanProblem/FATAL results, tool failure, unclassified
HIGH/CRITICAL findings, or a grade below A fail the harness. Retained certificates
are public CA/leaf chains only; private keys were temporary and were not copied
to the report. System trust and hosts files were unchanged.

Earlier intermediate reports are archived outside the repository. This single
report set represents the CI-accepted native receive-budget and TLS shutdown
fixes. Throughput, full HTTP/2 conformance/priority/push behavior, public
certificate deployment, and the final 24-hour soak remain separate gates.
