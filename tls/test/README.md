# Native TLS acceptance

The new fixture uses the public native HTTP transport and dedicated TLS workers.
The existing `test_tls.py` suite remains a regression suite for public TLS entry
points. These are correctness and resource tests, not throughput measurements.

Build and run from the repository root:

```sh
lake -d tls build lean-net-tls-reactor-fixture
python3 tls/test/test_tls_reactor.py -v
```

OpenSSL 3+, Python with TLS 1.3 support, and curl with HTTP/2 support are required.
On macOS, select the intended build dependency explicitly when needed:

```sh
PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@3/lib/pkgconfig \
  lake -d tls build lean-net-tls-reactor-fixture
```

`LEAN_NET_TEST_OPENSSL` and `LEAN_NET_TEST_CURL` select client executables.
`LEAN_NET_TLS_REACTOR_BIN` selects an alternate fixture. The default client
selection prefers versioned Homebrew OpenSSL 3 and HTTP/2-enabled Homebrew curl
when present. These client choices do not determine the server's linked OpenSSL
version; inspect the actual executable separately.

The suite creates a temporary root and intermediate CA plus distinct
`alpha.test`/`beta.test` leaves. Every ordinary client verifies its hostname and
chain; no system trust store or hosts file changes. The SNI tests also compare
leaf SHA-256 fingerprints. Cached sessions are tested separately with tickets
disabled, and TLS 1.2/1.3 tickets must resume on different actual workers. TLS 1.3
tickets are captured after application I/O, rather than inferred from a
successful initial handshake.

The default resource gate performs 1,000 successful connections plus malformed
and reset connections. `LEAN_NET_TLS_CYCLES=20` is available for a short diagnostic
run; such a run does not satisfy the 1,000-cycle gate. Native sanitizer/lifetime
fixtures provide additional ownership evidence; flat descriptor counts alone do
not prove absence of memory leaks. The final 24-hour soak remains separate.

Fixture CLI:

```text
lean-net-tls-reactor-fixture ALPHA_CHAIN ALPHA_KEY BETA_CHAIN BETA_KEY PORT MODE WORKERS
```

Modes are `normal`, `tiny`, `bad-budget`, `queue3`, `deadlines`, and `cache-only`. `tiny` uses one
worker, one HTTP output buffer, four native 4 KiB cells (HTTP output, TLS
ciphertext output, separate plaintext input, wire receive), and TLS queues of capacity one.
`bad-budget` has only three cells and must fail startup while releasing its endpoint. `queue3` exercises
non-power-of-two TLS queues. `deadlines` uses a 350 ms handshake deadline, 650 ms
request deadline, 2 s idle timeout, and 1.5 s write timeout. `cache-only` disables
tickets so successful resumption demonstrates the server session cache.

# Full testssl grade

Install the official pinned scanner outside the repository; no Homebrew or pip
changes are needed:

```sh
git clone --depth 1 --branch v3.2.5 \
  https://github.com/testssl/testssl.sh.git /tmp/lean-net-testssl-v3.2.5
python3 tls/test/run_testssl.py \
  --testssl /tmp/lean-net-testssl-v3.2.5 \
  --output /tmp/lean-net-testssl-report
```

The harness verifies peeled commit
`4f17be931a9d60f3f987975aea8221f1a8eaf7aa`, starts the real fixture, and performs
the full default scan for both SNI hosts. It never substitutes a reduced scan or
converts another tool's compliance result into a letter grade. Both completed
scans must report `A` or `A+`; missing ratings, `A-`, scanner errors, incomplete
JSON, or unclassified high/critical findings fail. Raw logs, full JSON, exact commands, source
status, executable/tool hashes, public test certificates, and assessment are
retained. An existing report directory is never overwritten.

Two exact findings have separate, explicit scope in `summary.json`: the pinned
client's optional missing GOST engine is retained as `scanner_limitations`, and
the generated private CA leaf's absent CRL/OCSP URI is retained (including its
HIGH severity) as `fixture_certificate_limitations`. These do not change the
tool's actual grade and do not establish public certificate revocation coverage.
No other warning or vulnerability is waived. `scanProblem`, FATAL, incomplete
scans, and tool failure exit codes always fail the harness.

The result is the pinned testssl tool's rating under its documented SSL Labs
rating implementation, with the ephemeral test CA explicitly added only to the
scanner's trust checks. It is not a hosted Qualys assessment or proof of public
certificate deployment. No private keys are copied to the report directory.
Full scans open many connections; run them only against an authorized fixture
and record their results separately from performance measurements.

Primary scanner documentation: [v3.2.5 manual](https://github.com/testssl/testssl.sh/blob/v3.2.5/doc/testssl.1.md).
