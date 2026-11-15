# Production-hardening validation

These tools are test artifacts. They do not establish the 24-hour requirement
until an actual full run finishes and its report says `passed: true`.

## Pure protocol fuzzing

The driver covers HTTP/1 parser and machine, HTTP/2 frame parser and machine,
and HPACK/Huffman decoding. Every case combines valid generated binary requests,
arbitrary bytes, byte mutations, truncation/insertion, sentinel-wrapped slices,
and randomized fragments. Fixed adversarial cases exercise framing conflicts,
header/body/frame/HPACK limits and overlong integers.

Properties include byte-consumption conservation, exact first-request boundary,
head/body decision barriers, unique monotonic request/output identifiers,
fragmentation equivalence, body limits, exact per-stream response DATA,
HPACK encode/decode table/field conservation and binary Huffman roundtrips.
Incoming frames are compared by parsed fields; outgoing encoder policy is not
used as an oracle for arbitrary peer padding.

The build coordinator supplies `lean-net-protocol-fuzz` (root `test.ProtocolFuzz`).
The wrapper uses that compiled binary by default and never builds. Override it
with `--binary` or `LEAN_NET_FUZZ_BIN`; the slow interpreter fallback requires
explicit `--interpret`.

Short CI profile (500 independent case seeds; no Lake build):

```sh
python3 test/fuzz_protocols.py --profile short --output /tmp/fuzz-short-UNIQUE
```

Explicit long profile (100,000 cases, 16KiB maximum input, two-hour deadline):

```sh
python3 test/fuzz_protocols.py --profile long --output /tmp/fuzz-long-UNIQUE
```

The wrapper bounds cases, bytes, algorithmic action/fragment steps, wall time
and log size. Linux additionally inherits a 2GiB per-process address-space
limit. Input/state caps apply on every platform; a runtime panic, allocation
failure, timeout, nonzero exit or missing final success marker fails the run.
It kills the process tree on failure. Each case flushes its independent seed
before execution. Caught failures print generated/mutated input hex. Logs and
JSON preserve the last case and a one-case replay command. Replaying a seed
also requires the recorded driver/source version and maximum input size.

The short profile passed 500 interpreted cases locally during implementation;
compiled final-source execution remains the next coordinator gate. This is not
exhaustive proof; the long profile and final-source CI remain separate gates.

## Actual 24-hour soak

The installed `h2load nghttp2/1.71.0 --help` was inspected before selecting the
workload: `--rate` creates connections, while `--rps` specifies requests per
second **per client**. Defaults are two loaders (plain h2c and TLS h2), each with
10 persistent connections and 510 RPS per connection: **10,200 offered aggregate
RPS**, with an unchanged **10,000 achieved-successful-RPS floor**.

The upstream [1.71.0 implementation](https://github.com/nghttp2/nghttp2/blob/v1.71.0/src/h2load.cc)
uses bounded reservoir sampling. The harness disables per-request log files
and raw-sample JSON dumps. Each loader emits only its normal bounded summary.
Access logs should target `{null}` during this performance observation; separate
real-file acceptance tests must establish structured-log content and lifetime.

Use the pinned independent decoder environment and a clean, frozen candidate:

```sh
/tmp/lean-net-tools/http2-python-4.2.0/bin/python test/soak24.py \
  --config test/soak24.example.json \
  --source-sha EXACT_FULL_FROZEN_COMMIT \
  --output /path/with/space/for/immutable-evidence
```

Root coordinates the actual launch after Phase 6 freezes. Do not launch it
against a moving implementation. Check the final CLI flags against the frozen
public binaries before using the example configuration.

The controller snapshots both server executables, both sibling native logger
helpers, h2load and a committed source
archive, records hashes/tool versions/commands, generates an isolated test PKI,
records helper hashes/source hashes, passes an explicit immutable `--log-helper`
path to each CLI, verifies the actual family image paths, and preserves server
logs, loader summaries, raw boundary metrics, and all
whole-process-family RSS/FD/counter samples. It never builds or overwrites an existing evidence
folder. Linux uses `/proc` FD counts; macOS uses numeric `lsof` descriptors;
Windows uses ToolHelp process-family discovery and native creation-time,
working-set and handle queries without external dependencies. Each sample
retains root/helper PIDs, parent IDs, creation identities, counts, RSS and
descriptors/handles. The gate sums RSS for the whole family, including the
log-writer helper; shared-map RSS is deliberately charged to both processes.
Child identity/count changes, zombies or census races fail. Every member must
keep its descriptors/handles flat, so a helper leak cannot hide behind a
parent descriptor release.
The actual acceptance host is the declared macOS M2 benchmark box.

A fixed clock guard checks at least once per controller-loop second. UTC versus
monotonic divergence above two seconds, or an observation gap above five
seconds on either clock, fails the run. This detects macOS suspend even when
monotonic time excludes sleep, and also detects SIGSTOP/scheduler stalls when
both clocks advance. Every resource sample records both clocks; the report
retains worst divergence/gaps. Rate uses the larger elapsed clock duration.
Clock correction/suspend failures require a fresh full run, not a paused timer.

Startup and 300-second warmup are separate from the common measured window.
Both loaders remain active beyond the measured end. Every five seconds,
persistent independent H2 sessions verify exact response bytes through warmup,
measurement and the loader tail; TLS probes use
CA verification, SNI and mandatory h2 ALPN. Persistent HTTP/1 metrics sessions
avoid creating transient FD noise. These keepalive probes require the frozen
server's idle deadline to exceed five seconds.

The four metrics selectors in the example are the stable Phase 6 contract.
The producer excludes `/metrics` from application counters. Body probes are
ordinary completed application requests and are counted separately, then
subtracted from measured completion deltas. Error, timeout or reset increases
fail immediately. Counter decreases or missing/noninteger samples fail.

Published metrics may be up to one second old. The harness records this
boundary uncertainty; it evaluates rate in 60-second intervals, then computes
a conservative full-window rate after subtracting two entire offered-rate
seconds plus the maximum outstanding load streams. The strict achieved floor
remains 10,000 RPS. A two-second publication guard while load continues catches
late-published errors/resets from the final measured second. Loader summaries
independently require every started request to succeed, all statuses to be
2xx, zero errors/timeouts, and exactly the expected aggregate body bytes.

Certificate reload and log rotation remain disabled during the strict soak;
separate 1,000-retirement and 100-wire-rotation tests establish reload lifetime
behavior without adding legitimate short-lived PEM descriptors to this census.
The example explicitly enables metrics and fixes eight workers/128 clients.

Every measured whole-family RSS sample must stay **strictly below 1% growth** from the
post-warmup baseline; numeric descriptors/handles may not exceed baseline.
Early exits, log overflow, rate shortfall, body mismatches and bounded-shutdown
failures produce failed reports. Successful server shutdown consumes GOAWAY
and TLS close_notify on the independent sessions before releasing them.

For orchestration only, `--smoke-seconds 60` is explicit and always records
`profile: smoke`, `smoke_completed`, and `passed: false`. It can never substitute
for an actual measured period of at least 86,400 seconds.

Pure controller accounting checks (no server or load):

```sh
python3 test/test_production_harness.py -v
```
