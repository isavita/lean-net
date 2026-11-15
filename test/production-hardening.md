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

The serial child explicitly uses `LEAN_NUM_THREADS=1`,
`LEAN_STACK_SIZE_KB=65536` and `LEAN_MAIN_USE_THREAD=0`, all recorded in its
report. It runs on its existing process thread. Linux sets that thread's lazy
stack soft limit to 64MiB only when the existing hard limit permits it, while
retaining the unchanged 2GiB address-space cap. Lean v4.35 defaults to a 1GiB
stack for a newly created runtime thread. Its generated module initialization
starts a libuv thread **before** `lean_run_main` reads those environment
variables. The compiled fuzz target therefore links `test/fuzz_runtime.c`
directly: its static constructor sets runtime thread stacks to 64MiB before
module initialization. Its source SHA-256 is recorded, and compiled mode
requires its `FUZZ_RUNTIME_INIT` marker before `FUZZ_START`. This object is
exclusive to the fuzz executable; servers and the shared native archive do
not link it. Explicit interpreter mode cannot use that static bootstrap and
is labelled ineligible for CI acceptance.

The task-manager constructor is lazy: earlier eager-pool and mandatory
allocator-overhead hypotheses were not established. Up to 32 bounded Linux startup samples record actual VA, RSS,
thread counts and largest mappings. A flushed `FUZZ_START` distinguishes
startup from the fixed adversarial prelude before the first `FUZZ_CASE`.
These settings change no cases or protocol limits. See the pinned runtime
[task-pool source](https://raw.githubusercontent.com/leanprover/lean4/v4.35.0/src/runtime/object.cpp)
and [thread/stack source](https://raw.githubusercontent.com/leanprover/lean4/v4.35.0/src/runtime/thread.cpp),
plus [module initialization](https://raw.githubusercontent.com/leanprover/lean4/v4.35.0/src/runtime/init_module.cpp)
and [early libuv thread creation](https://raw.githubusercontent.com/leanprover/lean4/v4.35.0/src/runtime/libuv.cpp).

Each report records the exact source, binary, seed, limits and runtime settings.
Short CI runs and the long profile remain separate evidence; neither proves
exhaustive parser correctness.

## HTTP/2 active keepalive

The public plain and TLS CLIs accept `--http2-ping-ms` and
`--http2-ping-timeout-ms`; the interval is default-off and the enabled timeout
defaults to 10000 milliseconds. The [production guide](../docs/production-hardening.md#active-http2-keepalive)
describes the library configuration and failure policy.

`HTTP2KeepaliveTest.lean` exercises the pure machine with a 100-millisecond
interval and 30-millisecond ACK timeout. It checks protocol-readiness gating,
one queued/in-flight nonce, physical-write deadline arming, early/fragmented
ACKs, stale/duplicate ACK and write-notification rejection, activity-independent
scheduling, timeout GOAWAY/request outcomes, default-off behavior, GOAWAY/EOF
cancellation, bounded timer arithmetic and intact header/file frame ordering.
The native driver supplies a timer-wheel slot; the pure machine performs no IO.

The independent `test_http2_keepalive.py` suite uses the public plain and TLS
servers with an 80-millisecond interval and 500-millisecond timeout. It checks
progress during application traffic, unanswered/wrong ACK isolation, incomplete
upload timeout accounting, HTTP/1 separation and clean process shutdown.
`KeepaliveTransportFixture.lean` delays only PING completion notifications by
800 milliseconds while bytes reach the peer immediately; its 100-millisecond
interval and 150-millisecond timeout exercise ACK-before-completion and late
old completion ordering. All peer operations have bounded time/frame budgets.

After the build coordinator provides the required public binaries, sibling log
helpers and `lean-net-keepalive-transport-fixture`, run:

```sh
lake env lean --run test/HTTP2KeepaliveTest.lean
python3 test/test_http2_keepalive.py -v
```

The wire harness accepts the observability binary/helper environment overrides
and `LEAN_NET_KEEPALIVE_TRANSPORT_BIN` for immutable snapshots. These focused
tests do not establish full-duration soak acceptance.

## Actual 24-hour soak

The installed `h2load nghttp2/1.71.0 --help` was inspected before selecting the
workload: `--rate` creates connections, while `--rps` specifies requests per
second **per client**. Defaults are two loaders (plain h2c and TLS h2), each with
10 persistent connections and 510 RPS per connection: **10,200 offered aggregate
RPS**, with an unchanged **10,000 achieved-successful-RPS floor**.

Each loader uses finite count mode: `-n` is
`ceil(warmup + measured duration + tail + 10) * connections * RPS per client`,
or **442,374,000 requests per server** for the default full profile. The report
records this exact plan and command. Rate control stays `--rps=510`; after the
measured window, all planned requests must finish naturally. Duration mode
`-D` is excluded because it can cancel active streams at its cutoff. Summary
validation requires `total == started == done == succeeded == planned` with
zero failed/errored/timed-out requests; canceled requests receive no tolerance.

The bounded completion phase allows pacing asymmetry without changing the
24-hour measured window or its 10,000 RPS floor. For each loader, the minimum
feasible rate is `10,000 - sum(other loaders' offered RPS)`, which must be
positive. Its deadline from common load start is `planned requests / minimum
feasible rate + 30 seconds`; the controller uses the maximum of those bounds.
The symmetric default gives 4,900 RPS, a 90,310.408-second deadline and at most
3,570.408 seconds beyond nominal pacing. The report records the formula,
rates, nominal spans and extra allowances. Persistent probes, clock-gap checks
and log-health checks continue while loaders drain. All measured resource,
reset, throughput and exact-summary gates remain unchanged.

The upstream [1.71.0 implementation](https://github.com/nghttp2/nghttp2/blob/v1.71.0/src/h2load.cc#L1560-L1608)
reserves at most `min(request count, max samples)` in count mode; its shared
[reservoir sampler](https://github.com/nghttp2/nghttp2/blob/v1.71.0/src/h2load.cc#L1674-L1692)
caps request statistics at 1,000,000 samples for the single loader thread.
The [request counters](https://github.com/nghttp2/nghttp2/blob/v1.71.0/src/h2load.h#L250-L269)
use `size_t`; the default planned count fits even 32 bits, and the controller
rejects plans beyond unsigned 64-bit range. No per-request array proportional
to the 442 million requests is allocated. The harness disables per-request log files
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
helpers, h2load and a committed runtime/source/controller archive, records
hashes/tool versions/commands, generates an isolated test PKI,
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

The strict configuration also explicitly enables active server PINGs on both
CLIs: `--http2-ping-ms 10000 --http2-ping-timeout-ms 10000` in the committed
example. The controller rejects missing/duplicate flags, intervals outside
1–10000 milliseconds or ACK timeouts outside 10000–3600000 milliseconds.
Those bounds allow the independent peers, serviced every five seconds, to
acknowledge probes during application load.

Each persistent independent H2 peer counts server PINGs received and ACKs
successfully sent, recorded as `keepalive.received` and
`keepalive.acknowledged` in every per-server resource sample. Both counters
must already be positive and equal at the post-warmup baseline, remain equal
and never decrease. Each assessed interval of at least 30 seconds requires
both to increase; shorter intervals, including the two-second publication
guard, require equality and monotonicity without demanding a new probe.
These are probe-side counters, not new Prometheus metrics. They prove actual
active PING/ACK progress on the independent plain and verified-TLS sessions;
ordinary response probes or merely passing CLI flags cannot substitute.
`test_production_harness.py` includes missing-option, invalid-timing, missing-ACK,
stalled-progress and short-guard accounting cases without starting a server.

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

Every metrics scrape also reads the five fixed access-log health fields:
accepted, written, dropped, I/O errors and pending records. Drops and I/O errors
must be zero, including at the baseline; cumulative counters cannot decrease.
Transient pending records are allowed within the native queue bounds and are
recorded in every resource sample. The harness does not assert
`written == accepted` during traffic, nor claim a zero-pending observation
after metrics shutdown. Separate native tests verify helper draining and join.

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
