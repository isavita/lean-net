# Native reactor migration

The completion API is implemented by epoll on Linux, kqueue on macOS, and an
IOCP backend on Windows, with native lifecycle tests in the CI matrix. Linux
uses one SO_REUSEPORT listener per worker. On macOS and Windows, multi-worker
servers use one dedicated acceptor and bounded per-worker handoff queues.
Each worker registers its adopted socket with its own kqueue/IOCP before the
first read. One-worker servers use their reactor's listener directly.

Each reactor owns its sockets, write operations, timer entries, event records,
and fixed-capacity 4 KiB/16 KiB/64 KiB buffer pools. Native connection and buffer
tokens carry generations; a token from a closed/recycled object cannot address
its replacement. Generations never wrap: exhausted socket and buffer slots are
retired before crossing the signed FFI token boundary. Established native I/O
uses startup-allocated storage. Lean's
FFI adapters and protocol dispatch can still allocate Lean result objects; this
is not a claim of allocation-free whole-program execution.

`LeanNet.Reactor.Socket state` exposes real fresh → bound → listening
transitions. Accepted completions supply connected sockets. `close` requires
`state ≠ .closed` and returns a closed-state handle. Private constructors prevent
applications from manufacturing a different state. Runtime generation checks
also reject stale aliases, which phantom types alone cannot eliminate in Lean.

A read completion transfers a buffer lease to the dispatcher. Queueing a write
pins native storage until completion; releasing the lease does not invalidate
an in-flight write. A ByteArray view can outlive a release without being mutated
underneath its owner. The pool waits for unique ownership before recycling the
cell. Buffer views belong to their reactor thread: do not share them with another
Lean task or loop. The runtime marks cross-task objects multi-threaded, which
can permanently prevent that cell from becoming exclusive until reactor cleanup.

`tryWrite` returns `wouldBlock` on exhausted write credits and leaves the lease
owned by its caller. The echo dispatcher reserves at least one write credit per
pooled buffer, so its one-write-per-read protocol cannot exhaust credits before
receive-pool backpressure stops more input. EOF drains already-queued echo bytes
before closing. A peer reset cancels obsolete completions in the same batch;
configuration, invalid-owned-descriptor, and close failures remain fatal.

The default echo server starts one dedicated Lean IO worker per active logical
CPU. These are long-lived loops; no task is scheduled per request and Std.Async
is absent from accept/read/write. Workers own independent protocol/native state.
On Linux each binds its own SO_REUSEPORT listener. A setup-only
endpoint lease prevents another cooperating lean-net process from accidentally
joining that address. It is not kernel-enforced exclusion of arbitrary apps
that deliberately use SO_REUSEPORT. A process-level signal group wakes workers,
joins them, unregisters handlers, and only then frees reactors.

`setAcceptTargets` is a setup operation: configure fresh reactors before socket
creation, listener startup, or polling. The acceptor sends only raw socket
ownership across preallocated lock-free SPSC rings, choosing available workers
round-robin. Full rings pause acceptance and retain the socket until capacity
returns. macOS channels own duplicated pipe wake descriptors; Windows channels
retain shared ownership of the original completion-port handle. Endpoint refs
allow either destruction order after every loop has stopped and joined.
Interrupted cross-loop wakeups retain pending work and surface EINTR; a caller's
next poll makes a new wake attempt. Collected completions survive poll errors,
and the deferred error is reported on the following poll without a syscall retry.

macOS SO_REUSEPORT permits duplicate bindings but did not distribute this host's
TCP connections. Its installed SDK exposes no TCP load-balancing option; the
acceptor design is the approved platform adaptation. The diagnostic evidence is
under `test/benchmarks`. This does not imply linear multicore throughput scaling.

The hashed timer wheel has eight timer kinds per connection and a configurable
tick. Timers are one-shot completion events and do not allocate one kernel timer
per connection. The newer HTTP protocol/TLS machines have not yet been ported to
this reactor; their existing tests remain regression coverage for later phases.
