import LeanNet.HTTP1.Streaming

namespace LeanNet.HTTP.Deferred

/-- Why the owner retired an unfinished application exchange. -/
inductive CancelReason where
  | disconnected | streamReset | timeout | shutdown | overloaded | failed
  deriving BEq, Repr, Inhabited

/-- Per-reactor application completion budgets. These bound retained application
work separately from the protocol's input and output budgets. -/
structure Config where
  maxPending : Nat := 1024
  maxPendingPerClient : Nat := 64
  maxRetainedBytes : Nat := 16 * 1024 * 1024
  maxTimeoutMs : Nat := 30000
  /-- Poll once per worker turn and sleep at most this long while jobs remain. -/
  pollIntervalMs : Nat := 5
  deriving Repr, Inhabited

/-- An unfinished response owned by the reactor worker which created it.

`poll` and `cancel` run synchronously on that worker and MUST NOT block. Poll
returns `none` until a nonblocking adapter has completed its owned-byte work.
Neither callback is passed a socket, transport endpoint, or borrowed input
slice. Do not capture those resources or move worker-local state to a task.

`retainedBytes` accounts for all data retained by this job (including request
snapshots). The server also charges the received body and headers, so adapters
should use this field for additional buffers. Successful completion removes the
job before publishing its reply; every other terminal path calls `cancel`
exactly once. A throwing poll is cancelled with `failed` and becomes HTTP 500.
External producers must use bounded queues and treat cancellation as final. -/
structure Job where
  poll : IO (Option HTTP1.Reply)
  cancel : CancelReason → IO Unit := fun _ => pure ()
  timeoutMs : Nat := 30000
  retainedBytes : Nat := 0

/-- Existing synchronous handlers stay source compatible. Applications opt in
with `Handlers.onRequestDeferred` and return either constructor. -/
inductive Result where
  | immediate (reply : HTTP1.Reply)
  | deferred (job : Job)

/-- Reject invalid budgets before listening or creating worker resources. -/
def Config.validate (config : Config) : Except String Unit := do
  if config.maxPending == 0 || config.maxPendingPerClient == 0 ||
      config.maxPendingPerClient > config.maxPending || config.maxRetainedBytes == 0 ||
      config.maxTimeoutMs == 0 || config.maxTimeoutMs > 9223372036854775807 ||
      config.pollIntervalMs == 0 || config.pollIntervalMs > 100 then
    throw "deferred reply budgets must be positive; per-client count must fit maxPending; poll interval must be at most 100ms"

end LeanNet.HTTP.Deferred
