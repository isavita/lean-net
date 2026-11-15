namespace LeanNet.HTTP.Observability

inductive Protocol where
  | http10 | http11 | http2
  deriving BEq, Repr, Inhabited
def Protocol.index : Protocol → Nat | .http10 => 0 | .http11 => 1 | .http2 => 2
def Protocol.label : Protocol → String | .http10 => "http10" | .http11 => "http11" | .http2 => "http2"
inductive Outcome where
  | completed | cancelled | error | timeout | shutdown
  deriving BEq, Repr, Inhabited
def Outcome.index : Outcome → Nat
  | .completed => 0 | .cancelled => 1 | .error => 2 | .timeout => 3 | .shutdown => 4
inductive Method where
  | get | head | post | put | delete | options | connect | trace | other
  deriving BEq, Repr, Inhabited
def Method.index : Method → Nat
  | .get => 0 | .head => 1 | .post => 2 | .put => 3 | .delete => 4
  | .options => 5 | .connect => 6 | .trace => 7 | .other => 8
def Method.classify : String → Method
  | "GET" => .get | "HEAD" => .head | "POST" => .post | "PUT" => .put
  | "DELETE" => .delete | "OPTIONS" => .options | "CONNECT" => .connect | "TRACE" => .trace
  | _ => .other
def Method.label : Method → String
  | .get => "GET" | .head => "HEAD" | .post => "POST" | .put => "PUT" | .delete => "DELETE"
  | .options => "OPTIONS" | .connect => "CONNECT" | .trace => "TRACE" | .other => "OTHER"

private def saturatingAdd (a b : UInt64) : UInt64 :=
  if b.toNat > 18446744073709551615 - a.toNat then 18446744073709551615 else a + b

/-- Fixed schema, never labeled by arbitrary request targets or method strings.
    A worker exclusively owns and updates its counter value. Publish snapshots
    cold; no native shared counter is mutated per successful request. -/
structure Counters where
  private values : Array UInt64 := Array.replicate 42 0
  deriving Inhabited

private def Counters.add (c : Counters) (index : Nat) (amount : UInt64 := 1) : Counters :=
  { values := c.values.modify index (fun value => saturatingAdd value amount) }
private def Counters.sub (c : Counters) (index : Nat) : Counters :=
  { values := c.values.modify index (fun value => if value == 0 then 0 else value - 1) }
def Counters.fields (c : Counters) : Array UInt64 := c.values
def Counters.connectionOpened (c : Counters) : Counters := (c.add 0).add 1
def Counters.connectionClosed (c : Counters) : Counters := c.sub 1
def Counters.requestStarted (c : Counters) : Counters := (c.add 2).add 3
def Counters.received (c : Counters) (bytes : UInt64) : Counters := c.add 9 bytes
def Counters.sent (c : Counters) (bytes : UInt64) : Counters := c.add 10 bytes
def Counters.connectionReset (c : Counters) : Counters := c.add 7

def durationBoundsUs : Array UInt64 :=
  #[1000, 5000, 10000, 25000, 50000, 100000, 250000, 500000, 1000000, 5000000, 18446744073709551615]

/-- Call exactly once when a request is terminal. Completed upgrades (101) and
    2xx/3xx responses count as successful; aborted/shutdown requests remain visible.
    Wire byte counters are updated separately on actual read/write completion. -/
def Counters.requestFinished (c : Counters) (protocol : Protocol) (method : Method)
    (status : Nat) (outcome : Outcome) (durationUs : UInt64) : Counters := Id.run do
  let mut c := c.sub 3
  match outcome with
  | .completed =>
    c := c.add (if status == 101 || (status >= 200 && status < 400) then 4 else 5)
    c := c.add (24 + protocol.index)
    c := c.add (27 + if status >= 100 && status < 600 then status / 100 else 0)
    c := c.add (33 + method.index)
  | .cancelled | .shutdown => c := c.add 8
  | .error => c := c.add 5
  | .timeout => c := (c.add 5).add 6
  c := (c.add 11 durationUs).add 12
  for index in [:durationBoundsUs.size] do
    if durationUs <= durationBoundsUs[index]! then c := c.add (13 + index)
  return c

structure Snapshot where
  private values : Array UInt64

def Snapshot.ofFields? (values : Array UInt64) : Option Snapshot :=
  if values.size == 47 then some ⟨values⟩ else none
def Snapshot.field (s : Snapshot) (index : Nat) : UInt64 := s.values[index]?.getD 0
def Snapshot.successfulCompleted (s : Snapshot) : UInt64 := s.field 4
def Snapshot.errors (s : Snapshot) : UInt64 := s.field 5
def Snapshot.timeouts (s : Snapshot) : UInt64 := s.field 6
def Snapshot.connectionResets (s : Snapshot) : UInt64 := s.field 7
def Snapshot.logDropped (s : Snapshot) : UInt64 := s.field 43
def Snapshot.logPending (s : Snapshot) : UInt64 := s.field 46

def metricsContentType : ByteArray := "text/plain; version=0.0.4; charset=utf-8".toUTF8

private def decimalSeconds (microseconds : UInt64) : String :=
  let fraction := toString (microseconds % 1000000)
  toString (microseconds / 1000000) ++ "." ++ String.ofList (List.replicate (6 - fraction.length) '0') ++ fraction

/-- Cold formatting, suitable for a bounded metrics endpoint response. The
    schema contains only fixed labels and eleven cumulative latency buckets. -/
def Snapshot.renderPrometheus (s : Snapshot) : ByteArray := Id.run do
  let mut out := ByteArray.empty
  let scalars : Array (String × String × Nat) := #[
    ("connections_total", "counter", 0), ("active_connections", "gauge", 1),
    ("requests_started_total", "counter", 2), ("active_requests", "gauge", 3),
    ("successful_completed_requests_total", "counter", 4), ("request_errors_total", "counter", 5),
    ("request_timeouts_total", "counter", 6), ("connection_resets_total", "counter", 7),
    ("requests_cancelled_total", "counter", 8), ("request_bytes_total", "counter", 9),
    ("response_bytes_total", "counter", 10), ("access_log_accepted_total", "counter", 42),
    ("access_log_dropped_total", "counter", 43), ("access_log_written_total", "counter", 44),
    ("access_log_io_errors_total", "counter", 45), ("access_log_pending_records", "gauge", 46)]
  for (name, kind, index) in scalars do
    if index == 9 then
      out := out ++ "# HELP lean_net_request_bytes_total Plaintext transport bytes received, including HTTP framing, control and metrics traffic.\n".toUTF8
    if index == 10 then
      out := out ++ "# HELP lean_net_response_bytes_total Plaintext transport bytes in fully completed native writes, including HTTP framing, control and metrics traffic; excludes aborted partial writes.\n".toUTF8
    out := out ++ s!"# TYPE lean_net_{name} {kind}\nlean_net_{name} {s.field index}\n".toUTF8
  out := out ++ "# TYPE lean_net_request_duration_seconds histogram\n".toUTF8
  let labels := #["0.001","0.005","0.01","0.025","0.05","0.1","0.25","0.5","1","5","+Inf"]
  for index in [:labels.size] do
    out := out ++ s!"lean_net_request_duration_seconds_bucket\{le=\"{labels[index]!}\"} {s.field (13 + index)}\n".toUTF8
  out := out ++ s!"lean_net_request_duration_seconds_sum {decimalSeconds (s.field 11)}\nlean_net_request_duration_seconds_count {s.field 12}\n".toUTF8
  out := out ++ "# TYPE lean_net_completed_requests_by_protocol_total counter\n".toUTF8
  for protocol in #[Protocol.http10, .http11, .http2] do
    out := out ++ s!"lean_net_completed_requests_by_protocol_total\{protocol=\"{protocol.label}\"} {s.field (24 + protocol.index)}\n".toUTF8
  out := out ++ "# TYPE lean_net_completed_requests_by_status_class_total counter\n".toUTF8
  for index in [:6] do
    let label := if index == 0 then "other" else s!"{index}xx"
    out := out ++ s!"lean_net_completed_requests_by_status_class_total\{status_class=\"{label}\"} {s.field (27 + index)}\n".toUTF8
  out := out ++ "# TYPE lean_net_completed_requests_by_method_total counter\n".toUTF8
  for method in #[Method.get, .head, .post, .put, .delete, .options, .connect, .trace, .other] do
    out := out ++ s!"lean_net_completed_requests_by_method_total\{method=\"{method.label}\"} {s.field (33 + method.index)}\n".toUTF8
  return out

end LeanNet.HTTP.Observability
