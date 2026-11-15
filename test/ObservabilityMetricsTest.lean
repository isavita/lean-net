import LeanNet.HTTP.Observability.Metrics
open LeanNet.HTTP.Observability
private def check (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)
private def contains (body : ByteArray) (needle : String) : Bool :=
  ((String.fromUTF8! body).splitOn needle).length != 1
def main : IO Unit := do
  let base := ({} : Counters).connectionOpened |>.requestStarted
  let completed := base.requestFinished .http2 .get 200 .completed 25000
  let failed := completed.requestStarted |>.requestFinished .http11 .post 404 .completed 1000
  let cancelled := failed.requestStarted |>.requestFinished .http10 .other 0 .cancelled 5000001
  let timedOut := cancelled.requestStarted |>.requestFinished .http11 .head 0 .timeout 5000
  let counters := timedOut.connectionReset.connectionClosed |>.received 7 |>.sent 11
  let values := counters.fields
  check (values.size == 42 && values[1]! == 0 && values[3]! == 0 && values[2]! == 4) "gauge/started counters"
  check (values[4]! == 1 && values[5]! == 2 && values[6]! == 1 && values[7]! == 1 && values[8]! == 1) "terminal classification"
  check (values[9]! == 7 && values[10]! == 11 && values[12]! == 4 && values[23]! == 4) "wire bytes/histogram count"
  check (values[13]! == 1 && values[14]! == 2 && values[16]! == 3) "cumulative buckets"
  check (values[24]! == 0 && values[25]! == 1 && values[26]! == 1 && values[29]! == 1 && values[31]! == 1) "bounded protocol/status labels"
  check (Method.classify "GET" == .get && Method.classify "secret-path-token" == .other) "method cardinality"
  let upgrade := (({} : Counters).requestStarted).requestFinished .http11 .get 101 .completed 1000
  check (upgrade.fields[4]! == 1 && upgrade.fields[5]! == 0 && upgrade.fields[28]! == 1)
    "completed 101 upgrade must be successful, with 1xx status label"
  check ((Snapshot.ofFields? values).isNone) "snapshot accepted wrong native schema"
  let some snapshot := Snapshot.ofFields? (values ++ #[2, 3, 2, 0, 0]) | throw (IO.userError "snapshot schema")
  check (snapshot.successfulCompleted == 1 && snapshot.logDropped == 3 && snapshot.field 99 == 0) "typed snapshot selectors"
  let output := snapshot.renderPrometheus
  check (contains output "lean_net_successful_completed_requests_total 1\n") "soak boundary selector"
  check (contains output "# HELP lean_net_request_bytes_total Plaintext transport bytes received" &&
    contains output "# HELP lean_net_response_bytes_total Plaintext transport bytes in fully completed native writes")
    "wire-byte semantics help"
  check (contains output "lean_net_request_duration_seconds_bucket{le=\"+Inf\"} 4\n" &&
    contains output "lean_net_request_duration_seconds_count 4\n") "histogram exposition"
  check (contains output "lean_net_completed_requests_by_method_total{method=\"OTHER\"}" &&
    !contains output "secret-path-token") "arbitrary method leaked into metric label"
  check (output[output.size - 1]! == 10 && output.size < 16384) "bounded newline terminated metrics"
  IO.println "Observability fixed-label counters and Prometheus output passed"
