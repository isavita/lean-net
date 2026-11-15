import LeanNet.Socket.Handle
import LeanNet.Reactor.Basic
import LeanNet.HTTP.Observability

namespace LeanNet.HTTP.Admin

/-- Prometheus process gauges shared by `/metrics` and the admin port. -/
def processPrometheus : IO ByteArray := do
  let mut out := ""
  if let some rss ← Reactor.processResidentBytes then
    out := out ++ s!"# TYPE lean_net_process_resident_memory_bytes gauge\nlean_net_process_resident_memory_bytes {rss}\n"
  if let some fds ← Reactor.processOpenFds then
    out := out ++ s!"# TYPE lean_net_process_open_fds gauge\nlean_net_process_open_fds {fds}\n"
  return out.toUTF8

/-- Read-only view the admin port serves; supplied by the server bracket. -/
structure Source where
  workers : Nat
  startedAtMs : UInt64
  snapshot : IO (Option Observability.Snapshot)
  draining : IO Bool
  /-- Additional Prometheus text from the transport (e.g. TLS counters). -/
  extraMetrics : IO ByteArray := pure ByteArray.empty
  /-- The complete server supplies cached off-loop process gauges. Standalone
      admin listeners collect them on their dedicated control thread. -/
  processMetrics : IO ByteArray := processPrometheus

private def statsJson (source : Source) : IO String := do
  let now ← Reactor.nowMs
  let rss ← Reactor.processResidentBytes
  let fds ← Reactor.processOpenFds
  let draining ← source.draining
  let optional := fun (value : Option Nat) => match value with | some n => toString n | none => "null"
  let mut fields : Array String := #[
    s!"\"workers\":{source.workers}",
    s!"\"uptime_ms\":{now - source.startedAtMs}",
    s!"\"draining\":{if draining then "true" else "false"}",
    s!"\"resident_memory_bytes\":{optional rss}",
    s!"\"open_fds\":{optional fds}"]
  if let some snapshot ← source.snapshot then
    fields := fields ++ #[
      s!"\"connections_total\":{snapshot.field 0}",
      s!"\"active_connections\":{snapshot.field 1}",
      s!"\"requests_started_total\":{snapshot.field 2}",
      s!"\"active_requests\":{snapshot.field 3}",
      s!"\"successful_requests_total\":{snapshot.successfulCompleted}",
      s!"\"request_errors_total\":{snapshot.errors}",
      s!"\"request_timeouts_total\":{snapshot.timeouts}",
      s!"\"connection_resets_total\":{snapshot.connectionResets}",
      s!"\"access_log_dropped_total\":{snapshot.logDropped}"]
  return "{" ++ ",".intercalate fields.toList ++ "}\n"

private def response (status : Nat) (reason contentType : String) (body : ByteArray) (head : Bool) : ByteArray :=
  let header := s!"HTTP/1.1 {status} {reason}\r\nContent-Type: {contentType}\r\nContent-Length: {body.size}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n".toUTF8
  if head then header else header ++ body

private def route (source : Source) (method target : String) : IO ByteArray := do
  let head := method == "HEAD"
  if method != "GET" && !head then
    return response 405 "Method Not Allowed" "text/plain; charset=utf-8" "method not allowed\n".toUTF8 head
  let path := (target.splitOn "?").headD target
  match path with
  | "/" | "/stats" => return response 200 "OK" "application/json" (← statsJson source).toUTF8 head
  | "/healthz" => return response 200 "OK" "text/plain; charset=utf-8" "ok\n".toUTF8 head
  | "/readyz" =>
    if ← source.draining then return response 503 "Service Unavailable" "text/plain; charset=utf-8" "draining\n".toUTF8 head
    return response 200 "OK" "text/plain; charset=utf-8" "ready\n".toUTF8 head
  | "/metrics" =>
    let mut body := ← source.processMetrics
    if let some snapshot ← source.snapshot then body := snapshot.renderPrometheus ++ body
    body := body ++ (← source.extraMetrics)
    return response 200 "OK" (String.fromUTF8! Observability.metricsContentType) body head
  | _ => return response 404 "Not Found" "text/plain; charset=utf-8" "not found\n".toUTF8 head

private def findHeadEnd (bytes : ByteArray) : Option Nat := Id.run do
  if bytes.size < 4 then return none
  for i in [:bytes.size - 3] do
    if bytes[i]! == 13 && bytes[i + 1]! == 10 && bytes[i + 2]! == 13 && bytes[i + 3]! == 10 then return some i
  return none

/-- One bounded request per connection: 8 KiB head, one-second deadlines. -/
private partial def serveConnection (source : Source) (connection : Connection) : IO Unit := do
  let deadline := (← Reactor.nowMs) + 1000
  let rec readHead (buffer : ByteArray) : IO (Option ByteArray) := do
    if let some stop := findHeadEnd buffer then
      if stop + 4 > 8192 then return none
      return some (buffer.extract 0 stop)
    if buffer.size >= 8192 then return none
    let now ← Reactor.nowMs
    if now >= deadline then return none
    match ← connection.recv (min 4096 (8192 - buffer.size)).toUSize with
    | .data bytes => readHead (buffer ++ bytes)
    | .wouldBlock | .interrupted | .wantWrite => IO.sleep 2; readHead buffer
    | .eof => return none
  let some head ← readHead ByteArray.empty | return
  let line := ((String.fromUTF8? head).getD "").splitOn "\r\n" |>.headD ""
  let reply ← match line.splitOn " " with
    | [method, target, version] =>
      if version.startsWith "HTTP/1." then route source method target
      else pure (response 505 "HTTP Version Not Supported" "text/plain" ByteArray.empty false)
    | _ => pure (response 400 "Bad Request" "text/plain" ByteArray.empty false)
  let rec writeAll (offset : Nat) : IO Unit := do
    if offset >= reply.size then return
    let now ← Reactor.nowMs
    if now >= deadline + 1000 then return
    match ← connection.sendAt reply offset (reply.size - offset) with
    | .written count => writeAll (offset + count)
    | _ =>
      IO.sleep 2
      writeAll offset
  writeAll 0

/-- Serve the admin API on `127.0.0.1:port` from the calling (dedicated) thread
    until `stop` becomes true. Never shares worker reactors; connections are
    handled one at a time with strict size and time bounds. -/
partial def withServer (port : UInt16) (source : Source) (stop : IO.Ref Bool)
    (use : IO Unit → IO α) : IO α :=
  withListener "127.0.0.1" port fun listener => withConnectionPool fun pool => do
    listener.setNonblocking
    let rec loop : IO Unit := do
      if ← stop.get then return
      -- Nonblocking accept with a short sleep: this low-traffic control port
      -- needs no readiness multiplexing and never touches worker reactors.
      -- Peer aborts and transient accept failures never stop the admin port.
      let accepted ← try pool.accept listener catch _ => pure .retry
      match accepted with
      | .accepted connection =>
        try serveConnection source connection
        catch _ => pure ()
        try pool.close connection catch _ => pure ()
      | .wouldBlock => IO.sleep 20
      | .retry | .interrupted => IO.sleep 1
      loop
    -- Bind before starting the control task so configuration errors fail the
    -- complete server startup, while the bracket outlives its awaited task.
    use loop

def serve (port : UInt16) (source : Source) (stop : IO.Ref Bool) : IO Unit :=
  withServer port source stop fun run => run

end LeanNet.HTTP.Admin
