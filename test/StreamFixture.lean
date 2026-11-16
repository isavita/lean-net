import LeanNet.HTTP.ReactorServer

open LeanNet LeanNet.HTTP1

private def handlers (_ : Nat) : IO Handlers := do
  let produced ← IO.mkRef (0 : Nat)
  let closed ← IO.mkRef (#[] : Array String)
  let ticks ← IO.mkRef (0 : Nat)
  let drain ← IO.mkRef (none : Option (Nat × Nat))
  let callbacks (kind : WebSocket.Opcode := .text) : IO WebSocket.Callbacks := do
    let sent ← IO.mkRef false
    return {
      onMessage := fun _ _ => pure none
      onPoll := do
        if ← sent.get then return none
        sent.set true
        return some { opcode := kind, payload := if kind == .close then ByteArray.mk #[17, 56] else "unsolicited".toUTF8 } }
  let policy : WebSocket.Handshake.Policy := { originAllowed := fun value => value == some "https://stream.test".toUTF8 }
  return {
    tickIntervalMs := 5
    onTick := fun _ => ticks.modify (· + 1)
    onDrain := fun cutoff => do
      let now ← IO.monoMsNow
      drain.set (some (now, cutoff))
      IO.println s!"DRAIN {now} {cutoff}"
    isDrained := do
      match ← drain.get with
      | none => return true
      | some (started, _) => return (← IO.monoMsNow) >= started + 40
    onShutdown := do IO.println s!"SHUTDOWN {(← IO.monoMsNow)} TICKS {(← ticks.get)}"
    onHeaders := fun head _ => do
      if ["/ws".toUTF8, "/ws-ping".toUTF8, "/ws-close".toUTF8].contains head.target then
        WebSocket.Server.acceptHTTP1 head policy (← callbacks (if head.target == "/ws-ping".toUTF8 then .ping else if head.target == "/ws-close".toUTF8 then .close else .text))
      else pure (.accept none)
    onWebSocket := fun head => do
      if ["/ws".toUTF8, "/ws-ping".toUTF8, "/ws-close".toUTF8].contains head.target then return some (policy, ← callbacks (if head.target == "/ws-ping".toUTF8 then .ping else if head.target == "/ws-close".toUTF8 then .close else .text))
      return none
    streamRequests := fun head => pure (["/upload", "/bidi", "/early"].contains (String.fromUTF8! head.target))
    onRequest := fun _ => pure { response := { status := 500 } }
    onRequestDeferred := some fun request => do
      let target := String.fromUTF8! request.target
      if target == "/trace" then
        return .immediate { response := { headers := #[
          { name := "x-generated", value := (toString request.traceGenerated).toUTF8 },
          { name := "x-trace", value := (request.headers.find? (·.name == "traceparent")).map (·.value) |>.getD ByteArray.empty }] } }
      if target == "/stats" then
        return .immediate { response := { headers := #[
          { name := "x-ticks", value := (toString (← ticks.get)).toUTF8 },
          { name := "x-produced", value := (toString (← produced.get)).toUTF8 },
          { name := "x-closed", value := (String.intercalate "," (← closed.get).toList).toUTF8 }] } }
      if target == "/empty" then return .immediate { response := {} }
      if target == "/immediate" then return .immediate { response := { body := "ok".toUTF8 } }
      if target == "/upload" || target == "/bidi" || target == "/early" then
        let some input := request.incoming | return .immediate { response := { status := 501 } }
        if target == "/early" then return .immediate { response := { body := "accepted".toUTF8 } }
        if target == "/upload" then
          let bytes ← IO.mkRef ByteArray.empty
          return .deferred {
            retainedBytes := 1024 * 1024
            poll := do
              let event ← input.poll 16384
              match event with
              | none => return none
              | some (.data chunk) => bytes.modify (· ++ chunk); return none
              | some (.finish trailers) =>
                let data ← bytes.get
                let sent ← IO.mkRef 0
                return some { response := { headers := trailers.filter (·.name == "x-client-finished") }, stream := some {
                  retainedBytes := data.size
                  knownLength := some data.size
                  poll := fun budget => do
                    let offset ← sent.get
                    if offset == data.size then return some (.finish #[])
                    if budget == 0 then return none
                    let count := min budget (data.size - offset)
                    sent.set (offset + count)
                    return some (.data (data.extract offset (offset + count)))
                  close := fun _ => pure () } }
              | some (.cancelled _) => return some { response := { status := 499 } }
            cancel := input.cancel }
        return .immediate { response := { headers := #[{ name := "content-type", value := "application/octet-stream".toUTF8 }] }, stream := some {
          declaredTrailers := #["x-finished"]
          poll := fun budget => do
            match ← input.poll budget with
            | none => return none
            | some (.data bytes) => return some (.data bytes)
            | some (.finish _) => return some (.finish #[{ name := "x-finished", value := "yes".toUTF8 }])
            | some (.cancelled _) => throw (IO.userError "upload cancelled")
          close := fun reason => do
            closed.modify (·.push (reason.map reprStr |>.getD "complete"))
            if let some reason := reason then input.cancel reason } }
      let offset ← IO.mkRef (0 : Nat)
      let started ← Reactor.nowMs
      let data := if target == "/big" then ByteArray.mk (Array.replicate (2 * 1024 * 1024) (65 : UInt8)) else "firstsecond".toUTF8
      let body : HTTP.Stream.Body := {
        retainedBytes := data.size
        knownLength := if target == "/known" then some data.size else none
        declaredTrailers := if target == "/known" then #[] else #["x-finished"]
        idleTimeoutMs := if target == "/timeout" then 80 else 3000
        lifetimeMs := 5000
        poll := fun budget => do
          if target == "/cancel" || target == "/timeout" then return none
          let current ← offset.get
          if current == data.size then
            return some (.finish (if target == "/known" then #[] else #[{ name := "x-finished", value := (if target == "/bad-trailer" then "yes\r\nx-injected: bad" else "yes").toUTF8 }]))
          if budget == 0 then return none
          if target == "/chunks" && current > 0 && (← Reactor.nowMs) - started < 200 then return none
          let count := min budget (if target == "/chunks" && current == 0 then 5 else data.size - current)
          offset.set (current + count)
          produced.modify (· + 1)
          return some (.data (data.extract current (current + count)))
        close := fun reason => closed.modify (·.push (reason.map reprStr |>.getD "complete")) }
      return .immediate { response := { headers := #[{ name := "content-type", value := "application/octet-stream".toUTF8 }] }, stream := some body }
  }

def main (args : List String) : IO Unit := do
  let some port := args[0]?.bind String.toNat? | throw (IO.userError "usage: fixture PORT")
  HTTP.ReactorServer.serveFactory handlers {
    workers := 1
    server := { maxClients := 8 }
    http2 := { enableConnectProtocol := true }
    maxOutputBytes := 65536
    outputBuffers := 8
    shutdownDrainMs := 100
    deferred := { maxRetainedBytes := 8 * 1024 * 1024, pollIntervalMs := 2 } }
    "127.0.0.1" port.toUInt16
