import LeanNet.HTTP.ReactorServer

open LeanNet

private structure HeldWrite where
  owner : Reactor.SocketId
  operation : UInt64
  count : Nat
  due : UInt64

private def isProbe (buffer : Reactor.Buffer) (offset length : UInt32) : IO Bool := do
  if length != 17 then return false
  let bytes ← buffer.view
  let start := offset.toNat
  return bytes.size >= start + 17 && bytes[start]! == 0 && bytes[start + 1]! == 0 &&
    bytes[start + 2]! == 8 && bytes[start + 3]! == 6 && bytes[start + 4]! == 0 &&
    bytes[start + 5]! == 0 && bytes[start + 6]! == 0 && bytes[start + 7]! == 0 && bytes[start + 8]! == 0

/-- Real bytes reach the peer immediately; only PING completion notifications
    are delayed. This exercises ACK-before-WN and stale-WN controller ordering. -/
private def withDelayedPing : HTTP.Transport.WithWorker := fun _ _ _ use => do
  let endpoints ← IO.mkRef ({} : Std.HashMap Reactor.SocketId HTTP.Transport.Endpoint)
  let tagged ← IO.mkRef ({} : Std.HashMap (Reactor.SocketId × UInt64) Bool)
  let held ← IO.mkRef (#[] : Array HeldWrite)
  let provider : HTTP.Transport.Worker := {
    deferClosed := true
    poll := pure #[]
    hasWork := pure false
    event := fun native => do
      let mut output := #[]
      for event in ← HTTP.Transport.plain.event native do
        match event with
        | .ready endpoint protocol =>
          let wrapped := { endpoint with tryWrite := fun buffer offset length operation => do
            let ping ← isProbe buffer offset length
            let result ← endpoint.tryWrite buffer offset length operation
            if ping then
              if let .queued := result then tagged.modify (·.insert (endpoint.id, operation) true)
            return result }
          endpoints.modify (·.insert endpoint.id endpoint)
          output := output.push (.ready wrapped protocol)
        | .written id operation count =>
          if (← tagged.get).contains (id, operation) then
            tagged.modify (·.erase (id, operation))
            let now ← Reactor.nowMs
            let pending := (← held.get).push { owner := id, operation, count, due := now + 800 }
            held.set pending
            let first := pending.foldl (fun due item => if item.owner == id then min due item.due else due) (now + 800)
            if let some endpoint := (← endpoints.get)[id]? then endpoint.armTimer 4 first
          else output := output.push event
        | .timer id 4 =>
          let now ← Reactor.nowMs
          let mut remaining := #[]
          let mut next : Option UInt64 := none
          for item in ← held.get do
            if item.owner == id && item.due <= now then
              output := output.push (.written id item.operation item.count)
            else
              remaining := remaining.push item
              if item.owner == id then next := some (min (next.getD item.due) item.due)
          held.set remaining
          if let some due := next then
            if let some endpoint := (← endpoints.get)[id]? then endpoint.armTimer 4 due
        | .closed id =>
          let mut remaining := #[]
          for item in ← held.get do
            if item.owner == id then output := output.push (.written id item.operation item.count)
            else remaining := remaining.push item
          held.set remaining
          endpoints.modify (·.erase id)
          tagged.modify fun values => values.filter (fun key _ => key.1 != id)
          output := output.push event
        | _ => output := output.push event
      return output }
  use provider

def main (args : List String) : IO UInt32 := do
  let some port := args[0]?.bind String.toNat? | throw (IO.userError "missing port")
  let some path := args[1]? | throw (IO.userError "missing access-log path")
  let some helper := args[2]? | throw (IO.userError "missing helper")
  if port == 0 || port > 65535 then throw (IO.userError "invalid port")
  let handlers : HTTP1.Handlers := {
    onRequest := fun _ => pure { response := { body := ByteArray.mk #[0, 255, 13, 10, 65] } } }
  let config : HTTP.ReactorServerConfig := {
    workers := 1, server := { maxClients := 64 }, outputBuffers := 256,
    http2 := { pingIntervalMs := 100, pingTimeoutMs := 150 },
    metricsPath := some "/metrics".toUTF8,
    accessLog := some {
      path := System.FilePath.mk path, helperBinary := System.FilePath.mk helper, pollIntervalMs := 1 } }
  HTTP.ReactorServer.serveFactoryWithTransport withDelayedPing (fun _ => pure handlers) config
    "127.0.0.1" (UInt16.ofNat port)
  return 0
