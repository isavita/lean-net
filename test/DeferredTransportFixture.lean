import LeanNet.HTTP.ReactorServer

open LeanNet

/-- Force a satisfied physical write to arrive after the controller has seen
    its socket die. This models an asynchronous provider's retirement contract
    without relying on TCP/TLS thread timing. Only the first write is delayed. -/
private def withDeferred : HTTP.Transport.WithWorker := fun _ _ reactor use => do
  let endpoints ← IO.mkRef ({} : Std.HashMap Reactor.SocketId HTTP.Transport.Endpoint)
  let held ← IO.mkRef (none : Option (Reactor.SocketId × HTTP.Transport.Event))
  let injected ← IO.mkRef false
  let provider : HTTP.Transport.Worker := {
    deferClosed := true
    poll := pure #[]
    hasWork := pure false
    event := fun native => do
      let mut output := #[]
      for event in ← HTTP.Transport.plain.event native do
        match event with
        | .ready endpoint _ =>
          endpoints.modify (·.insert endpoint.id endpoint)
          output := output.push event
        | .written id _ _ =>
          if !(← injected.get) then
            let some endpoint := (← endpoints.get)[id]? |
              throw (IO.userError "missing deferred-test endpoint")
            injected.set true
            held.set (some (id, event))
            endpoint.close
            if ← id.isLive reactor then
              throw (IO.userError "deferred-test close did not retire physical identity")
          else output := output.push event
        | .closed id =>
          if let some (owner, written) ← held.get then
            if owner == id then
              IO.println "delivered satisfied WN after physical CLOSED"
              output := output.push written
              held.set none
          endpoints.modify (·.erase id)
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
    onRequest := fun _ => pure { response := { body := "finished".toUTF8 } } }
  let config : HTTP.ReactorServerConfig := {
    workers := 1, metricsPath := some "/metrics".toUTF8,
    accessLog := some {
      path := System.FilePath.mk path,
      helperBinary := System.FilePath.mk helper, pollIntervalMs := 1 } }
  HTTP.ReactorServer.serveFactoryWithTransport withDeferred (fun _ => pure handlers) config
    "127.0.0.1" (UInt16.ofNat port)
  return 0
