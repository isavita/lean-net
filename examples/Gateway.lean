import LeanNet

open LeanNet

private def policy (upstreamPort : UInt16) := "
limits { headers 64 ; header-bytes 16KiB ; target-bytes 8KiB ; path-depth 16 }
ratelimit process 200/s burst 100 by global
ratelimit client 20/s burst 10 by client-ip
backend local { http 127.0.0.1:" ++ toString upstreamPort ++ " ; serves localhost }
host localhost {
  limit process
  limit client
  body 1MiB
  headers { forbid x-internal-* ; strip x-debug }
  route GET /about -> app about
  route * /* -> proxy local
}
on unknown-host 421
"

private def app (upstreamPort : UInt16) : Gate.App := {
  handlers := #[("about", fun _ _ => pure {
    response := {
      status := 200
      headers := #[{ name := "content-type", value := "text/plain; charset=utf-8".toUTF8 }]
      body := s!"lean-net gateway: localhost -> 127.0.0.1:{upstreamPort}\n".toUTF8 } })]
}

private def parsePort (text : String) : IO UInt16 := do
  let some port := text.toNat?
    | throw (IO.userError "PORT must be an integer from 1 to 65535")
  if port == 0 || port > 65535 then
    throw (IO.userError "PORT must be an integer from 1 to 65535")
  return port.toUInt16

def main (args : List String) : IO Unit := do
  let (port, upstreamPort) ← match args with
    | [] => pure ((8083 : UInt16), (8080 : UInt16))
    | [port] => pure (← parsePort port, (8080 : UInt16))
    | [port, upstreamPort] => pure (← parsePort port, ← parsePort upstreamPort)
    | _ => throw (IO.userError "usage: gateway-server [PORT [UPSTREAM_PORT]]")
  let spec ← IO.ofExcept ((Gate.Spec.parse (policy upstreamPort)).mapError toString)
  let workers := 2
  Gate.withLive { spec, app := app upstreamPort } workers fun live =>
    HTTP.ReactorServer.serveFactory
      (fun _ => pure HTTP1.Handlers.default)
      { workers
        server := { maxClients := 128 }
        admission := some live.factory
        gateway := some {
          pool := { maxTotal := 16, maxPerTarget := 8, connectTimeoutMs := 2000 }
          responseTimeoutMs := 5000 }
        healthPaths := true
        metricsPath := some "/metrics".toUTF8
        extraMetrics := live.metrics }
      "127.0.0.1" port
