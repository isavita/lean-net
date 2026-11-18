import LeanNet.HTTP.ReactorServer

open LeanNet
open LeanNet.HTTP1

private def header (name value : String) : Header := { name, value := value.toUTF8 }
private def binary : ByteArray := ByteArray.mk #[0, 255, 13, 10, 65]

private def handlers (worker : Nat) : IO Handlers := do
  return {
    onHeaders := fun head framing => do
      if head.target == "/refuse".toUTF8 then
        return .reject { response := { status := 417, body := "refused".toUTF8 } }
      if head.target == "/legacy".toUTF8 && head.version == "HTTP/1.0" && framing == .none then
        return .accept (some .closeDelimited)
      if head.target == "/upgrade".toUTF8 then
        let pipe : RawPipe := {
          onBytes := fun view => pure { output := #[view] }
          onEOF := pure { output := #[ByteSlice.full "raw-eof".toUTF8], closeAfterWrites := true } }
        return .upgrade { response := { status := 101, headers := #[header "Upgrade" "test-echo"] } } pipe
      if head.target == "/upgrade-written-error".toUTF8 then
        let pipe : RawPipe := {
          onBytes := fun view => pure { output := #[view], ticket := some 1 }
          onWritten := fun _ => throw (IO.userError "fixture onWritten failure") }
        return .upgrade { response := { status := 101, headers := #[header "Upgrade" "test-echo"] } } pipe
      if head.target == "/upgrade-timeout-error".toUTF8 then
        let pipe : RawPipe := {
          onBytes := fun view => pure { output := #[view], closeStarted := true }
          onTimeout := throw (IO.userError "fixture onTimeout failure") }
        return .upgrade { response := { status := 101, headers := #[header "Upgrade" "test-echo"] } } pipe
      if head.target == "/upgrade-shutdown-error".toUTF8 then
        let pipe : RawPipe := {
          onBytes := fun view => pure { output := #[view] }
          onShutdown := throw (IO.userError "fixture onShutdown failure") }
        return .upgrade { response := { status := 101, headers := #[header "Upgrade" "test-echo"] } } pipe
      return .accept none
    onRequest := fun request => do
      if request.target == "/echo".toUTF8 || request.target == "/legacy".toUTF8 then
        return { response := { body := request.body } }
      if request.target == "/binary".toUTF8 then
        return { response := { headers := #[header "Content-Type" "application/octet-stream"], body := binary } }
      if request.target == "/chunked".toUTF8 then
        return { response := { body := binary }, options := {
          framing := some .chunked, trailers := #[header "X-Finished" "yes"] } }
      if request.target == "/trailers".toUTF8 then
        let trailer := (request.trailers.find? (fun h => h.name == "x-check")).map (·.value)
        return { response := { body := (request.body.append "|".toUTF8).append (trailer.getD ByteArray.empty) } }
      if request.target == "/close".toUTF8 then
        return { response := { body := binary }, options := { framing := some .closeDelimited } }
      if request.target == "/head".toUTF8 then
        return { response := { body := "representation".toUTF8 } }
      if request.target == "/head-known".toUTF8 then
        if request.method == "HEAD" then
          return { response := {}, options := { framing := some (.contentLength 12345) } }
        return { response := { body := ByteArray.mk (Array.replicate 12345 (65 : UInt8)) } }
      if request.target == "/informational".toUTF8 then
        return { response := { body := "ok".toUTF8 }, informational := #[
          ({ status := 103, headers := #[header "Link" "</style.css>; rel=preload"] }, {}),
          ({ status := 102 }, {})] }
      if request.target == "/custom".toUTF8 then
        return { response := { status := 299, body := "ready".toUTF8 }, options := { reason := some "Custom Ready" } }
      if request.target == "/bad-info".toUTF8 then
        return { response := {}, informational := #[({ status := 103 }, {}), ({ status := 200 }, {})] }
      if request.target == "/invalid".toUTF8 then
        return { response := { headers := #[header "X-Test" "ok\r\nInjected: yes"] } }
      if request.target == "/large".toUTF8 then
        return { response := { body := ByteArray.mk (Array.replicate (2 * 1024 * 1024) (65 : UInt8)) } }
      if request.target == "/who".toUTF8 then
        return { response := { headers := #[header "X-Worker" (toString worker)], body := (toString worker).toUTF8 } }
      if request.target == "/fold".toUTF8 then
        return { response := { body := ((request.headers.find? (fun h => h.name == "x-fold")).map (·.value)).getD ByteArray.empty } }
      if request.target == "/date".toUTF8 then
        return { response := { headers := #[header "dAtE" "Sun, 06 Nov 1994 08:49:37 GMT"] } }
      if request.target == "/204".toUTF8 then return { response := { status := 204 } }
      if request.target == "/304".toUTF8 then return { response := { status := 304 } }
      if request.target == "/refuse".toUTF8 || request.target == "/upgrade".toUTF8 then
        return { response := { status := 500, body := "unexpected application request".toUTF8 } }
      return { response := { body := "ok".toUTF8 } }
  }

def main (args : List String) : IO UInt32 := do
  let some port := args.head?.bind String.toNat?
    | throw (IO.userError "usage: fixture PORT [normal|tiny|deadlines|fold|bench|bad-budget|bad-deadline] [WORKERS] [TIMEOUT]")
  if port == 0 || port > 65535 then throw (IO.userError "invalid port")
  let mode := (args.drop 1).head?.getD "normal"
  if !["normal", "tiny", "deadlines", "fold", "bench", "bad-budget", "bad-deadline"].contains mode then
    throw (IO.userError "invalid mode")
  let workers := ((args.drop 2).head?.bind String.toNat?).getD 1
  if workers == 0 || workers > 256 then throw (IO.userError "invalid worker count")
  if (mode == "tiny" || mode == "bad-budget") && workers != 1 then throw (IO.userError "bounded-pool fixture uses one worker")
  let server : ServerConfig := if mode == "deadlines" then {
      maxClients := 1, idleTimeoutMs := 350, requestTimeoutMs := 650, writeTimeoutMs := 3000 }
    else if mode == "tiny" then { maxClients := 1 }
    else if mode == "bad-budget" then { maxClients := 2 }
    else if mode == "bench" then { maxClients := 128 }
    else { maxClients := 64 }
  let native : Reactor.Config := if mode == "tiny" || mode == "bad-budget" then {
      maxConnections := 8, maxEvents := 8, maxWrites := 2,
      buffers4k := 2, buffers16k := 0, buffers64k := 0 }
    else {}
  let machine : Machine.Config := if mode == "fold" then { parserOptions := { allowObsFold := true } } else {}
  let config : HTTP.ReactorServerConfig := {
    server, native, machine, workers, outputBuffers := if mode == "tiny" || mode == "bad-budget" then 1 else if mode == "bench" then 512 else 128 }
  let config ← if mode != "bad-deadline" then pure config else do
    let oversized := 9223372036854775808
    match (args.drop 3).head? with
    | some "idleTimeoutMs" => pure { config with server := { server with idleTimeoutMs := oversized } }
    | some "requestTimeoutMs" => pure { config with server := { server with requestTimeoutMs := oversized } }
    | some "writeTimeoutMs" => pure { config with server := { server with writeTimeoutMs := oversized } }
    | some "shutdownDrainMs" => pure { config with shutdownDrainMs := oversized }
    | some "deferred.maxTimeoutMs" => pure { config with deferred := { config.deferred with maxTimeoutMs := oversized } }
    | some "http2.pingIntervalMs" => pure { config with http2 := { config.http2 with pingIntervalMs := oversized } }
    | some "http2.pingTimeoutMs" => pure { config with http2 := { config.http2 with pingIntervalMs := 100, pingTimeoutMs := oversized } }
    | _ => throw (IO.userError "invalid fixture timeout name")
  HTTP.ReactorServer.serveFactory handlers config "127.0.0.1" (UInt16.ofNat port)
  return 0
