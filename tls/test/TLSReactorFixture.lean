import LeanNetTLS.ReactorServer

open LeanNet
open LeanNet.HTTP1

private def header (name value : String) : Header := { name, value := value.toUTF8 }
private def binary : ByteArray := ByteArray.mk #[0, 255, 13, 10, 65]

private def handlers (worker : Nat) (diagnostics : IO LeanNetTLS.Reactor.Stats) : IO Handlers := do
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
        return .upgrade { response := { status := 101, headers := #[header "Upgrade" "test-echo",
          header "X-Worker" (toString worker)] } } pipe
      return .accept none
    onRequest := fun request => do
      if request.target == "/echo".toUTF8 || request.target == "/legacy".toUTF8 then
        return { response := { body := request.body } }
      if request.target == "/binary".toUTF8 then return { response := { body := binary } }
      if request.target == "/large".toUTF8 then
        return { response := { body := ByteArray.mk (Array.replicate (2 * 1024 * 1024) (65 : UInt8)) } }
      if request.target == "/worker".toUTF8 then
        return { response := { headers := #[header "X-Worker" (toString worker)], body := (toString worker).toUTF8 } }
      if request.target == "/stats".toUTF8 then
        let stats ← diagnostics
        return { response := { headers := #[header "X-Worker" (toString worker),
          header "X-SSL-Calls" (toString stats.sslCalls),
          header "X-Owner-Violations" (toString stats.ownerViolations),
          header "X-Active-TLS-Threads" (toString stats.activeThreads)], body := (toString worker).toUTF8 } }
      if request.target == "/chunked".toUTF8 then
        return { response := { body := binary }, options := {
          framing := some .chunked, trailers := #[header "X-Finished" "yes"] } }
      if request.target == "/trailers".toUTF8 then
        let value := ((request.trailers.find? (fun h => h.name == "x-check")).map (·.value)).getD ByteArray.empty
        return { response := { body := (request.body.append "|".toUTF8).append value } }
      if request.target == "/close".toUTF8 then
        return { response := { body := binary }, options := { framing := some .closeDelimited } }
      if request.target == "/head".toUTF8 then return { response := { body := "representation".toUTF8 } }
      if request.target == "/204".toUTF8 then return { response := { status := 204 } }
      if request.target == "/304".toUTF8 then return { response := { status := 304 } }
      if request.target == "/invalid".toUTF8 then
        return { response := { headers := #[header "X-Test" "ok\r\nInjected: yes"] } }
      if request.target == "/custom".toUTF8 then
        return { response := { status := 299, body := "ready".toUTF8 }, options := { reason := some "Custom Ready" } }
      if request.target == "/informational".toUTF8 then
        return { response := { body := "ok".toUTF8 }, informational := #[({ status := 103 }, {}), ({ status := 102 }, {})] }
      return { response := { headers := #[header "Strict-Transport-Security" "max-age=31536000"],
                              body := "Hello from lean-net!\n".toUTF8 } }
  }

def main (args : List String) : IO UInt32 := do
  let some certA := args[0]? | throw (IO.userError "missing alpha certificate chain")
  let some keyA := args[1]? | throw (IO.userError "missing alpha private key")
  let some certB := args[2]? | throw (IO.userError "missing beta certificate chain")
  let some keyB := args[3]? | throw (IO.userError "missing beta private key")
  let some port := args[4]?.bind String.toNat? | throw (IO.userError "missing port")
  if port == 0 || port > 65535 then throw (IO.userError "invalid port")
  let mode := args[5]?.getD "normal"
  unless ["normal", "tiny", "bad-budget", "queue3", "deadlines", "cache-only"].contains mode do
    throw (IO.userError "invalid TLS reactor fixture mode")
  let workers := (args[6]?.bind String.toNat?).getD 4
  if workers == 0 || workers > 256 then throw (IO.userError "invalid worker count")
  if (mode == "tiny" || mode == "bad-budget") && workers != 1 then
    throw (IO.userError "bounded-pool fixture requires one worker")
  let tls : LeanNetTLS.Reactor.Config := {
    certificateChain := certA, privateKey := keyA,
    hosts := #[{ name := "alpha.test", certificateChain := certA, privateKey := keyA },
               { name := "beta.test", certificateChain := certB, privateKey := keyB }],
    queueCapacity := if mode == "tiny" || mode == "bad-budget" then 1 else if mode == "queue3" then 3 else 4,
    handshakeTimeoutMs := if mode == "deadlines" then 350 else 5000,
    shutdownTimeoutMs := 1000, tickets := mode != "cache-only" }
  let server : ServerConfig := if mode == "deadlines" then {
      maxClients := 8, idleTimeoutMs := 2000, requestTimeoutMs := 650, writeTimeoutMs := 1500 }
    else if mode == "tiny" || mode == "bad-budget" then { maxClients := 1 }
    else { maxClients := 64 }
  let native : Reactor.Config := if mode == "tiny" || mode == "bad-budget" then {
      maxConnections := 8, maxEvents := 8, maxWrites := 2,
      buffers4k := if mode == "tiny" then 4 else 3, buffers16k := 0, buffers64k := 0 }
    else {}
  let http : HTTP.ReactorServerConfig := {
    server, native, workers, outputBuffers := if mode == "tiny" || mode == "bad-budget" then 1 else 128 }
  LeanNetTLS.ReactorServer.serveFactoryWithDiagnostics handlers tls http "127.0.0.1" (UInt16.ofNat port)
  return 0
