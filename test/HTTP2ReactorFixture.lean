import LeanNet.HTTP.ReactorServer

open LeanNet
open LeanNet.HTTP1

private def header (name value : String) : Header := { name, value := value.toUTF8 }
private def binary : ByteArray := ByteArray.mk #[0, 255, 13, 10, 65]
private def large (byte : UInt8 := 65) (size : Nat := 256 * 1024) : ByteArray :=
  ByteArray.mk (Array.replicate size byte)

private def handlers (worker : Nat) : IO Handlers := do
  return {
    onRequest := fun request => do
      if request.target == "/binary".toUTF8 then
        return { response := { headers := #[header "content-type" "application/octet-stream"], body := binary } }
      if request.target == "/echo".toUTF8 then return { response := { body := request.body } }
      if request.target == "/trailers".toUTF8 then
        let trailer := ((request.trailers.find? (fun h => h.name == "x-check")).map (·.value)).getD ByteArray.empty
        return { response := { body := (request.body.append "|".toUTF8).append trailer } }
      if request.target == "/response-trailers".toUTF8 then
        return { response := { body := binary }, options := { trailers := #[header "x-finished" "yes"] } }
      if request.target == "/informational".toUTF8 then
        return { response := { body := "ok".toUTF8 }, informational := #[
          ({ status := 103, headers := #[header "link" "</asset>; rel=preload"] }, {}), ({ status := 102 }, {})] }
      if request.target == "/large".toUTF8 || request.target == "/priority-a".toUTF8 then
        return { response := { body := large 65 } }
      if request.target == "/priority-b".toUTF8 then return { response := { body := large 66 } }
      if request.target == "/priority-c".toUTF8 then return { response := { body := large 67 } }
      if request.target == "/huge".toUTF8 then return { response := { body := large 65 (2 * 1024 * 1024) } }
      if request.target == "/worker".toUTF8 then
        return { response := { headers := #[header "x-worker" (toString worker)], body := (toString worker).toUTF8 } }
      if request.target == "/sensitive".toUTF8 then
        return { response := { headers := #[header "authorization" "Bearer response-secret",
          header "cookie" "request-looking-secret=yes", header "set-cookie" "session=response-secret; Secure"], body := binary } }
      if request.target == "/big-headers".toUTF8 then
        return { response := { headers := #[{ name := "x-large", value := large 120 32000 }], body := binary } }
      if request.target == "/head".toUTF8 then return { response := { body := "representation".toUTF8 } }
      if request.target == "/204".toUTF8 then return { response := { status := 204 } }
      if request.target == "/304".toUTF8 then return { response := { status := 304 } }
      if request.target == "/push-parent".toUTF8 then return { response := { body := "parent".toUTF8 } }
      if request.target == "/pushed-a".toUTF8 then return { response := { body := "pushed-a".toUTF8 } }
      if request.target == "/pushed-b".toUTF8 then return { response := { body := "pushed-b".toUTF8 } }
      return { response := { body := "Hello from lean-net!\n".toUTF8 } }
    onPush := fun request => do
      if request.target != "/push-parent".toUTF8 then return #[]
      return #[{
          target := "/pushed-a".toUTF8,
          headers := #[header "authorization" "Bearer push-secret", header "cookie" "push-cookie=secret"],
          response := { headers := #[header "set-cookie" "pushed=a; Secure"], body := "pushed-a".toUTF8 } },
        { target := "/pushed-b".toUTF8,
          response := { body := "pushed-b".toUTF8 } }]
  }

def main (args : List String) : IO UInt32 := do
  let some port := args[0]?.bind String.toNat? | throw (IO.userError "usage: fixture PORT [mixed|mixed-limits|h2-only|push|limits|bench|bench-observe] [WORKERS]")
  if port == 0 || port > 65535 then throw (IO.userError "invalid port")
  let mode := args[1]?.getD "mixed"
  unless ["mixed", "mixed-limits", "h2-only", "push", "limits", "bench", "bench-observe"].contains mode do throw (IO.userError "invalid HTTP/2 fixture mode")
  let benchmark := mode == "bench" || mode == "bench-observe"
  let accessLog ← if mode == "bench-observe" then do
      let executable ← IO.appPath
      let directory := executable.parent.getD (System.FilePath.mk ".")
      pure (some {
        path := System.FilePath.mk (if System.Platform.isWindows then "NUL" else "/dev/null"),
        helperBinary := directory / (if System.Platform.isWindows then "lean-net-access-log-helper.exe" else "lean-net-access-log-helper")
        : HTTP.Observability.AccessConfig })
    else pure none
  let workers := (args[2]?.bind String.toNat?).getD 1
  if workers == 0 || workers > 256 then throw (IO.userError "invalid worker count")
  let connection : HTTP2.Connection.Config := if mode == "limits" then {
      maxConcurrentStreams := 2, initialWindowSize := 1024, maxHeaderListBytes := 2048,
      maxHeaderFields := 16, maxHeaderBlockBytes := 4096, maxContinuationFrames := 4,
      maxRequestBodyBytes := 4096, maxBufferedRequestBytes := 8192 }
    else if mode == "mixed-limits" then { maxRequestBodyBytes := 16 }
    else { enablePush := mode == "push" }
  let config : HTTP.ReactorServerConfig := {
    workers, http2 := connection,
    machine := if mode == "mixed-limits" then { limits := { maxBodyBytes := 8 } } else {},
    cleartextProtocol := if mode == "mixed" || mode == "mixed-limits" then .detect else .http2,
    server := { maxClients := if benchmark then 128 else 64,
                maxResponseBytes := 8 * 1024 * 1024, maxResponseHeaderBytes := 65536 },
    outputBuffers := if benchmark then 512 else 128,
    metricsPath := if mode == "bench-observe" then some "/metrics".toUTF8 else none,
    accessLog }
  HTTP.ReactorServer.serveFactory handlers config "127.0.0.1" (UInt16.ofNat port)
  return 0
