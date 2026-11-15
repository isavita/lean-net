import LeanNet.HTTP.ReactorServer

open LeanNet
open LeanNet.HTTP1

private def header (name value : String) : Header := { name, value := value.toUTF8 }
private def binary : ByteArray := ByteArray.mk #[0, 255, 13, 10, 65]
private def large : ByteArray := ByteArray.mk (Array.replicate (2 * 1024 * 1024) (65 : UInt8))

private def handlers (worker : Nat) (file : FileRegion) : Handlers := {
  onHeaders := fun head _ => do
    if head.target == "/refuse".toUTF8 then
      return .reject { response := { status := 417, body := "refused".toUTF8 } }
    if head.target == "/upgrade".toUTF8 then
      let pipe : RawPipe := {
        onBytes := fun view => pure { output := #[view] }
        onEOF := pure { output := #[ByteSlice.full "raw-eof".toUTF8], closeAfterWrites := true } }
      return .upgrade { response := { status := 101, headers := #[header "Upgrade" "obs-echo"] } } pipe
    return .accept none
  onRequest := fun request => do
    -- The logger, rather than the application, removes query strings.
    let path := (String.fromUTF8! request.target).splitOn "?" |>.head!
    if path == "/binary" then
      return { response := { headers := #[header "content-type" "application/octet-stream"], body := binary } }
    if path == "/chunked" then
      return { response := { body := binary }, options := {
        framing := some .chunked, trailers := #[header "x-finished" "yes"] } }
    if path == "/trailers" then
      let trailer := ((request.trailers.find? (fun h => h.name == "x-check")).map (·.value)).getD ByteArray.empty
      return { response := { body := (request.body.append "|".toUTF8).append trailer } }
    if path == "/echo" then return { response := { body := request.body } }
    if path == "/head" then return { response := { body := "representation".toUTF8 } }
    if path == "/204" then return { response := { status := 204 } }
    if path == "/304" then return { response := { status := 304 } }
    if path == "/invalid" then
      return { response := { headers := #[header "x-test" "ok\r\nInjected: yes"] } }
    if path == "/informational" then
      return { response := { body := "ok".toUTF8 }, informational := #[({ status := 103 }, {}), ({ status := 102 }, {})] }
    if path == "/custom" then
      return { response := { status := 299, body := "ready".toUTF8 }, options := { reason := some "Custom Ready" } }
    if path == "/large" then return { response := { body := large } }
    if path == "/file" then return { response := {}, fileRegion := some file }
    if path == "/worker" then
      return { response := { headers := #[header "x-worker" (toString worker)], body := (toString worker).toUTF8 } }
    if path.startsWith "/item/" then
      return { response := { body := (path.drop 6).toString.toUTF8 } }
    return { response := { body := "ok".toUTF8 } }
}

def main (args : List String) : IO UInt32 := do
  let some port := args[0]?.bind String.toNat? |
    throw (IO.userError "usage: observability-fixture PORT LOGPATH HELPER [WORKERS] [normal|overflow]")
  if port == 0 || port > 65535 then throw (IO.userError "invalid port")
  let some path := args[1]? | throw (IO.userError "missing log path")
  let some helper := args[2]? | throw (IO.userError "missing helper")
  let workers := (args[3]?.bind String.toNat?).getD 1
  let mode := args[4]?.getD "normal"
  if workers == 0 || workers > 64 || !["normal", "overflow"].contains mode then
    throw (IO.userError "invalid worker count or fixture mode")
  let source ← File.withBuilder "." {} fun builder => do
    let _ ← builder.addBytes (ByteArray.mk (Array.replicate (1024 * 1024) (65 : UInt8))) 0
    builder.publish (8 * 1024 * 1024) true
  try
    let config : HTTP.ReactorServerConfig := {
      workers, metricsPath := some "/metrics".toUTF8,
      accessLog := some {
        path := System.FilePath.mk path, helperBinary := System.FilePath.mk helper,
        queueCapacity := if mode == "overflow" then 1 else 4096,
        maxFileBytes := 16 * 1024 * 1024, fileCount := 2, pollIntervalMs := 1 },
      server := { maxClients := 64, maxResponseBytes := 4 * 1024 * 1024 },
      outputBuffers := 256 }
    HTTP.ReactorServer.serveWorkerFactory (fun worker _ reactor use => do
      reactor.setupFiles 1
      let region ← reactor.importFile source
      use HTTP.Transport.plain (handlers worker region)) config "127.0.0.1" (UInt16.ofNat port)
  finally source.close
  return 0
