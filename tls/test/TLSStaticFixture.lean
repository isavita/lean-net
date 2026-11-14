import LeanNetTLS.ReactorServer

open LeanNet

def main (args : List String) : IO UInt32 := do
  let some root := args[0]? | throw (IO.userError "missing static root")
  let some certificate := args[1]? | throw (IO.userError "missing certificate")
  let some key := args[2]? | throw (IO.userError "missing private key")
  let some port := args[3]?.bind String.toNat? | throw (IO.userError "missing port")
  if port == 0 || port > 65535 then throw (IO.userError "invalid port")
  let http : HTTP.ReactorServerConfig := {
    workers := 1
    outputBuffers := 8
    server := {
      maxClients := 8
      idleTimeoutMs := 30000
      requestTimeoutMs := 30000
      writeTimeoutMs := 30000 }
    native := {
      maxConnections := 16
      maxEvents := 32
      maxWrites := 64
      buffers4k := 64
      buffers16k := 4
      buffers64k := 2 } }
  let tls : LeanNetTLS.Reactor.Config := {
    certificateChain := certificate
    privateKey := key
    queueCapacity := 1
    handshakeTimeoutMs := 5000
    shutdownTimeoutMs := 1000 }
  LeanNetTLS.ReactorServer.serveStaticRoot (System.FilePath.mk root) tls {} http "127.0.0.1" (UInt16.ofNat port)
  return 0
