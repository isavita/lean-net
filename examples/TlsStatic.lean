import LeanNetTLS

open LeanNet

private def parsePort (text : String) : IO UInt16 := do
  let some port := text.toNat?
    | throw (IO.userError "PORT must be an integer from 1 to 65535")
  if port == 0 || port > 65535 then
    throw (IO.userError "PORT must be an integer from 1 to 65535")
  return port.toUInt16

def main (args : List String) : IO Unit := do
  let (root, certificate, key, port) ← match args with
    | [root, certificate, key] => pure (root, certificate, key, (8443 : UInt16))
    | [root, certificate, key, port] => pure (root, certificate, key, ← parsePort port)
    | _ => throw (IO.userError "usage: tls-static-server ROOT CERTIFICATE_CHAIN_PEM PRIVATE_KEY_PEM [PORT]")
  LeanNetTLS.ReactorServer.serveStaticRoot root
    { certificateChain := certificate, privateKey := key }
    { residentBytes := 1024 * 1024 }
    { workers := 0
      server := { maxClients := 128 }
      healthPaths := true
      metricsPath := some "/metrics".toUTF8 }
    "127.0.0.1" port
