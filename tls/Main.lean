import LeanNetTLS
import LeanNet.HTTP.CLI

def main (args : List String) : IO UInt32 := do
  let options ← match LeanNet.HTTP.CLI.parse args with
    | .ok value => pure value | .error message => throw (IO.userError message)
  let (certificate, privateKey, argument) ← match options.positional with
    | [certificate, privateKey] => pure (certificate, privateKey, none)
    | [certificate, privateKey, argument] => pure (certificate, privateKey, some argument)
    | _ => throw (IO.userError "usage: lean-net-tls <cert.pem> <key.pem> [--enable-push] [--static DIRECTORY] [--static-memory MiB] [port]")
  let port ← match LeanNet.HTTP.CLI.port argument 8443 with
    | .ok value => pure value | .error message => throw (IO.userError message)
  let http : LeanNet.HTTP.ReactorServerConfig := { http2 := { enablePush := options.enablePush } }
  if let some root := options.staticRoot then
    let bytes := options.staticMemoryMiB * 1024 * 1024
    LeanNetTLS.Server.serveStaticWithOptions certificate privateKey root
      { builder := { maxFileBytes := bytes, maxPackBytes := bytes }, residentBytes := bytes }
      http "127.0.0.1" port
  else LeanNetTLS.Server.serveWithOptions certificate privateKey http "127.0.0.1" port
  return 0
