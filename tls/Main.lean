import LeanNetTLS
import LeanNet.HTTP.CLI
import LeanNetTLS.CLI

def main (args : List String) : IO UInt32 := do
  let options ← match LeanNet.HTTP.CLI.parse args with
    | .ok value => pure value | .error message => throw (IO.userError message)
  let (certificate, privateKey, argument) ← match options.positional with
    | [certificate, privateKey] => pure (certificate, privateKey, none)
    | [certificate, privateKey, argument] => pure (certificate, privateKey, some argument)
    | _ => throw (IO.userError "usage: lean-net-tls <cert.pem> <key.pem> [--reload-certs-ms MS] [--workers N] [--max-clients N] [--metrics] [--access-log PATH] [--log-helper PATH] [--http2-ping-ms MS] [--http2-ping-timeout-ms MS] [--enable-push] [--static DIRECTORY] [--static-memory MiB] [port]")
  let port ← match LeanNet.HTTP.CLI.port argument 8443 with
    | .ok value => pure value | .error message => throw (IO.userError message)
  LeanNetTLS.CLI.serve options certificate privateKey "127.0.0.1" port
  return 0
