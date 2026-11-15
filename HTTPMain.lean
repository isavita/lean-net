import LeanNet
import LeanNet.HTTP.CLI

def main (args : List String) : IO UInt32 := do
  let options ← match LeanNet.HTTP.CLI.parse args with
    | .ok value => pure value | .error message => throw (IO.userError message)
  if options.positional.length > 1 then
    throw (IO.userError "usage: lean-net-http1 [--workers N] [--max-clients N] [--metrics] [--access-log PATH] [--log-helper PATH] [--enable-push] [--static DIRECTORY] [--static-memory MiB] [port]")
  let port ← match LeanNet.HTTP.CLI.port options.positional.head? 8080 with
    | .ok value => pure value | .error message => throw (IO.userError message)
  options.serve "127.0.0.1" port
  return 0
