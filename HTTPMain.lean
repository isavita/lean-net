import LeanNet
import LeanNet.HTTP.CLI

def main (args : List String) : IO UInt32 := do
  let options ← match LeanNet.HTTP.CLI.parse args with
    | .ok value => pure value | .error message => throw (IO.userError message)
  if options.positional.length > 1 then
    throw (IO.userError "usage: lean-net-http1 [--host ADDR] [--workers N] [--max-clients N] [--connection-rate TOKENS/PERIOD_MS/BURST] [--metrics] [--access-log PATH] [--access-log-queue-capacity RECORDS] [--log-helper PATH] [--http2-ping-ms MS] [--http2-ping-timeout-ms MS] [--enable-push] [--static DIRECTORY] [--static-memory MiB] [--no-security-headers] [--health] [--admin-port PORT] [--pin-workers] [--gate POLICY] [port]")
  let port ← match LeanNet.HTTP.CLI.port options.positional.head? 8080 with
    | .ok value => pure value | .error message => throw (IO.userError message)
  options.serve (options.listenHost "127.0.0.1") port
  return 0
