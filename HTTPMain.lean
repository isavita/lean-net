import LeanNet
import LeanNet.HTTP.CLI

def main (args : List String) : IO UInt32 := do
  let options ← match LeanNet.HTTP.CLI.parse args with
    | .ok value => pure value | .error message => throw (IO.userError message)
  if options.positional.length > 1 then
    throw (IO.userError "usage: lean-net-http1 [--enable-push] [--static DIRECTORY] [--static-memory MiB] [port]")
  let port ← match LeanNet.HTTP.CLI.port options.positional.head? 8080 with
    | .ok value => pure value | .error message => throw (IO.userError message)
  let http : LeanNet.HTTP.ReactorServerConfig := { http2 := { enablePush := options.enablePush } }
  if let some root := options.staticRoot then
    let bytes := options.staticMemoryMiB * 1024 * 1024
    LeanNet.HTTP.Static.serveRoot root
      { builder := { maxFileBytes := bytes, maxPackBytes := bytes }, residentBytes := bytes }
      http "127.0.0.1" port
  else LeanNet.HTTP2.serveWithOptions http "127.0.0.1" port
  return 0
