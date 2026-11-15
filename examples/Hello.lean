import LeanNet

open LeanNet

private def parsePort : List String → Except String UInt16
  | [] => .ok 8080
  | [text] => do
    if text.isEmpty || !text.toUTF8.data.all (fun byte => byte >= 48 && byte <= 57) then
      throw "PORT must be an integer from 1 to 65535"
    let some value := text.toNat? | throw "invalid PORT"
    if value == 0 || value > 65535 then throw "PORT must be between 1 and 65535"
    return value.toUInt16
  | _ => .error "usage: hello-server [PORT]"

def main (args : List String) : IO Unit := do
  let port ← match parsePort args with
    | .ok port => pure port
    | .error message => throw (IO.userError message)
  HTTP.ReactorServer.serveFactory
    (fun _ => pure {
      onRequest := fun _ =>
        pure { response := {
          headers := #[{ name := "content-type", value := "text/plain; charset=utf-8".toUTF8 }]
          body := "Hello from lean-net!\n".toUTF8 } }
    })
    { workers := 0, server := { maxClients := 128 } }
    "127.0.0.1" port
