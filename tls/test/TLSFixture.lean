import LeanNetTLS.Server

open LeanNet.HTTP1

private def router (request : Request) : IO Response := do
  if request.target == "/binary".toUTF8 then
    return { body := ByteArray.mk #[0, 255, 13, 10, 65] }
  if request.target == "/echo".toUTF8 then return { body := request.body }
  if request.target == "/large".toUTF8 then
    return { body := ByteArray.mk (Array.replicate (4 * 1024 * 1024) (65 : UInt8)) }
  return ← defaultRouter request

def main (args : List String) : IO UInt32 := do
  let cert ← match args[0]? with | some value => pure value | none => throw (IO.userError "missing cert")
  let key ← match args[1]? with | some value => pure value | none => throw (IO.userError "missing key")
  let some port := args[2]?.bind String.toNat? | throw (IO.userError "missing port")
  if args.drop 3 == ["deadlines"] then
    let config : ServerConfig := { maxClients := 1, idleTimeoutMs := 350, requestTimeoutMs := 650, writeTimeoutMs := 5000 }
    LeanNetTLS.Server.serveWithConfig router config cert key "127.0.0.1" (UInt16.ofNat port)
  else
    LeanNetTLS.Server.serveWith router cert key "127.0.0.1" (UInt16.ofNat port)
  return 0
