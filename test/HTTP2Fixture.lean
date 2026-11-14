import LeanNet.HTTP2.Server

open LeanNet.HTTP1

private def router (request : Request) : IO Response := do
  if request.target == "/echo".toUTF8 then return { body := request.body }
  if request.target == "/binary".toUTF8 then
    return { headers := #[{ name := "content-type", value := "application/octet-stream".toUTF8 }],
             body := ByteArray.mk #[0, 255, 13, 10, 65] }
  if request.target == "/large".toUTF8 then
    return { body := ByteArray.mk (Array.replicate (256 * 1024) (65 : UInt8)) }
  if request.target == "/huge".toUTF8 then
    return { body := ByteArray.mk (Array.replicate (8 * 1024 * 1024) (65 : UInt8)) }
  return { status := 404 }

def main (args : List String) : IO Unit := do
  let some port := args.head?.bind String.toNat? | throw (IO.userError "expected port")
  if port == 0 || port > 65535 then throw (IO.userError "invalid port")
  let config : ServerConfig := { idleTimeoutMs := 10000, requestTimeoutMs := 1500,
                                  writeTimeoutMs := 10000 }
  LeanNet.HTTP2.serveWith router config "127.0.0.1" (UInt16.ofNat port)
