import LeanNet.HTTP1.Server

open LeanNet.HTTP1

private def fixtureRouter (request : Request) : IO Response := do
  if request.target == "/echo".toUTF8 then
    return { body := request.body }
  if request.target == "/binary".toUTF8 then
    return { headers := #[{ name := "content-type", value := "application/octet-stream".toUTF8 }],
             body := ByteArray.mk #[0, 255, 13, 10, 65] }
  if request.target == "/large".toUTF8 then
    return { body := ByteArray.mk (Array.replicate (8 * 1024 * 1024) (65 : UInt8)) }
  if request.target == "/oversized".toUTF8 then
    return { body := ByteArray.mk (Array.replicate (8 * 1024 * 1024 + 1) (65 : UInt8)) }
  if request.target == "/invalid".toUTF8 then
    return { headers := #[{ name := "X-Invalid", value := "ok\r\nInjected: yes".toUTF8 }] }
  if request.target == "/throw".toUTF8 then
    throw (IO.userError "intentional test router failure")
  if request.target == "/date".toUTF8 then
    return { headers := #[{ name := "dAtE", value := "Sun, 06 Nov 1994 08:49:37 GMT".toUTF8 }] }
  if request.target == "/204".toUTF8 then return { status := 204 }
  if request.target == "/205".toUTF8 then return { status := 205 }
  if request.target == "/304".toUTF8 then return { status := 304 }
  return { status := 404 }

def main (args : List String) : IO UInt32 := do
  let some port := args.head?.bind String.toNat? | throw (IO.userError "usage: fixture PORT")
  if port == 0 || port > 65535 then throw (IO.userError "invalid port")
  if args.drop 1 == ["deadlines"] then
    let config : ServerConfig := { maxClients := 1, idleTimeoutMs := 350, requestTimeoutMs := 650, writeTimeoutMs := 5000 }
    serveWithConfig fixtureRouter config "127.0.0.1" (UInt16.ofNat port)
  else if args.drop 1 == ["zero"] then
    let config : ServerConfig := { maxResponseBytes := 0, maxResponseHeaders := 0, maxResponseHeaderBytes := 0 }
    serveWithConfig fixtureRouter config "127.0.0.1" (UInt16.ofNat port)
  else
    serveWith fixtureRouter "127.0.0.1" (UInt16.ofNat port)
  return 0
