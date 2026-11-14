import LeanNet.HTTP1.Config

namespace LeanNet.HTTP1

private def requestPath (target : ByteArray) : ByteArray := Id.run do
  let raw := target.toList
  if raw.head? == some 47 then
    return ByteArray.mk ((raw.takeWhile (· != 63)).toArray)
  let afterScheme := (raw.dropWhile (· != 58)).drop 1
  match afterScheme with
  | 47 :: 47 :: rest =>
    let path := rest.dropWhile (fun c => c != 47 && c != 63)
    if path.isEmpty || path.head? == some 63 then return "/".toUTF8
    return ByteArray.mk ((path.takeWhile (· != 63)).toArray)
  | _ => return ByteArray.empty

/-- Demonstration route shared by HTTP/1 and HTTP/2 adapters. -/
def defaultRouter (request : Request) : IO Response := do
  if (request.method == "GET" || request.method == "HEAD") && requestPath request.target == "/".toUTF8 then
    return { status := 200, headers := #[{ name := "content-type", value := "text/plain; charset=utf-8".toUTF8 }],
             body := "Hello from lean-net!\n".toUTF8 }
  return { status := 404, headers := #[{ name := "content-type", value := "text/plain; charset=utf-8".toUTF8 }],
           body := "Not Found\n".toUTF8 }

end LeanNet.HTTP1
