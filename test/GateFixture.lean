import LeanNet

/-! End-to-end gate fixture: a text policy plus application handlers. -/

open LeanNet LeanNet.HTTP LeanNet.HTTP1 LeanNet.Gate

private def policy := "
limits { headers 40 ; header-bytes 8KiB }
ratelimit perclient 3/m burst 3 by client-ip
ratelimit perroute 2/m burst 2 by route
host api.test, api.test:8443 {
  tls sni off
  headers { forbid x-internal-* ; strip x-debug }
  route GET      /items/:id      -> app item
  route POST     /upload         -> app upload { body 16 }
  route POST     /stream         -> app stream { body 16 }
  route *        /admin/*        -> deny 403
  route GET      /legacy         -> app
  route GET      /keyed          -> app item { check api-key }
  route GET      /limited        -> app item { limit perclient }
  route GET      /route-a        -> app item { limit perroute }
  route GET      /route-b        -> app item { limit perroute }
}
host *.tenant.test { tls sni off ; route * /* -> app tenant }
on unknown-host 421
"

private def text (body : String) : Reply :=
  { response := { status := 200, headers := #[{ name := "content-type", value := "text/plain".toUTF8 }], body := body.toUTF8 } }

private def app : App := {
  handlers := #[
    ("item", fun a request => pure (text
      s!"item id={(String.fromUTF8? ((a.capture "id").getD .empty)).getD "?"} host={(String.fromUTF8? a.authority.host).getD "?"} debug={request.headers.any (·.name == "x-debug")}\n")),
    ("upload", fun _ request => pure (text s!"upload bytes={request.body.size}\n")),
    ("stream", fun _ request => pure (text s!"stream bytes={request.body.size} trailers={request.trailers.size}\n")),
    ("tenant", fun a request => pure (text s!"tenant={(String.fromUTF8? a.authority.host).getD "?"} path={(String.fromUTF8? a.path.path).getD "?"} method={request.method}\n"))]
  checks := #[("api-key", fun a => pure <|
    if a.head.headers.any (fun h => h.name == "x-api-key" && h.value == "secret".toUTF8) then .ok ()
    else .error (.make .checkFailed 401))] }

private def server : Handlers := {
  onRequest := fun request => pure (text s!"server debug={request.headers.any (·.name == "x-debug")}\n")
  streamRequests := fun head => pure (head.target == "/stream".toUTF8) }

def main (args : List String) : IO Unit := do
  let some port := args.head?.bind String.toNat? | throw (IO.userError "expected port")
  let spec ← IO.ofExcept ((Spec.parse policy).mapError toString)
  RateLimiter.withLimiter spec 1 fun limits => do
    let factory ← IO.ofExcept ((Gate.factory { spec, app, limiter := some limits.limiter }).mapError toString)
    ReactorServer.serveWithHandlers server { admission := some factory } "127.0.0.1" port.toUInt16
