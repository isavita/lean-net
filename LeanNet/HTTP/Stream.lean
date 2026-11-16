import LeanNet.HTTP.Cancel
import LeanNet.HTTP1.Request

namespace LeanNet.HTTP.Stream

/-- One owned application output event. `finish` carries final HTTP trailers. -/
inductive Event where
  | data (bytes : ByteArray)
  | finish (trailers : Array HTTP1.Header := #[])

/-- A cooperative body producer. All callbacks execute on its reactor worker.
`poll budget` must not block and may retain at most `retainedBytes`; data must
contain 1..budget bytes. Budget zero permits only pending or finish, allowing
trailers to complete without HTTP/2 DATA credit. The server retains at most one
64KiB chunk and stops pulling while its output/flow credits are unavailable.

`close none` means the producer finished or its HEAD body was suppressed;
`close (some reason)` is cancellation. The owner invokes close exactly once,
removing the producer before calling it. Completion means admission into the
bounded output queue, not an acknowledgement by the remote application. -/
structure Body where
  poll : Nat → IO (Option Event)
  close : Option Deferred.CancelReason → IO Unit := fun _ => pure ()
  retainedBytes : Nat := 65536
  knownLength : Option Nat := none
  declaredTrailers : Array String := #[]
  idleTimeoutMs : Nat := 30000
  lifetimeMs : Nat := 3600000

def Body.validate (body : Body) : Except String Unit := do
  if body.idleTimeoutMs == 0 || body.lifetimeMs == 0 ||
      body.idleTimeoutMs > 9223372036854775807 || body.lifetimeMs > 9223372036854775807 ||
      body.knownLength.any (· > 18446744073709551615) || body.declaredTrailers.size > 100 then
    throw "invalid application stream bounds"
  for name in body.declaredTrailers do
    if name.isEmpty || name.utf8ByteSize > 256 || name.toUTF8.data.any (fun b =>
        !((b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122) ||
          [33,35,36,37,38,39,42,43,45,46,94,95,96,124,126].contains b.toNat)) ||
        ["content-length", "transfer-encoding", "connection", "host", "trailer", "upgrade",
          "set-cookie", "cookie", "authorization", "proxy-authorization", "te"].contains name.toLower then
      throw "invalid application stream trailer declaration"

end LeanNet.HTTP.Stream
