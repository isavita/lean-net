import LeanNet

/-! Admission hook fixture: a hand-written hook exercising reject, body limits
    and dispatch over HTTP/1.1, h2c prior knowledge and h2c Upgrade. -/

open LeanNet LeanNet.HTTP LeanNet.HTTP1

private def text (status : Nat) (body : String) : Reply :=
  { response := { status, headers := #[{ name := "content-type", value := "text/plain".toUTF8 }], body := body.toUTF8 } }

private def hook (decisions : IO.Ref Nat) : Admission.Hook := {
  decide := fun facts head => do
    decisions.modify (· + 1)
    let path := (String.fromUTF8? head.target).getD ""
    if head.authority == "blocked.test".toUTF8 then
      return .reject { status := 403, body := "forbidden\n".toUTF8 }
    if path.startsWith "/limited" then
      return .reject { status := 429, headers := #[{ name := "retry-after", value := "1".toUTF8 }] }
    if path == "/small" then return .accept (some 8)
    if path == "/dispatch" then
      let kind := match head.kind with
        | .request => "request" | .upgrade => "upgrade" | .tunnel => "tunnel" | .internal => "internal"
      return .accept none (some fun request => pure (text 200
        s!"dispatched secure={facts.secure} peer={facts.peer.size} kind={kind} body={request.body.size}\n"))
    if path == "/decisions" then
      return .accept none (some fun _ => do pure (text 200 s!"{← decisions.get}\n"))
    return .accept }

private def handlers : Handlers := {
  onRequest := fun request => pure (text 200 s!"app body={request.body.size}\n") }

def main (args : List String) : IO Unit := do
  let some port := args.head?.bind String.toNat? | throw (IO.userError "expected port")
  let decisions ← IO.mkRef 0
  ReactorServer.serveWithHandlers handlers { admission := some (Admission.Factory.shared (hook decisions)) } "127.0.0.1" port.toUInt16
