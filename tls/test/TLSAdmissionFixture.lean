import LeanNetTLS

/-! TLS admission fixture: reports the transport facts the hook receives. -/

open LeanNet LeanNet.HTTP LeanNet.HTTP1

def main (args : List String) : IO UInt32 := do
  let some cert := args[0]? | throw (IO.userError "missing cert")
  let some key := args[1]? | throw (IO.userError "missing key")
  let some port := args[2]?.bind String.toNat? | throw (IO.userError "missing port")
  let clientCA := args[3]?
  let hook : Admission.Hook := { decide := fun facts head => do
    let sni := match facts.sni with | some name => (String.fromUTF8? name).getD "?" | none => "none"
    let principal := match facts.principal with
      | some identity => ",".intercalate identity.subjectAltNames.toList
      | none => "none"
    let line := s!"secure={facts.secure} sni={sni} alpn={(String.fromUTF8? facts.alpn).getD "?"} peer={facts.peer.size} principal={principal} authority={(String.fromUTF8? head.authority).getD "?"}\n"
    return .accept none (some fun _ => pure { response := { status := 200, body := line.toUTF8 } }) }
  let tls : LeanNetTLS.Reactor.Config := { certificateChain := cert, privateKey := key, clientCA }
  LeanNetTLS.ReactorServer.serveFactory (fun _ => pure Handlers.default) tls
    { admission := some hook, workers := 2 } "127.0.0.1" port.toUInt16
  return 0
