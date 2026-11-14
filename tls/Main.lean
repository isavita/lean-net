import LeanNetTLS

def main (args : List String) : IO UInt32 := do
  let (certificate, privateKey, port) ← match args with
    | [certificate, privateKey] => pure (certificate, privateKey, 8443)
    | [certificate, privateKey, port] =>
      match port.toNat? with
      | some n =>
        if n > 0 && n ≤ 65535 then pure (certificate, privateKey, n)
        else throw (IO.userError "port must be between 1 and 65535")
      | none => throw (IO.userError "port must be a decimal number")
    | _ => throw (IO.userError "usage: lean-net-tls <cert.pem> <key.pem> [port]")
  LeanNetTLS.Server.serve certificate privateKey "127.0.0.1" (UInt16.ofNat port)
  return 0
