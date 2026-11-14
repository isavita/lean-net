import LeanNet

def main (args : List String) : IO UInt32 := do
  let port ← match args with
    | [] => pure 8080
    | [arg] =>
      match arg.toNat? with
      | some n =>
        if n > 0 && n ≤ 65535 then pure n
        else throw (IO.userError "port must be between 1 and 65535")
      | none => throw (IO.userError "port must be a decimal number")
    | _ => throw (IO.userError "usage: lean-net-http1 [port]")
  LeanNet.HTTP2.serve "127.0.0.1" (UInt16.ofNat port)
  return 0
