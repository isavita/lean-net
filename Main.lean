import LeanNet

def main (args : List String) : IO UInt32 := do
  let port ← match args with
    | [] => pure 8080
    | [arg] | [arg, _] =>
      match arg.toNat? with
      | some n =>
        if n > 0 && n ≤ 65535 then pure n
        else throw (IO.userError "port must be between 1 and 65535")
      | none => throw (IO.userError "port must be a decimal number")
    | _ => throw (IO.userError "usage: lean-net-echo [port [workers]]")
  let workers ← match args[1]? with
    | none => pure 0
    | some text =>
      match text.toNat? with
      | some n => if n > 0 && n ≤ 256 then pure n else throw (IO.userError "workers must be between 1 and 256")
      | none => throw (IO.userError "workers must be a decimal number")
  LeanNet.Echo.serve "127.0.0.1" (UInt16.ofNat port) workers
  return 0
