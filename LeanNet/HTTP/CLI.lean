namespace LeanNet.HTTP.CLI

structure Options where
  enablePush : Bool := false
  staticRoot : Option System.FilePath := none
  staticMemoryMiB : Nat := 8
  positional : List String := []
  private memoryExplicit : Bool := false

private def collect (args : List String) (options : Options) : Except String Options :=
  match args with
  | [] => .ok { options with positional := options.positional.reverse }
  | "--" :: rest => .ok { options with positional := options.positional.reverse ++ rest }
  | "--enable-push" :: rest => collect rest { options with enablePush := true }
  | "--static" :: directory :: rest =>
    if options.staticRoot.isSome then .error "--static may be supplied once"
    else if directory.isEmpty || directory.startsWith "--" then .error "--static requires a directory"
    else collect rest { options with staticRoot := some (System.FilePath.mk directory) }
  | "--static" :: [] => .error "--static requires a directory"
  | "--static-memory" :: amount :: rest =>
    match amount.toNat? with
    | some value =>
      if value == 0 || value > 1024 then .error "--static-memory must be between 1 and 1024 MiB"
      else collect rest { options with staticMemoryMiB := value, memoryExplicit := true }
    | none => .error "--static-memory requires a decimal MiB budget"
  | "--static-memory" :: [] => .error "--static-memory requires a MiB budget"
  | arg :: rest =>
    if arg.startsWith "--" then .error s!"unknown option: {arg}"
    else collect rest { options with positional := arg :: options.positional }

def parse (args : List String) : Except String Options := do
  let options ← collect args {}
  if options.memoryExplicit && options.staticRoot.isNone then
    throw "--static-memory requires --static"
  return options

def port (argument : Option String) (fallback : UInt16) : Except String UInt16 := do
  let some text := argument | return fallback
  let some value := text.toNat? | throw "port must be a decimal number"
  if value == 0 || value > 65535 then throw "port must be between 1 and 65535"
  return value.toUInt16

end LeanNet.HTTP.CLI
