import LeanNet.HTTP1.Parser

open LeanNet.HTTP1

private def runBody (size step : Nat) : IO Unit := do
  let header := s!"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {size}\r\n\r\n" |>.toUTF8
  let mut parser ← match (Parser.new).feed header with
    | .needMore parser => pure parser
    | .error message => throw (IO.userError message)
    | _ => throw (IO.userError "unexpected completion while reading header")
  let body := ByteArray.mk (Array.replicate size (97 : UInt8))
  let start ← IO.monoMsNow
  let mut offset := 0
  let mut complete := false
  while offset < size do
    let stop := min size (offset + step)
    match parser.feed (body.extract offset stop) with
    | .needMore next => parser := next
    | .complete request rest =>
      if stop != size || !rest.isEmpty || request.body != body then
        throw (IO.userError "incorrect completed body")
      complete := true
    | .error message => throw (IO.userError message)
    | .eof => throw (IO.userError "unexpected EOF")
    offset := stop
  unless complete do throw (IO.userError "body incomplete")
  let elapsed := (← IO.monoMsNow) - start
  IO.println s!"size={size} step={step} elapsed_ms={elapsed}"

def main (args : List String) : IO Unit := do
  let size := args.head?.bind String.toNat? |>.getD 1048576
  let step := (args.drop 1).head?.bind String.toNat? |>.getD 8192
  if size == 0 || step == 0 || size > 1048576 then
    throw (IO.userError "usage: HTTP1Perf size(1..1048576) step(>0)")
  runBody size step
