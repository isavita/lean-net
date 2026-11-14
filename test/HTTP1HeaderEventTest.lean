import LeanNet.HTTP1.Parser

open LeanNet.HTTP1

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do throw (IO.userError message)

private def headerSplits (label : String) (head body pipeline decoded : ByteArray) : IO Unit := do
  for split in [0:head.size + 1] do
    let first := head.extract 0 split
    let rest := ((head.extract split head.size).append body).append pipeline
    let result := match (Parser.new).feedWithHeaders first with
      | .needMore parser => parser.feedWithHeaders rest
      | .headers request parser remaining => .headers request parser (remaining.append rest)
      | result => result
    match result with
    | .headers request parser remaining =>
      check (request.method == "POST" && request.target == "/".toUTF8) s!"{label}: incorrect head"
      check (request.headers.any (fun h => h.name == "host")) s!"{label}: missing head fields"
      check (remaining == body.append pipeline) s!"{label}: bytes consumed before event at split {split}"
      match parser.feedWithHeaders remaining with
      | .complete request trailing =>
        check (request.body == decoded && trailing == pipeline) s!"{label}: incorrect body or pipeline"
      | .headers .. => throw (IO.userError s!"{label}: duplicate header event")
      | .needMore _ => throw (IO.userError s!"{label}: request incomplete")
      | .error message => throw (IO.userError s!"{label}: {message}")
    | .error message => throw (IO.userError s!"{label}, split {split}: {message}")
    | _ => throw (IO.userError s!"{label}, split {split}: missing header event")

def main : IO Unit := do
  let pipeline := "GET /next HTTP/1.1\r\nHost: example.test\r\n\r\n".toUTF8
  headerSplits "fixed" "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n".toUTF8
    "data".toUTF8 pipeline "data".toUTF8
  headerSplits "chunked" "POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n".toUTF8
    "4\r\ndata\r\n0\r\n\r\n".toUTF8 pipeline "data".toUTF8
  match (Parser.new).feedWithHeaders ("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".toUTF8.append pipeline) with
  | .complete request rest => check (request.body.isEmpty && rest == pipeline) "bodyless request remainder"
  | _ => throw (IO.userError "bodyless request did not complete directly")
  IO.println "HTTP/1 header event tests passed"
