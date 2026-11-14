import LeanNet.HTTP1.Machine

open LeanNet LeanNet.HTTP1

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do throw (IO.userError message)
private def ok (value : Except String α) : IO α := do
  match value with
  | .ok result => return result
  | .error message => throw (IO.userError message)
private def rejected (value : Except String α) : IO Unit :=
  match value with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError "invalid file response accepted")
private def joined (parts : Array ByteArray) : ByteArray := parts.foldl ByteArray.append ByteArray.empty
private def contains (bytes : ByteArray) (text : String) : Bool := Id.run do
  let needle := text.toUTF8
  for i in [:bytes.size + 1] do
    if bytes.extract i (i + needle.size) == needle then return true
  return false
private def region : FileRegion := { owner := 7, token := 11, offset := 31, length := 1000000 }
private def get : ByteArray := "GET /file HTTP/1.1\r\nHost: x\r\n\r\n".toUTF8
private def application (request : ByteArray) (state : Machine.State := Machine.State.new) : IO (Nat × Nat × Machine.State) := do
  let head := state.feed request
  let [(id, _, _)] := head.actions.filterMap (fun | .inspectHead id head framing => some (id, head, framing) | _ => none)
    | throw (IO.userError "missing header decision")
  let accepted := head.state.decideHead id (.accept none)
  let ready := accepted.state.feed ByteArray.empty
  check (ready.actions.any (fun | .request actual _ => actual == id | _ => false)) "missing application action"
  return (id, head.consumed, ready.state)
private def byteWrite (step : Machine.Step) : IO ByteArray := do
  let [parts] := step.actions.filterMap (fun | .write _ parts _ => some parts | _ => none)
    | throw (IO.userError "expected one byte output")
  return joined parts

private def encoding : IO Unit := do
  let encoded ← ok (({} : Response).encodeFileFor region {})
  check (encoded.fileRegion == some region && encoded.framing == .contentLength 1000000 &&
    encoded.next == .nextRequest .keepAlive) "GET file metadata"
  check (joined encoded.headParts == "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n".toUTF8) "file headers contain payload or wrong length"
  let head ← ok (({} : Response).encodeFileFor region { requestMethod := "HEAD" })
  check (head.fileRegion.isNone && joined head.headParts == joined encoded.headParts) "HEAD did not preserve GET metadata without source IO"
  let empty ← ok (({} : Response).encodeFileFor { region with length := 0 } {})
  check (empty.fileRegion.isNone && empty.framing == .contentLength 0) "empty file means empty response"
  let ranged ← ok (({ status := 206, headers := #[{ name := "Content-Range", value := "bytes 2-4/10".toUTF8 }] } : Response).encodeFileFor
    { region with offset := 33, length := 3 } {})
  check (ranged.fileRegion == some { region with offset := 33, length := 3 } &&
    contains (joined ranged.headParts) "Content-Length: 3\r\n") "range metadata"
  let legacy ← ok (({} : Response).encodeFileFor region { version := .http10 })
  check (legacy.next == .nextRequest .close && contains (joined legacy.headParts) "Connection: close\r\n") "HTTP/1.0 file closure"
  let keep ← ok (({} : Response).encodeFileFor region { version := .http10, requestHeaders := #[{ name := "connection", value := "keep-alive".toUTF8 }] })
  check (keep.next == .nextRequest .keepAlive && contains (joined keep.headParts) "Connection: keep-alive\r\n") "HTTP/1.0 file persistence"
  let dated ← ok (({} : Response).encodeFileFor region { date := some "Sun, 06 Nov 1994 08:49:37 GMT".toUTF8 }
    { forceClose := true, framing := some (.contentLength region.length) })
  check (dated.next == .nextRequest .close && contains (joined dated.headParts) "Date: Sun, 06 Nov 1994 08:49:37 GMT\r\n") "Date input or explicit closure"
  for status in #[100, 101, 103, 204, 205, 304, 600] do
    rejected (({ status } : Response).encodeFileFor region {})
  rejected (({ body := "mixed".toUTF8 } : Response).encodeFileFor region {})
  rejected (({} : Response).encodeFileFor { region with owner := 0 } {})
  rejected (({} : Response).encodeFileFor { region with token := 0 } {})
  rejected (({} : Response).encodeFileFor { region with offset := 9223372036854775807 } {})
  rejected (({} : Response).encodeFileFor region {} { framing := some .chunked })
  rejected (({} : Response).encodeFileFor region {} { framing := some .closeDelimited })
  rejected (({} : Response).encodeFileFor region {} { framing := some (.contentLength 1) })
  rejected (({} : Response).encodeFileFor region {} { trailers := #[{ name := "X-End", value := "yes".toUTF8 }] })
  let old ← ok (({ body := "old".toUTF8 } : Response).serialize "GET")
  check (contains old "Content-Length: 3\r\n" && old.extract (old.size - 3) old.size == "old".toUTF8) "legacy Response.serialize changed"

private def machine : IO Unit := do
  let input := get.append get
  let (requestId, consumed, state) ← application input
  check (consumed == get.size) "first file request consumed pipeline tail"
  let reply : Reply := { response := {}, fileRegion := some region, informational := #[({ status := 103 }, {})] }
  let output := state.respond requestId reply
  let [(ticket, parts, file, barrier)] := output.actions.filterMap
    (fun | .writeFile id parts region barrier => some (id, parts, region, barrier) | _ => none)
    | throw (IO.userError "expected one file ticket")
  check (file == region && !barrier && parts.size == 2 &&
    !output.actions.any (fun | .write .. => true | _ => false)) "file header/body split across logical tickets"
  check (!output.state.wantsInput && (output.state.feed get).consumed == 0) "pipeline advanced before file was queued"
  let accepted := output.state.outputAccepted ticket
  check accepted.state.wantsInput "file acceptance did not release next request"
  let (nextRequest, _, nextState) ← application (input.extract consumed input.size) accepted.state
  check (nextRequest == requestId + 1) "pipeline request identity"
  let next := nextState.respond nextRequest { response := { body := "next".toUTF8 } }
  check (contains (← byteWrite next) "next") "byte response after file lost compatibility"
  let headRequest := "HEAD /file HTTP/1.1\r\nHost: x\r\n\r\n".toUTF8
  let (id, _, headState) ← application headRequest
  let head := headState.respond id { response := {}, fileRegion := some region }
  check (!head.actions.any (fun | .writeFile .. => true | _ => false) &&
    contains (← byteWrite head) "Content-Length: 1000000\r\n") "HEAD produced a file operation"
  let (id, _, capped) ← application get (Machine.State.new { maxFileResponseBytes := 3 })
  check (contains (← byteWrite (capped.respond id { response := {}, fileRegion := some region })) "500 Internal Server Error") "machine file cap ignored"
  let (id, _, mixed) ← application get
  check (contains (← byteWrite (mixed.respond id { response := { body := "bad".toUTF8 }, fileRegion := some region })) "500 Internal Server Error") "mixed body bypassed machine validation"
  let (id, _, endedState) ← application get
  let ended := endedState.finish
  let output := ended.state.respond id { response := {}, fileRegion := some region }
  let [ticket] := output.actions.filterMap (fun | .writeFile id _ _ _ => some id | _ => none)
    | throw (IO.userError "missing EOF file output")
  check ((output.state.outputAccepted ticket).actions.any (fun | .drainClose => true | _ => false)) "EOF file did not drain after ticket acceptance"

def main : IO Unit := do
  encoding
  machine
  IO.println "HTTP/1 file metadata and output-ticket tests passed"
