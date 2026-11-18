import LeanNet

open LeanNet

private def reply (body : ByteArray) (status : Nat := 200) : HTTP1.Reply := {
  response := { status, body, headers := #[{
    name := "content-type", value := "text/plain; charset=utf-8".toUTF8 }] }
}

private def report : IO HTTP1.Reply := do
  let first := "first line\n".toUTF8
  let second := "second line\n".toUTF8
  let bytes := first ++ second
  let firstSize := first.size
  let sent ← IO.mkRef 0
  let secondReadyAt ← IO.mkRef 0
  let stream : HTTP.Stream.Body := {
    knownLength := some bytes.size
    retainedBytes := bytes.size
    poll := fun budget => do
      let offset ← sent.get
      if offset == bytes.size then return some (.finish #[])
      if budget == 0 then return none
      let limit := if offset < firstSize then firstSize else bytes.size
      if offset >= firstSize && (← IO.monoMsNow) < (← secondReadyAt.get) then return none
      let stop := min (offset + budget) limit
      if offset < firstSize && stop == firstSize then
        secondReadyAt.set ((← IO.monoMsNow) + 250)
      sent.set stop
      return some (.data (bytes.extract offset stop))
  }
  return { reply ByteArray.empty with stream := some stream }

private def app (_worker : Nat) : IO HTTP1.Handlers := pure {
  onRequest := fun _ => pure (reply "ready\n".toUTF8)
  onRequestDeferred := some fun request => do
    if request.target == "/".toUTF8 then return .immediate (reply "ready\n".toUTF8)
    if request.target != "/report".toUTF8 then
      return .immediate (reply "not found\n".toUTF8 404)
    let readyAt := (← IO.monoMsNow) + 250
    -- A timer stands in for a bounded, nonblocking adapter. Returning `none`
    -- leaves this job queued while the reactor serves other clients and streams.
    return .deferred {
      timeoutMs := 5000
      poll := do
        if (← IO.monoMsNow) < readyAt then return none
        return some (← report)
    }
}

def main (args : List String) : IO Unit := do
  let port ← match args with
    | [] => pure 8084
    | [value] => do
      let some port := value.toNat? | throw (IO.userError "PORT must be between 1 and 65535")
      if 0 < port && port < 65536 then pure port
      else throw (IO.userError "PORT must be between 1 and 65535")
    | _ => throw (IO.userError "usage: cooperative-server [PORT]")
  HTTP.ReactorServer.serveFactory app
    { workers := 1, server := { maxClients := 32 } } "127.0.0.1" port.toUInt16
