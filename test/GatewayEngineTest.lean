import LeanNet.Gateway.Engine

open LeanNet
open LeanNet.Gateway

private def check (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

private def fail (message : String) : IO α := throw (IO.userError message)

private def endsWith (bytes suffix : ByteArray) : Bool :=
  suffix.size <= bytes.size && bytes.extract (bytes.size - suffix.size) bytes.size == suffix

private def plan (port : UInt16) : HTTP.Admission.ProxyPlan := {
  targets := #[{ host := "127.0.0.1", port, tls := false, verifyName := "" }]
  serialize := fun request =>
    let head := s!"{request.method} / HTTP/1.1\r\nHost: example.com\r\nContent-Length: {request.body.size}\r\n\r\n".toUTF8
    .ok #[head, request.body]
}

private def request (method : String) (body : ByteArray := ByteArray.empty) : HTTP1.Request := {
  method, target := "/".toUTF8, headers := #[], body
}

private structure Backend where
  connections : IO.Ref (Array (Reactor.Socket .connected))
  accepted : IO.Ref Nat
  received : IO.Ref ByteArray
  readyAt : IO.Ref (Option Nat)
  sent : IO.Ref Bool

private def Backend.new : IO Backend := do
  let connections ← IO.mkRef #[]
  let accepted ← IO.mkRef 0
  let received ← IO.mkRef ByteArray.empty
  let readyAt ← IO.mkRef none
  let sent ← IO.mkRef false
  return { connections, accepted, received, readyAt, sent }

private def Backend.reset (backend : Backend) : IO Unit := do
  backend.received.set ByteArray.empty
  backend.readyAt.set none
  backend.sent.set false

private def Backend.acceptedSocket? (backend : Backend) (id : Reactor.SocketId) : IO (Option (Reactor.Socket .connected)) := do
  return (← backend.connections.get).find? (·.id == id)

private def Backend.send (backend : Backend) (reactor : Reactor.Reactor)
    (bytes : ByteArray) : IO Unit := do
  let some socket := (← backend.connections.get).back? | fail "backend has no accepted socket"
  let buffer ← reactor.acquire bytes.size.toUInt32
  try
    buffer.copyFrom bytes
    socket.write buffer 0 bytes.size.toUInt32
  finally
    buffer.release
  backend.sent.set true

/-- One transaction through the actual reactor, with a backend listener on the
same loop. The backend waits two polls after receiving the complete request so
the outbound request's `.written` completions can be accounted before reuse. -/
private def drive (reactor : Reactor.Reactor) (engine : Engine) (backend : Backend)
    (expectedTail : ByteArray) (response : Option ByteArray) : IO Outcome := do
  for tick in [:250] do
    let mut outcomes : Array Outcome := #[]
    match ← reactor.poll 10 with
    | .interrupted => pure ()
    | .completions count =>
      for i in [:count] do
        let event ← reactor.event i.toUInt32
        let (handled, completed) ← engine.onNative event (← Reactor.nowMs)
        outcomes := outcomes ++ completed
        if !handled then
          match event with
          | .accepted socket =>
            backend.connections.modify (·.push socket)
            backend.accepted.modify (· + 1)
          | .read socket buffer offset length =>
            let bytes ← try buffer.view finally buffer.release
            let some _ ← backend.acceptedSocket? socket.id | fail "unowned read from an unknown socket"
            let received ← backend.received.get
            let received := received.append (bytes.extract offset.toNat (offset + length).toNat)
            backend.received.set received
            if endsWith received expectedTail && (← backend.readyAt.get).isNone then
              backend.readyAt.set (some tick)
          | .error id _ code =>
            if (← backend.acceptedSocket? id).isSome then
              fail s!"backend socket error: {code}"
          | _ => pure ()
    outcomes := outcomes ++ (← engine.pump (← Reactor.nowMs))
    if let some ready := ← backend.readyAt.get then
      if tick >= ready + 2 && !(← backend.sent.get) then
        if let some bytes := response then backend.send reactor bytes
        else backend.sent.set true
    if let some outcome := outcomes[0]? then return outcome
  fail "gateway transaction did not complete"

private def pollGateway (reactor : Reactor.Reactor) (engine : Engine)
    (backend : Backend) : IO (Array Outcome) := do
  let mut outcomes := #[]
  match ← reactor.poll 10 with
  | .interrupted => pure ()
  | .completions count =>
    for i in [:count] do
      let event ← reactor.event i.toUInt32
      let (handled, produced) ← engine.onNative event (← Reactor.nowMs)
      outcomes := outcomes ++ produced
      if !handled then
        match event with
        | .accepted socket =>
          backend.connections.modify (·.push socket)
          backend.accepted.modify (· + 1)
        | .read socket buffer offset length =>
          let bytes ← try buffer.view finally buffer.release
          let some _ ← backend.acceptedSocket? socket.id | fail "unowned read from unknown backend socket"
          backend.received.modify (·.append (bytes.extract offset.toNat (offset + length).toNat))
        | .error id _ code =>
          if (← backend.acceptedSocket? id).isSome then fail s!"backend socket error: {code}"
        | _ => pure ()
  return outcomes ++ (← engine.pump (← Reactor.nowMs))

private def run (port : UInt16) : IO Unit := do
  Reactor.withReactor {
    maxConnections := 24, maxEvents := 64, maxWrites := 64,
    buffers4k := 64, buffers16k := 8, buffers64k := 2, timerTickMs := 1
  } fun reactor => do
    let listener ← reactor.listen "127.0.0.1" port
    let engine ← Engine.new reactor {
      pool := { maxTotal := 4, maxPerTarget := 2, idleTimeoutMs := 5000, connectTimeoutMs := 1000 }
      responseTimeoutMs := 200
    }
    let backend ← Backend.new
    try
      let getTicket : Ticket := { downstream := listener.id, requestId := 1 }
      check ((← engine.start getTicket (plan port) (request "GET") (← Reactor.nowMs)).isNone)
        "GET returned before upstream transaction"
      let getOutcome ← drive reactor engine backend "\r\n\r\n".toUTF8
        (some "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".toUTF8)
      check (getOutcome.ticket.requestId == 1 && getOutcome.reply.response.status == 200 &&
        getOutcome.reply.response.body == "ok".toUTF8) "GET proxy reply mismatch"
      check ((← backend.accepted.get) == 1) "GET opened unexpected backend sockets"

      backend.reset
      let postTicket : Ticket := { downstream := listener.id, requestId := 2 }
      check ((← engine.start postTicket (plan port) (request "POST" "payload".toUTF8)
        (← Reactor.nowMs)).isNone) "POST returned before upstream transaction"
      let postOutcome ← drive reactor engine backend "payload".toUTF8
        (some "HTTP/1.1 201 Created\r\nContent-Length: 4\r\n\r\npost".toUTF8)
      check (postOutcome.ticket.requestId == 2 && postOutcome.reply.response.status == 201 &&
        postOutcome.reply.response.body == "post".toUTF8) "POST proxy reply mismatch"
      check ((← backend.accepted.get) == 1) "POST did not reuse the idle upstream socket"

      backend.reset
      let malformed : Ticket := { downstream := listener.id, requestId := 3 }
      check ((← engine.start malformed (plan port) (request "GET") (← Reactor.nowMs)).isNone)
        "malformed-response case did not start"
      let malformedOutcome ← drive reactor engine backend "\r\n\r\n".toUTF8
        (some "HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n".toUTF8)
      check (malformedOutcome.ticket.requestId == 3 && malformedOutcome.reply.response.status == 502)
        "malformed upstream response did not produce 502"
      check ((← engine.pool.size) == 0) "malformed response returned a socket to idle"

      backend.reset
      let timeout : Ticket := { downstream := listener.id, requestId := 4 }
      check ((← engine.start timeout (plan port) (request "GET") (← Reactor.nowMs)).isNone)
        "timeout case did not start"
      let timeoutOutcome ← drive reactor engine backend "\r\n\r\n".toUTF8 none
      check (timeoutOutcome.ticket.requestId == 4 && timeoutOutcome.reply.response.status == 504)
        "backend response timeout did not produce 504"
      check ((← engine.pool.size) == 0) "timed-out backend retained pool capacity"

      backend.reset
      let streamed : Ticket := { downstream := listener.id, requestId := 5 }
      check ((← engine.start streamed (plan port) (request "GET") (← Reactor.nowMs)).isNone)
        "streaming case did not start"
      let mut receivedRequest := false
      for _ in [:100] do
        if receivedRequest then break
        let outcomes ← pollGateway reactor engine backend
        check outcomes.isEmpty "streaming case completed before backend reply"
        receivedRequest := endsWith (← backend.received.get) "\r\n\r\n".toUTF8
      check receivedRequest "streaming backend did not receive request"

      backend.send reactor "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n".toUTF8
      let mut started := false
      for _ in [:40] do
        if started then break
        for outcome in ← pollGateway reactor engine backend do
          match outcome.stream with
          | some (.start head) =>
            check (outcome.ticket == streamed && head.status == 200)
              "stream start head mismatch"
            started := true
          | _ => fail "unexpected outcome before stream start"
      check started "gateway did not start a streamed response"
      let activeOutcomes ← engine.pump ((← Reactor.nowMs) + 5001)
      check activeOutcomes.isEmpty "idle reaper aborted an active upstream response"
      check ((← engine.pool.size) == 1) "idle reaper discarded an active upstream lease"

      backend.send reactor "hello".toUTF8
      let mut firstChunk := false
      for _ in [:40] do
        if firstChunk then break
        for outcome in ← pollGateway reactor engine backend do
          match outcome.stream with
          | some (.data bytes) =>
            check (outcome.ticket == streamed && bytes == "hello".toUTF8)
              "first streamed body chunk mismatch"
            firstChunk := true
          | _ => fail "unexpected outcome before first stream chunk"
      check firstChunk "gateway did not forward the first stream chunk"
      check (← engine.isPaused streamed) "streamed upstream read was not paused"
      backend.send reactor "world".toUTF8
      let early ← pollGateway reactor engine backend
      check early.isEmpty "paused upstream emitted a second body chunk"
      let mut rest ← engine.resume streamed (← Reactor.nowMs)
      for _ in [:40] do
        if rest.any (fun o => match o.stream with | some (.finish _) => true | _ => false) then break
        rest := rest ++ (← pollGateway reactor engine backend)
      let mut secondChunk := false
      let mut finished := false
      for outcome in rest do
        check (outcome.ticket == streamed) "stream event ticket mismatch"
        match outcome.stream with
        | some (.data bytes) =>
          check (bytes == "world".toUTF8) "second streamed body chunk mismatch"
          secondChunk := true
        | some (.finish trailers) =>
          check trailers.isEmpty "unexpected stream trailers"
          finished := true
        | _ => fail "unexpected streamed response outcome"
      check (secondChunk && finished) "streaming response did not complete after resume"
      check ((← engine.pool.size) == 1) "clean streamed response did not retain idle upstream"
      let idleOutcomes ← engine.pump ((← Reactor.nowMs) + 6501)
      check idleOutcomes.isEmpty "idle reaper produced a spurious gateway response"
      check ((← engine.pool.size) == 0) "worker pump did not expire an idle upstream socket"

      backend.reset
      let brokenStream : Ticket := { downstream := listener.id, requestId := 6 }
      check ((← engine.start brokenStream (plan port) (request "GET") (← Reactor.nowMs)).isNone)
        "broken stream case did not start"
      let mut brokenReceived := false
      for _ in [:100] do
        if brokenReceived then break
        let outcomes ← pollGateway reactor engine backend
        check outcomes.isEmpty "broken stream completed before backend head"
        brokenReceived := endsWith (← backend.received.get) "\r\n\r\n".toUTF8
      check brokenReceived "broken stream backend did not receive request"
      backend.send reactor "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n".toUTF8
      let mut brokenStarted := false
      for _ in [:40] do
        if brokenStarted then break
        for outcome in ← pollGateway reactor engine backend do
          match outcome.stream with
          | some (.start _) => brokenStarted := true
          | _ => fail "broken stream returned an unexpected pre-head outcome"
      check brokenStarted "broken stream did not emit its head"
      let brokenStartMs ← Reactor.nowMs
      let mut aborted := false
      while !aborted && (← Reactor.nowMs) - brokenStartMs < 1000 do
        for outcome in ← pollGateway reactor engine backend do
          match outcome.stream with
          | some .abort =>
            check (outcome.ticket == brokenStream) "stream abort ticket mismatch"
            aborted := true
          | _ => fail "started stream returned a replacement response"
      check aborted s!"timed-out stream did not abort after {(← Reactor.nowMs) - brokenStartMs} ms"
      check ((← engine.pool.size) == 0) "broken stream retained upstream socket"

      let canceled : Ticket := { downstream := listener.id, requestId := 7 }
      check ((← engine.start canceled (plan port) (request "GET") (← Reactor.nowMs)).isNone)
        "cancellation case did not start"
      let mut connected := false
      for _ in [:100] do
        if connected then break
        match ← reactor.poll 10 with
        | .interrupted => pure ()
        | .completions count =>
          for i in [:count] do
            let event ← reactor.event i.toUInt32
            let (handled, outcomes) ← engine.onNative event (← Reactor.nowMs)
            check outcomes.isEmpty "cancellation case completed before cancel"
            if !handled then
              match event with
              | .accepted socket =>
                backend.connections.modify (·.push socket)
                backend.accepted.modify (· + 1)
              | .read _ buffer _ _ => buffer.release
              | _ => pure ()
            match event with
            | .connected _ => connected := true
            | _ => pure ()
        let outcomes ← engine.pump (← Reactor.nowMs)
        check outcomes.isEmpty "cancellation case failed while connecting"
      check connected "cancellation case never connected"
      engine.cancelDownstream listener.id
      check ((← engine.pool.size) == 0) "downstream cancellation retained an upstream socket"
    finally
      engine.close
  IO.println "gateway engine tests passed"

def main (args : List String) : IO Unit := do
  let [raw] := args | fail "expected a loopback TCP port"
  let some port := raw.toNat? | fail "invalid loopback port"
  if port == 0 || port > 65535 then fail "invalid loopback port"
  run port.toUInt16
