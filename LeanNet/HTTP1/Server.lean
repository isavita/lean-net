import LeanNet.HTTP1.Parser
import LeanNet.HTTP1.Response
import LeanNet.HTTP1.Config
import LeanNet.HTTP1.Router
import LeanNet.HTTP.ReactorServer
import LeanNet.Socket.Handle
import LeanNet.HTTP2.Preface
import LeanNet.HTTP2.Connection

namespace LeanNet.HTTP1

private def tokenByte (b : UInt8) : Bool :=
  let n := b.toNat
  (n >= 48 && n <= 57) || (n >= 65 && n <= 90) || (n >= 97 && n <= 122) ||
    [33, 35, 36, 37, 38, 39, 42, 43, 45, 46, 94, 95, 96, 124, 126].contains n

private def ows (b : UInt8) : Bool := b == 32 || b == 9

private def lowerAscii (b : UInt8) : UInt8 :=
  if b.toNat >= 65 && b.toNat <= 90 then UInt8.ofNat (b.toNat + 32) else b

private def splitCommas (xs : List UInt8) : List (List UInt8) :=
  go xs [] []
where
  go (remaining : List UInt8) (current : List UInt8) (out : List (List UInt8)) :=
    match remaining with
    | [] => (current.reverse :: out).reverse
    | 44 :: rest => go rest [] (current.reverse :: out)
    | x :: rest => go rest (x :: current) out

/-- Invalid Connection options conservatively close the connection. -/
private def closeRequested (request : Request) : Bool :=
  (request.headers.filter (fun h => h.name == "connection")).any fun h =>
    (splitCommas h.value.toList).any fun item =>
      let item := ((item.dropWhile ows).reverse.dropWhile ows).reverse
      item.isEmpty || !item.all tokenByte || item.map lowerAscii == "close".toUTF8.toList

private inductive Expectation where
  | none | continue | unsupported

private def expectation (headers : Array Header) : Expectation := Id.run do
  let fields := headers.filter (fun h => h.name == "expect")
  if fields.isEmpty then return .none
  for h in fields do
    for item in splitCommas h.value.toList do
      let item := ((item.dropWhile ows).reverse.dropWhile ows).reverse
      if item.map lowerAscii != "100-continue".toUTF8.toList then
        return .unsupported
  return .continue

private def badRequest : Response :=
  { status := 400 }

private def expectationFailed : Response :=
  { status := 417 }

private inductive Protocol where
  | detect (detector : HTTP2.PrefaceDetector)
  | http1
  | http2 (connection : HTTP2.Connection)

private inductive SecurePhase where
  | active | handshakingRead | handshakingWrite | shutdownRead | shutdownWrite
  deriving BEq

private structure Client where
  connection : Connection
  protocol : Protocol := .detect HTTP2.PrefaceDetector.new
  parser : Parser := Parser.new
  pending : ByteArray := ByteArray.empty
  output : ByteArray := ByteArray.empty
  offset : Nat := 0
  closeAfter : Bool := false
  lastActivity : Nat
  requestStarted : Option Nat := none
  writeStarted : Option Nat := none
  secure : Bool := false
  phase : SecurePhase := .active
  readWantWrite : Bool := false
  writeWantRead : Bool := false
  writeAttempt : Option ByteArray := none

private def isWriting (client : Client) : Bool := client.offset < client.output.size

private def responseWire (config : ServerConfig) (response : Response) (method : String)
    (close : Bool) : IO (Option ByteArray) := do
  if response.body.size > config.maxResponseBytes || response.headers.size > config.maxResponseHeaders then
    return none
  let headerBytes := response.headers.foldl (fun n h => n + h.name.toUTF8.size + h.value.size + 4) 0
  if headerBytes > config.maxResponseHeaderBytes then return none
  let response ← response.withCurrentDate
  match response.serialize method close with
  | .ok wire => return some wire
  | .error _ => return none

private def queueResponse (config : ServerConfig) (client : Client) (response : Response)
    (method : String) (close : Bool) (now : Nat) (pending : ByteArray := ByteArray.empty) : IO Client := do
  match ← responseWire config response method close with
  | some output =>
    return { client with output := output, offset := 0, closeAfter := close, pending := pending, requestStarted := none, writeStarted := some now }
  | none =>
    -- Application response errors affect only this connection. The fallback is
    -- a fixed-size server response and does not depend on application limits.
    let fallback ← (Response.mk 500 #[] ByteArray.empty).withCurrentDate
    let output ← match fallback.serialize method true with
      | .ok bytes => pure bytes
      | .error message => throw (IO.userError s!"invalid internal response: {message}")
    return { client with output := output, offset := 0, closeAfter := true, pending := ByteArray.empty, requestStarted := none, writeStarted := some now }

private def processHttp1 (router : Router) (config : ServerConfig) (client : Client)
    (input : ByteArray) (now : Nat) : IO Client := do
  match client.parser.feedWithHeaders input with
  | .error _ => queueResponse config client badRequest "GET" true now
  | .needMore parser => return { client with parser := parser, pending := ByteArray.empty }
  | .headers head parser remaining =>
    let client := { client with parser := parser, pending := remaining }
    match expectation head.headers with
    | .unsupported => queueResponse config client expectationFailed head.method true now
    | .continue =>
      return { client with output := "HTTP/1.1 100 Continue\r\n\r\n".toUTF8, offset := 0, writeStarted := some now }
    | .none => return client
  | .complete request remaining =>
    match expectation request.headers with
    | .unsupported => queueResponse config client expectationFailed request.method true now
    | _ =>
      let close := closeRequested request
      let response ← try
        some <$> router request
      catch _ => pure none
      let client := { client with parser := Parser.new }
      match response with
      | some response => queueResponse config client response request.method close now remaining
      | none => queueResponse config client { status := 500 } request.method true now

private def queueH2 (client : Client) (connection : HTTP2.Connection) (output : ByteArray)
    (now : Nat) (close : Bool := false) : Client :=
  let writing := isWriting client
  let compact := writing && client.offset >= 1048576
  let previous := if !writing then ByteArray.empty else if compact then client.output.extract client.offset client.output.size else client.output
  let offset := if compact || !writing then 0 else client.offset
  let combined := previous.append output
  { client with protocol := .http2 connection, output := combined, offset := offset, closeAfter := client.closeAfter || close, pending := ByteArray.empty, writeStarted := if combined.size <= offset then none else some (client.writeStarted.getD now), requestStarted := if connection.hasPartialInput then client.requestStarted else none }

private def failH2 (client : Client) (connection : HTTP2.Connection)
    (error : HTTP2.ProtocolError) (now : Nat) : Client :=
  queueH2 client connection (connection.goAway error) now true

private def processHttp2 (router : Router) (config : ServerConfig) (client : Client)
    (connection : HTTP2.Connection) (input : ByteArray) (now : Nat)
    (initial : ByteArray := ByteArray.empty) : IO Client := do
  let connection := (connection.setTime now).setDate (← currentDate)
  match connection.feed input with
  | .error error =>
    let output := initial.append (connection.goAway error)
    return queueH2 client connection output now true
  | .ok (connection, frames, requests) =>
    let mut connection := connection
    let mut output := initial.append frames
    if output.size + (client.output.size - client.offset) > 4 * 1024 * 1024 then
      let error : HTTP2.ProtocolError := ⟨.enhanceYourCalm, .connection, "output batch too large"⟩
      return queueH2 client connection (initial.append (connection.goAway error)) now true
    for event in requests do
      let response ← try
        some <$> router event.request
      catch _ => pure none
      let response := response.getD { status := 500 }
      let headerBytes := response.headers.foldl (fun n h => n + h.name.toUTF8.size + h.value.size + 4) 0
      let response := if response.body.size > config.maxResponseBytes ||
          response.headers.size > config.maxResponseHeaders || headerBytes > config.maxResponseHeaderBytes
        then { status := 500 } else response
      let response ← response.withCurrentDate
      match connection.respond event.streamId response with
      | .ok (next, bytes) =>
        connection := next
        output := output.append bytes
      | .error _ =>
        let fallback ← (Response.mk 500 #[] ByteArray.empty).withCurrentDate
        match connection.respond event.streamId fallback with
        | .ok (next, bytes) =>
          connection := next
          output := output.append bytes
        | .error error => return queueH2 client connection (output.append (connection.goAway error)) now true
      if output.size + (client.output.size - client.offset) > 4 * 1024 * 1024 then
        let error : HTTP2.ProtocolError := ⟨.enhanceYourCalm, .connection, "output batch too large"⟩
        return queueH2 client connection (initial.append (connection.goAway error)) now true
    return queueH2 client connection output now

private def processInput (router : Router) (config : ServerConfig) (client : Client)
    (input : ByteArray) (now : Nat) : IO Client := do
  match client.protocol with
  | .http1 => processHttp1 router config client input now
  | .http2 connection => processHttp2 router config client connection input now
  | .detect detector =>
    match detector.feed input with
    | .needMore next => return { client with protocol := .detect next, pending := ByteArray.empty }
    | .http1 wire => processHttp1 router config { client with protocol := .http1 } wire now
    | .http2 remaining =>
      let preface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toUTF8
      processHttp2 router config client HTTP2.Connection.new (preface.append remaining) now HTTP2.Connection.initialSettings

private def peerRead (client : Client) : IO (Option ReadOutcome) := do
  try return some (← client.connection.recv 16384)
  catch error =>
    match error with
    | .resourceVanished .. => return none
    | _ => throw error

private def peerWrite (client : Client) : IO (Option (WriteOutcome × Option ByteArray)) := do
  try
    let length := min 16384 (client.output.size - client.offset)
    if client.secure then
      let slice := match client.writeAttempt with
        | some retained => retained
        | none => client.output.extract client.offset (client.offset + length)
      let result ← client.connection.sendAt slice 0 slice.size
      return some (result, some slice)
    let result ← client.connection.sendAt client.output client.offset length
    return some (result, none)
  catch error =>
    match error with
    | .resourceVanished .. => return none
    | _ => throw error

private def transportProgress (client : Client) (shutdown : Bool) : IO (Option TransportProgress) := do
  try
    let progress ← if shutdown then client.connection.shutdownTransport else client.connection.handshake
    return some progress
  catch error =>
    match error with
    | .resourceVanished .. => return none
    | _ => throw error

private def beginShutdown (client : Client) (now : Nat) : IO (Option Client) := do
  if !client.secure then return none
  match ← transportProgress client true with
  | none | some (.complete _) => return none
  | some .wantRead => return some { client with phase := .shutdownRead, writeStarted := some now }
  | some .wantWrite | some .interrupted => return some { client with phase := .shutdownWrite, writeStarted := some now }

private def advanceSecure (client : Client) (ready : PollReady) (now : Nat) : IO (Option Client) := do
  let wantsRead := client.phase == .handshakingRead || client.phase == .shutdownRead
  if (wantsRead && !ready.readable && !ready.hangup && !ready.error) ||
      (!wantsRead && !ready.writable && !ready.hangup && !ready.error) then return some client
  let shutting := client.phase == .shutdownRead || client.phase == .shutdownWrite
  match ← transportProgress client shutting with
  | none => return none
  | some .interrupted => return some client
  | some .wantRead => return some { client with phase := if shutting then .shutdownRead else .handshakingRead }
  | some .wantWrite => return some { client with phase := if shutting then .shutdownWrite else .handshakingWrite }
  | some (.complete protocol) =>
    if shutting then return none
    let client := { client with phase := .active, lastActivity := now, requestStarted := none }
    match protocol with
    | .detect => return some { client with protocol := .detect HTTP2.PrefaceDetector.new }
    | .http1 => return some { client with protocol := .http1 }
    | .http2 =>
      let connection := HTTP2.Connection.new
      return some (queueH2 { client with requestStarted := some now } connection HTTP2.Connection.initialSettings now)

private def readClient (router : Router) (config : ServerConfig) (client : Client)
    (now : Nat) : IO (Option Client) := do
  match ← peerRead client with
  | none => return none
  | some .interrupted => return some client
  | some .wouldBlock => return some { client with readWantWrite := false }
  | some .wantWrite => return some { client with readWantWrite := true }
  | some .eof =>
    if isWriting client then return some { client with closeAfter := true, readWantWrite := false }
    match client.protocol with
    | .http2 _ | .detect _ => beginShutdown client now
    | .http1 =>
      match client.parser.finish with
      | .eof => beginShutdown client now
      | .error _ => return some (← queueResponse config client badRequest "GET" true now)
      | _ => throw (IO.userError "parser returned an invalid EOF outcome")
  | some (.data bytes) =>
    let start := client.requestStarted.getD now
    let client := { client with requestStarted := some start, lastActivity := now, readWantWrite := false }
    return some (← processInput router config client bytes now)

private def serviceClient (router : Router) (config : ServerConfig) (client : Client)
    (ready : PollReady) (now : Nat) : IO (Option Client) := do
  if ready.invalid then throw (IO.userError "poll reported invalid client descriptor (library bug)")
  if client.phase != .active then return ← advanceSecure client ready now
  -- A write that needs inbound TLS records must be retried before an SSL_read.
  let shouldRead := !client.closeAfter && !client.writeWantRead &&
    (if client.readWantWrite then ready.writable || ready.error || ready.hangup else ready.readable || ready.hangup || ready.error) &&
    (if isWriting client then match client.protocol with | .http2 _ => true | _ => client.readWantWrite else true)
  let closingRead := client.closeAfter && client.readWantWrite &&
    (ready.writable || ready.error || ready.hangup)
  let client ← if closingRead then do
    -- Complete a TLS read that needed a write before flushing a final response.
    -- Application bytes that arrive after closing began are discarded.
    match ← peerRead client with
    | none => pure none
    | some .wantWrite | some .interrupted => pure (some client)
    | some .wouldBlock | some .eof | some (.data _) => pure (some { client with readWantWrite := false })
  else if shouldRead then readClient router config client now else pure (some client)
  let some client := client | return none
  if client.phase != .active then return some client
  if isWriting client then
    -- Retry exactly the retained bytes and length after either TLS WANT result.
    let readyForWrite := if client.writeWantRead then ready.readable || ready.hangup else ready.writable || ready.error || ready.hangup
    if !readyForWrite || client.readWantWrite then return some client
    match ← peerWrite client with
    | none => return none
    | some (.interrupted, attempt) => return some { client with writeAttempt := attempt }
    | some (.wouldBlock, attempt) => return some { client with writeAttempt := attempt, writeWantRead := false }
    | some (.wantRead, attempt) => return some { client with writeAttempt := attempt, writeWantRead := true }
    | some (.written n, _) =>
      let attempted := client.writeAttempt.map (·.size) |>.getD (min 16384 (client.output.size - client.offset))
      if n == 0 || n > attempted || n > client.output.size - client.offset then
        throw (IO.userError "send: invalid progress")
      let next := client.offset + n
      if next == client.output.size then
        let client := { client with output := ByteArray.empty, offset := 0, writeStarted := none, lastActivity := now, writeAttempt := none, writeWantRead := false }
        if client.closeAfter then return ← beginShutdown client now
        return some client
      return some { client with offset := next, lastActivity := now, writeAttempt := none, writeWantRead := false }
  return some client

private def expired (config : ServerConfig) (client : Client) (now : Nat) : Bool :=
  if client.closeAfter && isWriting client then
    client.writeStarted.any (fun start => now - start >= config.writeTimeoutMs)
  else
    now - client.lastActivity >= config.idleTimeoutMs ||
      client.requestStarted.any (fun start => now - start >= config.requestTimeoutMs) ||
      client.writeStarted.any (fun start => now - start >= config.writeTimeoutMs)

private def h2ParseDeadline (config : ServerConfig) (client : Client) (now : Nat) : Option Client :=
  if client.closeAfter then none
  else match client.protocol with
    | .http2 connection =>
      if connection.hasPartialInput && client.requestStarted.any (fun start => now - start >= config.requestTimeoutMs) then
        let error : HTTP2.ProtocolError := ⟨.enhanceYourCalm, .connection, "partial HTTP/2 input timed out"⟩
        some { (failH2 client connection error now) with requestStarted := none, lastActivity := now }
      else none
    | _ => none

private def canReadBuffered (client : Client) : Bool :=
  client.secure && client.phase == .active && !client.closeAfter &&
    !client.readWantWrite && !client.writeWantRead &&
    (!isWriting client || match client.protocol with | .http2 _ => true | _ => false)

private def servicePending (router : Router) (config : ServerConfig) (pool : ConnectionPool)
    (clients : Array Client) : IO (Array Client) := do
  let mut updated := #[]
  for client in clients do
    let now ← IO.monoMsNow
    if let some timedOut := h2ParseDeadline config client now then
      updated := updated.push timedOut
    else if expired config client now then pool.close client.connection
    else
      let client ← if client.phase != .active then pure client else do
        match client.protocol with
        | .http2 connection =>
          match connection.expireRequests now config.requestTimeoutMs with
          | .error error =>
            let output := client.output.append (connection.goAway error)
            pure { client with output := output, closeAfter := true, writeStarted := some (client.writeStarted.getD now) }
          | .ok (connection, reset) =>
            let mut client := { client with protocol := .http2 connection }
            if !reset.isEmpty then
              client := { client with output := client.output.append reset, writeStarted := some (client.writeStarted.getD now) }
            if !isWriting client && connection.canDrain then
              match connection.drain with
              | .error error => client := failH2 client connection error now
              | .ok (next, bytes) =>
                client := { client with protocol := .http2 next, output := bytes, offset := 0, writeStarted := if bytes.isEmpty then none else some now }
            pure client
        | _ =>
          if !isWriting client && !client.pending.isEmpty then
            let input := client.pending
            let start := client.requestStarted.getD now
            processInput router config { client with pending := ByteArray.empty, requestStarted := some start } input now
          else pure client
      if canReadBuffered client && (← client.connection.buffered) then
        match ← readClient router config client now with
        | some next => updated := updated.push next
        | none => pool.close client.connection
      else updated := updated.push client
  return updated

/-- On SIGINT, attempt close_notify once for each established TLS session.
    Never retry a pending application write with different arguments. A blocked
    socket or incomplete handshake is released by the normal pool bracket. -/
private def notifyInterruptedClients (clients : Array Client) : IO Unit := do
  for client in clients do
    if client.secure && client.phase == .active && client.writeAttempt.isNone && !client.readWantWrite then
      let _ ← transportProgress client true
      pure ()
    else if !client.secure then
      -- Consume a bounded amount of already-arrived input before close, so
      -- small in-flight control frames do not turn the FIN into a TCP reset.
      for _ in [:4] do
        match ← peerRead client with
        | some (.data _) | some .interrupted => pure ()
        | _ => break

private partial def eventLoop (router : Router) (config : ServerConfig) (listener : Listener)
    (pool : ConnectionPool) (setup : Option (Connection → IO Unit)) (clients : Array Client := #[]) : IO Unit := do
  if ← interruptRequested then
    notifyInterruptedClients clients
    return
  let clients ← servicePending router config pool clients
  let acceptEnabled := clients.size < config.maxClients
  let mut requests := #[]
  if acceptEnabled then requests := requests.push (.listener listener)
  for client in clients do
    let interest := match client.phase with
      | .handshakingRead | .shutdownRead => PollRequest.read client.connection
      | .handshakingWrite | .shutdownWrite => PollRequest.write client.connection
      | .active =>
        if client.writeWantRead then PollRequest.read client.connection
        else if client.readWantWrite then PollRequest.write client.connection
        else if isWriting client then
          match client.protocol with
          | .http2 _ => if client.closeAfter then PollRequest.write client.connection else .readWrite client.connection
          | _ => PollRequest.write client.connection
        else PollRequest.read client.connection
    requests := requests.push interest
  let mut pendingWork := clients.any (fun c => c.phase == .active && !isWriting c && !c.pending.isEmpty)
  for client in clients do
    if canReadBuffered client && (← client.connection.buffered) then pendingWork := true
  let interval := min 1000 (min config.idleTimeoutMs (min config.requestTimeoutMs config.writeTimeoutMs))
  let timeout : Int32 := if pendingWork then 0 else Int32.ofInt (Int.ofNat interval)
  match ← poll requests timeout with
  | .interrupted => eventLoop router config listener pool setup clients
  | .ready events =>
    let mut nextClients : Array Client := #[]
    let base := if acceptEnabled then 1 else 0
    for index in [:clients.size] do
      let some client := clients[index]? | throw (IO.userError "client index out of range")
      let some ready := events[index + base]? | throw (IO.userError "poll event index out of range")
      let clientNow ← IO.monoMsNow
      if let some timedOut := h2ParseDeadline config client clientNow then
        nextClients := nextClients.push timedOut
      else if expired config client clientNow then pool.close client.connection
      else
        let client ← if client.phase != .active then pure client else match client.protocol with
          | .http2 connection =>
            match connection.expireRequests clientNow config.requestTimeoutMs with
            | .error error =>
              pure { client with output := client.output.append (connection.goAway error), closeAfter := true, writeStarted := some (client.writeStarted.getD clientNow) }
            | .ok (next, reset) =>
              pure { client with protocol := .http2 next, output := client.output.append reset, writeStarted := if reset.isEmpty then client.writeStarted else some (client.writeStarted.getD clientNow) }
          | _ => pure client
        match ← serviceClient router config client ready clientNow with
        | some next => nextClients := nextClients.push next
        | none => pool.close client.connection
    if acceptEnabled then
      let some ready := events[0]? | throw (IO.userError "missing listener poll event")
      if ready.invalid || ready.error || ready.hangup then
        throw (IO.userError "listener poll failure")
      if ready.readable then
        match ← pool.accept listener with
        | .accepted connection =>
          let installed ← try
            if let some setup := setup then setup connection
            pure true
          catch error =>
            match error with
            | .resourceVanished .. => pure false
            | _ => throw error
          if installed then
            let acceptedAt ← IO.monoMsNow
            let secure := setup.isSome
            nextClients := nextClients.push { connection := connection, lastActivity := acceptedAt, secure := secure, phase := if secure then .handshakingRead else .active, requestStarted := if secure then some acceptedAt else none }
          else pool.close connection
        | .interrupted | .wouldBlock | .retry => pure ()
    eventLoop router config listener pool setup nextClients

/-- Serve with an optional per-connection transport installer. The installer
    borrows sockets already owned by the pool; attached transport state is freed
    before the descriptor is closed on every exit. -/
def serveWithTransport (router : Router) (config : ServerConfig)
    (setup : Option (Connection → IO Unit)) (host : String := "127.0.0.1")
    (port : UInt16 := 8080) : IO Unit := do
  if config.maxClients == 0 || config.idleTimeoutMs == 0 || config.requestTimeoutMs == 0 ||
      config.writeTimeoutMs == 0 then throw (IO.userError "server limits and timeouts must be positive")
  withInterruptHandler <| withListener host port fun listener => do
    listener.setNonblocking
    withConnectionPool (fun pool => eventLoop router config listener pool setup)

/-- Compatibility callback ownership on one native reactor. Advanced multicore
    applications construct independent handlers with HTTP.ReactorServer.serveFactory. -/
def serveWithConfig (router : Router) (config : ServerConfig) (host : String := "127.0.0.1")
    (port : UInt16 := 8080) : IO Unit :=
  HTTP.ReactorServer.serveWithConfig router config host port

def serveWith (router : Router) (host : String := "127.0.0.1") (port : UInt16 := 8080) : IO Unit :=
  serveWithConfig router {} host port

/-- Run the demonstration route with one native protocol worker per core. -/
def serve (host : String := "127.0.0.1") (port : UInt16 := 8080) : IO Unit :=
  HTTP.ReactorServer.serve host port

end LeanNet.HTTP1
