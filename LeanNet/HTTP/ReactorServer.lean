import Std.Data.HashMap
import LeanNet.Reactor.Basic
import LeanNet.HTTP1.Handlers
import LeanNet.HTTP2.Connection
import LeanNet.HTTP.WorkerPool

namespace LeanNet.HTTP

open HTTP1

structure ReactorServerConfig where
  server : ServerConfig := {}
  machine : Machine.Config := {}
  native : Reactor.Config := {}
  workers : Nat := 0
  outputBuffers : Nat := 128
  maxInputBytes : Nat := 2 * 1024 * 1024 + 65536
  maxOutputBytes : Nat := 16 * 1024 * 1024
  workPerClient : Nat := 64

namespace ReactorServer

private def preface : ByteArray := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toUTF8

private inductive Protocol where
  | detect (matched : Nat)
  | http1 (machine : Machine.State)
  | http2 (connection : HTTP2.Connection)
  | raw

private structure InputChunk where
  view : ByteSlice
  lease : Option Reactor.Buffer := none
  arrived : UInt64 := 0

private structure Output where
  parts : List ByteSlice
  id : Option Nat := none
  barrier : Bool := false
  started : UInt64

private structure Flight where
  owner : Reactor.SocketId
  operation : UInt64
  outputId : Option Nat
  barrier : Bool
  last : Bool
  started : UInt64
  length : Nat

private structure OutputSlot where
  buffer : Reactor.Buffer
  generation : UInt64 := 0
  flight : Option Flight := none

private structure Client where
  socket : Reactor.Socket .connected
  protocol : Protocol := .detect 0
  inputFront : List InputChunk := []
  inputBack : List InputChunk := []
  inputBytes : Nat := 0
  outputs : List Output := []
  outputBytes : Nat := 0
  inFlight : Nat := 0
  pipe : Option RawPipe := none
  peerEOF : Bool := false
  finishSent : Bool := false
  kick : Bool := true
  closing : Bool := false
  reading : Bool := true
  closeWhenQueued : Bool := false
  idleDeadline : Option UInt64 := none
  requestDeadline : Option UInt64 := none
  writeDeadline : Option UInt64 := none

private structure WorkerState where
  clients : Std.HashMap Reactor.SocketId Client := {}
  slots : Array OutputSlot := #[]
  now : UInt64 := 0
  dateSecond : UInt64 := 0
  date : ByteArray := ByteArray.empty
  roundRobin : Nat := 0
  writeBlocked : Bool := false

private structure Driver where
  reactor : Reactor.Reactor
  group : Reactor.Group
  config : ReactorServerConfig
  handlers : Handlers
  clientLimit : Nat
  state : IO.Ref WorkerState

private def Driver.client? (driver : Driver) (id : Reactor.SocketId) : IO (Option Client) := do
  return (← driver.state.get).clients[id]?

private def Driver.put (driver : Driver) (id : Reactor.SocketId) (client : Client) : IO Unit :=
  driver.state.modify fun state => { state with clients := state.clients.insert id client }

private def normalizedInput (client : Client) : Client :=
  if client.inputFront.isEmpty then
    { client with inputFront := client.inputBack.reverse, inputBack := [] }
  else client

private def releaseInput (client : Client) : IO Unit := do
  for chunk in client.inputFront ++ client.inputBack do
    if let some lease := chunk.lease then lease.release

private def Driver.consume (driver : Driver) (id : Reactor.SocketId) (count : Nat) : IO Unit := do
  let some current ← driver.client? id | return
  let client := normalizedInput current
  match client.inputFront with
  | [] =>
    if count != 0 then throw (IO.userError "HTTP input cursor exceeds retained bytes")
  | chunk :: rest =>
    if count > chunk.view.length then throw (IO.userError "HTTP input cursor exceeds retained slice")
    if count == chunk.view.length then
      driver.put id { client with inputFront := rest, inputBytes := client.inputBytes - count }
      if let some lease := chunk.lease then lease.release
    else
      driver.put id { client with
        inputFront := ({ chunk with view := chunk.view.drop count } :: rest)
        inputBytes := client.inputBytes - count }

private def Driver.setReading (driver : Driver) (id : Reactor.SocketId) (enabled : Bool) : IO Unit := do
  let some client ← driver.client? id | return
  let enabled := enabled && !client.peerEOF && !client.closing
  if client.reading != enabled then
    client.socket.setReadEnabled enabled
    driver.put id { client with reading := enabled }

private def Driver.closeNow (driver : Driver) (id : Reactor.SocketId) : IO Unit := do
  let some client ← driver.client? id | return
  driver.state.modify fun state => { state with clients := state.clients.erase id }
  try
    releaseInput client
  finally
    if let some pipe := client.pipe then
      try pipe.onClose catch _ => pure ()
    let _ ← client.socket.close (by decide)
    pure ()

private def Driver.forget (driver : Driver) (id : Reactor.SocketId) : IO Unit := do
  let some client ← driver.client? id | return
  driver.state.modify fun state => { state with clients := state.clients.erase id }
  try releaseInput client
  finally
    if let some pipe := client.pipe then
      try pipe.onClose catch _ => pure ()

private def Driver.now (driver : Driver) : IO UInt64 := do return (← driver.state.get).now

private def deadline (now : UInt64) (duration : Nat) : IO UInt64 := do
  let result := now.toNat + duration
  if result > 9223372036854775807 then throw (IO.userError "HTTP timeout exceeds native clock range")
  return UInt64.ofNat result

private def Driver.cancelRequest (driver : Driver) (id : Reactor.SocketId) : IO Unit := do
  let some client ← driver.client? id | return
  if client.requestDeadline.isSome then
    client.socket.cancelTimer 1
    driver.put id { client with requestDeadline := none }

private def Driver.syncWriteTimer (driver : Driver) (id : Reactor.SocketId) : IO Unit := do
  unless ← id.isLive driver.reactor do
    driver.forget id
    return
  let state ← driver.state.get
  let some client := state.clients[id]? | return
  let mut earliest : Option UInt64 := none
  for output in client.outputs do
    earliest := some (min (earliest.getD output.started) output.started)
  for slot in state.slots do
    if let some flight := slot.flight then
      if flight.owner == id then
        earliest := some (min (earliest.getD flight.started) flight.started)
  let wanted ← match earliest with
    | none => pure none
    | some start => some <$> deadline start driver.config.server.writeTimeoutMs
  if wanted != client.writeDeadline then
    match wanted with
    | none => client.socket.cancelTimer 2
    | some value => client.socket.armTimer 2 value
    driver.put id { client with writeDeadline := wanted }
  let some client ← driver.client? id | return
  if earliest.isSome then
    if client.idleDeadline.isSome then
      client.socket.cancelTimer 0
      driver.put id { client with idleDeadline := none }
  else if !client.closing && client.idleDeadline.isNone then
    let value ← deadline state.now driver.config.server.idleTimeoutMs
    client.socket.armTimer 0 value
    driver.put id { client with idleDeadline := some value }

private def limitedReply (config : ReactorServerConfig) (reply : Reply) : Reply := Id.run do
  let mut count := 0
  let mut bytes := 0
  let mut valid : Bool := reply.informational.size <= config.machine.maxInformational
  for (response, options) in reply.informational.push (reply.response, reply.options) do
    valid := valid && response.body.size <= config.server.maxResponseBytes
    count := count + response.headers.size + options.trailers.size
    for header in response.headers ++ options.trailers do
      bytes := bytes + header.name.toUTF8.size + header.value.size + 4
    if let some reason := options.reason then bytes := bytes + reason.toUTF8.size
    if let some (.contentLength length) := options.framing then
      valid := valid && length <= 18446744073709551615
  valid := valid && count <= config.server.maxResponseHeaders && bytes <= config.server.maxResponseHeaderBytes
  if valid then return reply
  return { response := { status := 500 }, options := { forceClose := true } }

private def Driver.appendOutput (driver : Driver) (id : Reactor.SocketId)
    (parts : Array ByteSlice) (outputId : Option Nat := none) (barrier : Bool := false) : IO Unit := do
  let some client ← driver.client? id | return
  if client.closing then return
  if parts.size > 4096 then driver.closeNow id; return
  let parts := parts.filter (fun part => !part.isEmpty)
  let bytes := parts.foldl (fun total part => total + part.length) 0
  if bytes > driver.config.maxOutputBytes - client.outputBytes then driver.closeNow id; return
  if parts.isEmpty then return
  let output : Output := { parts := parts.toList, id := outputId, barrier, started := ← driver.now }
  driver.put id { client with outputs := client.outputs ++ [output], outputBytes := client.outputBytes + bytes }
  driver.syncWriteTimer id

private def Driver.beginDrain (driver : Driver) (id : Reactor.SocketId) : IO Unit := do
  let some client ← driver.client? id | return
  if client.closing then return
  if !client.outputs.isEmpty then
    driver.put id { client with closeWhenQueued := true }
  else
    driver.setReading id false
    let some client ← driver.client? id | return
    driver.put id { client with closing := true }
    client.socket.closeAfterWrites

private partial def Driver.applyStep (driver : Driver) (id : Reactor.SocketId) (step : Machine.Step) : IO Unit := do
  let some client ← driver.client? id | return
  driver.put id { client with protocol := .http1 step.state, kick := true }
  for action in step.actions do
    let some client ← driver.client? id | return
    match action with
    | .readEnabled enabled => driver.setReading id enabled
    | .write outputId parts barrier => driver.appendOutput id (parts.map ByteSlice.full) (some outputId) barrier
    | .abort _ => driver.closeNow id
    | .drainClose => driver.beginDrain id
    | .inspectHead requestId head framing =>
      let decision ← try driver.handlers.onHeaders head framing
        catch _ => pure (.reject { response := { status := 500 }, options := { forceClose := true } })
      let some client ← driver.client? id | return
      let .http1 machine := client.protocol | return
      match decision with
      | .accept framing => driver.applyStep id (machine.decideHead requestId (.accept framing))
      | .reject reply => driver.applyStep id (machine.decideHead requestId (.reject (limitedReply driver.config reply)))
      | .upgrade reply pipe =>
        driver.cancelRequest id
        let some client ← driver.client? id | return
        driver.put id { client with pipe := some pipe }
        driver.applyStep id (machine.decideHead requestId (.upgrade (limitedReply driver.config reply)))
    | .request requestId request =>
      driver.cancelRequest id
      let reply ← try driver.handlers.onRequest request
        catch _ => pure { response := { status := 500 }, options := { forceClose := true } }
      let some client ← driver.client? id | return
      let .http1 machine := client.protocol | return
      driver.applyStep id (machine.respond requestId (limitedReply driver.config reply))
    | .upgraded _ =>
      if client.pipe.isNone then driver.closeNow id
      else
        driver.put id { client with protocol := .raw, kick := true, finishSent := false }
        driver.setReading id true

private def availableSlot (slots : Array OutputSlot) : Option Nat := Id.run do
  for index in [:slots.size] do
    if let some slot := slots[index]? then
      if slot.flight.isNone then return some index
  return none

/-- Copy only the next bounded wire range into one permanently reserved output
    lease. Native vectors combine these logical operations without copying. -/
private def Driver.flushOne (driver : Driver) (id : Reactor.SocketId) : IO Bool := do
  let state ← driver.state.get
  let some client := state.clients[id]? | return false
  if client.closing || state.writeBlocked then return false
  if client.inFlight >= max 1 (state.slots.size / driver.clientLimit) then return false
  let some index := availableSlot state.slots | return false
  let output :: rest := client.outputs | return false
  let part :: tail := output.parts | throw (IO.userError "empty HTTP output ticket")
  let some slot := state.slots[index]? | throw (IO.userError "HTTP output slot index is invalid")
  let length := min 4096 part.length
  if length == 0 || part.offset > 4294967295 then
    driver.closeNow id
    return false
  if slot.generation >= 281474976710655 then throw (IO.userError "HTTP write operation generation exhausted")
  let generation := slot.generation + 1
  let operation := generation * 65536 + UInt64.ofNat (index + 1)
  slot.buffer.copySliceFrom part.bytes (UInt32.ofNat part.offset) (UInt32.ofNat length)
  match ← client.socket.tryWrite slot.buffer 0 (UInt32.ofNat length) operation with
  | .wouldBlock =>
    driver.state.modify fun state => { state with writeBlocked := true }
    return false
  | .queued => pure ()
  let parts := if length == part.length then tail else part.drop length :: tail
  let last := parts.isEmpty
  let flight : Flight := {
    owner := id
    operation := operation
    outputId := output.id
    barrier := output.barrier
    last := last
    started := output.started
    length := length }
  driver.state.modify fun state =>
    { state with slots := state.slots.set! index { slot with generation, flight := some flight } }
  driver.put id { client with
    outputs := (if last then rest else ({ output with parts } :: rest))
    outputBytes := client.outputBytes - length
    inFlight := client.inFlight + 1 }
  if last && !output.barrier then
    if let some outputId := output.id then
      let some client ← driver.client? id | return true
      if let .http1 machine := client.protocol then
        driver.applyStep id (machine.outputAccepted outputId)
  driver.syncWriteTimer id
  if let some client ← driver.client? id then
    if client.closeWhenQueued && client.outputs.isEmpty then driver.beginDrain id
  return true

private def Driver.startRequest (driver : Driver) (id : Reactor.SocketId) (started : UInt64) : IO Unit := do
  let some client ← driver.client? id | return
  if client.requestDeadline.isNone then
    let value ← deadline started driver.config.server.requestTimeoutMs
    client.socket.armTimer 1 value
    driver.put id { client with requestDeadline := some value }

private def withDate (response : Response) (date : ByteArray) : Response :=
  if response.headers.any (fun header => header.name.toLower == "date") then response
  else { response with headers := response.headers.push { name := "Date", value := date } }

private def Driver.failH2 (driver : Driver) (id : Reactor.SocketId)
    (connection : HTTP2.Connection) (error : HTTP2.ProtocolError) : IO Unit := do
  driver.appendOutput id #[ByteSlice.full (connection.goAway error)]
  let some client ← driver.client? id | return
  driver.put id { client with closeWhenQueued := true }
  driver.setReading id false

private def Driver.feedH2 (driver : Driver) (id : Reactor.SocketId) (part : ByteSlice) : IO Unit := do
  let state ← driver.state.get
  let some client := state.clients[id]? | return
  let .http2 connection := client.protocol | return
  let connection := (connection.setTime state.now.toNat).setDate state.date
  -- This is the compatibility adapter for the existing pure H2 machine.
  -- Its slice/frame parser migration is retained for phase four.
  match connection.feed part.copy with
  | .error error => driver.failH2 id connection error
  | .ok (next, control, requests) =>
    driver.put id { client with protocol := .http2 next }
    driver.appendOutput id #[ByteSlice.full control]
    for event in requests do
      let some client ← driver.client? id | return
      let .http2 connection := client.protocol | return
      if !connection.canRespond event.streamId then continue
      let reply ← try driver.handlers.onRequest event.request
        catch _ => pure { response := { status := 500 } }
      let response := withDate (limitedReply driver.config reply).response state.date
      let encoded : Except HTTP2.ProtocolError (HTTP2.Connection × ByteArray) := match connection.respond event.streamId response with
        | .ok result => .ok result
        | .error _ => connection.respond event.streamId (withDate { status := 500 } state.date)
      match encoded with
      | .error error => driver.failH2 id connection error
      | .ok (next, wire) =>
        let some client ← driver.client? id | return
        driver.put id { client with protocol := .http2 next }
        driver.appendOutput id #[ByteSlice.full wire]
    if let some client ← driver.client? id then
      if let .http2 connection := client.protocol then
        if !connection.hasPartialInput then driver.cancelRequest id

private def Driver.serviceH2 (driver : Driver) (id : Reactor.SocketId) : IO Bool := do
  let state ← driver.state.get
  let some client := state.clients[id]? | return false
  let .http2 connection := client.protocol | return false
  if client.closing || client.closeWhenQueued then return false
  match connection.expireRequests state.now.toNat driver.config.server.requestTimeoutMs with
  | .error error => driver.failH2 id connection error; return true
  | .ok (connection, resets) =>
    driver.put id { client with protocol := .http2 connection }
    if !resets.isEmpty then driver.appendOutput id #[ByteSlice.full resets]
    let some client ← driver.client? id | return true
    if connection.canDrain && client.outputs.isEmpty then
      match connection.drain with
      | .error error => driver.failH2 id connection error
      | .ok (next, wire) =>
        driver.put id { client with protocol := .http2 next }
        driver.appendOutput id #[ByteSlice.full wire]
      return true
    return !resets.isEmpty

private inductive Detection where
  | more (matched consumed : Nat)
  | http1 (matched consumed : Nat)
  | http2 (consumed : Nat)

private def detect (matched : Nat) (part : ByteSlice) : Detection := Id.run do
  let mut matched := matched
  for index in [:part.length] do
    if part.bytes[part.offset + index]! != preface[matched]! then return .http1 matched index
    matched := matched + 1
    if matched == preface.size then return .http2 (index + 1)
  return .more matched part.length

private def Driver.detectProtocol (driver : Driver) (id : Reactor.SocketId)
    (matched : Nat) (chunk : InputChunk) : IO Unit := do
  driver.startRequest id chunk.arrived
  match detect matched chunk.view with
  | .more matched consumed =>
    driver.consume id consumed
    if let some client ← driver.client? id then driver.put id { client with protocol := .detect matched }
  | .http1 matched consumed =>
    driver.consume id consumed
    let state ← driver.state.get
    let some current := state.clients[id]? | return
    let client := normalizedInput current
    let prefixChunk : InputChunk := { view := (ByteSlice.full preface).take matched, arrived := chunk.arrived }
    let input := if matched == 0 then client.inputFront else prefixChunk :: client.inputFront
    driver.put id { client with
      protocol := .http1 ((Machine.State.new driver.config.machine).setDate state.date)
      inputFront := input
      inputBytes := client.inputBytes + matched
      kick := true }
  | .http2 consumed =>
    driver.consume id consumed
    let state ← driver.state.get
    let some client := state.clients[id]? | return
    match ((HTTP2.Connection.new.setTime state.now.toNat).setDate state.date).feed preface with
    | .error error => driver.failH2 id HTTP2.Connection.new error
    | .ok (connection, _, _) =>
      driver.put id { client with protocol := .http2 connection, kick := true }
      driver.appendOutput id #[ByteSlice.full HTTP2.Connection.initialSettings]

private def Driver.rawResult (driver : Driver) (id : Reactor.SocketId) (result : RawResult) : IO Unit := do
  driver.appendOutput id result.output
  if result.closeAfterWrites then
    if let some client ← driver.client? id then
      driver.put id { client with closeWhenQueued := true }
      driver.setReading id false

private def Driver.finishInput (driver : Driver) (id : Reactor.SocketId) : IO Unit := do
  let some client ← driver.client? id | return
  if !client.peerEOF || client.finishSent || client.inputBytes != 0 || client.closing then return
  driver.put id { client with finishSent := true }
  match client.protocol with
  | .http1 machine => driver.applyStep id machine.finish
  | .detect matched =>
    if matched == 0 then driver.beginDrain id
    else
      let state ← driver.state.get
      driver.applyStep id (((Machine.State.new driver.config.machine).setDate state.date).feed
        (preface.extract 0 matched))
      if let some client ← driver.client? id then
        if let .http1 machine := client.protocol then driver.applyStep id machine.finish
  | .http2 connection =>
    if !connection.hasPartialInput then driver.beginDrain id else driver.closeNow id
  | .raw =>
    match client.pipe with
    | none => driver.closeNow id
    | some pipe =>
      let result ← try pipe.onEOF catch _ => pure { closeAfterWrites := true }
      driver.rawResult id result

/-- Bounded controller work. Parser decisions may complete with zero input, so
    each transition explicitly kicks the next empty-input step as needed. -/
private def Driver.pump (driver : Driver) (id : Reactor.SocketId) : IO Unit := do
  unless ← id.isLive driver.reactor do
    driver.forget id
    return
  for _ in [:driver.config.workPerClient] do
    let some current ← driver.client? id | return
    if current.closing then return
    let client := normalizedInput current
    driver.put id client
    let flushed ← driver.flushOne id
    let some client ← driver.client? id | return
    if client.closing then return
    if client.closeWhenQueued then
      if client.outputs.isEmpty then driver.beginDrain id
      if !flushed then return
      continue
    let mut advanced := flushed
    match client.inputFront.head?, client.protocol with
    | some chunk, .detect matched =>
      driver.detectProtocol id matched chunk
      advanced := true
    | some chunk, .http1 machine =>
      if machine.wantsInput then
        if machine.isIdle then driver.startRequest id chunk.arrived
        let state ← driver.state.get
        let step := (machine.setDate state.date).feedSlice chunk.view.bytes chunk.view.offset chunk.view.length
        driver.consume id step.consumed
        driver.applyStep id step
        advanced := step.consumed != 0 || !step.actions.isEmpty
    | some chunk, .http2 _ =>
      driver.startRequest id chunk.arrived
      driver.feedH2 id chunk.view
      driver.consume id chunk.view.length
      advanced := true
    | some chunk, .raw =>
      match client.pipe with
      | none => driver.closeNow id
      | some pipe =>
        let result ← try pipe.onBytes chunk.view catch _ => pure { closeAfterWrites := true }
        driver.consume id chunk.view.length
        driver.rawResult id result
      advanced := true
    | none, .http1 machine =>
      if client.kick && machine.wantsInput then
        driver.put id { client with kick := false }
        let step := machine.feed ByteArray.empty
        driver.applyStep id step
        if step.actions.isEmpty then
          if let some client ← driver.client? id then driver.put id { client with kick := false }
        advanced := !step.actions.isEmpty
    | none, .http2 _ => advanced := (← driver.serviceH2 id) || advanced
    | none, _ => pure ()
    driver.finishInput id
    if let some client ← driver.client? id then
      if client.closeWhenQueued && client.outputs.isEmpty then driver.beginDrain id
    if !advanced then return

private def Driver.accepted (driver : Driver) (socket : Reactor.Socket .connected) : IO Unit := do
  let id := socket.id
  let state ← driver.state.get
  if state.clients.contains id then throw (IO.userError "duplicate native HTTP accept identity")
  let value ← deadline state.now driver.config.server.idleTimeoutMs
  socket.armTimer 0 value
  driver.put id { socket, idleDeadline := some value }

private def Driver.read (driver : Driver) (socket : Reactor.Socket .connected)
    (buffer : Reactor.Buffer) (offset length : UInt32) : IO Unit := do
  let id := socket.id
  let some client ← driver.client? id | buffer.release; return
  if client.closing || client.closeWhenQueued then buffer.release; return
  let bytes ← try buffer.view catch error => buffer.release; throw error
  let some view := ByteSlice.ofRange? bytes offset.toNat length.toNat
    | buffer.release; throw (IO.userError "native HTTP read range is invalid")
  if view.length > driver.config.maxInputBytes - client.inputBytes then
    buffer.release
    driver.closeNow id
    return
  let state ← driver.state.get
  let chunk : InputChunk := { view, lease := some buffer, arrived := state.now }
  driver.put id { client with
    inputBack := chunk :: client.inputBack
    inputBytes := client.inputBytes + view.length
    kick := true }
  if let some client ← driver.client? id then
    if client.idleDeadline.isSome then
      let value ← deadline state.now driver.config.server.idleTimeoutMs
      socket.armTimer 0 value
      driver.put id { client with idleDeadline := some value }
  driver.pump id

private def Driver.closed (driver : Driver) (id : Reactor.SocketId) : IO Unit := do
  -- CLOSED can follow a user abort that already removed the client. Its write
  -- records are nevertheless the final owner of reserved output slots.
  driver.state.modify fun state => { state with
    slots := state.slots.map fun slot =>
      if slot.flight.any (fun flight => flight.owner == id) then { slot with flight := none } else slot
    writeBlocked := false }
  driver.forget id

private def Driver.written (driver : Driver) (id : Reactor.SocketId)
    (operation : UInt64) (count : Nat) : IO Unit := do
  let low := (operation % 65536).toNat
  if low == 0 then throw (IO.userError "invalid HTTP write completion operation")
  let index := low - 1
  let state ← driver.state.get
  let some slot := state.slots[index]? | throw (IO.userError "HTTP write completion slot is invalid")
  let some flight := slot.flight | return
  if flight.owner != id || flight.operation != operation then return
  if count != flight.length then throw (IO.userError "HTTP write completion length changed")
  driver.state.modify fun state => { state with
    slots := state.slots.set! index { slot with flight := none }
    writeBlocked := false }
  if let some client ← driver.client? id then
    driver.put id { client with inFlight := client.inFlight - 1 }
  unless ← id.isLive driver.reactor do
    driver.forget id
    return
  if flight.last && flight.barrier then
    if let some outputId := flight.outputId then
      if let some client ← driver.client? id then
        if let .http1 machine := client.protocol then
          driver.applyStep id (machine.outputAccepted outputId)
  driver.syncWriteTimer id

private def Driver.timer (driver : Driver) (id : Reactor.SocketId) (kind : UInt32) : IO Unit := do
  let state ← driver.state.get
  let some client := state.clients[id]? | return
  unless ← id.isLive driver.reactor do
    driver.forget id
    return
  if kind == 2 then
    if client.writeDeadline.any (· <= state.now) then driver.closeNow id
  else if !client.closing then
    if kind == 0 then
      if client.idleDeadline.any (· <= state.now) then driver.closeNow id
    else if kind == 1 && client.requestDeadline.any (· <= state.now) then
      driver.put id { client with requestDeadline := none }
      match client.protocol with
      | .http1 machine => driver.applyStep id ((machine.setDate state.date).timeout .request)
      | .http2 connection => driver.failH2 id connection ⟨.enhanceYourCalm, .connection, "partial HTTP/2 input timed out"⟩
      | .detect _ => driver.closeNow id
      | .raw => pure ()

private def Driver.event (driver : Driver) : Reactor.Event → IO Unit
  | .accepted socket => driver.accepted socket
  | .read socket buffer offset length => driver.read socket buffer offset length
  | .written id operation count => driver.written id operation count
  | .closed socket => driver.closed socket.id
  | .eof socket => do
    let id := socket.id
    if let some client ← driver.client? id then
      driver.put id { client with peerEOF := true, reading := false, kick := true }
      driver.pump id
  | .timer socket kind => driver.timer socket.id kind
  | .wake => pure ()
  | .error id flags code => do
    if (flags &&& 6) != 0 then throw (← Errno.error "HTTP native setup/close" code)
    if (flags &&& 1) != 0 then
      if !(← Reactor.isRecoverableAcceptError code) then throw (← Errno.error "HTTP accept" code)
    else if code == -(Int.ofNat (← FFI.errnoEbadf).toNat) then
      throw (← Errno.error "HTTP owned descriptor (library bug)" code)
    else if !(← Errno.isInterrupted code) then driver.forget id

private def Driver.refresh (driver : Driver) : IO Unit := do
  let now ← Reactor.nowMs
  let state ← driver.state.get
  let second := now / 1000
  let date ← if second != state.dateSecond || state.date.isEmpty then currentDate else pure state.date
  driver.state.modify fun state => { state with now, dateSecond := second, date }

private def Driver.pumpAll (driver : Driver) : IO Unit := do
  let state ← driver.state.get
  let clients := state.clients.toArray
  if clients.isEmpty then return
  for offset in [:clients.size] do
    let index := (state.roundRobin + offset) % clients.size
    if let some (id, _) := clients[index]? then driver.pump id
  driver.state.modify fun state => { state with roundRobin := state.roundRobin + 1 }

private def Driver.hasWork (driver : Driver) : IO Bool := do
  let state ← driver.state.get
  let writable := (availableSlot state.slots).isSome && !state.writeBlocked
  for (_, client) in state.clients.toArray do
    if client.closing then continue
    if writable && !client.outputs.isEmpty &&
        client.inFlight < max 1 (state.slots.size / driver.clientLimit) then return true
    if client.closeWhenQueued then continue
    if client.peerEOF && !client.finishSent && client.inputBytes == 0 then return true
    match client.protocol with
    | .http1 machine =>
      if machine.wantsInput && (client.inputBytes != 0 || client.kick) then return true
    | .http2 connection =>
      if client.inputBytes != 0 || (connection.canDrain && client.outputs.isEmpty) then return true
    | _ => if client.inputBytes != 0 then return true
  return false

private partial def Driver.loop (driver : Driver) : IO Unit := do
  if ← driver.group.stopping then return
  driver.refresh
  driver.pumpAll
  let timeout : Int32 := if ← driver.hasWork then 0 else 100
  match ← driver.reactor.poll timeout with
  | .interrupted => pure ()
  | .completions count =>
    driver.refresh
    -- The native batch can already contain historical write records. CLOSED
    -- first reclaims known owners; explicit liveness handles a deferred CLOSED.
    let mut events := #[]
    for index in [:count] do events := events.push (← driver.reactor.event index.toUInt32)
    for event in events do
      if let .closed socket := event then driver.closed socket.id
    for event in events do
      match event with
      | .closed _ => pure ()
      | _ => driver.event event
  driver.loop

private def withOutputSlots (reactor : Reactor.Reactor) (count : Nat)
    (use : Array OutputSlot → IO α) : IO α := go count #[]
where
  go (remaining : Nat) (slots : Array OutputSlot) : IO α :=
    match remaining with
    | 0 => use slots
    | n + 1 => do
      let buffer ← reactor.acquire 4096
      Reactor.withBuffer buffer fun buffer => go n (slots.push { buffer })

private def runWorker (factory : Nat → IO Handlers) (config : ReactorServerConfig)
    (workerId clientLimit : Nat) (reactor : Reactor.Reactor) (group : Reactor.Group) : IO Unit := do
  let pool := config.native.buffers4k.toNat + config.native.buffers16k.toNat + config.native.buffers64k.toNat
  let count := min config.outputBuffers (min (clientLimit * 4) (min config.native.maxWrites.toNat (pool - 1)))
  if count == 0 || count > 65535 then throw (IO.userError "HTTP requires reserved output and receive buffer credits")
  if count < clientLimit then
    throw (IO.userError "HTTP output buffer credits must cover every admitted client")
  withOutputSlots reactor count fun slots => do
    let handlers ← factory workerId
    let state ← IO.mkRef { slots : WorkerState }
    let driver : Driver := { reactor, group, config, handlers, clientLimit, state }
    try driver.loop
    finally
      let state ← driver.state.get
      for (id, _) in state.clients.toArray do driver.forget id

/-- Construct independent callbacks and state inside each dedicated worker.
    The global client limit is partitioned, rather than multiplied by workers. -/
def serveFactory (factory : Nat → IO Handlers) (config : ReactorServerConfig := {})
    (host : String := "127.0.0.1") (port : UInt16 := 8080) : IO Unit := do
  if config.server.maxClients == 0 || config.server.idleTimeoutMs == 0 ||
      config.server.requestTimeoutMs == 0 || config.server.writeTimeoutMs == 0 ||
      config.outputBuffers == 0 || config.maxInputBytes == 0 || config.maxOutputBytes < 4096 ||
      config.workPerClient == 0 then throw (IO.userError "HTTP limits and timeouts must be positive")
  withWorkerPool host port config.workers config.server.maxClients config.native
    (runWorker factory config)

/-- Compatibility callbacks may close over mutable application state. Keep
    their original single-worker ownership; multicore callers use the factory. -/
def serveWithHandlers (handlers : Handlers) (config : ReactorServerConfig := {})
    (host : String := "127.0.0.1") (port : UInt16 := 8080) : IO Unit :=
  serveFactory (fun _ => pure handlers) { config with workers := 1 } host port

def serveWithConfig (router : Router) (config : ServerConfig)
    (host : String := "127.0.0.1") (port : UInt16 := 8080) : IO Unit :=
  serveWithHandlers (.ofRouter router) { server := config, workers := 1 } host port

def serve (host : String := "127.0.0.1") (port : UInt16 := 8080) : IO Unit :=
  serveFactory (fun _ => pure .default) {} host port

end ReactorServer
end LeanNet.HTTP
