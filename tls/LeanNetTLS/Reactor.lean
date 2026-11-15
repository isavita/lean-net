import Std.Data.HashMap
import LeanNet.HTTP.Transport
import LeanNetTLS.ReactorConfig
import LeanNetTLS.FFI.Worker

namespace LeanNetTLS.Reactor

open LeanNet

structure Bundle where
  private mk ::
  private handle : UInt64
  private alive : IO.Ref Bool

private def check (operation : String) (raw : UInt64) (message : String := "") : IO UInt64 := do
  let code := Errno.decode raw
  if code < 0 then
    let error ← Errno.error operation code
    throw (IO.userError s!"{error}{if message.isEmpty then "" else ": " ++ message}")
  return raw

private def checkZero (operation : String) (raw : UInt64) : IO Unit := do
  let value ← check operation raw
  if value != 0 then throw (IO.userError s!"{operation}: unexpected native result {value}")

/-- Atomically request off-loop loading. Requests may coalesce; `completed`
    reaching this ticket means the loader recorded a success or failure. -/
def Bundle.requestReload (bundle : Bundle) : IO UInt64 := do
  unless ← bundle.alive.get do throw (IO.userError "TLS certificate bundle is closed")
  check "TLS certificate reload request" (← FFI.Worker.bundleReloadRequest bundle.handle)

def Bundle.reloadStatus (bundle : Bundle) : IO ReloadStatus := do
  unless ← bundle.alive.get do throw (IO.userError "TLS certificate bundle is closed")
  let raw ← FFI.Worker.bundleReloadStats bundle.handle
  return {
    generation := raw.generation
    attempts := raw.attempts
    publications := raw.publications
    failures := raw.failures
    lastError := Errno.decode raw.lastError
    liveVersions := raw.liveVersions
    loaderThreads := raw.loaderThreads
    requested := raw.requested
    completed := raw.completed }

/-- Each TLS worker joins before the loader is stopped/joined and immutable
    context snapshots and their resumption caches are released. -/
def withBundle (config : Config) (use : Bundle → IO α) : IO α := do
  if config.queueCapacity == 0 || config.queueCapacity > 256 ||
      config.handshakeTimeoutMs == 0 || config.shutdownTimeoutMs == 0 ||
      config.handshakeTimeoutMs > 9223372036854775807 || config.shutdownTimeoutMs > 9223372036854775807 then
    throw (IO.userError "TLS queue capacity and deadlines must be positive and bounded")
  let names := config.hosts.map (·.name)
  let certs := config.hosts.map (·.certificateChain)
  let keys := config.hosts.map (·.privateKey)
  for text in #[config.certificateChain, config.privateKey] ++ names ++ certs ++ keys do
    if text.toUTF8.toList.contains 0 then throw (IO.userError "TLS configuration contains NUL")
  let (raw, message) ← FFI.Worker.bundleNew config.certificateChain config.privateKey names certs keys
    (if config.tickets then 1 else 0)
  let handle ← check "TLS certificate bundle" raw message
  if handle == 0 then throw (IO.userError "TLS certificate bundle returned null")
  let bundle : Bundle := ⟨handle, ← IO.mkRef true⟩
  try
    if let some reload := config.reload then
      if reload.intervalMs > 9223372036854775807 then throw (IO.userError "TLS reload interval exceeds native range")
      checkZero "TLS certificate loader start" (← FFI.Worker.bundleReloadStart handle reload.intervalMs)
    use bundle
  finally
    bundle.alive.set false
    checkZero "TLS certificate bundle free" (← FFI.Worker.bundleFree handle)

private structure CipherChunk where
  buffer : LeanNet.Reactor.Buffer
  offset : UInt32
  length : UInt32

private structure Session where
  wire : LeanNet.Reactor.Wire .tls_handshaking
  ready : Option (LeanNet.Reactor.Wire .tls_ready) := none
  native : UInt64
  pendingFront : List CipherChunk := []
  pendingBack : List CipherChunk := []
  peerEOF : Bool := false
  eofSent : Bool := false
  pendingBytes : Nat := 0
  cipherReading : Bool := true
  nativeClosed : Bool := false
  nativeErrors : Array (UInt32 × Int) := #[]

private structure State where
  sessions : Std.HashMap LeanNet.Reactor.SocketId Session := {}
  identities : Std.HashMap UInt64 LeanNet.Reactor.SocketId := {}
  shutdownBefore : Option UInt64 := none

private structure Driver where
  handle : UInt64
  reactor : LeanNet.Reactor.Reactor
  state : IO.Ref State
  alive : IO.Ref Bool

private def Driver.ensureAlive (driver : Driver) : IO Unit := do
  unless ← driver.alive.get do throw (IO.userError "TLS worker is closed")

private def Driver.ensureSession (driver : Driver) (id : LeanNet.Reactor.SocketId) : IO Session := do
  driver.ensureAlive
  let some session := (← driver.state.get).sessions[id]?
    | throw (IO.userError "TLS session is closed")
  return session

private def Driver.put (driver : Driver) (id : LeanNet.Reactor.SocketId) (session : Session) : IO Unit :=
  driver.state.modify fun state => { state with sessions := state.sessions.insert id session }

private def releasePending (session : Session) : IO Unit := do
  let mut failure : Option IO.Error := none
  for chunk in session.pendingFront ++ session.pendingBack do
    try chunk.buffer.release
    catch error => if failure.isNone then failure := some error
  if let some error := failure then throw error

private def Driver.forget (driver : Driver) (id : LeanNet.Reactor.SocketId) : IO Unit := do
  let some session := (← driver.state.get).sessions[id]? | return
  driver.state.modify fun state => { state with
    sessions := state.sessions.erase id, identities := state.identities.erase session.native }
  releasePending session

private def Driver.abort (driver : Driver) (id : LeanNet.Reactor.SocketId) : IO Unit := do
  driver.ensureAlive
  let some session := (← driver.state.get).sessions[id]? | return
  if session.native == 0 then
    if ← id.isLive driver.reactor then session.wire.close (by decide)
  else checkZero "TLS abort" (← FFI.Worker.abort driver.handle session.native)

private def Driver.setCipherReading (driver : Driver) (id : LeanNet.Reactor.SocketId)
    (enabled : Bool) : IO Unit := do
  let some session := (← driver.state.get).sessions[id]? | return
  if session.cipherReading == enabled then return
  unless ← id.isLive driver.reactor do return
  match session.ready with
  | some wire => wire.setReadEnabled enabled
  | none => session.wire.setReadEnabled enabled
  driver.put id { session with cipherReading := enabled }

/-- Drain only bounded copies into native queue cells. A full queue retains the
    original reactor lease until the TLS worker returns credit. -/
private def Driver.feedPending (driver : Driver) (id : LeanNet.Reactor.SocketId) : IO Unit := do
  let some initial := (← driver.state.get).sessions[id]? | return
  if initial.native == 0 || initial.nativeClosed then return
  let budget := (initial.pendingFront.length + initial.pendingBack.length) * 16 + 1
  for _ in [:budget] do
    let some current := (← driver.state.get).sessions[id]? | return
    let session := if current.pendingFront.isEmpty then
      { current with pendingFront := current.pendingBack.reverse, pendingBack := [] } else current
    driver.put id session
    match session.pendingFront with
    | [] =>
      driver.setCipherReading id true
      let session ← driver.ensureSession id
      if session.peerEOF && !session.eofSent then
        checkZero "TLS transport EOF" (← FFI.Worker.peerEOF driver.handle session.native)
        driver.put id { session with eofSent := true }
      return
    | chunk :: rest =>
      let consumed ← check "TLS ciphertext input" (← FFI.Worker.feed driver.handle session.native
        chunk.buffer chunk.offset chunk.length)
      if consumed > chunk.length.toUInt64 then throw (IO.userError "TLS input consumed beyond its lease")
      if consumed == 0 then
        driver.setCipherReading id false
        return
      if consumed == chunk.length.toUInt64 then
        driver.put id { session with pendingFront := rest, pendingBytes := session.pendingBytes - consumed.toNat }
        chunk.buffer.release
      else
        let next : CipherChunk := {
          buffer := chunk.buffer
          offset := chunk.offset + consumed.toUInt32
          length := chunk.length - consumed.toUInt32 }
        driver.put id { session with pendingFront := next :: rest, pendingBytes := session.pendingBytes - consumed.toNat }
  if let some session := (← driver.state.get).sessions[id]? then
    if session.pendingBytes != 0 then driver.setCipherReading id false

private def Driver.endpoint (driver : Driver) (id : LeanNet.Reactor.SocketId)
    (wire : LeanNet.Reactor.Wire .tls_ready) : HTTP.Transport.Endpoint := {
  id
  tryWrite := fun buffer offset length operation => do
    let session ← driver.ensureSession id
    let result ← check "TLS plaintext write" (← FFI.Worker.write driver.handle session.native buffer offset length operation)
    if result == 0 then return .queued
    if result == 1 then return .wouldBlock
    throw (IO.userError "TLS plaintext write returned an invalid submission")
  tryFile := fun region operation => do
    let session ← driver.ensureSession id
    if !region.valid || region.length > 4294967295 then throw (IO.userError "invalid TLS file range")
    let raw ← FFI.Worker.writeFile driver.handle session.native region.owner region.token
      region.offset region.length.toUInt32 operation
    let code := Errno.decode raw
    if code < 0 && (← Errno.isInterrupted code) then return .interrupted
    let result ← check "TLS file submission" raw
    if result == 0 then return .queued
    if result == 1 then return .wouldBlock
    throw (IO.userError "TLS file write returned an invalid submission")
  setReadEnabled := fun enabled => do
    let session ← driver.ensureSession id
    checkZero "TLS application read credit" (← FFI.Worker.readEnabled driver.handle session.native (if enabled then 1 else 0))
  close := driver.abort id
  closeAfterWrites := do
    let session ← driver.ensureSession id
    checkZero "TLS shutdown" (← FFI.Worker.shutdown driver.handle session.native)
  armTimer := fun kind value => do driver.ensureAlive; wire.armTimer kind value
  cancelTimer := fun kind => do driver.ensureAlive; wire.cancelTimer kind }

/-- A canceled native TLS session can outlive its socket until its thread
    acknowledges cancellation. Admit its replacement without treating this
    ordinary bounded resource pressure as a server failure. -/
private def Driver.tryAttach (driver : Driver) (id : LeanNet.Reactor.SocketId) : IO Unit := do
  let some session := (← driver.state.get).sessions[id]? | return
  if session.native != 0 || session.nativeClosed then return
  unless ← id.isLive driver.reactor do return
  let raw ← FFI.Worker.attach driver.handle session.wire
  let code := Errno.decode raw
  if code < 0 && (← Errno.isWouldBlock code) then return
  let native ← check "TLS session attach" raw
  if native == 0 then throw (IO.userError "TLS session attach returned null")
  driver.put id { session with native }
  driver.state.modify fun state => { state with identities := state.identities.insert native id }

private def Driver.attach (driver : Driver) (socket : LeanNet.Reactor.Socket .connected) : IO Unit := do
  let id := socket.id
  unless ← id.isLive driver.reactor do return
  let wire ← socket.claim
  driver.put id { wire, native := 0 }
  try driver.tryAttach id
  catch error => driver.abort id; throw error

private def Driver.readCipher (driver : Driver) (id : LeanNet.Reactor.SocketId)
    (buffer : LeanNet.Reactor.Buffer) (offset length : UInt32) : IO Unit := do
  let some session := (← driver.state.get).sessions[id]? | buffer.release; return
  if session.nativeClosed then buffer.release; return
  if length.toNat > 65536 - session.pendingBytes then
    buffer.release
    driver.abort id
    return
  driver.put id { session with
    pendingBack := { buffer, offset, length } :: session.pendingBack
    pendingBytes := session.pendingBytes + length.toNat }
  driver.feedPending id

private def Driver.nativeEvent (driver : Driver) : LeanNet.Reactor.Event → IO (Array HTTP.Transport.Event)
  | .accepted socket => do driver.attach socket; return #[]
  | .read socket buffer offset length => do driver.readCipher socket.id buffer offset length; return #[]
  | .wireRead id buffer offset length => do driver.readCipher id buffer offset length; return #[]
  | .written _id operation count => do
    if operation &&& 0x8000000000000000 == 0 then
      throw (IO.userError "TLS connection received a plain write completion")
    checkZero "TLS ciphertext written" (← FFI.Worker.onWritten driver.handle operation (UInt64.ofNat count))
    return #[]
  | .closed socket => do
    if let some session := (← driver.state.get).sessions[socket.id]? then
      if session.native != 0 then
        checkZero "TLS native close acknowledgement" (← FFI.Worker.nativeClosed driver.handle session.native)
        -- The TLS thread can still publish a final acknowledged write fence.
        -- Keep its identity until TLSW_CLOSED, but return raw input immediately.
        driver.put socket.id { session with
          nativeClosed := true
          pendingFront := []
          pendingBack := []
          pendingBytes := 0 }
        releasePending session
        return #[]
    driver.forget socket.id
    return #[.closed socket.id]
  | .eof socket => do
    if let some session := (← driver.state.get).sessions[socket.id]? then
      driver.put socket.id { session with peerEOF := true }
      driver.feedPending socket.id
    return #[]
  | .wireEOF id => do
    if let some session := (← driver.state.get).sessions[id]? then
      driver.put id { session with peerEOF := true }
      driver.feedPending id
    return #[]
  | .timer socket kind => pure #[.timer socket.id kind]
  | .wireTimer id kind => pure #[.timer id kind]
  | .wake => pure #[.wake]
  | .error id flags code => do
    if !(← Errno.isInterrupted code) then
      if let some session := (← driver.state.get).sessions[id]? then
        if session.native != 0 then
          driver.abort id
          driver.put id { session with nativeErrors := session.nativeErrors.push (flags, code) }
          return #[]
      driver.abort id
    return #[.error id flags code]

private def Driver.poll (driver : Driver) : IO (Array HTTP.Transport.Event) := do
  let result ← FFI.Worker.pump driver.handle
  -- A negative pump result is a sticky TLS-worker control failure. The native
  -- bridge delivers historical completions first; the default policy is to
  -- stop this bracket, including on EINTR. File retry is a flagged event below.
  let count ← check "TLS completion pump" result
  let mut events := #[]
  for index in [:count.toNat] do
    let raw ← FFI.Worker.event driver.handle index.toUInt32
    let id? := (← driver.state.get).identities[raw.connection]?
    if raw.kind == 2 then
      let buffer ← FFI.Worker.eventBuffer driver.handle index.toUInt32
      let release := do
        -- Forced bracket cleanup consumes the permanent native loan. A late
        -- external release remains idempotent and must not touch a freed handle.
        if ← driver.alive.get then
          checkZero "TLS plaintext input credit" (← FFI.Worker.releasePlain driver.handle raw.connection)
      if let some id := id? then events := events.push (.read id buffer raw.offset raw.length (some release))
      else release
    else if let some id := id? then
      match raw.kind.toNat with
      | 1 =>
        unless ← id.isLive driver.reactor do
          driver.abort id
          continue
        let session ← driver.ensureSession id
        if session.ready.isSome then throw (IO.userError "duplicate TLS handshake completion")
        let ready ← session.wire.ready
        driver.put id { session with ready := some ready }
        let protocol ← match raw.flags with
          | 1 => pure HTTP.Transport.Protocol.http1
          | 2 => pure HTTP.Transport.Protocol.http2
          | _ => throw (IO.userError "TLS negotiated an unknown application protocol")
        events := events.push (.ready (driver.endpoint id ready) protocol)
      | 3 => events := events.push (.written id raw.operation (Errno.decode raw.result).toNat)
      | 4 => events := events.push (.eof id)
      | 6 =>
        if let some session := (← driver.state.get).sessions[id]? then
          for (flags, code) in session.nativeErrors do
            events := events.push (.error id flags code)
        driver.forget id
        events := events.push (.closed id)
      | 7 =>
        let code := Errno.decode raw.result
        if raw.flags &&& 256 != 0 && (← Errno.isInterrupted code) then
          -- The native file operation preserves its offset and cipher fence.
          -- Retrying is an explicit decision on the owning Lean loop.
          checkZero "TLS interrupted file resume" (← FFI.Worker.resumeFile driver.handle raw.connection)
        else if !(← Errno.isInterrupted code) then driver.abort id
        -- An unflagged interrupted ciphertext submission stays queued for
        -- the next owning-loop poll; it is not a paused file operation.
        events := events.push (.error id raw.flags code)
      | _ => throw (IO.userError "TLS worker returned an invalid completion")
  for (id, _) in (← driver.state.get).sessions.toArray do
    driver.tryAttach id
    driver.feedPending id
  return events

private def Driver.stopEvents (driver : Driver) (events : Array HTTP.Transport.Event) : IO Unit := do
  for event in events do
    match event with
    | .read _ buffer _ _ release => release.getD buffer.release
    | .ready endpoint _ =>
      if let some session := (← driver.state.get).sessions[endpoint.id]? then
        checkZero "TLS completed handshake during shutdown" (← FFI.Worker.shutdown driver.handle session.native)
    | _ => pure ()

/-- Preserve clean TLS close-notify on process shutdown, even for incomplete
    HTTP requests. Full HTTP/2 stream draining is handled by the HTTP controller. -/
private def Driver.stop (driver : Driver) (duration : UInt64) : IO Unit := do
  try
    for (_id, session) in (← driver.state.get).sessions.toArray do
      if session.ready.isSome then
        checkZero "TLS worker shutdown" (← FFI.Worker.shutdown driver.handle session.native)
    let proposed := (← LeanNet.Reactor.nowMs) + duration + 100
    let stopDeadline := ((← driver.state.get).shutdownBefore.map (min proposed)).getD proposed
    let mut draining := true
    while draining && (← LeanNet.Reactor.nowMs) < stopDeadline do
      driver.stopEvents (← driver.poll)
      let sessions := (← driver.state.get).sessions.toArray
      draining := !sessions.isEmpty
      if draining then
        match ← driver.reactor.poll 10 with
        | .interrupted => pure ()
        | .completions count =>
          for index in [:count] do
            let event ← driver.reactor.event index.toUInt32
            match event with
            | .accepted socket => let _ ← socket.close (by decide); pure ()
            | _ => driver.stopEvents (← driver.nativeEvent event)
  finally
    let mut failure : Option IO.Error := none
    for (id, _) in (← driver.state.get).sessions.toArray do
      try driver.abort id
      catch error => if failure.isNone then failure := some error
    if let some error := failure then throw error

/-- All OpenSSL calls and their objects belong to the native TLS thread. This
    bracket stops and joins it while the reactor and every buffer are alive. -/
def withWorkerStats (bundle : Bundle) (config : Config) (reactor : LeanNet.Reactor.Reactor)
    (maxClients : Nat) (use : HTTP.Transport.Worker → IO Stats → IO Unit) : IO Unit := do
  unless ← bundle.alive.get do throw (IO.userError "TLS certificate bundle is closed")
  if maxClients == 0 || maxClients > 1000000 then throw (IO.userError "invalid TLS admission limit")
  let (raw, message) ← FFI.Worker.workerNew bundle.handle reactor maxClients.toUInt32 config.queueCapacity
    config.handshakeTimeoutMs config.shutdownTimeoutMs
  let handle ← check "TLS worker create" raw message
  if handle == 0 then throw (IO.userError "TLS worker create returned null")
  let driver : Driver := { handle, reactor, state := ← IO.mkRef {}, alive := ← IO.mkRef true }
  try
    let transport : HTTP.Transport.Worker := {
      deferClosed := true
      event := fun event => do driver.ensureAlive; driver.nativeEvent event
      poll := do driver.ensureAlive; driver.poll
      hasWork := do driver.ensureAlive; return (← check "TLS pending work" (← FFI.Worker.hasWork handle)) != 0
      shutdownBefore := fun deadline => do
        driver.ensureAlive
        driver.state.modify fun state =>
          { state with shutdownBefore := some ((state.shutdownBefore.map (min deadline)).getD deadline) }
      reservedBuffers := 2 * maxClients }
    let diagnostics : IO Stats := do
      unless ← driver.alive.get do throw (IO.userError "TLS worker is closed")
      FFI.Worker.stats handle
    use transport diagnostics
  finally
    try driver.stop config.shutdownTimeoutMs
    finally
      driver.alive.set false
      try
        checkZero "TLS worker stop and join" (← FFI.Worker.workerFree handle)
      finally
        let mut failure : Option IO.Error := none
        for (_, session) in (← driver.state.get).sessions.toArray do
          try releasePending session
          catch error => if failure.isNone then failure := some error
        if let some error := failure then throw error

/-- Standard serving does not expose the diagnostic callback. -/
def withWorker (bundle : Bundle) (config : Config) (reactor : LeanNet.Reactor.Reactor)
    (maxClients : Nat) (use : HTTP.Transport.Worker → IO Unit) : IO Unit :=
  withWorkerStats bundle config reactor maxClients (fun worker _ => use worker)

end LeanNetTLS.Reactor
