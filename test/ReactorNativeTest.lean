import LeanNet.FFI.Reactor
import LeanNet.FFI.Errno
import LeanNet.Reactor.Basic
import LeanNet.Gateway.Resolve

open LeanNet

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do throw (IO.userError message)
private def ok (label : String) (operation : IO UInt64) : IO UInt64 := do
  let raw ← operation
  check (Errno.decode raw >= 0) s!"{label}: {Errno.decode raw}"
  return raw
private def zero (label : String) (operation : IO UInt64) : IO Unit := do
  check ((← ok label operation) == 0) s!"{label}: nonzero success"
private def rejected (label : String) (operation : IO UInt64) : IO Unit := do
  check (Errno.decode (← operation) < 0) s!"{label}: unexpectedly succeeded"

private def retainedLease (reactor buffer : UInt64) : IO Unit := do
  let (result, view) ← FFI.Reactor.buffer reactor buffer
  check (result == 0 && view == "immutable pool bytes".toUTF8) "pool view content"
  rejected "mutating shared pool view" (FFI.Reactor.copy reactor buffer "new".toUTF8)
  zero "release aliased lease" (FFI.Reactor.release reactor buffer)
  rejected "reusing aliased pool storage" (FFI.Reactor.acquire reactor 4096)
  -- Keep the view live through both operations: releasing a lease must not
  -- mutate or invalidate a ByteArray reference retained by the application.
  check (view == "immutable pool bytes".toUTF8) "released immutable view changed"

private def sliceSnapshot (reactor buffer : UInt64) (source : ByteArray) : IO Unit := do
  let (result, view) ← FFI.Reactor.buffer reactor buffer
  check (result == 0 && view == ByteArray.mk #[0, 255, 13, 10]) "binary copySlice contents"
  rejected "copySlice mutates retained view" (FFI.Reactor.copySlice reactor buffer source 0 1)
  check (view == ByteArray.mk #[0, 255, 13, 10]) "failed copySlice changed immutable contents"

private def checkRawBuffer (reactor buffer : UInt64) (expected : ByteArray) : IO Unit := do
  let (result, view) ← FFI.Reactor.buffer reactor buffer
  check (result == 0 && view == expected) "copySlice changed logical buffer length or contents"

private def rawSliceChecks (reactor : UInt64) : IO Unit := do
  let buffer ← ok "acquire slice buffer" (FFI.Reactor.acquire reactor 4096)
  let source := ByteArray.mk #[90, 0, 255, 13, 10, 65, 91]
  zero "copy binary source range" (FFI.Reactor.copySlice reactor buffer source 1 4)
  sliceSnapshot reactor buffer source
  -- The snapshot is gone: bounds failures must be rejected independently of
  -- the native mutation guard for shared buffers.
  rejected "copySlice offset past source" (FFI.Reactor.copySlice reactor buffer source 8 0)
  rejected "copySlice range past source" (FFI.Reactor.copySlice reactor buffer source 6 2)
  rejected "copySlice offset overflow" (FFI.Reactor.copySlice reactor buffer source 4294967295 1)
  rejected "copySlice length overflow" (FFI.Reactor.copySlice reactor buffer source 1 4294967295)
  checkRawBuffer reactor buffer (ByteArray.mk #[0, 255, 13, 10])
  zero "copy empty range at source end" (FFI.Reactor.copySlice reactor buffer source 7 0)
  checkRawBuffer reactor buffer ByteArray.empty
  let large := ByteArray.mk (Array.replicate 4097 (42 : UInt8))
  rejected "copySlice exceeds destination capacity" (FFI.Reactor.copySlice reactor buffer large 0 4097)
  checkRawBuffer reactor buffer ByteArray.empty
  zero "copySlice exact destination capacity" (FFI.Reactor.copySlice reactor buffer large 1 4096)
  checkRawBuffer reactor buffer (ByteArray.mk (Array.replicate 4096 (42 : UInt8)))
  zero "release slice buffer" (FFI.Reactor.release reactor buffer)
  rejected "copySlice released lease" (FFI.Reactor.copySlice reactor buffer source 1 4)

private def typedAliasExhaustion (reactor : Reactor.Reactor) (buffer : Reactor.Buffer) : IO Unit := do
  buffer.copySliceFrom (ByteArray.mk #[7, 0, 255, 8]) 1 2
  let view ← buffer.view
  buffer.release
  check ((← reactor.tryAcquire 4096).isNone) "retained typed view bypassed pool backpressure"
  check (view == ByteArray.mk #[0, 255]) "released typed view changed under acquisition"

private def typedAcquireChecks : IO Unit :=
  Reactor.withReactor {
    maxConnections := 2, maxEvents := 2, maxWrites := 2,
    buffers4k := 1, buffers16k := 0, buffers64k := 0, timerTickMs := 1 } fun reactor => do
    let some buffer ← reactor.tryAcquire 4096 | throw (IO.userError "typed initial acquisition failed")
    check ((← reactor.tryAcquire 4096).isNone) "typed pool exhaustion must return none"
    typedAliasExhaustion reactor buffer
    let some again ← reactor.tryAcquire 4096 | throw (IO.userError "typed released view did not recycle")
    again.release
    let invalid ← try
      let _ ← reactor.tryAcquire 0
      pure false
    catch _ => pure true
    check invalid "typed invalid acquisition must remain an error"

private def coreMain : IO Unit := do
  for native in [FFI.errnoEpipe, FFI.errnoEnotconn, FFI.errnoEtimedout,
      FFI.errnoEconnrefused, FFI.errnoEconnreset, FFI.errnoEconnaborted,
      FFI.errnoEnetreset, FFI.errnoEnetdown, FFI.errnoEnetunreach,
      FFI.errnoEhostunreach, FFI.errnoEintr, FFI.errnoEagain,
      FFI.errnoEwouldblock] do
    let code ← native
    if code != 0 then
      check (← Reactor.isRecoverableAcceptError (-(Int.ofNat code.toNat)))
        s!"confirmed accept peer error is fatal: {code}"
  check (!(← Reactor.isRecoverableAcceptError (-(Int.ofNat (← FFI.errnoEbadf).toNat))))
    "invalid owned descriptor must remain fatal"
  for code in [0, 1, -999999] do
    check (!(← Reactor.isRecoverableAcceptError code)) "unexpected accept result accepted as peer failure"
  let reactor ← ok "create" (FFI.Reactor.create 8 32 16 1 0 0 1)
  check (reactor != 0) "null reactor"
  try
    rejected "zero buffer" (FFI.Reactor.acquire reactor 0)
    rejected "oversized buffer" (FFI.Reactor.acquire reactor 65537)
    let buffer ← ok "acquire" (FFI.Reactor.acquire reactor 4096)
    zero "copy pool bytes" (FFI.Reactor.copy reactor buffer "immutable pool bytes".toUTF8)
    retainedLease reactor buffer
    let next ← ok "reacquire released storage" (FFI.Reactor.acquire reactor 4096)
    check (next != buffer) "buffer generation did not advance"
    let (stale, _) ← FFI.Reactor.buffer reactor buffer
    check (Errno.decode stale < 0) "stale buffer view accepted"
    rejected "stale buffer release" (FFI.Reactor.release reactor buffer)
    zero "release reused storage" (FFI.Reactor.release reactor next)
    rejected "double buffer release" (FFI.Reactor.release reactor next)
    rawSliceChecks reactor

    let socket ← ok "fresh socket" (FFI.Reactor.socketNew reactor)
    rejected "invalid timer kind" (FFI.Reactor.armTimer reactor socket 8 0)
    let now ← FFI.Reactor.now
    zero "arm timer" (FFI.Reactor.armTimer reactor socket 3 (now + 5))
    let mut sawTimer := false
    for _ in [:20] do
      let count ← ok "poll timer" (FFI.Reactor.step reactor 10)
      for i in [:count.toNat] do
        let event ← FFI.Reactor.event reactor i.toUInt32
        if event.kind == 5 then
          check (event.connection == socket && event.operation == 3) "timer identity changed"
          sawTimer := true
      if sawTimer then break
    check sawTimer "timer wheel failed to expire"
    zero "arm canceled timer" (FFI.Reactor.armTimer reactor socket 2 ((← FFI.Reactor.now) + 5))
    zero "cancel timer" (FFI.Reactor.cancelTimer reactor socket 2)
    let count ← ok "poll canceled timer" (FFI.Reactor.step reactor 20)
    for i in [:count.toNat] do
      let event ← FFI.Reactor.event reactor i.toUInt32
      check (event.kind != 5) "canceled timer fired"
    zero "close fresh socket" (FFI.Reactor.close reactor socket)
    rejected "double close" (FFI.Reactor.close reactor socket)
    let count ← ok "poll close" (FFI.Reactor.step reactor 0)
    check (count == 1) "missing close event"
    let event ← FFI.Reactor.event reactor 0
    check (event.kind == 6 && event.connection == socket && event.result == 0) "wrong close event"
    let reused ← ok "reused socket" (FFI.Reactor.socketNew reactor)
    check (reused != socket) "socket generation did not advance"
    rejected "stale socket timer" (FFI.Reactor.armTimer reactor socket 0 0)
    zero "close reused socket" (FFI.Reactor.close reactor reused)
  finally
    zero "free reactor" (FFI.Reactor.free reactor)
  let small ← ok "create single-event reactor" (FFI.Reactor.create 2 1 2 1 0 0 1)
  try
    let socket ← ok "fresh timer socket" (FFI.Reactor.socketNew small)
    let due := (← FFI.Reactor.now) + 3
    for kind in [:8] do zero "arm simultaneous timers" (FFI.Reactor.armTimer small socket kind.toUInt32 due)
    let mut seen : Array UInt64 := #[]
    for _ in [:20] do
      let count ← ok "poll timer backlog" (FFI.Reactor.step small 10)
      check (count <= 1) "event capacity was exceeded"
      if count == 1 then
        let event ← FFI.Reactor.event small 0
        check (event.kind == 5 && event.connection == socket) "timer backlog identity"
        check (!seen.contains event.operation) "timer delivered twice"
        seen := seen.push event.operation
      if seen.size == 8 then break
    check (seen.size == 8) "event-capacity pressure lost due timers"
    zero "close timer socket" (FFI.Reactor.close small socket)
  finally
    zero "free single-event reactor" (FFI.Reactor.free small)
  typedAcquireChecks
  IO.println "native reactor pool, timer and generation tests passed"


private def mustReject (label : String) (action : IO α) : IO Unit := do
  let failed ← try let _ ← action; pure false catch _ => pure true
  check failed label

private def typedConnectInputChecks : IO Unit :=
  Reactor.withReactor {
    maxConnections := 2, maxEvents := 4, maxWrites := 2,
    buffers4k := 1, buffers16k := 0, buffers64k := 0, timerTickMs := 1
  } fun reactor => do
    let fresh ← reactor.socket
    mustReject "typed connect accepted malformed address"
      (fresh.startConnect (ByteArray.mk #[127, 0, 0]) 8080)
    check (!(← fresh.id.isLive reactor)) "invalid connect left a live socket"
    let fresh ← reactor.socket
    mustReject "typed connect accepted port zero"
      (fresh.startConnect (ByteArray.mk #[127, 0, 0, 1]) 0)
    let mut closed := 0
    for _ in [:4] do
      if let .completions count ← reactor.poll 0 then
        for i in [:count] do
          match ← reactor.event i.toUInt32 with
          | .closed _ => closed := closed + 1
          | _ => throw (IO.userError "invalid connect produced unexpected completion")
    check (closed == 2) "invalid connect did not retire both slots"

private def typedResolverChecks : IO Unit := do
  let .ok ipv4 ← LeanNet.Gateway.Resolve.resolve "127.0.0.1"
    | throw (IO.userError "typed IPv4 resolution failed")
  check (ipv4 == ByteArray.mk #[127, 0, 0, 1]) "typed IPv4 bytes changed"
  let .ok ipv6 ← LeanNet.Gateway.Resolve.resolve "::1" .preferIPv6
    | throw (IO.userError "typed IPv6 resolution failed")
  check (ipv6.size == 16 && ipv6[15]! == 1) "typed IPv6 bytes changed"
  let .error .invalidHost ← LeanNet.Gateway.Resolve.resolve "example.com:443"
    | throw (IO.userError "typed resolver accepted host with port")
  let .ok localhost ← LeanNet.Gateway.Resolve.resolve "localhost" .preferIPv4
    | throw (IO.userError "typed localhost resolution failed")
  check (localhost.size == 4 || localhost.size == 16) "typed DNS result invalid"

private def wireMain (port : UInt16) : IO Unit := do
  let held ← IO.mkRef (none : Option Reactor.Waker)
  Reactor.withReactor {
    maxConnections := 4, maxEvents := 8, maxWrites := 4,
    buffers4k := 4, buffers16k := 0, buffers64k := 0, timerTickMs := 1 } fun reactor => do
    let waker ← reactor.waker
    held.set (some waker)
    waker.wake
    let _ ← reactor.listen "127.0.0.1" port
    IO.println "READY"
    let mut wire : Option (Reactor.Wire .tls_ready) := none
    let mut received := 0
    let mut closed := false
    for _ in [:500] do
      match ← reactor.poll 10 with
      | .interrupted => pure ()
      | .completions count =>
        -- Decode before claim to exercise immutable same-batch connected aliases.
        let mut batch := #[]
        for i in [:count] do batch := batch.push (← reactor.event i.toUInt32)
        for event in batch do
          match event with
          | .accepted socket =>
            let handshake ← socket.claim
            mustReject "duplicate transport claim accepted" socket.claim
            mustReject "stale connected read control accepted" (socket.setReadEnabled false)
            let ready ← handshake.ready
            mustReject "old handshaking alias survived ready" (handshake.armTimer 3 0)
            mustReject "duplicate ready accepted" handshake.ready
            ready.armTimer 3 ((← Reactor.nowMs) + 3000)
            ready.cancelTimer 3
            check (← ready.isLive) "ready Wire not live"
            wire := some ready
          | .read socket buffer offset length =>
            mustReject "same-batch raw write bypassed claim" (socket.write buffer offset length)
            let some ready := wire | throw (IO.userError "read before accepted wire")
            Reactor.withBuffer buffer fun buffer => ready.write buffer offset length 77
            received := received + length.toNat
          | .wireRead id buffer offset length =>
            let some ready := wire | throw (IO.userError "ciphertext before ready Wire")
            check (id == ready.id) "ciphertext identity changed"
            Reactor.withBuffer buffer fun buffer => ready.write buffer offset length 77
            received := received + length.toNat
          | .eof socket =>
            mustReject "same-batch plaintext drain bypassed claim" socket.closeAfterWrites
            let some ready := wire | throw (IO.userError "EOF before accepted wire")
            ready.closeAfterWrites
          | .wireEOF id =>
            let some ready := wire | throw (IO.userError "cipher EOF before ready wire")
            check (id == ready.id) "cipher EOF identity changed"
            ready.closeAfterWrites
          | .closed _ => closed := true
          | .timer .. | .wireTimer .. | .connectTimer .. => throw (IO.userError "unexpected wire timer")
          | .error .. => throw (IO.userError "unexpected wire error")
          | .connected socket => do
            let _ ← socket.close (by decide)
            throw (IO.userError "unexpected outbound connection")
          | .written .. | .wake => pure ()
      if closed then break
    check (closed && received == 5) "wire fixture failed to drain binary input"
    if let some ready := wire then check (!(← ready.isLive)) "closed Wire still live"
  let some waker ← held.get | throw (IO.userError "missing retained waker")
  mustReject "late waker reached destroyed reactor" waker.wake
  waker.release
  mustReject "waker double release accepted" waker.release
  IO.println "typed wire and retained waker tests passed"

def main (args : List String) : IO Unit := do
  match args with
  | ["wire", port] =>
    let some number := port.toNat? | throw (IO.userError "invalid port")
    if number == 0 || number > 65535 then throw (IO.userError "invalid port")
    wireMain (UInt16.ofNat number)
  | [] => do
    coreMain
    typedConnectInputChecks
    typedResolverChecks
  | _ => throw (IO.userError "unexpected reactor fixture arguments")
