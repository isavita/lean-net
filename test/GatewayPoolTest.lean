import LeanNet.Gateway.Pool

open LeanNet
open LeanNet.Gateway

private def check (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

private def fail (message : String) : IO α := throw (IO.userError message)

private def expectAcquireError (result : Except Pool.Error Pool.Acquire)
    (expected : Pool.Error) (message : String) : IO Unit :=
  match result with
  | .error actual => check (actual == expected) message
  | .ok _ => fail message

private def expectCapacity (result : Except Pool.Error Pool.Acquire)
    (message : String) : IO Unit :=
  match result with
  | .ok .atCapacity => pure ()
  | _ => fail message

private def responseHead (reusable : Bool) : HTTP1.ClientResponse.Head := {
  version := .http11
  status := 200
  reason := ByteArray.empty
  headers := #[]
  framing := .contentLength 0
  reusable
}

private def loopback (port : UInt16) : Pool.Target := {
  address := ByteArray.mk #[127, 0, 0, 1]
  port
}

private def awaitConnected (reactor : Reactor.Reactor) (pool : Pool.Pool)
    (pending : IO.Ref (Array Pool.Lease))
    (target : Pool.Target) : IO Pool.Lease := do
  for _ in [:200] do
    let saved ← pending.get
    if let some lease := saved.find? (·.target == target) then
      pending.set (saved.filter (·.target != target))
      return lease
    match ← reactor.poll 10 with
    | .interrupted => pure ()
    | .completions count =>
      for i in [:count] do
        match ← reactor.event i.toUInt32 with
        | .connected socket =>
          if let some lease ← pool.onConnected socket then
            pending.modify (·.push lease)
        | .accepted socket =>
          -- The listener peer is kept open by the reactor until the bracket
          -- ends. Closing it here would make the upstream socket unusable.
          let _ := socket
        | .read socket buffer _ _ =>
          buffer.release
          check (!(← pool.onUnexpectedRead socket.id)) "unexpected data on a pending connection"
        | .eof socket =>
          let _ ← pool.onError socket.id
        | .error id _ _ =>
          if ← pool.onError id then fail "outbound connect failed"
        | .closed socket =>
          let _ ← pool.onClosed socket.id
        | .connectTimer id kind =>
          if ← pool.onConnectTimer id kind then fail "outbound connect timed out"
        | _ => pure ()
  fail "outbound connect did not complete"

private def attachMockTLS (pool : Pool.Pool) (lease : Pool.Lease) :
    IO (IO.Ref Bool × IO.Ref Bool) := do
  let handshaking ← lease.socket.claim
  let ready ← handshaking.ready
  let closed ← IO.mkRef false
  let clean ← IO.mkRef true
  let session : TLSSession := {
    id := lease.id
    handshake := pure true
    feedCipher := fun _ => pure ()
    drainCipher := pure ByteArray.empty
    submitCipher := fun _ => pure .queued
    armTimer := fun kind deadline => ready.armTimer kind deadline
    cancelTimer := fun kind => ready.cancelTimer kind
    setReadEnabled := fun enabled => ready.setReadEnabled enabled
    markWireReady := pure ()
    writePlain := fun bytes => pure bytes.size
    readPlain := pure .pending
    cleanForReuse := clean.get
    close := do
      closed.set true
      ready.close (by decide)
  }
  let .ok () ← pool.attachTLS lease session |
    fail "TLS session could not take close ownership"
  return (closed, clean)

private def run (firstPort secondPort : UInt16) : IO Unit := do
  Reactor.withReactor {
    maxConnections := 16, maxEvents := 32, maxWrites := 16,
    buffers4k := 16, buffers16k := 0, buffers64k := 0, timerTickMs := 1
  } fun reactor => do
    let _ ← reactor.listen "127.0.0.1" firstPort
    let _ ← reactor.listen "127.0.0.1" secondPort
    let .ok pool ← Pool.new reactor {
      maxTotal := 2, maxPerTarget := 1, idleTimeoutMs := 50, connectTimeoutMs := 5000
    } | fail "pool rejected valid configuration"
    try
      let pending ← IO.mkRef (#[] : Array Pool.Lease)
      let target1 := loopback firstPort
      let target2 := loopback secondPort
      let target3 := { target1 with address := ByteArray.mk #[127, 0, 0, 2] }
      let tls := { target1 with security := .tls "example.com".toUTF8 1 }
      expectAcquireError (← pool.acquire tls (← Reactor.nowMs)) .unsupportedTransport
        "TLS target yielded a plaintext socket"
      expectAcquireError (← pool.acquire { target1 with address := ByteArray.empty } (← Reactor.nowMs))
        .invalidTarget "invalid address accepted"
      check ((← pool.size) == 0) "invalid targets consumed capacity"

      let now ← Reactor.nowMs
      let .ok (.connecting firstId) ← pool.acquire target1 now | fail "first connect was not pending"
      expectCapacity (← pool.acquire target1 now) "per-target cap was bypassed"
      let .ok (.connecting secondId) ← pool.acquire target2 now | fail "second connect was not pending"
      check (firstId != secondId) "distinct connects got the same generation token"
      check ((← pool.size) == 2) "pending connects did not count toward total cap"
      expectCapacity (← pool.acquire target3 now) "total cap was bypassed by a different target"

      let first ← awaitConnected reactor pool pending target1
      let second ← awaitConnected reactor pool pending target2
      check (first.id == firstId && second.id == secondId) "connect event changed socket identity"
      expectCapacity (← pool.acquire target1 now) "busy connection was leased twice"

      let .ok () ← pool.finishResponse first (responseHead true) true true 0 (now + 1) |
        fail "complete reusable response was not returned to idle"
      let .ok (.ready again) ← pool.acquire target1 (now + 2) |
        fail "idle target was not reused"
      check (again.id == first.id) "idle checkout opened another socket"
      match ← pool.discard first with
      | .error .staleLease => pure ()
      | _ => fail "stale lease was accepted"
      check (← again.id.isLive reactor) "stale lease closed a newer checkout"

      let .ok () ← pool.finishResponse again (responseHead false) true true 0 (now + 3) |
        fail "non-reusable response did not discard its connection"
      check (!(← pool.owns firstId)) "non-reusable connection remained in pool"
      let .ok () ← pool.finishResponse second (responseHead true) true true 1 (now + 3) |
        fail "response with unread bytes did not discard its connection"
      check ((← pool.size) == 0) "discarded connections still consume capacity"

      let .ok (.connecting replacementId) ← pool.acquire target1 (now + 4) |
        fail "capacity was not released after discard"
      check (replacementId != firstId) "reused native slot kept a stale generation"
      check (!(← pool.onClosed firstId)) "stale close removed a newer connection"
      let replacement ← awaitConnected reactor pool pending target1
      let .ok () ← pool.finishResponse replacement (responseHead true) true true 0 (now + 5) |
        fail "replacement connection did not become idle"
      pool.reap (now + 60)
      check ((← pool.size) == 0) "expired idle socket was retained"
      check (!(← pool.onClosed replacementId)) "late close altered an expired entry"

      let .ok (.connecting timeoutId) ← pool.acquire target1 (now + 61) |
        fail "timed connect could not start"
      check (!(← pool.onConnectTimer timeoutId 4)) "foreign timer kind canceled connect"
      check (← pool.owns timeoutId) "foreign timer changed pending state"
      check (← pool.onConnectTimer timeoutId Pool.connectTimerKind) "connect timer did not cancel pending socket"
      check ((← pool.size) == 0) "timed-out connect retained capacity"

      let .ok (.connecting finalId) ← pool.acquire target1 (now + 62) |
        fail "capacity was not released after connect timeout"
      let finalLease ← awaitConnected reactor pool pending target1
      check (finalLease.id == finalId) "late completion replaced the active generation"
      let .ok () ← pool.finishResponse finalLease (responseHead true) true false 0 (now + 63) |
        fail "unfinished request writes did not discard connection"
      check ((← pool.size) == 0) "unfinished writes retained a pool entry"

      let .ok (.connecting idleId) ← pool.acquire target1 (now + 64) |
        fail "capacity was not released after unfinished writes"
      let idleLease ← awaitConnected reactor pool pending target1
      check (idleLease.id == idleId) "new idle candidate used a stale generation"
      let .ok () ← pool.finishResponse idleLease (responseHead true) true true 0 (now + 65) |
        fail "final connection did not become idle"
      check (← pool.onUnexpectedRead idleId) "idle unexpected read was not discarded"
      check ((← pool.size) == 0) "contaminated idle connection remained in pool"
    finally
      pool.close

    let .ok securePool ← Pool.new reactor {
      maxTotal := 1, maxPerTarget := 1, idleTimeoutMs := 50,
      connectTimeoutMs := 5000, allowTls := true
    } | fail "TLS-capable pool rejected valid configuration"
    try
      let pending ← IO.mkRef (#[] : Array Pool.Lease)
      let tlsTarget : Pool.Target := {
        address := ByteArray.mk #[127, 0, 0, 1], port := firstPort,
        security := .tls "example.com".toUTF8 1
      }
      let now ← Reactor.nowMs
      let .ok (.connecting tlsId) ← securePool.acquire tlsTarget now |
        fail "TLS target could not start a raw TCP connect"
      let tlsLease ← awaitConnected reactor securePool pending tlsTarget
      check (tlsLease.id == tlsId) "TLS connect generation changed"
      let (closed, clean) ← attachMockTLS securePool tlsLease
      let .ok () ← securePool.finishResponse tlsLease (responseHead true) true true 0 (now + 1) |
        fail "TLS response did not complete"
      check (!(← closed.get) && (← securePool.size) == 1) "clean TLS session was not retained"
      let .ok (.secureReady again session) ← securePool.acquire tlsTarget (now + 2) |
        fail "clean TLS session was not leased securely"
      check (again.id == tlsId && session.id == tlsId) "secure idle checkout lost session identity"
      match ← securePool.discard tlsLease with
      | .error .staleLease => pure ()
      | _ => fail "stale TLS lease was accepted"
      check (!(← closed.get)) "stale TLS lease closed a newer checkout"
      clean.set false
      let .ok () ← securePool.finishResponse again (responseHead true) true true 0 (now + 3) |
        fail "unclean TLS response did not discard"
      check (← closed.get) "unclean TLS session remained live"
      check ((← securePool.size) == 0) "unclean TLS socket retained capacity"

      let .ok (.connecting secondId) ← securePool.acquire tlsTarget (now + 4) |
        fail "secure capacity was not released"
      check (secondId != tlsId) "TLS replacement retained stale socket generation"
      let second ← awaitConnected reactor securePool pending tlsTarget
      let (closedSecond, _) ← attachMockTLS securePool second
      let .ok () ← securePool.finishResponse second (responseHead true) true true 0 (now + 5) |
        fail "second TLS session did not become idle"
      check (← securePool.onUnexpectedRead secondId) "unsolicited idle TLS read was not discarded"
      check (← closedSecond.get) "unsolicited idle TLS read retained session"
      check ((← securePool.size) == 0) "contaminated secure idle socket retained capacity"

      let .ok (.connecting thirdId) ← securePool.acquire tlsTarget (now + 6) |
        fail "secure capacity was not released after idle contamination"
      let third ← awaitConnected reactor securePool pending tlsTarget
      let (closedThird, _) ← attachMockTLS securePool third
      let .ok () ← securePool.finishResponse third (responseHead true) true true 0 (now + 7) |
        fail "third TLS session did not become idle"
      securePool.reap (now + 58)
      check (← closedThird.get) "expired secure idle session remained live"
      check ((← securePool.size) == 0) "expired secure idle socket retained capacity"
      check (!(← securePool.onClosed thirdId)) "late close removed an expired TLS entry"
    finally
      securePool.close
  IO.println "gateway pool tests passed"

def main (args : List String) : IO Unit := do
  let [first, second] := args | fail "expected two loopback TCP ports"
  let some firstPort := first.toNat? | fail "invalid first port"
  let some secondPort := second.toNat? | fail "invalid second port"
  if firstPort == 0 || secondPort == 0 || firstPort > 65535 || secondPort > 65535 ||
      firstPort == secondPort then fail "invalid distinct TCP ports"
  run firstPort.toUInt16 secondPort.toUInt16
