import LeanNet.HTTP2.Stream

open LeanNet.HTTP2

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do throw (IO.userError message)

private def ok (label : String) (result : Except ProtocolError α) : IO α := do
  match result with
  | .ok value => return value
  | .error error => throw (IO.userError s!"{label}: unexpected error {repr error}")

private def rejected (label : String) (result : Except ProtocolError α)
    (code : ErrorCode) (scope : ErrorScope) : IO Unit := do
  match result with
  | .ok _ => throw (IO.userError s!"{label}: expected error")
  | .error error => check (error.code == code && error.scope == scope) s!"{label}: wrong error {repr error}"

private def transition (s : Stream) (role : EndpointRole) (event : StreamEvent)
    (expected : StreamState) (disposition : StreamDisposition := .process) : IO Stream := do
  let (next, action) ← ok "stream transition" (s.apply role event)
  check (next.state == expected && action == disposition) s!"unexpected transition {repr s.state} on {repr event}"
  return next

def main : IO Unit := do
  rejected "stream 0" (Stream.new 0) .protocolError .connection
  rejected "reserved stream bit" (Stream.new 2147483648) .protocolError .connection
  rejected "oversized initial window" (Stream.new 1 (maxWindow + 1)) .flowControlError .connection
  let idle ← ok "new stream" (Stream.new 1)
  let _ ← transition idle .server (.priority .inbound) .idle .ignore
  let _ ← transition idle .server (.extension .inbound) .idle .ignore
  rejected "idle DATA" (idle.apply .server (.data .inbound false)) .protocolError .connection
  rejected "idle reset" (idle.apply .server (.reset .inbound)) .protocolError .connection
  rejected "idle window update" (idle.apply .server (.windowUpdate .inbound)) .protocolError .connection
  rejected "server opens odd stream" (idle.apply .server (.headers .outbound false)) .protocolError .connection
  let openStream ← transition idle .server (.headers .inbound false) .open
  let _ ← transition openStream .server (.data .inbound false) .open
  let halfRemote ← transition openStream .server (.data .inbound true) .halfClosedRemote
  rejected "DATA after peer END_STREAM" (halfRemote.apply .server (.data .inbound false)) .streamClosed (.stream 1)
  rejected "HEADERS after peer END_STREAM" (halfRemote.apply .server (.headers .inbound true)) .streamClosed (.stream 1)
  let closed ← transition halfRemote .server (.headers .outbound true) .closed
  let _ ← transition closed .server (.windowUpdate .inbound) .closed .ignore
  let _ ← transition closed .server (.reset .inbound) .closed .ignore
  rejected "DATA on closed" (closed.apply .server (.data .inbound false)) .streamClosed .connection
  let halfLocal ← transition openStream .server (.headers .outbound true) .halfClosedLocal
  let _ ← transition halfLocal .server (.data .inbound true) .closed
  let reset ← transition openStream .server (.reset .outbound) .closed
  let _ ← transition reset .server (.data .inbound false) .closed .discard
  let _ ← transition reset .server (.headers .inbound false) .closed .discard
  let _ ← transition idle .client (.headers .outbound true) .halfClosedLocal
  let even ← ok "push stream" (Stream.new 2)
  rejected "peer opens even stream" (even.apply .server (.headers .inbound false)) .protocolError .connection
  let localPush ← transition even .server .reserveLocal .reservedLocal
  let _ ← transition localPush .server (.headers .outbound false) .halfClosedRemote
  let _ ← transition localPush .server (.headers .outbound true) .closed
  let remotePush ← transition even .client .reserveRemote .reservedRemote
  let _ ← transition remotePush .client (.headers .inbound false) .halfClosedLocal
  let _ ← transition remotePush .client (.headers .inbound true) .closed
  rejected "DATA on reserved" (remotePush.apply .client (.data .inbound false)) .protocolError .connection

  let flow : Flow := {}
  let some (sentFlow, sentStream) := flow.sendData openStream 100 false | throw (IO.userError "send credit missing")
  check (sentFlow.sendWindow == 65435 && sentStream.sendWindow == 65435) "send must debit both windows"
  check ((flow.sendData openStream 65536 false).isNone) "send beyond window should block"
  let adjusted ← ok "settings decrease" (openStream.adjustInitialSend (-70000))
  check (adjusted.sendWindow == -4465) "settings decrease must preserve negative window"
  check ((flow.sendData adjusted 1 false).isNone) "negative stream window should block"
  check ((flow.sendData adjusted 0 true).isSome) "empty END_STREAM should remain possible"
  let restored ← ok "window update" (adjusted.updateSend 4466)
  check (restored.sendWindow == 1 && (flow.sendData restored 1 false).isSome) "window update did not restore credit"
  rejected "zero stream window update" (openStream.updateSend 0) .protocolError (.stream 1)
  rejected "zero connection window update" (flow.updateSend 0) .protocolError .connection
  rejected "stream update overflow" ({ openStream with sendWindow := Int.ofNat maxWindow }.updateSend 1) .flowControlError (.stream 1)
  rejected "connection update overflow" ({ flow with sendWindow := Int.ofNat maxWindow }.updateSend 1) .flowControlError .connection
  rejected "settings delta overflow" ({ openStream with sendWindow := Int.ofNat maxWindow }.adjustInitialSend 1) .flowControlError .connection
  let (recvFlow, result) ← ok "received data" (flow.receiveData openStream 100)
  let recvStream ← ok "stream credit" result
  check (recvFlow.recvWindow == 65435 && recvStream.recvWindow == 65435) "receive must debit both windows"
  rejected "connection receive overflow" (flow.receiveData openStream 65536) .flowControlError .connection
  let limited := { openStream with recvWindow := 3 }
  let (debited, streamResult) ← ok "connection credit survives stream violation" (flow.receiveData limited 4)
  check (debited.recvWindow == 65531) "connection credit lost on stream error"
  rejected "stream receive overflow" streamResult .flowControlError (.stream 1)
  let receiveAdjusted ← ok "local SETTINGS receive decrease" (openStream.adjustInitialReceive (-70000))
  check (receiveAdjusted.recvWindow == -4465) "local receive decrease lost negative window"
  let (_, zeroCredit) ← ok "empty DATA on negative receive window" (flow.receiveData receiveAdjusted 0)
  let zeroCredit ← ok "empty DATA stream credit" zeroCredit
  check (zeroCredit.recvWindow == -4465) "empty DATA changed negative receive credit"
  rejected "local receive delta overflow" ({ openStream with recvWindow := Int.ofNat maxWindow }.adjustInitialReceive 1) .flowControlError .connection
  IO.println "HTTP/2 stream and flow tests passed"
