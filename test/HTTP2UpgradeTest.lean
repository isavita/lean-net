import LeanNet.HTTP2.Upgrade
import LeanNet.HTTP2.Connection

open LeanNet.HTTP1 LeanNet.HTTP2

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do throw (IO.userError message)

private def field (name value : String) : LeanNet.HTTP1.Header :=
  { name, value := value.toUTF8 }

private def head (settings : String := "AAMAAABkAAQAAP__") : LeanNet.HTTP1.RequestHead := {
  method := "GET", target := "/".toUTF8,
  headers := #[field "host" "example.test",
    field "connection" "Upgrade, HTTP2-Settings, X-Hop",
    field "upgrade" "h2c", field "http2-settings" settings,
    field "x-hop" "connection-local", field "x-end" "application"] }

private def setting (id value : Nat) : ByteArray :=
  ByteArray.mk #[UInt8.ofNat (id / 256), UInt8.ofNat id,
    UInt8.ofNat (value / 16777216), UInt8.ofNat (value / 65536),
    UInt8.ofNat (value / 256), UInt8.ofNat value]

def main : IO Unit := do
  check (Upgrade.base64url ByteArray.empty == some ByteArray.empty)
    "canonical empty base64url did not decode to empty bytes"
  check (Upgrade.validSettings ByteArray.empty) "empty wire SETTINGS payload was refused"
  check (!(Upgrade.candidate (head "") .none 1048576).isSome)
    "empty HTTP2-Settings token selected an upgrade"
  for (encoded, decoded) in [("AA", ByteArray.mk #[0]),
      ("AAA", ByteArray.mk #[0, 0]), ("AAAA", ByteArray.mk #[0, 0, 0])] do
    check (Upgrade.base64url encoded.toUTF8 == some decoded) "canonical base64url decoding"
  for encoded in ["====", "A=", "AA=", "AA==", "AAkAAAAB=", "A", "AB", "AAB", "!!", "AA+_", "AA /", "AA\n"] do
    check ((Upgrade.base64url encoded.toUTF8).isNone) "noncanonical base64url was accepted"
  let original := head
  let some (settings, request) := Upgrade.candidate original .none 1048576
    | throw (IO.userError "valid h2c request was not eligible")
  check (!request.headers.any (fun header => header.name == "x-hop"))
    "Connection-nominated field reached upgraded application request"
  check (!request.headers.any (fun header =>
    ["connection", "upgrade", "http2-settings"].contains header.name))
    "upgrade metadata reached upgraded application request"
  check (request.headers.any (fun header => header.name == "x-end" && header.value == "application".toUTF8))
    "end-to-end application field was removed"
  check (original.headers.any (fun header => header.name == "x-hop"))
    "pure upgrade mutated original metadata"
  match Connection.new.upgrade settings request original with
  | .error error => throw (IO.userError s!"valid upgrade failed: {repr error}")
  | .ok (_, started, requests) =>
    let some start := started[0]? | throw (IO.userError "missing upgraded request start")
    let some event := requests[0]? | throw (IO.userError "missing upgraded request")
    check (started.size == 1 && start.streamId == 1 &&
      requests.size == 1 && event.streamId == 1)
      "upgraded request was not delivered exactly once as stream 1"
    check (!event.request.headers.any (fun header => header.name == "x-hop"))
      "Connection-nominated field reappeared during stream 1 delivery"
  for payload in [setting 9 0, setting 9 1, setting 2 0, setting 4 0,
      setting 5 16384, setting 5 16777215, setting 65535 4294967295] do
    check (Upgrade.validSettings payload) "valid SETTINGS header payload was refused"
  for (payload, code) in [(setting 9 2, ErrorCode.protocolError),
      (setting 2 2, .protocolError), (setting 4 2147483648, .flowControlError),
      (setting 5 16383, .protocolError), (setting 5 16777216, .protocolError)] do
    check (!Upgrade.validSettings payload) "invalid SETTINGS header payload was accepted"
    match Connection.new.upgrade payload request original with
    | .ok _ => throw (IO.userError "direct upgrade bypassed SETTINGS semantic validation")
    | .error error => check (error.code == code) "upgrade changed SETTINGS error classification"
  check (!(Upgrade.candidate (head "AAkAAAAC") .none 1048576).isSome)
    "SETTINGS_NO_RFC7540_PRIORITIES=2 selected an h2c upgrade"
  check (!Upgrade.validSettings (ByteArray.mk #[0])) "partial SETTINGS item was accepted"
  IO.println "HTTP/2 upgrade field removal and SETTINGS validation tests passed"
