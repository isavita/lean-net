import LeanNetTLS.GatewayProvider
import LeanNet.Reactor.Basic

open LeanNet LeanNetTLS

private def check (ok : Bool) (message : String) : IO Unit := do
  unless ok do throw (IO.userError message)

private def flushCipher (session : LeanNet.Gateway.TLSSession) : IO Nat := do
  let mut writes := 0
  for _ in [:64] do
    let bytes ← session.drainCipher
    if bytes.isEmpty then break
    match ← session.submitCipher bytes with
    | .queued => writes := writes + 1
    | .wouldBlock => throw (IO.userError "test TLS cipher queue exhausted")
  return writes

private def run (port : UInt16) (caFile verifyName : String) (expectVerified : Bool) : IO Unit := do
  Reactor.withReactor {
    maxConnections := 4, maxEvents := 16, maxWrites := 64,
    buffers4k := 16, buffers16k := 8, buffers64k := 2, timerTickMs := 1 } fun reactor =>
    GatewayProvider.withProvider reactor (some caFile) fun provider => do
      let fresh ← reactor.socket
      let _ ← fresh.startConnect (ByteArray.mk #[127, 0, 0, 1]) port
      let mut active : Option LeanNet.Gateway.TLSSession := none
      let mut queued := 0
      let mut verified := false
      let mut wireReady := false
      let mut failed := false
      let mut failureDetail := ""
      let mut reply := ByteArray.empty
      for _ in [:1000] do
        match ← reactor.poll 10 with
        | .interrupted => pure ()
        | .completions count =>
          for i in [:count] do
            match ← reactor.event i.toUInt32 with
            | .connected socket =>
              let session ← provider.start socket verifyName.toUTF8
              active := some session
              try
                verified := ← session.handshake
                queued := queued + (← flushCipher session)
              catch error =>
                failureDetail := toString error
                failed := true
            | .wireRead _ buffer offset length =>
              let some session := active | throw (IO.userError "TLS read before connect")
              try
                let bytes ← buffer.view
                session.feedCipher (bytes.extract offset.toNat (offset + length).toNat)
                if wireReady then
                  for _ in [:64] do
                    match ← session.readPlain with
                    | .pending | .eof => break
                    | .data plain => reply := reply ++ plain
                else if !verified then verified := ← session.handshake
                queued := queued + (← flushCipher session)
              catch error =>
                failureDetail := toString error
                failed := true
              buffer.release
            | .written _ _ _ =>
              check (queued > 0) "unexpected TLS write completion"
              queued := queued - 1
            | .error _ _ code =>
              failureDetail := s!"reactor error {code}"
              failed := true
            | .wireEOF .. | .eof .. =>
              failureDetail := "TLS peer EOF"
              failed := true
            | .closed .. => pure ()
            | .read _ buffer _ _ => buffer.release
            | _ => pure ()
        if verified && !wireReady && queued == 0 then
          let some session := active | throw (IO.userError "missing TLS session")
          check (!(← session.cleanForReuse)) "handshaking TLS session claimed reusable"
          session.markWireReady
          wireReady := true
          check (← session.cleanForReuse) "verified idle TLS session not clean"
          let request := "GET / HTTP/1.1\r\nHost: backend.test\r\n\r\n".toUTF8
          check ((← session.writePlain request) == request.size) "TLS request was not encrypted in full"
          queued := queued + (← flushCipher session)
        if reply.size > 0 && (String.fromUTF8? reply).any (·.contains "tls gateway ok") then
          let some session := active | throw (IO.userError "missing TLS session")
          check (← session.cleanForReuse) "complete TLS response left buffered data"
          session.close
          active := none
          break
        if failed then break
      check (verified == expectVerified) s!"upstream TLS verification result mismatch: {failureDetail}"
      if expectVerified then
        check (!failed) s!"verified upstream TLS failed: {failureDetail}"
        check ((String.fromUTF8? reply).any (·.contains "HTTP/1.1 200 OK")) "TLS HTTP response was not decrypted"
      if let some session := active then session.close

def main (arguments : List String) : IO Unit := do
  let args := arguments.toArray
  if args.size != 4 then throw (IO.userError "usage: TLSGatewayTest PORT CA_PEM VERIFY_NAME expected|rejected")
  let some port := args[0]!.toNat? | throw (IO.userError "invalid port")
  check (port > 0 && port <= 65535) "port out of range"
  let expected := args[3]! == "expected"
  run port.toUInt16 args[1]! args[2]! expected
  IO.println (if expected then "VERIFIED" else "REJECTED")
