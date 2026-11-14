import LeanNet.HTTP2.Priority
open LeanNet.HTTP2

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do throw (IO.userError message)

private def parsed (text : String) (urgency : UInt8) (incremental : Bool) : IO Unit := do
  match Priority.parse text.toUTF8 with
  | .ok result => check (result.urgency == urgency && result.incremental == incremental) s!"incorrect priority: {text}"
  | .error error => throw (IO.userError s!"unexpected error for {text}: {error}")

private def rejected (text : String) : IO Unit := do
  match Priority.parse text.toUTF8 with
  | .ok _ => throw (IO.userError s!"invalid dictionary accepted: {text}")
  | .error _ => pure ()

private def frameError (frame : Frame) (code : ErrorCode) : IO Unit := do
  match PriorityUpdate.decode frame with
  | .ok _ => throw (IO.userError "invalid PRIORITY_UPDATE accepted")
  | .error e => check (e.scope == .connection && e.code == code) "wrong PRIORITY_UPDATE error scope/code"

def main : IO Unit := do
  parsed "" 3 false
  for n in [:8] do
    match Priority.ofValues (UInt8.ofNat n) with
    | .ok value => check (value.valid && value.urgency.toNat == n) "valid urgency construction"
    | .error _ => throw (IO.userError "valid urgency rejected")
  match Priority.ofValues 8 with
  | .ok _ => throw (IO.userError "invalid urgency accepted")
  | .error _ => pure ()
  parsed "u=0, i" 0 true
  parsed "i=?0, u=7" 7 false
  parsed "u=8, i=4" 3 false
  parsed "u=1.0, i=\"yes\"" 3 false
  parsed "i=?1, u=-1" 3 true
  parsed "u=2, u=6, i, i=?0" 6 false
  parsed "u=0, u=100, i, i=foo" 3 false
  parsed "u=3;foo=?1, i;ext=token, unknown=(1 \"x\";a=?0);p=1" 3 true
  parsed "unknown=:YWJj:, u=4" 4 false
  parsed "unknown=:YQ==:, i=?1" 3 true
  parsed "unknown=:YQ=:, i=?1" 3 true
  parsed "\t u=5 \t,\ti=?1 \t" 5 true
  for text in ["u=", "i=?2", "u=3,", "U=1", "u =1", "u=1.2345", "u=1234567890123456", "x=\"bad\\q\"", "x=(1\t2)", "x=:!:", "x=:a:", "u=1,,i"] do rejected text
  let a : Priority := ⟨0, true⟩
  let b : Priority := ⟨2, false⟩
  check (a.precedes b && !b.precedes a && !a.precedes a) "urgency ordering"
  check ((Priority.mk 2 false).precedes (Priority.mk 2 true)) "incremental tie ordering"
  let update : PriorityUpdate := ⟨0x1234567, "u=1, i".toUTF8⟩
  let frame ← match update.encode with | .ok v => pure v | .error e => throw (IO.userError e.message)
  check (frame.kind == 16 && frame.streamId == 0 && frame.payload.extract 0 4 == ByteArray.mk #[1,35,69,103]) "update encoding"
  let decoded ← match PriorityUpdate.decode frame with | .ok v => pure v | .error e => throw (IO.userError e.message)
  check (decoded.target == update.target && decoded.fieldValue == update.fieldValue) "update round trip"
  let reserved : Frame := ⟨16, 0, 0, ByteArray.mk #[128,0,0,1,117,61,55]⟩
  match PriorityUpdate.decode reserved with
  | .ok v => check (v.target == 1 && v.fieldValue == "u=7".toUTF8) "reserved bit masking"
  | .error _ => throw (IO.userError "reserved bit rejected")
  match (PriorityUpdate.mk 1 "u=?2".toUTF8).encode with
  | .ok _ => throw (IO.userError "invalid outbound priority accepted")
  | .error _ => pure ()
  frameError ⟨16, 0, 1, ByteArray.mk #[0,0,0,1]⟩ .protocolError
  frameError ⟨16, 0, 0, ByteArray.mk #[0,0,0]⟩ .frameSizeError
  frameError ⟨16, 0, 0, ByteArray.mk #[128,0,0,0]⟩ .protocolError
  IO.println "HTTP/2 priority tests passed"
