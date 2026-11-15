import LeanNet.HTTP1.Encoding

/-! Pure bounded wire framing for one HTTP/1.1 streamed response. The plan is
created from validated metadata before any bytes are committed; each body step
references one bounded input ByteArray without joining the response body. -/

namespace LeanNet.HTTP1.Streaming

structure Plan where
  private mk ::
  private response : Response
  private context : EncodeContext
  private declared : Array String
  head : ByteArray
  framing : BodyFraming
  next : ResponseNext

structure Chunk where
  parts : Array ByteArray
  /-- Offset and length of application bytes in the concatenated parts. -/
  payloadOffset : Nat
  payloadLength : Nat

private def hexLength (length : Nat) : ByteArray := Id.run do
  let mut n := length
  let mut digits : List UInt8 := []
  repeat
    let digit := n % 16
    digits := UInt8.ofNat (if digit < 10 then 48 + digit else 87 + digit) :: digits
    n := n / 16
    if n == 0 then break
  return ByteArray.mk digits.toArray

/-- `knownLength` retains Content-Length; unknown HTTP/1.1 bodies use chunked
framing, and unknown HTTP/1.0 bodies require connection closure. Trailer names
must be declared before the head is sent. -/
def Plan.new (response : Response) (context : EncodeContext)
    (knownLength : Option Nat := none) (declaredTrailers : Array String := #[])
    (forceClose : Bool := false) : Except String Plan := do
  let framing := match knownLength with
    | some n => BodyFraming.contentLength n
    | none => if context.version == .http11 then .chunked else .closeDelimited
  let encoded ← response.encodeStreamHeadFor context framing declaredTrailers forceClose
  return ⟨response, context, declaredTrailers.map String.toLower,
    encoded.head, encoded.framing, encoded.next⟩

/-- One nonempty body slice, at most 64 KiB. Empty input cannot accidentally
become a terminating zero chunk. -/
def Plan.chunk (plan : Plan) (bytes : ByteArray) : Except String Chunk := do
  if bytes.isEmpty || bytes.size > 65536 then throw "stream body chunk must contain 1..65536 bytes"
  match plan.framing with
  | .contentLength _ | .closeDelimited =>
    return { parts := #[bytes], payloadOffset := 0, payloadLength := bytes.size }
  | .chunked =>
    let chunkPrefix := (hexLength bytes.size).append "\r\n".toUTF8
    let parts := #[chunkPrefix, bytes, "\r\n".toUTF8]
    return { parts, payloadOffset := chunkPrefix.size, payloadLength := bytes.size }
  | .none => throw "stream response has no body framing"

/-- Validate actual trailers against the prior declaration and the ordinary
response encoder's forbidden-field rules. Known-length and close-delimited
responses have no terminal wire bytes. -/
def Plan.finish (plan : Plan) (trailers : Array Header := #[]) : Except String ByteArray := do
  if trailers.any (fun field => !plan.declared.contains field.name.toLower) then
    throw "undeclared response trailer"
  match plan.framing with
  | .chunked =>
    let encoded ← plan.response.encodeFor plan.context
      { framing := some .chunked, trailers }
    let some terminal := encoded.parts.back? | throw "chunked stream has no terminator"
    return terminal
  | .contentLength _ | .closeDelimited =>
    if !trailers.isEmpty then throw "trailers require chunked framing"
    return ByteArray.empty
  | .none => throw "stream response has no body framing"

end LeanNet.HTTP1.Streaming
