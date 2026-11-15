import LeanNet.HTTP1.Request

namespace LeanNet.HTTP.TraceContext

/-- A W3C Trace Context (`traceparent`) entry. -/
structure Context where
  traceId : ByteArray
  parentId : ByteArray
  flags : UInt8
  deriving Inhabited

private def hexValue (c : UInt8) : Option UInt8 :=
  if c >= 48 && c <= 57 then some (c - 48)
  else if c >= 97 && c <= 102 then some (c - 87)
  else none

/-- Lowercase hex only, as the specification requires. -/
private def decodeHex (bytes : ByteArray) (start count : Nat) : Option ByteArray := Id.run do
  let mut out := ByteArray.emptyWithCapacity count
  for i in [:count] do
    let some high := hexValue bytes[start + 2 * i]! | return none
    let some low := hexValue bytes[start + 2 * i + 1]! | return none
    out := out.push (high * 16 + low)
  return some out

private def allZero (bytes : ByteArray) : Bool := bytes.data.all (· == 0)

/-- Parse `version-traceid-parentid-flags` (W3C Trace Context §3.2). Version
    `ff` and all-zero identifiers are invalid; future versions may append
    fields after a dash. -/
def parse (value : ByteArray) : Option Context := do
  if value.size < 55 then none
  let version ← decodeHex value 0 1
  if version[0]! == 255 then none
  if version[0]! == 0 && value.size != 55 then none
  if value.size > 55 && value[55]! != 45 then none
  if value[2]! != 45 || value[35]! != 45 || value[52]! != 45 then none
  let traceId ← decodeHex value 3 16
  let parentId ← decodeHex value 36 8
  let flags ← decodeHex value 53 1
  if allZero traceId || allZero parentId then none
  return { traceId, parentId, flags := flags[0]! }

private def hexDigit (n : UInt8) : UInt8 := if n < 10 then 48 + n else 87 + n

def hex (bytes : ByteArray) : ByteArray := Id.run do
  let mut out := ByteArray.emptyWithCapacity (bytes.size * 2)
  for byte in bytes.data do
    out := (out.push (hexDigit (byte >>> 4))).push (hexDigit (byte &&& 15))
  return out

/-- Version-00 `traceparent` header value. -/
def Context.format (context : Context) : ByteArray :=
  (("00-".toUTF8 ++ hex context.traceId).push 45 ++ hex context.parentId).push 45 ++ hex (ByteArray.mk #[context.flags])

/-- Per-worker splitmix64 generator for trace and span identifiers. Seeded
    from the OS random source; identifiers need uniqueness, not secrecy. -/
structure Generator where
  state : UInt64
  deriving Inhabited

def Generator.next (generator : Generator) : UInt64 × Generator :=
  let state := generator.state + 0x9e3779b97f4a7c15
  let z := (state ^^^ (state >>> 30)) * 0xbf58476d1ce4e5b9
  let z := (z ^^^ (z >>> 27)) * 0x94d049bb133111eb
  (z ^^^ (z >>> 31), { state })

private def bigEndian (value : UInt64) : ByteArray :=
  ByteArray.mk ((Array.range 8).map fun i => (value >>> (UInt64.ofNat (56 - 8 * i))).toUInt8)

/-- Fresh non-zero identifiers of `count` 64-bit words. -/
def Generator.bytes (generator : Generator) (words : Nat) : ByteArray × Generator := Id.run do
  let mut out := ByteArray.empty
  let mut generator := generator
  for _ in [:words] do
    let (value, next) := generator.next
    out := out ++ bigEndian value
    generator := next
  if allZero out then out := out.set! (out.size - 1) 1
  return (out, generator)

def Generator.seeded : IO Generator := do
  let bytes ← IO.getRandomBytes 8
  let seed := bytes.data.foldl (fun (acc : UInt64) (byte : UInt8) => (acc <<< 8) ||| byte.toUInt64) 0
  return { state := seed }

/-- Return the request's valid incoming context, or a freshly generated one
    (unsampled) that is injected as the request's `traceparent` so the
    application propagates it to downstream calls. Invalid incoming values
    are replaced, as the specification requires. -/
def ensure (headers : Array HTTP1.Header) (generator : Generator) :
    Context × Array HTTP1.Header × Generator := Id.run do
  let incoming := headers.filter (·.name.toLower == "traceparent")
  if incoming.size == 1 then
    if let some context := parse incoming[0]!.value then
      return (context, headers, generator)
  let (traceId, generator) := generator.bytes 2
  let (parentId, generator) := generator.bytes 1
  let context : Context := { traceId, parentId, flags := 0 }
  let headers := (headers.filter (·.name.toLower != "traceparent")).push
    { name := "traceparent", value := context.format }
  return (context, headers, generator)

end LeanNet.HTTP.TraceContext
