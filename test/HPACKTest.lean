import LeanNet.HTTP2.HPACK

open LeanNet.HTTP2.HPACK

private def fromHex (s : String) : ByteArray := Id.run do
  let mut result := ByteArray.empty
  let mut high : Option Nat := none
  for c in s.toUTF8 do
    let n := c.toNat
    let digit := if n >= 48 && n <= 57 then n - 48 else n - 87
    match high with
    | none => high := some digit
    | some h =>
      result := result.push (UInt8.ofNat (h * 16 + digit))
      high := none
  return result

private def ensure (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

private def resultEq [BEq α] (result : Except String α) (expected : α) : Bool :=
  match result with | .ok value => value == expected | .error _ => false

private def isError (result : Except String α) : Bool :=
  match result with | .error _ => true | .ok _ => false

private def checkField (headers : Array Header) (index : Nat) (name value : String) : IO Unit := do
  let h := headers[index]!
  ensure (h.name == name.toUTF8 && h.value == value.toUTF8) s!"field {index} mismatch"

private def decodeOk (context : Context) (hex : String) : IO (Context × Array Header) := do
  match decode context (fromHex hex) with
  | .ok result => return result
  | .error message => throw (IO.userError s!"decode failed: {message}")

private def expectBad (hex : String) : IO Unit :=
  match decode Context.new (fromHex hex) with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError s!"invalid HPACK accepted: {hex}")

def main : IO Unit := do
  ensure (resultEq (encodeInteger 1337 5 0) (fromHex "1f9a0a")) "RFC integer encode"
  ensure (resultEq (decodeInteger (fromHex "1f9a0a") 0 5) (1337, 3)) "RFC integer decode"
  ensure (isError (decodeInteger (fromHex "1f8080808080") 0 5)) "overlong integer"
  let maxEncoded ← match encodeInteger 4294967295 5 0 with | .ok v => pure v | .error e => throw (IO.userError e)
  ensure (resultEq (decodeInteger maxEncoded 0 5) (4294967295, maxEncoded.size)) "maximum integer roundtrip"
  ensure (isError (encodeInteger 4294967296 5 0)) "integer overflow accepted"
  let exampleValue := "www.example.com".toUTF8
  ensure (huffmanEncode exampleValue == fromHex "f1e3c2e5f23a6ba0ab90f4ff") "RFC Huffman encoding"
  ensure (resultEq (huffmanDecode (fromHex "f1e3c2e5f23a6ba0ab90f4ff")) exampleValue) "RFC Huffman decoding"
  ensure (isError (huffmanDecode (fromHex "ffffffff"))) "EOS accepted"
  ensure (isError (huffmanDecode (fromHex "ff"))) "too-long padding accepted"
  ensure (isError (huffmanDecode (fromHex "00"))) "invalid padding accepted"
  let mut all := ByteArray.empty
  for i in [:256] do all := all.push (UInt8.ofNat i)
  ensure (resultEq (huffmanDecode (huffmanEncode all)) all) "all-byte Huffman roundtrip"
  let (ctx, first) ← decodeOk Context.new "828684418cf1e3c2e5f23a6ba0ab90f4ff"
  ensure (first.size == 4 && ctx.dynamicBytes == 57) "RFC request 1 table"
  checkField first 0 ":method" "GET"
  checkField first 1 ":scheme" "http"
  checkField first 2 ":path" "/"
  checkField first 3 ":authority" "www.example.com"
  let (ctx, second) ← decodeOk ctx "828684be5886a8eb10649cbf"
  ensure (second.size == 5 && ctx.dynamicBytes == 110) "RFC request 2 table"
  checkField second 4 "cache-control" "no-cache"
  let (ctx, third) ← decodeOk ctx "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"
  ensure (third.size == 5 && ctx.dynamicBytes == 164) "RFC request 3 table"
  checkField third 4 "custom-key" "custom-value"
  let (plainContext, plain1) ← decodeOk Context.new "828684410f7777772e6578616d706c652e636f6d"
  checkField plain1 3 ":authority" "www.example.com"
  let (plainContext, plain2) ← decodeOk plainContext "828684be58086e6f2d6361636865"
  checkField plain2 4 "cache-control" "no-cache"
  let (_, plain3) ← decodeOk plainContext "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565"
  checkField plain3 4 "custom-key" "custom-value"
  let responseContext := Context.new { maxTableBytes := 256 }
  let (responseContext, response1) ← decodeOk responseContext
    "3fe101488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3"
  ensure (response1.size == 4) "RFC response 1 count"
  checkField response1 0 ":status" "302"
  checkField response1 3 "location" "https://www.example.com"
  let (responseContext, response2) ← decodeOk responseContext "4883640effc1c0bf"
  ensure (response2.size == 4) "RFC response 2 count"
  checkField response2 0 ":status" "307"
  let (_, response3) ← decodeOk responseContext
    "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007"
  ensure (response3.size == 6) "RFC response 3 count"
  checkField response3 0 ":status" "200"
  checkField response3 4 "content-encoding" "gzip"
  checkField response3 5 "set-cookie" "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"
  expectBad "80"
  expectBad "ff00"
  expectBad "4081ff00"
  expectBad "8220"
  expectBad "3fe21f"
  expectBad "40840102030405"
  let (_, _) ← decodeOk Context.new "3b33"
  let hard8192 := Context.new { maxTableBytes := 8192 }
  ensure (isError (decode hard8192 (fromHex "3fe21f"))) "unnegotiated table expansion accepted"
  let (_, _) ← decodeOk (hard8192.setMaximum 8192) "3fe21f"
  let headers : Array Header := #[
    { name := ":method".toUTF8, value := "GET".toUTF8 },
    { name := "x-bytes".toUTF8, value := all },
    { name := "authorization".toUTF8, value := "secret".toUTF8, sensitive := true }]
  let (encoder, encoded) ← match encode Context.new headers with
    | .ok v => pure v | .error e => throw (IO.userError e)
  let (decoder, decoded) ← match decode Context.new encoded with
    | .ok v => pure v | .error e => throw (IO.userError e)
  ensure (decoded.size == headers.size) "roundtrip count"
  for i in [:headers.size] do
    ensure (decoded[i]!.name == headers[i]!.name && decoded[i]!.value == headers[i]!.value &&
      decoded[i]!.sensitive == headers[i]!.sensitive) "roundtrip fields"
  let (_, encoded2) ← match encode encoder headers with | .ok v => pure v | .error e => throw (IO.userError e)
  let (_, decoded2) ← match decode decoder encoded2 with | .ok v => pure v | .error e => throw (IO.userError e)
  ensure (decoded2.size == headers.size && decoded2[1]!.value == all) "dynamic reuse"
  let reduced := (Context.new.setMaximum 0).setMaximum 4096
  ensure (isError (decode reduced (fromHex "3fe11f82"))) "missing required minimum accepted"
  let (_, resized) ← decodeOk reduced "203fe11f82"
  ensure (resized.size == 1) "required minimum update"
  let mut encoder := Context.new
  let mut decoder := Context.new
  for i in [:200] do
    let sample : Array Header := #[
      { name := "x-key".toUTF8, value := (toString (i % 37)).toUTF8 },
      { name := "x-other".toUTF8, value := (toString i).toUTF8 },
      { name := "authorization".toUTF8, value := (toString (i * 5)).toUTF8, sensitive := true }]
    let (nextEncoder, block) ← match encode encoder sample with | .ok v => pure v | .error e => throw (IO.userError e)
    let (nextDecoder, fields) ← match decode decoder block with | .ok v => pure v | .error e => throw (IO.userError e)
    for j in [:sample.size] do
      ensure (fields[j]!.name == sample[j]!.name && fields[j]!.value == sample[j]!.value &&
        fields[j]!.sensitive == sample[j]!.sensitive) "stateful property roundtrip"
    ensure (nextEncoder.dynamicBytes == nextDecoder.dynamicBytes) "dynamic table size mismatch"
    encoder := nextEncoder
    decoder := nextDecoder
  IO.println "HPACK RFC vectors and roundtrips passed"
