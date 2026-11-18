import LeanNet.HTTP.Static.Selection

open LeanNet LeanNet.HTTP1 LeanNet.HTTP.Static

private def check (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

private def testRepresentation (coding : Coding) (offset length : Nat) (tag : String) : Representation :=
  { coding, region := { owner := 1, token := 2, offset := UInt64.ofNat offset, length }, etag := tag.toUTF8 }

private def entry : Entry := {
  path := "/asset.txt".toUTF8, contentType := "text/plain; charset=utf-8".toUTF8,
  modifiedSeconds := 784111777, lastModified := "Sun, 06 Nov 1994 08:49:37 GMT".toUTF8,
  identity := testRepresentation .identity 100 10 "\"identity\"",
  gzip := some (testRepresentation .gzip 200 6 "\"gzip\""), brotli := some (testRepresentation .br 300 5 "\"brotli\"") }

private def request (headers : List (String × String) := []) (method : String := "GET") : Request :=
  { method, target := "/asset.txt".toUTF8, headers := headers.toArray.map (fun (name,value) => { name, value := value.toUTF8 }), body := ByteArray.empty }

private def plan (headers : List (String × String) := []) (method : String := "GET") (resource : Entry := entry) : Reply :=
  Selection.plan resource (request headers method) { nowSeconds := 1767225600 }

private def value (reply : Reply) (name : String) : Option ByteArray :=
  (reply.response.headers.find? (fun field => field.name == name)).map (·.value)

def main : IO Unit := do
  for input in ["Sun, 06 Nov 1994 08:49:37 GMT", "Sunday, 06-Nov-94 08:49:37 GMT", "Sun Nov  6 08:49:37 1994"] do
    check (parseHttpDate? input.toUTF8 1767225600 == some 784111777) s!"HTTP date {input}"
  check (formatHttpDate 784111777 == entry.lastModified) "date formatting"
  for input in ["Mon, 06 Nov 1994 08:49:37 GMT", "Sun, 31 Nov 1994 08:49:37 GMT", "Sun, 06 Nov 1994 24:49:37 GMT", "garbage"] do
    check ((parseHttpDate? input.toUTF8 1767225600).isNone) "invalid HTTP date accepted"
  check (parseHttpDate? "Tuesday, 01-Jan-75 00:00:00 GMT".toUTF8 1767225600 == some 3313526400) "RFC850 near-future century"
  check (parseHttpDate? "Saturday, 01-Jan-00 00:00:00 GMT".toUTF8 1767225600 == some 946684800) "RFC850 past century"
  check (parseHttpDate? "Wednesday, 01-Jan-76 00:00:00 GMT".toUTF8 1767225600 == some 3345062400) "RFC850 exactly fifty years ahead"
  check (parseHttpDate? "Friday, 02-Jan-76 00:00:00 GMT".toUTF8 1767225600 == some 189388800) "RFC850 more than fifty years ahead uses past century"
  check (parseHttpDateTicks? "Sat, 31 Dec 2016 23:59:60 GMT".toUTF8 1767225600 == some 2966457599) "valid leap second has a distinct comparison tick"
  check ((plan [("if-modified-since","Sat, 31 Dec 2016 23:59:60 GMT")] "GET" { entry with modifiedSeconds := 1483228800 }).response.status == 200) "leap second does not validate next-second modification"
  check ((plan [("range","bytes=0-1"),("if-range","Sat, 31 Dec 2016 23:59:60 GMT")] "GET" { entry with modifiedSeconds := 1483228799, dateValidatorStrong := true }).response.status == 200) "leap second does not equal adjacent strong file date"
  check ((plan).fileRegion.map (·.length) == some 10) "identity GET length"
  check ((plan [("accept-encoding","gzip;q=0.5")]).fileRegion.map (·.offset) == some 200) "explicit coding before implicit identity fallback"
  check ((plan [("accept-encoding","gzip, br")]).fileRegion.map (·.offset) == some 300) "br tie preference"
  check ((plan [("accept-encoding","br;q=0.4, identity;q=0.8")]).fileRegion.map (·.offset) == some 100) "explicit identity quality"
  check ((plan [("accept-encoding","*;q=0, gzip;q=0.8")]).fileRegion.map (·.offset) == some 200) "explicit coding overrides wildcard exclusion"
  check ((plan [("accept-encoding","*;q=0")]).response.status == 406) "excluded identity"
  check ((plan [("accept-encoding","br, identity;q=0")] "GET" { entry with gzip := none, brotli := none }).response.status == 406) "omitted variants cannot satisfy q0 identity"
  for encoding in ["gzip;q=1.1", "gzip;q=.5", "gzip;q=0.1234", "gzip;q=0, gzip;q=1"] do
    check ((plan [("accept-encoding",encoding)]).response.status == 400) "invalid or conflicting encoding weight"
  let limited := fun headers => Selection.plan entry (request headers) { nowSeconds := 1767225600 }
    { maxEncodingMembers := 2 }
  check ((limited [("Accept-Encoding", ", gzip, \t,"), ("Accept-Encoding", "gzip")]).response.status == 200)
    "repeated codings count toward the limit and empty members do not"
  check ((limited [("Accept-Encoding", "gzip, gzip"), ("Accept-Encoding", "gzip")]).response.status == 400)
    "repeated codings cannot exceed the configured member limit"
  check ((plan [("if-none-match","W/\"identity\"")]).response.status == 304) "weak If-None-Match"
  check ((plan [("if-none-match","\"other\""),("if-modified-since","Sun, 06 Nov 1994 08:49:37 GMT")]).response.status == 200) "ETag precedence over date"
  check ((plan [("if-none-match","*"),("range","bytes=99-")]).response.status == 304) "conditional before range"
  check ((plan [("if-match","W/\"identity\"")]).response.status == 412) "If-Match requires strong comparison"
  check ((plan [("if-match","\"identity\""),("if-unmodified-since","Sat, 01 Jan 1994 00:00:00 GMT")]).response.status == 200) "If-Match precedes date precondition"
  check ((plan [("if-modified-since","Sun Nov  6 08:49:37 1994")]).response.status == 304) "obsolete-date cache validation"
  check ((plan [("if-modified-since","bad date")]).response.status == 200) "invalid IMS ignored"
  let notModified := plan [("if-none-match","\"identity\"")]
  check (notModified.fileRegion.isNone && notModified.response.body.isEmpty && value notModified "vary" == some "Accept-Encoding".toUTF8) "304 metadata/body"
  let head := plan [("accept-encoding","br"),("range","bytes=1-2")] "HEAD"
  check (head.response.status == 200 && head.fileRegion.map (·.length) == some 5) "HEAD ignores Range and retains logical length"
  let .ok encoded := head.response.encodeFileFor head.fileRegion.get! { requestMethod := "HEAD" } | throw (IO.userError "HEAD encoding failed")
  check (encoded.fileRegion.isNone && encoded.framing == .contentLength 5) "HEAD file is not transmitted"
  for (range,offset,length) in [("bytes=1-3",101,3),("bytes=8-",108,2),("bytes=-3",107,3),("bytes=8-999",108,2),("bytes=-999",100,10)] do
    let response := plan [("range",range)]
    check (response.response.status == 206 && response.fileRegion.map (·.offset) == some (UInt64.ofNat offset) && response.fileRegion.map (·.length) == some length) s!"range {range}"
  for range in ["bytes=10-", "bytes=-0", "bytes=999999999999999999999999999999999999999999999999-"] do
    let response := plan [("range",range)]
    check (response.response.status == 416 && response.fileRegion.isNone && value response "content-range" == some "bytes */10".toUTF8) "unsatisfiable range"
  for range in ["bytes=2-1", "bytes=0-1,3-4", "items=0-1", "bytes=abc-"] do
    check ((plan [("range",range)]).response.status == 200) "unsupported/malformed range policy"
  let codedRange := plan [("accept-encoding","br"),("range","bytes=1-3")]
  check (codedRange.fileRegion.map (·.offset) == some 301 && value codedRange "content-range" == some "bytes 1-3/5".toUTF8 && value codedRange "content-encoding" == some "br".toUTF8) "ranges count encoded bytes"
  for validator in ["W/\"identity\"", "\"different\"", "Sun, 06 Nov 1994 08:49:37 GMT"] do
    check ((plan [("range","bytes=0-1"),("if-range",validator)]).response.status == 200) "weak/mismatching If-Range ignores Range"
  check ((plan [("range","bytes=0-1"),("if-range","\"identity\"")]).response.status == 206) "strong If-Range"
  check ((plan [("range","bytes=0-1"),("if-range","Sun, 06 Nov 1994 08:49:37 GMT")] "GET" { entry with dateValidatorStrong := true }).response.status == 206) "known-strong date If-Range"
  let empty := { entry with identity := testRepresentation .identity 100 0 "\"empty\"", gzip := none, brotli := none }
  check ((plan [("range","bytes=-1")] "GET" empty).response.status == 200) "empty positive suffix is deliberately ignored"
  check ((plan [("range","bytes=0-")] "GET" empty).response.status == 416) "empty ordinary range"
  check ((plan [] "POST").response.status == 405) "method gate"
  for path in ["/../x", "/%2e%2e/x", "/a%2fb", "/a%5Cb", "/a:b", "//host/x", "/a//b", "/x%00", "/x%", "/%FF", "/NUL.txt", "/name.", "/name%20"] do
    check (match decodePath path.toUTF8 with | .error _ => true | .ok _ => false) s!"unsafe path {path}"
  let .ok decoded := decodePath "/a%3Fb/%252e?ignored=/../".toUTF8 | throw (IO.userError "safe encoded path rejected")
  check (decoded.path == "/a?b/%2e".toUTF8 && decoded.query == "ignored=/../".toUTF8) "single decode and raw query split"
  check (encodePath "/a?b/%2e".toUTF8 == "/a%3Fb/%252e".toUTF8) "path encoding"
  check (escapeHtml "\"><&'" == "&quot;&gt;&lt;&amp;&#39;") "HTML escaping"
  IO.println "Static selection, validators, ranges, dates and URL safety passed"
