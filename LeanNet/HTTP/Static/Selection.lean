import LeanNet.HTTP1.Encoding
import LeanNet.HTTP.Static.Date
import LeanNet.HTTP.Static.Path

namespace LeanNet.HTTP.Static

open HTTP1

inductive Coding where
  | identity | gzip | br
  deriving BEq, Repr, Inhabited

def Coding.wire : Coding → String
  | .identity => "identity"
  | .gzip => "gzip"
  | .br => "br"

structure Representation where
  region : FileRegion
  etag : ByteArray
  coding : Coding := .identity

structure Entry where
  path : ByteArray
  contentType : ByteArray
  modifiedSeconds : Int
  lastModified : ByteArray
  dateValidatorStrong : Bool := false
  identity : Representation
  gzip : Option Representation := none
  brotli : Option Representation := none

structure Context where
  nowSeconds : Int

structure Config where
  cacheControl : ByteArray := "public, max-age=0, must-revalidate".toUTF8
  maxEncodingMembers : Nat := 64
  maxEntityTags : Nat := 128

private def whitespace (byte : UInt8) : Bool := byte == 32 || byte == 9

private def trim (value : ByteArray) : ByteArray :=
  ByteArray.mk (((value.toList.dropWhile whitespace).reverse.dropWhile whitespace).reverse.toArray)

private def ascii? (value : ByteArray) : Option String :=
  if value.toList.all (fun byte => byte.toNat < 128) then String.fromUTF8? value else none

private def textTrim (value : String) : String := String.fromUTF8! (trim value.toUTF8)

private def fields (request : Request) (name : String) : Array ByteArray :=
  (request.headers.filter (fun field => field.name.toLower == name)).map (·.value)

private def combined (request : Request) (name : String) : Option ByteArray :=
  let values := fields request name
  if values.isEmpty then none else some (Id.run do
    let mut output := values[0]!
    for index in [1:values.size] do output := (output.push 44) ++ values[index]!
    return output)

private def header (name : String) (value : ByteArray) : Header := { name, value }

private def token (value : String) : Bool :=
  !value.isEmpty && value.toUTF8.toList.all (fun byte =>
    let n := byte.toNat
    (n >= 48 && n <= 57) || (n >= 65 && n <= 90) || (n >= 97 && n <= 122) ||
      [33, 35, 36, 37, 38, 39, 42, 43, 45, 46, 94, 95, 96, 124, 126].contains n)

private def qvalue? (value : String) : Option Nat := do
  let value := value.toUTF8
  if value.isEmpty || (value[0]! != 48 && value[0]! != 49) then failure
  if value.size == 1 then return if value[0]! == 49 then 1000 else 0
  if value.size > 5 || value[1]! != 46 then failure
  let mut number := 0
  for index in [2:value.size] do
    let digit := value[index]!.toNat
    if digit < 48 || digit > 57 || (value[0]! == 49 && digit != 48) then failure
    number := number * 10 + digit - 48
  for _ in [value.size:5] do number := number * 10
  return if value[0]! == 49 then 1000 else number

private def encodingWeights (value : ByteArray) (limit : Nat) : Except String (Array (String × Nat)) := do
  let some text := ascii? value | throw "Accept-Encoding must be ASCII"
  let mut result := #[]
  for member in text.splitOn "," do
    let member := textTrim member
    if member.isEmpty then continue
    if result.size >= limit then throw "too many content codings"
    let parts := member.splitOn ";"
    let name := (textTrim parts.head!).toLower
    if !token name then throw "invalid content coding"
    let weight ← match parts.tail with
      | [] => pure 1000
      | [parameter] =>
        let pair := (textTrim parameter).splitOn "="
        let [key, raw] := pair | throw "invalid content coding weight"
        if (textTrim key).toLower != "q" then throw "unknown content coding parameter"
        let some weight := qvalue? (textTrim raw) | throw "invalid content coding weight"
        pure weight
      | _ => throw "multiple content coding weights"
    if let some previous := result.find? (fun item => item.1 == name) then
      if previous.2 != weight then throw "conflicting content coding weights"
    else result := result.push (name, weight)
  return result

/-- Explicit coding weights compete, with br/gzip/identity as a stable tie
    order. Implicit identity is a fallback; absent/empty fields select identity.
    A q=0 representation is never selected, including wildcard exclusions. -/
def selectRepresentation (entry : Entry) (request : Request) (config : Config := {}) :
    Except String (Option Representation) := do
  let some value := combined request "accept-encoding" | return some entry.identity
  if (trim value).isEmpty then return some entry.identity
  let weights ← encodingWeights value config.maxEncodingMembers
  let lookup := fun name => (weights.find? (fun item => item.1 == name)).map (·.2)
  let weight := fun name => (lookup name).getD ((lookup "*").getD 0)
  let mut candidates : Array (Representation × Nat) := #[]
  if let some variant := entry.brotli then
    if weight "br" > 0 then candidates := candidates.push (variant, weight "br")
  if let some variant := entry.gzip then
    if weight "gzip" > 0 then candidates := candidates.push (variant, weight "gzip")
  if let some identityWeight := lookup "identity" then
    if identityWeight > 0 then candidates := candidates.push (entry.identity, identityWeight)
  let mut chosen : Option (Representation × Nat) := none
  for candidate in candidates do
    if chosen.isNone || candidate.2 > (chosen.map (·.2)).getD 0 then chosen := some candidate
  if let some candidate := chosen then return some candidate.1
  if (lookup "identity") == some 0 || (lookup "identity").isNone && lookup "*" == some 0 then return none
  return some entry.identity

private structure Tag where
  weak : Bool
  value : ByteArray

private def skipWhitespace (bytes : ByteArray) (start : Nat) : Nat := Id.run do
  let mut next := start
  for index in [start:bytes.size] do
    if !whitespace bytes[index]! then break
    next := index + 1
  return next

private def tagAt (bytes : ByteArray) (start : Nat) : Except String (Tag × Nat) := do
  let weak := start + 1 < bytes.size && bytes[start]! == 87 && bytes[start + 1]! == 47
  let begin := start + if weak then 2 else 0
  if begin >= bytes.size || bytes[begin]! != 34 then throw "invalid entity tag"
  for index in [begin + 1:bytes.size] do
    let byte := bytes[index]!
    if byte == 34 then return (⟨weak, bytes.extract (begin + 1) index⟩, index + 1)
    if byte != 33 && (byte.toNat < 35 || byte == 127) then throw "invalid entity tag"
  throw "unterminated entity tag"

private inductive Tags where
  | any
  | list (tags : Array Tag)

private def tagList (bytes : ByteArray) (limit : Nat) : Except String Tags := do
  let bytes := trim bytes
  if bytes == "*".toUTF8 then return .any
  let mut tags := #[]
  let mut cursor := 0
  for _ in [:bytes.size + 1] do
    cursor := skipWhitespace bytes cursor
    if cursor >= bytes.size then return .list tags
    if bytes[cursor]! == 44 then cursor := cursor + 1; continue
    if tags.size >= limit then throw "too many entity tags"
    let (tag, next) ← tagAt bytes cursor
    tags := tags.push tag
    cursor := skipWhitespace bytes next
    if cursor == bytes.size then return .list tags
    if bytes[cursor]! != 44 then throw "invalid entity tag list"
    cursor := cursor + 1
  throw "invalid entity tag list"

private def currentTag? (representation : Representation) : Option Tag := do
  let .ok (tag, stop) := tagAt representation.etag 0 | none
  if tag.weak || stop != representation.etag.size then failure
  return tag

private def tagsMatch (tags : Tags) (tag : Tag) (strong : Bool) : Bool :=
  match tags with
  | .any => true
  | .list values => values.any (fun value => value.value == tag.value && (!strong || !value.weak && !tag.weak))

private def dateField? (request : Request) (name : String) (context : Context) : Option Int := do
  let values := fields request name
  if values.size != 1 then failure
  parseHttpDateTicks? values[0]! context.nowSeconds

private def precondition (entry : Entry) (representation : Representation) (request : Request)
    (context : Context) (config : Config) : Except String (Option Nat) := do
  let some current := currentTag? representation | throw "invalid catalog entity tag"
  if let some value := combined request "if-match" then
    if !tagsMatch (← tagList value config.maxEntityTags) current true then return some 412
  else if let some date := dateField? request "if-unmodified-since" context then
    if entry.modifiedSeconds * 2 > date then return some 412
  if let some value := combined request "if-none-match" then
    if tagsMatch (← tagList value config.maxEntityTags) current false then return some 304
  else if let some date := dateField? request "if-modified-since" context then
    if entry.modifiedSeconds * 2 <= date then return some 304
  return none

private def ifRangeMatches (entry : Entry) (representation : Representation) (request : Request)
    (context : Context) : Bool := Id.run do
  let values := fields request "if-range"
  if values.isEmpty then return true
  if values.size != 1 then return false
  let value := trim values[0]!
  match tagAt value 0, currentTag? representation with
  | .ok (tag, stop), some current =>
    return stop == value.size && !tag.weak && tag.value == current.value
  | _, _ =>
    return entry.dateValidatorStrong && parseHttpDateTicks? value context.nowSeconds == some (entry.modifiedSeconds * 2)

inductive RangeSelection where
  | ignore
  | unsatisfiable
  | slice (offset length : Nat)
  deriving BEq, Repr

private def decimal? (value : String) : Option Nat := do
  if value.isEmpty then failure
  let mut number : UInt64 := 0
  -- Values beyond the signed file offset limit retain their semantic meaning
  -- (beyond EOF, or a suffix covering everything) without unbounded integers.
  for byte in value.toUTF8 do
    if byte.toNat < 48 || byte.toNat > 57 then failure
    let digit := UInt64.ofNat (byte.toNat - 48)
    if number > (9223372036854775807 - digit) / 10 then number := 9223372036854775807
    else number := number * 10 + digit
  return number.toNat

/-- Single byte range policy: malformed/multiple/unknown units are ignored.
    Valid unsatisfiable ranges select416. Empty positive suffixes are ignored
    to avoid inventing an invalid zero-length206 Content-Range. -/
def selectRange (value : ByteArray) (length : Nat) : RangeSelection := Id.run do
  let some value := ascii? value | return .ignore
  let [unit, value] := value.splitOn "=" | return .ignore
  if (textTrim unit).toLower != "bytes" || value.contains ',' then return .ignore
  let [first, last] := (textTrim value).splitOn "-" | return .ignore
  if first.isEmpty then
    let some suffix := decimal? last | return .ignore
    if suffix == 0 then return .unsatisfiable
    if length == 0 then return .ignore
    let count := min suffix length
    return .slice (length - count) count
  let some start := decimal? first | return .ignore
  let endPosition ← if last.isEmpty then pure (length - 1) else
    match decimal? last with
    | none => return .ignore
    | some value => pure value
  if !last.isEmpty && endPosition < start then return .ignore
  if start >= length then return .unsatisfiable
  let stop := min endPosition (length - 1)
  return .slice start (stop - start + 1)

private def cacheHeaders (representation : Representation) (config : Config) : Array Header :=
  #[header "etag" representation.etag, header "vary" "Accept-Encoding".toUTF8,
    header "cache-control" config.cacheControl]

private def errorReply (status : Nat) (headers : Array Header := #[]) : Reply :=
  { response := { status, headers } }

private def serve (entry : Entry) (request : Request) (context : Context) (config : Config) :
    Except String Reply := do
  if request.method != "GET" && request.method != "HEAD" then
    return errorReply 405 #[header "allow" "GET, HEAD".toUTF8]
  let selected ← selectRepresentation entry request config
  let some representation := selected | return errorReply 406 #[header "vary" "Accept-Encoding".toUTF8]
  if !representation.region.valid || (currentTag? representation).isNone then
    return { response := { status := 500 }, options := { forceClose := true } }
  let cache := cacheHeaders representation config
  if let some status ← precondition entry representation request context config then
    return errorReply status cache
  let mut responseFields := cache ++ #[header "content-type" entry.contentType,
    header "last-modified" entry.lastModified, header "accept-ranges" "bytes".toUTF8,
    header "x-content-type-options" "nosniff".toUTF8]
  if representation.coding != .identity then
    responseFields := responseFields.push (header "content-encoding" representation.coding.wire.toUTF8)
  if request.method == "GET" then
    if let some range := combined request "range" then
      if ifRangeMatches entry representation request context then
        match selectRange range representation.region.length with
        | .ignore => pure ()
        | .unsatisfiable =>
          return errorReply 416 (cache.push (header "content-range"
            ("bytes */" ++ toString representation.region.length).toUTF8))
        | .slice start length =>
          let contentRange := ("bytes " ++ toString start ++ "-" ++ toString (start + length - 1) ++
            "/" ++ toString representation.region.length).toUTF8
          return { response := { status := 206, headers := responseFields.push (header "content-range" contentRange) },
                   fileRegion := some ((representation.region.drop start).take length) }
  return { response := { headers := responseFields }, fileRegion := some representation.region }

/-- Pure selection over immutable metadata. The file reference is retained for
    HEAD so both encoders derive its GET length and suppress actual file output.
    Catalog/path lookup and source lifetime belong to the startup/driver layer. -/
def Selection.plan (entry : Entry) (request : Request) (context : Context)
    (config : Config := {}) : Reply :=
  match serve entry request context config with
  | .ok reply => reply
  | .error _ => errorReply 400

end LeanNet.HTTP.Static
