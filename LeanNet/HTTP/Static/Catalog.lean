import Std.Data.HashMap
import Std.Data.HashSet
import LeanNet.HTTP.Static.Selection
import LeanNet.HTTP1.Handlers
import LeanNet.FileSource
import LeanNet.Reactor.Basic

namespace LeanNet.HTTP.Static

namespace Catalog

/-- Preparation requires a stable input tree. All content is copied into the
    private resident pack before any network worker starts serving requests. -/
structure Config where
  builder : File.BuilderConfig := {}
  residentBytes : Nat := 8 * 1024 * 1024
  adjustWorkingSet : Bool := true
  maxDepth : Nat := 32
  /-- Prefer named index files; otherwise generate a bounded directory page. -/
  directoryIndex : Bool := true
  indexNames : Array String := #["index.html", "index.htm"]
  selection : Static.Config := {}
  maxListingBytes : Nat := 256 * 1024

end Catalog

private structure PreparedRepresentation where
  offset : UInt64
  length : Nat
  etag : ByteArray
  coding : Coding

private structure PreparedEntry where
  path : String
  contentType : ByteArray
  modifiedSeconds : Int
  lastModified : ByteArray
  dateValidatorStrong : Bool
  identity : PreparedRepresentation
  gzip : Option PreparedRepresentation
  brotli : Option PreparedRepresentation

structure Catalog where
  private mk ::
  source : File.Source
  private config : Catalog.Config
  private entries : Array PreparedEntry
  private directories : Std.HashSet String

structure BoundCatalog where
  private mk ::
  private source : File.Source
  private entries : Std.HashMap String Entry
  private directories : Std.HashSet String
  private selection : Static.Config

private structure WalkState where
  entries : Std.HashMap String PreparedEntry := {}
  directories : Std.HashSet String := {}
  visited : Nat := 0
  produced : Nat := 0

private def wallSeconds : IO Int := do
  return (← Std.Time.Timestamp.now).toSecondsSinceUnixEpoch.val

private def startupCheck (cutoff : Nat) : IO Unit := do
  if (← IO.monoMsNow) >= cutoff then throw (IO.userError "static catalog startup deadline exceeded")

private def validateName (name : String) : IO Unit := do
  let encoded := "/".toUTF8 ++ encodeSegment name.toUTF8
  match decodePath encoded with
  | .error message => throw (IO.userError s!"static catalog unsafe filename {repr name}: {message}")
  | .ok decoded =>
    if decoded.path != "/".toUTF8 ++ name.toUTF8 || decoded.trailingSlash then
      throw (IO.userError "static catalog filename is not one portable path segment")

private def mimeType (path : String) : ByteArray := Id.run do
  let lower := path.toLower
  for (suffix, mime) in (#[(".html", "text/html; charset=utf-8"), (".htm", "text/html; charset=utf-8"), (".css", "text/css; charset=utf-8"), (".js", "text/javascript; charset=utf-8"), (".mjs", "text/javascript; charset=utf-8"), (".json", "application/json"), (".txt", "text/plain; charset=utf-8"), (".xml", "application/xml"), (".svg", "image/svg+xml"), (".png", "image/png"), (".jpg", "image/jpeg"), (".jpeg", "image/jpeg"), (".gif", "image/gif"), (".webp", "image/webp"), (".avif", "image/avif"), (".ico", "image/vnd.microsoft.icon"), (".pdf", "application/pdf"), (".wasm", "application/wasm"), (".woff2", "font/woff2"), (".woff", "font/woff"), (".ttf", "font/ttf"), (".otf", "font/otf"), (".mp4", "video/mp4"), (".webm", "video/webm"), (".mp3", "audio/mpeg"), (".ogg", "audio/ogg"), (".wav", "audio/wav"), (".zip", "application/zip"), (".gz", "application/gzip")] : Array (String × String)) do
    if lower.endsWith suffix then return mime.toUTF8
  return "application/octet-stream".toUTF8

private def metadata64 (builder : File.Builder) (id : UInt32) (field : Nat) : IO Nat := do
  let low ← builder.field id field.toUInt32
  let high ← builder.field id (field + 1).toUInt32
  return low.toNat + high.toNat * 4294967296

private def signed64 (bits : Nat) : Int :=
  if bits >= 9223372036854775808 then Int.ofNat bits - 18446744073709551616 else Int.ofNat bits

private def representation (builder : File.Builder) (id : UInt32) (index : Nat)
    (coding : Coding) : IO PreparedRepresentation := do
  let start := 3 + 12 * index
  let offset ← metadata64 builder id start
  let length ← metadata64 builder id (start + 2)
  if offset + length > 9223372036854775807 then throw (IO.userError "static representation exceeds native offset range")
  let mut digest := ""
  for word in [:8] do
    let value ← builder.field id (start + 4 + word).toUInt32
    for digit in [:8] do
      let nibble := value.toNat / (16 ^ (7 - digit)) % 16
      digest := digest.push (Char.ofNat (if nibble < 10 then 48 + nibble else 87 + nibble))
  return { offset := offset.toUInt64, length, etag := ("\"" ++ coding.wire ++ "-" ++ digest ++ "\"").toUTF8, coding }

private def preparedEntry (builder : File.Builder) (id : UInt32) (path : String)
    (contentType : ByteArray) (now : Int) (generated : Bool := false) : IO PreparedEntry := do
  let present ← builder.field id 0
  if present.toNat > 7 || (present.toNat % 2) != 1 then throw (IO.userError "static catalog lacks identity representation")
  let rawModified ← metadata64 builder id 1
  let modified := if generated then now else min now (signed64 rawModified)
  if modified < -62135596800 then throw (IO.userError "static modification time precedes HTTP date range")
  let identity ← representation builder id 0 .identity
  let gzip ← if present.toNat / 2 % 2 == 1 then some <$> representation builder id 1 .gzip else pure none
  let brotli ← if present.toNat / 4 % 2 == 1 then some <$> representation builder id 2 .br else pure none
  return { path, contentType, modifiedSeconds := modified, lastModified := formatHttpDate modified, dateValidatorStrong := modified + 60 <= now, identity, gzip, brotli }

private def reserveEntry (state : IO.Ref WalkState) (limit : Nat) : IO Unit := do
  let current ← state.get
  if current.produced >= limit then throw (IO.userError "static catalog entry count exceeded")
  state.set { current with produced := current.produced + 1 }

private def listing (url : String) (children : Array (String × Bool)) (limit : Nat) : IO ByteArray := do
  let title := escapeHtml url
  let mut bytes := ("<!doctype html><html><head><meta charset=\"utf-8\"><title>Index of " ++ title ++
    "</title></head><body><h1>Index of " ++ title ++ "</h1><ul>\n").toUTF8
  if bytes.size > limit then throw (IO.userError "static directory page exceeds byte limit")
  let ending := "</ul></body></html>\n".toUTF8
  if url != "/" then
    let parent := "<li><a href=\"../\">../</a></li>\n".toUTF8
    if bytes.size + parent.size + ending.size > limit then throw (IO.userError "static directory page exceeds byte limit")
    bytes := bytes ++ parent
  for (name, directory) in children do
    let suffix := if directory then "/" else ""
    let href := String.fromUTF8! (encodeSegment name.toUTF8)
    let row := ("<li><a href=\"" ++ href ++ suffix ++ "\">" ++ escapeHtml name ++ suffix ++ "</a></li>\n").toUTF8
    if bytes.size + row.size + ending.size > limit then throw (IO.userError "static directory page exceeds byte limit")
    bytes := bytes ++ row
  if bytes.size + ending.size > limit then throw (IO.userError "static directory page exceeds byte limit")
  return bytes ++ ending

/-- The input tree must remain stable while preparing. Enumeration and content
    reads both use bounded native opens anchored to the original root handle. -/
private partial def walk (relative url : String) (remaining : Nat)
    (builder : File.Builder) (config : Catalog.Config) (state : IO.Ref WalkState)
    (now : Int) (cutoff : Nat) : IO Unit := do
  startupCheck cutoff
  let current ← state.get
  state.set { current with directories := current.directories.insert url }
  builder.checkDirectory relative.toUTF8
  let raw ← builder.readDirectory relative.toUTF8 (config.builder.maxEntries + 1 - current.visited)
  if raw.size > config.builder.maxEntries then throw (IO.userError "static directory entry count exceeded")
  let current ← state.get
  if current.visited + raw.size > config.builder.maxEntries + 1 then
    throw (IO.userError "static traversal entry count exceeded")
  -- Account for every discovered entry before descending. Ancestor arrays then
  -- share the same global bound, including entries that will be skipped.
  state.set { current with visited := current.visited + raw.size }
  let mut named : Array (String × UInt32) := #[]
  for (bytes, kind) in raw do
    let some name := String.fromUTF8? bytes | throw (IO.userError "static catalog filename is not UTF-8")
    validateName name
    if kind < 1 || kind > 4 then throw (IO.userError "static catalog returned an invalid entry type")
    named := named.push (name, kind)
  let ordered := named.qsort (fun a b => decide (a.1 < b.1))
  let mut children := #[]
  for (name, kind) in ordered do
    startupCheck cutoff
    if kind == 3 || kind == 4 then continue
    let childRelative := if relative.isEmpty then name else relative ++ "/" ++ name
    if kind == 1 then
      if remaining == 0 then throw (IO.userError "static directory depth exceeded")
      walk childRelative (url ++ name ++ "/") (remaining - 1) builder config state now cutoff
      children := children.push (name, true)
    else
      reserveEntry state config.builder.maxEntries
      let id ← builder.addPath childRelative.toUTF8
      let entry ← preparedEntry builder id (url ++ name) (mimeType name) now
      state.modify (fun current => { current with entries := current.entries.insert entry.path entry })
      children := children.push (name, false)
  let current ← state.get
  let mut index : Option PreparedEntry := none
  for name in config.indexNames do
    if let some found := current.entries[url ++ name]? then index := some found; break
  if let some entry := index then
    state.modify (fun current => { current with entries := current.entries.insert url { entry with path := url } })
  else if config.directoryIndex then
    builder.checkDirectory relative.toUTF8
    let bytes ← listing url children (min config.maxListingBytes config.builder.maxFileBytes)
    reserveEntry state config.builder.maxEntries
    let id ← builder.addBytes bytes
    let entry ← preparedEntry builder id url "text/html; charset=utf-8".toUTF8 now true
    state.modify (fun current => { current with entries := current.entries.insert url entry })
  builder.checkDirectory relative.toUTF8

/-- Build once before listen. Registrations retained by all worker reactors
    must be destroyed before `use` returns and this source bracket closes. -/
def Catalog.withCatalog (root : System.FilePath) (config : Catalog.Config := {})
    (use : Catalog → IO α) : IO α := do
  if config.residentBytes == 0 || config.residentBytes > 9223372036854775807 || config.maxDepth > 256 ||
      config.maxListingBytes == 0 || config.indexNames.size > 64 then
    throw (IO.userError "invalid static catalog limits")
  for name in config.indexNames do validateName name
  let now ← wallSeconds
  let cutoff := (← IO.monoMsNow) + config.builder.startupTimeoutMs
  let published ← IO.mkRef (none : Option File.Source)
  try
    let catalog ← File.withBuilder root config.builder fun builder => do
      let state ← IO.mkRef ({ visited := 1 } : WalkState)
      walk "" "/" config.maxDepth builder config state now cutoff
      let prepared ← state.get
      let source ← builder.publish config.residentBytes config.adjustWorkingSet
      published.set (some source)
      let entries := (prepared.entries.toArray.map (·.2)).qsort (fun a b => decide (a.path < b.path))
      pure (Catalog.mk source config entries prepared.directories)
    -- Builder scratch space and the original root handle are already closed.
    -- Only the private immutable source and prepared metadata reach serving.
    use catalog
  finally
    if let some source ← published.get then source.close

private def bindRepresentation (base : FileRegion) (prepared : PreparedRepresentation) : IO Representation := do
  if prepared.offset.toNat + prepared.length > base.length then throw (IO.userError "static representation exceeds published source")
  let region : FileRegion := { base with offset := prepared.offset, length := prepared.length }
  if !region.valid then throw (IO.userError "invalid static representation identity")
  return { region, etag := prepared.etag, coding := prepared.coding }

/-- Register once before this worker polls. The reactor owns the registration
    through native teardown; releasing on handler exit could race canceled IOCP. -/
def Catalog.bind (catalog : Catalog) (reactor : Reactor.Reactor) : IO BoundCatalog := do
  catalog.source.ensureAlive
  reactor.setupFiles 1
  let base ← reactor.importFile catalog.source
  let mut entries : Std.HashMap String Entry := {}
  for prepared in catalog.entries do
    let identity ← bindRepresentation base prepared.identity
    let gzip ← match prepared.gzip with | none => pure none | some value => some <$> bindRepresentation base value
    let brotli ← match prepared.brotli with | none => pure none | some value => some <$> bindRepresentation base value
    let entry : Entry := { path := prepared.path.toUTF8, contentType := prepared.contentType, modifiedSeconds := prepared.modifiedSeconds, lastModified := prepared.lastModified, dateValidatorStrong := prepared.dateValidatorStrong, identity, gzip, brotli }
    entries := entries.insert prepared.path entry
  return ⟨catalog.source, entries, catalog.directories, catalog.config.selection⟩

private def errorReply (status : Nat) (body : String) (headers : Array HTTP1.Header := #[]) : HTTP1.Reply :=
  { response := { status, headers := #[{ name := "Content-Type", value := "text/plain; charset=utf-8".toUTF8 }] ++ headers, body := body.toUTF8 } }

/-- Pure lookup and request selection after startup; filenames are never opened
    or statted here. Only selected regions reference native immutable bytes. -/
def BoundCatalog.plan (catalog : BoundCatalog) (request : HTTP1.Request) (context : Context) : HTTP1.Reply := Id.run do
  let .ok decoded := decodePath request.target | return errorReply 400 "Bad Request\n"
  if request.method != "GET" && request.method != "HEAD" then
    return errorReply 405 "Method Not Allowed\n" #[{ name := "Allow", value := "GET, HEAD".toUTF8 }]
  let path := String.fromUTF8! decoded.path
  if !decoded.trailingSlash && catalog.directories.contains (path ++ "/") then
    let mut location := encodePath decoded.path ++ "/".toUTF8
    if !decoded.query.isEmpty || request.target.data.contains 63 then location := location ++ "?".toUTF8 ++ decoded.query
    return { response := { status := 308, headers := #[{ name := "Location", value := location }] } }
  if let some entry := catalog.entries[path]? then return Selection.plan entry request context catalog.selection
  if catalog.directories.contains path then return errorReply 403 "Forbidden\n"
  return errorReply 404 "Not Found\n"

/-- Each worker owns its clock cache; wall-clock/date parsing context refreshes
    at most once per monotonic second. Selection and lookup remain pure. -/
def BoundCatalog.handlers (catalog : BoundCatalog) : IO HTTP1.Handlers := do
  catalog.source.ensureAlive
  let clock ← IO.mkRef ((← IO.monoMsNow) / 1000, ← wallSeconds)
  return { onRequest := fun request => do
    catalog.source.ensureAlive
    let tick := (← IO.monoMsNow) / 1000
    let (previous, seconds) ← clock.get
    let seconds ← if tick == previous then pure seconds else do
      let seconds ← wallSeconds
      clock.set (tick, seconds)
      pure seconds
    return catalog.plan request { nowSeconds := seconds } }

end LeanNet.HTTP.Static
