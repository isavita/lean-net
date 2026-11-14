/- HPACK constants and algorithms follow RFC 7541, Appendices A and B. -/
namespace LeanNet.HTTP2.HPACK

structure Header where
  name : ByteArray
  value : ByteArray
  sensitive : Bool := false
  deriving Inhabited

private def staticTable : Array Header := #[
  { name := ":authority".toUTF8, value := "".toUTF8 },
  { name := ":method".toUTF8, value := "GET".toUTF8 },
  { name := ":method".toUTF8, value := "POST".toUTF8 },
  { name := ":path".toUTF8, value := "/".toUTF8 },
  { name := ":path".toUTF8, value := "/index.html".toUTF8 },
  { name := ":scheme".toUTF8, value := "http".toUTF8 },
  { name := ":scheme".toUTF8, value := "https".toUTF8 },
  { name := ":status".toUTF8, value := "200".toUTF8 },
  { name := ":status".toUTF8, value := "204".toUTF8 },
  { name := ":status".toUTF8, value := "206".toUTF8 },
  { name := ":status".toUTF8, value := "304".toUTF8 },
  { name := ":status".toUTF8, value := "400".toUTF8 },
  { name := ":status".toUTF8, value := "404".toUTF8 },
  { name := ":status".toUTF8, value := "500".toUTF8 },
  { name := "accept-charset".toUTF8, value := "".toUTF8 },
  { name := "accept-encoding".toUTF8, value := "gzip, deflate".toUTF8 },
  { name := "accept-language".toUTF8, value := "".toUTF8 },
  { name := "accept-ranges".toUTF8, value := "".toUTF8 },
  { name := "accept".toUTF8, value := "".toUTF8 },
  { name := "access-control-allow-origin".toUTF8, value := "".toUTF8 },
  { name := "age".toUTF8, value := "".toUTF8 },
  { name := "allow".toUTF8, value := "".toUTF8 },
  { name := "authorization".toUTF8, value := "".toUTF8 },
  { name := "cache-control".toUTF8, value := "".toUTF8 },
  { name := "content-disposition".toUTF8, value := "".toUTF8 },
  { name := "content-encoding".toUTF8, value := "".toUTF8 },
  { name := "content-language".toUTF8, value := "".toUTF8 },
  { name := "content-length".toUTF8, value := "".toUTF8 },
  { name := "content-location".toUTF8, value := "".toUTF8 },
  { name := "content-range".toUTF8, value := "".toUTF8 },
  { name := "content-type".toUTF8, value := "".toUTF8 },
  { name := "cookie".toUTF8, value := "".toUTF8 },
  { name := "date".toUTF8, value := "".toUTF8 },
  { name := "etag".toUTF8, value := "".toUTF8 },
  { name := "expect".toUTF8, value := "".toUTF8 },
  { name := "expires".toUTF8, value := "".toUTF8 },
  { name := "from".toUTF8, value := "".toUTF8 },
  { name := "host".toUTF8, value := "".toUTF8 },
  { name := "if-match".toUTF8, value := "".toUTF8 },
  { name := "if-modified-since".toUTF8, value := "".toUTF8 },
  { name := "if-none-match".toUTF8, value := "".toUTF8 },
  { name := "if-range".toUTF8, value := "".toUTF8 },
  { name := "if-unmodified-since".toUTF8, value := "".toUTF8 },
  { name := "last-modified".toUTF8, value := "".toUTF8 },
  { name := "link".toUTF8, value := "".toUTF8 },
  { name := "location".toUTF8, value := "".toUTF8 },
  { name := "max-forwards".toUTF8, value := "".toUTF8 },
  { name := "proxy-authenticate".toUTF8, value := "".toUTF8 },
  { name := "proxy-authorization".toUTF8, value := "".toUTF8 },
  { name := "range".toUTF8, value := "".toUTF8 },
  { name := "referer".toUTF8, value := "".toUTF8 },
  { name := "refresh".toUTF8, value := "".toUTF8 },
  { name := "retry-after".toUTF8, value := "".toUTF8 },
  { name := "server".toUTF8, value := "".toUTF8 },
  { name := "set-cookie".toUTF8, value := "".toUTF8 },
  { name := "strict-transport-security".toUTF8, value := "".toUTF8 },
  { name := "transfer-encoding".toUTF8, value := "".toUTF8 },
  { name := "user-agent".toUTF8, value := "".toUTF8 },
  { name := "vary".toUTF8, value := "".toUTF8 },
  { name := "via".toUTF8, value := "".toUTF8 },
  { name := "www-authenticate".toUTF8, value := "".toUTF8 }
]

private def huffmanCodes : Array (Nat × Nat) := #[
  (8184, 13),
  (8388568, 23),
  (268435426, 28),
  (268435427, 28),
  (268435428, 28),
  (268435429, 28),
  (268435430, 28),
  (268435431, 28),
  (268435432, 28),
  (16777194, 24),
  (1073741820, 30),
  (268435433, 28),
  (268435434, 28),
  (1073741821, 30),
  (268435435, 28),
  (268435436, 28),
  (268435437, 28),
  (268435438, 28),
  (268435439, 28),
  (268435440, 28),
  (268435441, 28),
  (268435442, 28),
  (1073741822, 30),
  (268435443, 28),
  (268435444, 28),
  (268435445, 28),
  (268435446, 28),
  (268435447, 28),
  (268435448, 28),
  (268435449, 28),
  (268435450, 28),
  (268435451, 28),
  (20, 6),
  (1016, 10),
  (1017, 10),
  (4090, 12),
  (8185, 13),
  (21, 6),
  (248, 8),
  (2042, 11),
  (1018, 10),
  (1019, 10),
  (249, 8),
  (2043, 11),
  (250, 8),
  (22, 6),
  (23, 6),
  (24, 6),
  (0, 5),
  (1, 5),
  (2, 5),
  (25, 6),
  (26, 6),
  (27, 6),
  (28, 6),
  (29, 6),
  (30, 6),
  (31, 6),
  (92, 7),
  (251, 8),
  (32764, 15),
  (32, 6),
  (4091, 12),
  (1020, 10),
  (8186, 13),
  (33, 6),
  (93, 7),
  (94, 7),
  (95, 7),
  (96, 7),
  (97, 7),
  (98, 7),
  (99, 7),
  (100, 7),
  (101, 7),
  (102, 7),
  (103, 7),
  (104, 7),
  (105, 7),
  (106, 7),
  (107, 7),
  (108, 7),
  (109, 7),
  (110, 7),
  (111, 7),
  (112, 7),
  (113, 7),
  (114, 7),
  (252, 8),
  (115, 7),
  (253, 8),
  (8187, 13),
  (524272, 19),
  (8188, 13),
  (16380, 14),
  (34, 6),
  (32765, 15),
  (3, 5),
  (35, 6),
  (4, 5),
  (36, 6),
  (5, 5),
  (37, 6),
  (38, 6),
  (39, 6),
  (6, 5),
  (116, 7),
  (117, 7),
  (40, 6),
  (41, 6),
  (42, 6),
  (7, 5),
  (43, 6),
  (118, 7),
  (44, 6),
  (8, 5),
  (9, 5),
  (45, 6),
  (119, 7),
  (120, 7),
  (121, 7),
  (122, 7),
  (123, 7),
  (32766, 15),
  (2044, 11),
  (16381, 14),
  (8189, 13),
  (268435452, 28),
  (1048550, 20),
  (4194258, 22),
  (1048551, 20),
  (1048552, 20),
  (4194259, 22),
  (4194260, 22),
  (4194261, 22),
  (8388569, 23),
  (4194262, 22),
  (8388570, 23),
  (8388571, 23),
  (8388572, 23),
  (8388573, 23),
  (8388574, 23),
  (16777195, 24),
  (8388575, 23),
  (16777196, 24),
  (16777197, 24),
  (4194263, 22),
  (8388576, 23),
  (16777198, 24),
  (8388577, 23),
  (8388578, 23),
  (8388579, 23),
  (8388580, 23),
  (2097116, 21),
  (4194264, 22),
  (8388581, 23),
  (4194265, 22),
  (8388582, 23),
  (8388583, 23),
  (16777199, 24),
  (4194266, 22),
  (2097117, 21),
  (1048553, 20),
  (4194267, 22),
  (4194268, 22),
  (8388584, 23),
  (8388585, 23),
  (2097118, 21),
  (8388586, 23),
  (4194269, 22),
  (4194270, 22),
  (16777200, 24),
  (2097119, 21),
  (4194271, 22),
  (8388587, 23),
  (8388588, 23),
  (2097120, 21),
  (2097121, 21),
  (4194272, 22),
  (2097122, 21),
  (8388589, 23),
  (4194273, 22),
  (8388590, 23),
  (8388591, 23),
  (1048554, 20),
  (4194274, 22),
  (4194275, 22),
  (4194276, 22),
  (8388592, 23),
  (4194277, 22),
  (4194278, 22),
  (8388593, 23),
  (67108832, 26),
  (67108833, 26),
  (1048555, 20),
  (524273, 19),
  (4194279, 22),
  (8388594, 23),
  (4194280, 22),
  (33554412, 25),
  (67108834, 26),
  (67108835, 26),
  (67108836, 26),
  (134217694, 27),
  (134217695, 27),
  (67108837, 26),
  (16777201, 24),
  (33554413, 25),
  (524274, 19),
  (2097123, 21),
  (67108838, 26),
  (134217696, 27),
  (134217697, 27),
  (67108839, 26),
  (134217698, 27),
  (16777202, 24),
  (2097124, 21),
  (2097125, 21),
  (67108840, 26),
  (67108841, 26),
  (268435453, 28),
  (134217699, 27),
  (134217700, 27),
  (134217701, 27),
  (1048556, 20),
  (16777203, 24),
  (1048557, 20),
  (2097126, 21),
  (4194281, 22),
  (2097127, 21),
  (2097128, 21),
  (8388595, 23),
  (4194282, 22),
  (4194283, 22),
  (33554414, 25),
  (33554415, 25),
  (16777204, 24),
  (16777205, 24),
  (67108842, 26),
  (8388596, 23),
  (67108843, 26),
  (134217702, 27),
  (67108844, 26),
  (67108845, 26),
  (134217703, 27),
  (134217704, 27),
  (134217705, 27),
  (134217706, 27),
  (134217707, 27),
  (268435454, 28),
  (134217708, 27),
  (134217709, 27),
  (134217710, 27),
  (134217711, 27),
  (134217712, 27),
  (67108846, 26),
  (1073741823, 30)
]

private structure HuffNode where
  zero : Nat := 0
  one : Nat := 0
  symbol : Nat := 257
  deriving Inhabited

private def huffmanTree : Array HuffNode := Id.run do
  let mut nodes : Array HuffNode := #[{}]
  for symbol in [:huffmanCodes.size] do
    let (code, length) := huffmanCodes[symbol]!
    let mut node := 0
    for index in [:length] do
      let bit := (code / 2 ^ (length - index - 1)) % 2
      let current := nodes[node]!
      let child := if bit == 0 then current.zero else current.one
      if child == 0 then
        let child := nodes.size
        nodes := nodes.push {}
        nodes := nodes.set! node (if bit == 0 then { current with zero := child } else { current with one := child })
        node := child
      else node := child
    let current := nodes[node]!
    nodes := nodes.set! node { current with symbol := symbol }
  return nodes

/-- Encode arbitrary octets using RFC 7541's fixed Huffman alphabet. -/
def huffmanEncode (input : ByteArray) : ByteArray := Id.run do
  let mut output := ByteArray.empty
  let mut accumulator := 0
  let mut bits := 0
  for byte in input do
    let (code, length) := huffmanCodes[byte.toNat]!
    accumulator := accumulator * 2 ^ length + code
    bits := bits + length
    for _ in [:4] do
      if bits >= 8 then
        bits := bits - 8
        output := output.push (UInt8.ofNat (accumulator / 2 ^ bits))
        accumulator := accumulator % 2 ^ bits
  if bits > 0 then
    output := output.push (UInt8.ofNat (accumulator * 2 ^ (8 - bits) + (2 ^ (8 - bits) - 1)))
  return output

/-- Decode Huffman data and reject EOS symbols, invalid paths and non-EOS padding. -/
def huffmanDecode (input : ByteArray) (maxBytes : Nat := 65536) : Except String ByteArray := do
  let mut output := ByteArray.empty
  let mut node := 0
  let mut tail := 0
  let mut tailBits := 0
  for byte in input do
    for index in [:8] do
      let bit := (byte.toNat / 2 ^ (7 - index)) % 2
      let current := huffmanTree[node]!
      node := if bit == 0 then current.zero else current.one
      if node == 0 then throw "invalid Huffman code"
      tail := tail * 2 + bit
      tailBits := tailBits + 1
      let symbol := huffmanTree[node]!.symbol
      if symbol != 257 then
        if symbol == 256 then throw "Huffman EOS in string"
        if output.size >= maxBytes then throw "Huffman output exceeds limit"
        output := output.push (UInt8.ofNat symbol)
        node := 0
        tail := 0
        tailBits := 0
  if tailBits > 7 || tail != 2 ^ tailBits - 1 then throw "invalid Huffman padding"
  return output

/-- Independent resource bounds for one compression context and header block. -/
structure Limits where
  maxTableBytes : Nat := 4096
  maxEncodedBytes : Nat := 65536
  maxStringBytes : Nat := 65536
  maxHeaderListBytes : Nat := 65536
  maxHeaderFields : Nat := 100
  deriving Repr

/-- A directional HPACK context. Encoder and decoder must use separate contexts. -/
structure Context where
  private limits : Limits := {}
  private table : Array Header := #[]
  private tableBytes : Nat := 0
  private capacity : Nat := 4096
  private maximum : Nat := 4096
  private requireUpdate : Bool := false
  private requiredMinimum : Option Nat := none
  private pendingMin : Option Nat := none
  private pendingFinal : Option Nat := none

/-- The initial negotiated maximum defaults to 4096 bytes. A hard bound below
    4096 assumes the peer has acknowledged the corresponding SETTINGS reduction;
    construct the decoder only after that negotiation has taken effect. -/
def Context.new (limits : Limits := {}) : Context :=
  let cap := min 4096 limits.maxTableBytes
  { limits := limits, capacity := cap, maximum := cap, requireUpdate := limits.maxTableBytes < 4096,
    requiredMinimum := if limits.maxTableBytes < 4096 then some cap else none,
    pendingMin := if limits.maxTableBytes < 4096 then some cap else none,
    pendingFinal := if limits.maxTableBytes < 4096 then some cap else none }

private def entrySize (header : Header) : Nat := header.name.size + header.value.size + 32

private def evict (context : Context) : Context := Id.run do
  let mut context := context
  for _ in [:context.table.size] do
    if context.tableBytes > context.capacity then
      let some last := context.table.back? | return context
      context := { context with table := context.table.pop, tableBytes := context.tableBytes - entrySize last }
  return context

private def insert (context : Context) (header : Header) : Context := Id.run do
  let size := entrySize header
  if size > context.capacity then return { context with table := #[], tableBytes := 0 }
  let mut context := { context with tableBytes := context.tableBytes + size }
  for _ in [:context.table.size] do
    if context.tableBytes > context.capacity then
      let some last := context.table.back? | return context
      context := { context with table := context.table.pop, tableBytes := context.tableBytes - entrySize last }
  return { context with table := #[{ header with sensitive := false }] ++ context.table }

/-- Change an encoder's table capacity. Updates are emitted at the next block. -/
def Context.setCapacity (context : Context) (capacity : Nat) : Except String Context := do
  if capacity > context.maximum then throw "HPACK capacity exceeds configured maximum"
  let low := match context.pendingMin with | some old => min old capacity | none => capacity
  return evict { context with capacity := capacity, pendingMin := some low, pendingFinal := some capacity }

/-- Change the decoder's SETTINGS limit. A decrease below the current table
    capacity requires the next block to begin with a size update. -/
def Context.setMaximum (context : Context) (maximum : Nat) : Context :=
  let maximum := min maximum context.limits.maxTableBytes
  let mustUpdate := context.capacity > maximum
  let low := if mustUpdate then
    some (match context.requiredMinimum with | some old => min old maximum | none => maximum)
    else context.requiredMinimum
  { context with maximum := maximum, requireUpdate := context.requireUpdate || mustUpdate, requiredMinimum := low }

/-- Current dynamic table size in octets, including the RFC's per-entry cost. -/
def Context.dynamicBytes (context : Context) : Nat := context.tableBytes

private def lookup (context : Context) (index : Nat) : Except String Header := do
  if index == 0 then throw "HPACK index zero"
  if index <= staticTable.size then
    let some header := staticTable[index - 1]? | throw "invalid static index"
    return header
  let some header := context.table[index - staticTable.size - 1]? | throw "invalid dynamic index"
  return header

private def maxInteger : Nat := 4294967295

/-- Decode an HPACK prefix integer at `offset`; returns the value and next offset. -/
def decodeInteger (input : ByteArray) (offset prefixBits : Nat) : Except String (Nat × Nat) := do
  if prefixBits == 0 || prefixBits > 8 then throw "invalid integer prefix"
  if offset >= input.size then throw "truncated integer"
  let mask := 2 ^ prefixBits - 1
  let first := input[offset]!.toNat % (mask + 1)
  if first < mask then return (first, offset + 1)
  let mut number := mask
  let mut shift := 0
  let mut position := offset + 1
  for _ in [:5] do
    if position >= input.size then throw "truncated integer"
    let byte := input[position]!.toNat
    position := position + 1
    number := number + (byte % 128) * 2 ^ shift
    if number > maxInteger then throw "HPACK integer exceeds limit"
    if byte < 128 then return (number, position)
    shift := shift + 7
  throw "HPACK integer too long"

/-- Encode an integer with prepopulated high-bit representation flags. -/
def encodeInteger (number prefixBits flags : Nat) : Except String ByteArray := do
  if prefixBits == 0 || prefixBits > 8 || number > maxInteger then throw "invalid HPACK integer"
  let base := 2 ^ prefixBits
  if flags >= 256 || flags % base != 0 then throw "invalid integer flags"
  let mask := base - 1
  if number < mask then return ByteArray.empty.push (UInt8.ofNat (flags + number))
  let mut result := ByteArray.empty.push (UInt8.ofNat (flags + mask))
  let mut rest := number - mask
  for _ in [:5] do
    if rest < 128 then return result.push (UInt8.ofNat rest)
    result := result.push (UInt8.ofNat (rest % 128 + 128))
    rest := rest / 128
  throw "HPACK integer too long"

private def decodeString (context : Context) (input : ByteArray) (offset : Nat) : Except String (ByteArray × Nat) := do
  if offset >= input.size then throw "truncated string"
  let compressed := input[offset]!.toNat >= 128
  let (length, start) ← decodeInteger input offset 7
  if length > input.size - start then throw "truncated string bytes"
  let stop := start + length
  let encoded := input.extract start stop
  let value ← if compressed then huffmanDecode encoded context.limits.maxStringBytes else do
    if length > context.limits.maxStringBytes then throw "string exceeds limit"
    pure encoded
  return (value, stop)

private def encodeString (value : ByteArray) : Except String ByteArray := do
  let compressed := huffmanEncode value
  if compressed.size < value.size then
    return (← encodeInteger compressed.size 7 128).append compressed
  return (← encodeInteger value.size 7 0).append value

/-- Decode one complete header block, returning the updated directional state.
    On failure no state is returned and the HTTP/2 connection must fail. -/
def decode (context : Context) (input : ByteArray) : Except String (Context × Array Header) := do
  if input.size > context.limits.maxEncodedBytes then throw "HPACK block exceeds limit"
  let mut context := context
  let mut position := 0
  let mut headers : Array Header := #[]
  let mut listBytes := 0
  let mut sawHeader := false
  let mut updates := 0
  for _ in [:input.size] do
    if position < input.size then
      let first := input[position]!.toNat
      if first >= 128 then
        if context.requireUpdate then throw "required HPACK table update missing"
        let (index, next) ← decodeInteger input position 7
        let header ← lookup context index
        if header.name.size > context.limits.maxStringBytes || header.value.size > context.limits.maxStringBytes then
          throw "HPACK field exceeds limit"
        listBytes := listBytes + entrySize header
        if headers.size >= context.limits.maxHeaderFields || listBytes > context.limits.maxHeaderListBytes then
          throw "HPACK header list exceeds limit"
        headers := headers.push header
        sawHeader := true
        position := next
      else if first >= 32 && first < 64 then
        if sawHeader then throw "HPACK table update after header"
        let (size, next) ← decodeInteger input position 5
        if size > context.maximum then throw "HPACK table update exceeds maximum"
        if let some required := context.requiredMinimum then
          if size > required then throw "HPACK table update misses required minimum"
        updates := updates + 1
        if updates > 2 then throw "invalid HPACK table updates"
        context := evict { context with capacity := size, requireUpdate := false, requiredMinimum := none }
        position := next
      else
        if context.requireUpdate then throw "required HPACK table update missing"
        let indexing := first >= 64
        let sensitive := first >= 16 && first < 32
        let prefixSize := if indexing then 6 else 4
        let (nameIndex, next) ← decodeInteger input position prefixSize
        position := next
        let name ← if nameIndex == 0 then do
          let (name, next) ← decodeString context input position
          position := next
          pure name
        else
          pure (← lookup context nameIndex).name
        if name.size > context.limits.maxStringBytes then throw "HPACK field exceeds limit"
        let (value, next) ← decodeString context input position
        position := next
        let header : Header := { name := name, value := value, sensitive := sensitive }
        listBytes := listBytes + entrySize header
        if headers.size >= context.limits.maxHeaderFields || listBytes > context.limits.maxHeaderListBytes then
          throw "HPACK header list exceeds limit"
        headers := headers.push header
        sawHeader := true
        if indexing then context := insert context header
  if position != input.size then throw "invalid HPACK block"
  if context.requireUpdate then throw "required HPACK table update missing"
  return (context, headers)

private def findExact (context : Context) (header : Header) : Option Nat := Id.run do
  for i in [:staticTable.size] do
    let entry := staticTable[i]!
    if entry.name == header.name && entry.value == header.value then return some (i + 1)
  for i in [:context.table.size] do
    let entry := context.table[i]!
    if entry.name == header.name && entry.value == header.value then return some (i + staticTable.size + 1)
  return none

private def findName (context : Context) (name : ByteArray) : Option Nat := Id.run do
  for i in [:staticTable.size] do
    if staticTable[i]!.name == name then return some (i + 1)
  for i in [:context.table.size] do
    if context.table[i]!.name == name then return some (i + staticTable.size + 1)
  return none

/-- Encode one complete header block. Sensitive fields are never indexed.
    Non-sensitive fields are indexed when they fit the dynamic table. -/
def encode (context : Context) (headers : Array Header) : Except String (Context × ByteArray) := do
  if headers.size > context.limits.maxHeaderFields then throw "HPACK header list exceeds limit"
  let mut total := 0
  for header in headers do
    if header.name.size > context.limits.maxStringBytes || header.value.size > context.limits.maxStringBytes then
      throw "HPACK field exceeds limit"
    total := total + entrySize header
    if total > context.limits.maxHeaderListBytes then throw "HPACK header list exceeds limit"
  let mut context := context
  if context.capacity > context.maximum then
    context ← context.setCapacity context.maximum
  let mut output := ByteArray.empty
  if let some low := context.pendingMin then
    output := output.append (← encodeInteger low 5 32)
    if let some final := context.pendingFinal then
      if final != low then output := output.append (← encodeInteger final 5 32)
    context := { context with pendingMin := none, pendingFinal := none, requireUpdate := false, requiredMinimum := none }
  for header in headers do
    let exact := if header.sensitive then none else findExact context header
    if let some index := exact then
      output := output.append (← encodeInteger index 7 128)
    else
      let indexing := !header.sensitive && entrySize header <= context.capacity
      let prefixSize := if indexing then 6 else 4
      let flags := if indexing then 64 else if header.sensitive then 16 else 0
      let nameIndex := (findName context header.name).getD 0
      output := output.append (← encodeInteger nameIndex prefixSize flags)
      if nameIndex == 0 then output := output.append (← encodeString header.name)
      output := output.append (← encodeString header.value)
      if indexing then context := insert context header
    if output.size > context.limits.maxEncodedBytes then throw "HPACK block exceeds limit"
  if output.size > context.limits.maxEncodedBytes then throw "HPACK block exceeds limit"
  return (context, output)

end LeanNet.HTTP2.HPACK
