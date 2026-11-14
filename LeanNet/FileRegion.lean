namespace LeanNet

/-- A borrowed immutable file range. The transport owns the file, mapping and
    lifetime; pure protocol machines carry only its owner-scoped identity.
    Offsets and lengths describe the selected representation's actual bytes. -/
structure FileRegion where
  owner : UInt64
  token : UInt64
  offset : UInt64 := 0
  length : Nat
  deriving BEq, Repr, Inhabited

/-- Native file APIs use signed 64-bit offsets. Empty ranges are valid and
    complete as empty operations, rather than meaning "send the whole file". -/
def FileRegion.valid (region : FileRegion) : Bool :=
  region.owner != 0 && region.token != 0 &&
    region.offset.toNat + region.length <= 9223372036854775807

def FileRegion.take (region : FileRegion) (count : Nat) : FileRegion :=
  { region with length := min count region.length }

def FileRegion.drop (region : FileRegion) (count : Nat) : FileRegion :=
  let used := min count region.length
  { region with offset := UInt64.ofNat (region.offset.toNat + used),
                length := region.length - used }

/-- Owned protocol bytes and borrowed immutable file ranges share one ordered
    wire sequence. The driver is responsible for completing each range before
    submitting later parts of that sequence. -/
inductive WirePart where
  | bytes (data : ByteArray)
  | file (region : FileRegion)

def WirePart.length : WirePart → Nat
  | .bytes data => data.size
  | .file region => region.length

end LeanNet
