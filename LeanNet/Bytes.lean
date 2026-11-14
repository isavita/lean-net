namespace LeanNet

/-- An immutable range retaining its underlying wire ByteArray. Constructors
    check bounds; making or trimming a view does not copy its bytes. -/
structure ByteSlice where
  private mk ::
  bytes : ByteArray
  offset : Nat
  length : Nat

def ByteSlice.full (bytes : ByteArray) : ByteSlice := ⟨bytes, 0, bytes.size⟩

def ByteSlice.ofRange? (bytes : ByteArray) (offset length : Nat) : Option ByteSlice :=
  if offset <= bytes.size && length <= bytes.size - offset then some ⟨bytes, offset, length⟩
  else none

def ByteSlice.isEmpty (slice : ByteSlice) : Bool := slice.length == 0

def ByteSlice.drop (slice : ByteSlice) (count : Nat) : ByteSlice :=
  let count := min count slice.length
  ⟨slice.bytes, slice.offset + count, slice.length - count⟩

def ByteSlice.take (slice : ByteSlice) (count : Nat) : ByteSlice :=
  ⟨slice.bytes, slice.offset, min count slice.length⟩

/-- Explicitly materialize a view when an application needs an owned copy. -/
def ByteSlice.copy (slice : ByteSlice) : ByteArray :=
  slice.bytes.extract slice.offset (slice.offset + slice.length)

end LeanNet
