import LeanNet.HTTP1.Protocol
import LeanNet.FileRegion

namespace LeanNet.HTTP

/-- Metadata for one ordered wire ticket. Payload ranges are offsets into the
    concatenation of parts; framing bytes, informational fields and trailers
    never count as application payload. The transport credits only actual ACKs. -/
structure ObservedOutput where
  requestId : Nat
  parts : Array WirePart
  payloadRanges : Array (Nat × Nat) := #[]
  finalResponse : Bool := false
  status : Nat := 0
  head : Option HTTP1.RequestHead := none
  startedAt : Nat := 0

namespace ObservedOutput

def wireBytes (output : ObservedOutput) : Nat :=
  output.parts.foldl (fun size part => size + part.length) 0

def payloadBytes (output : ObservedOutput) : Nat :=
  output.payloadRanges.foldl (fun size range => size + range.2) 0

/-- Ranges are ordered and disjoint, and remain inside the immutable ticket. -/
def valid (output : ObservedOutput) : Bool := Id.run do
  let mut finish := 0
  for (start, length) in output.payloadRanges do
    if length == 0 || start < finish || start + length > output.wireBytes then return false
    finish := start + length
  return true

/-- Credit the payload intersection of an acknowledged physical byte window. -/
def payloadOverlap (output : ObservedOutput) (start length : Nat) : Nat :=
  output.payloadRanges.foldl (fun size range =>
    size + (min (start + length) (range.1 + range.2) - max start range.1)) 0

end ObservedOutput

inductive ResponseAbortReason where
  | cancelled | error | timeout
  deriving BEq, Repr, Inhabited

end LeanNet.HTTP
