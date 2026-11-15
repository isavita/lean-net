import LeanNet.FFI.Errno

namespace LeanNet.Gateway.Resolve

/-- DNS is performed off the reactor owner loop. Numeric literals return
    immediately. The second family is used when the preferred one is absent. -/
inductive Preference where
  | preferIPv4
  | preferIPv6
  deriving BEq, Repr, Inhabited

inductive Error where
  | invalidHost
  | lookupFailed (code : Int)
  deriving BEq, Repr

namespace FFI
@[extern "shim_gateway_resolve"]
opaque resolveRaw (host : @& String) (preferIPv6 : UInt8) : IO (UInt64 × ByteArray)
end FFI

/-- Resolve a configuration-owned DNS A-label, IPv4 literal, or IPv6 literal
    to one network-order IP. Call from an `IO.asTask` worker and cache the
    result before entering the reactor loop; DNS lookup can block. Host must
    contain no port, URL scheme, path, bracket, zone, or embedded NUL. -/
def resolve (host : String) (preference : Preference := .preferIPv4) :
    IO (Except Error ByteArray) := do
  let (raw, address) ← FFI.resolveRaw host (if preference == .preferIPv6 then 1 else 0)
  let status := LeanNet.Errno.decode raw
  if status == 1 then return .error .invalidHost
  if status < 0 then return .error (.lookupFailed status)
  if status != 0 || (address.size != 4 && address.size != 16) then
    return .error (.lookupFailed (-1))
  return .ok address

end LeanNet.Gateway.Resolve
