import LeanNet.HTTP1.Response

namespace LeanNet.HTTP1

/-- Compatibility application callback; advanced handlers return a Reply. -/
abbrev Router := Request → IO Response

/-- Server-wide resource and time bounds. Compatibility serving uses one
    worker, preserving the original admission limit and callback ownership. -/
structure ServerConfig where
  maxClients : Nat := 32
  maxResponseBytes : Nat := 8 * 1024 * 1024
  maxResponseHeaderBytes : Nat := 65536
  maxResponseHeaders : Nat := 100
  idleTimeoutMs : Nat := 30000
  requestTimeoutMs : Nat := 30000
  writeTimeoutMs : Nat := 30000
  deriving Repr

end LeanNet.HTTP1
