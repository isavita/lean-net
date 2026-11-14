namespace LeanNetTLS.Reactor

/-- Each virtual host has its own certificate and resumption namespace. -/
structure HostConfig where
  name : String
  certificateChain : String
  privateKey : String
  deriving Repr

/-- The bundle is sealed before listeners start. TLS work runs on dedicated
    native threads, with bounded per-session queues and absolute deadlines. -/
structure Config where
  certificateChain : String
  privateKey : String
  hosts : Array HostConfig := #[]
  queueCapacity : UInt32 := 4
  handshakeTimeoutMs : UInt64 := 10000
  shutdownTimeoutMs : UInt64 := 2000
  tickets : Bool := true
  deriving Repr

/-- Atomic diagnostics read without invoking OpenSSL on the loop. -/
structure Stats where
  sslCalls : UInt64
  ownerViolations : UInt64
  activeThreads : UInt64
  deriving Repr

end LeanNetTLS.Reactor
