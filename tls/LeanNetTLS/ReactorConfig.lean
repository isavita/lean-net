namespace LeanNetTLS.Reactor

/-- Each virtual host has its own certificate and resumption namespace. -/
structure HostConfig where
  name : String
  certificateChain : String
  privateKey : String
  /-- DER OCSP response stapled for this host's certificate. -/
  ocspResponse : Option String := none
  deriving Repr

/-- Reload reads the configured paths on one dedicated native loader. Zero
    disables periodic checks but permits explicit `Bundle.requestReload`. -/
structure ReloadConfig where
  intervalMs : UInt64 := 1000
  deriving Repr

/-- TLS work runs on dedicated native threads, with immutable context snapshots,
    bounded per-session queues and absolute deadlines. -/
structure Config where
  certificateChain : String
  privateKey : String
  hosts : Array HostConfig := #[]
  queueCapacity : UInt32 := 4
  handshakeTimeoutMs : UInt64 := 10000
  shutdownTimeoutMs : UInt64 := 2000
  tickets : Bool := true
  reload : Option ReloadConfig := none
  /-- DER OCSP response for the default certificate. It must be a successful,
      currently valid GOOD response for that leaf; reloads re-read it, so an
      external refresher only needs to replace the file and send SIGHUP. -/
  ocspResponse : Option String := none
  /-- PEM CA bundle for client certificate verification (mTLS). -/
  clientCA : Option String := none
  /-- Reject handshakes without a client certificate (requires `clientCA`). -/
  requireClientCert : Bool := false
  deriving Repr

/-- Scalar-only native ABI. `lastError` encodes zero or negative errno. -/
structure RawReloadStats where
  generation : UInt64
  attempts : UInt64
  publications : UInt64
  failures : UInt64
  lastError : UInt64
  liveVersions : UInt64
  loaderThreads : UInt64
  requested : UInt64
  completed : UInt64
  deriving Repr

structure ReloadStatus where
  generation : UInt64
  attempts : UInt64
  publications : UInt64
  failures : UInt64
  lastError : Int
  liveVersions : UInt64
  loaderThreads : UInt64
  requested : UInt64
  completed : UInt64
  deriving Repr

/-- Atomic diagnostics read without invoking OpenSSL on the loop. -/
structure Stats where
  sslCalls : UInt64
  ownerViolations : UInt64
  activeThreads : UInt64
  deriving Repr

end LeanNetTLS.Reactor
