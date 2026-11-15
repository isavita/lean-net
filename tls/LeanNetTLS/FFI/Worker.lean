import LeanNet.Reactor.Basic
import LeanNetTLS.ReactorConfig

namespace LeanNetTLS.FFI.Worker

@[extern "lean_tlsw_bundle_new"] opaque bundleNew (cert key : @& String)
  (names certs keys : @& Array String) (tickets : UInt8) (ocsp : @& Array String)
  (clientCA : @& String) (verifyMode : UInt8) : IO (UInt64 × String)
@[extern "lean_tlsw_sni"] opaque sni (handle session : UInt64) : IO ByteArray
@[extern "lean_tlsw_peer"] opaque peer (handle session : UInt64) : IO (UInt8 × String × Array String)
@[extern "lean_tlsw_handshake_stats"] opaque handshakeStats : IO (Array UInt64)
@[extern "lean_tlsw_bundle_free"] opaque bundleFree (handle : UInt64) : IO UInt64
@[extern "lean_tlsw_bundle_reload_start"] opaque bundleReloadStart (handle intervalMs : UInt64) : IO UInt64
@[extern "lean_tlsw_bundle_reload_request"] opaque bundleReloadRequest (handle : UInt64) : IO UInt64
@[extern "lean_tlsw_bundle_reload_stats"] opaque bundleReloadStats (handle : UInt64) : IO LeanNetTLS.Reactor.RawReloadStats
@[extern "lean_tlsw_worker_new"] opaque workerNew (bundle : UInt64)
  (reactor : @& LeanNet.Reactor.Reactor) (maxSessions queueCapacity : UInt32)
  (handshakeMs shutdownMs : UInt64) : IO (UInt64 × String)
@[extern "lean_tlsw_worker_free"] opaque workerFree (handle : UInt64) : IO UInt64
@[extern "lean_tlsw_attach"] opaque attach (handle : UInt64)
  (wire : @& LeanNet.Reactor.Wire .tls_handshaking) : IO UInt64
@[extern "lean_tlsw_feed"] opaque feed (handle session : UInt64)
  (buffer : @& LeanNet.Reactor.Buffer) (offset length : UInt32) : IO UInt64
@[extern "lean_tlsw_write"] opaque write (handle session : UInt64)
  (buffer : @& LeanNet.Reactor.Buffer) (offset length : UInt32) (operation : UInt64) : IO UInt64
@[extern "lean_tlsw_write_file"] opaque writeFile (handle session owner file offset : UInt64)
  (length : UInt32) (operation : UInt64) : IO UInt64
@[extern "lean_tlsw_resume_file"] opaque resumeFile (handle session : UInt64) : IO UInt64
@[extern "lean_tlsw_release_plain"] opaque releasePlain (handle session : UInt64) : IO UInt64
@[extern "lean_tlsw_peer_eof"] opaque peerEOF (handle session : UInt64) : IO UInt64
@[extern "lean_tlsw_shutdown"] opaque shutdown (handle session : UInt64) : IO UInt64
@[extern "lean_tlsw_abort"] opaque abort (handle session : UInt64) : IO UInt64
@[extern "lean_tlsw_native_closed"] opaque nativeClosed (handle session : UInt64) : IO UInt64
@[extern "lean_tlsw_stats"] opaque stats (handle : UInt64) : IO LeanNetTLS.Reactor.Stats
@[extern "lean_tlsw_read_enabled"] opaque readEnabled (handle session : UInt64) (enabled : UInt8) : IO UInt64
@[extern "lean_tlsw_pump"] opaque pump (handle : UInt64) : IO UInt64
@[extern "lean_tlsw_event"] opaque event (handle : UInt64) (index : UInt32) : IO LeanNet.FFI.Reactor.NativeEvent
@[extern "lean_tlsw_event_buffer"] opaque eventBuffer (handle : UInt64) (index : UInt32) : IO LeanNet.Reactor.Buffer
@[extern "lean_tlsw_on_written"] opaque onWritten (handle operation count : UInt64) : IO UInt64
@[extern "lean_tlsw_has_work"] opaque hasWork (handle : UInt64) : IO UInt64

end LeanNetTLS.FFI.Worker
