namespace LeanNetTLS.FFI

/-- All handles are internal opaque pointers encoded in UInt64. Negative first
    results are -errno; messages carry OpenSSL's diagnostic when available. -/
@[extern "lean_tls_context_new"] opaque contextNew (cert key : @& String) : IO (UInt64 × String)
@[extern "lean_tls_context_free"] opaque contextFree (context : UInt64) : IO UInt64
/-- Stage 0 is success, 1 is a setup failure, 2 is a peer failure confirmed by SO_ERROR. -/
@[extern "lean_tls_session_new"] opaque sessionNew (context : UInt64) (fd : Int64) : IO ((UInt64 × UInt8) × String)
@[extern "lean_tls_session_free"] opaque sessionFree (session : UInt64) : IO UInt64

/-- Status is 0 for completion/failure, 1 WANT_READ, 2 WANT_WRITE, 3 clean EOF. -/
@[extern "lean_tls_handshake"] opaque handshake (session : UInt64) : IO ((UInt64 × UInt8) × String)
@[extern "lean_tls_read"] opaque read (session : UInt64) (size : USize) : IO ((UInt64 × UInt8) × (ByteArray × String))
@[extern "lean_tls_write"] opaque write (session : UInt64) (data : @& ByteArray)
  (offset length : USize) : IO ((UInt64 × UInt8) × String)
@[extern "lean_tls_alpn"] opaque alpn (session : UInt64) : IO ((UInt64 × UInt8) × (ByteArray × String))
@[extern "lean_tls_shutdown"] opaque shutdown (session : UInt64) : IO ((UInt64 × UInt8) × String)
@[extern "lean_tls_pending"] opaque pending (session : UInt64) : IO UInt64

end LeanNetTLS.FFI
