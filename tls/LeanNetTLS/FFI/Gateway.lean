namespace LeanNetTLS.FFI.Gateway

@[extern "lean_tg_context_new"] opaque contextNew (caFile : @& String) : IO (UInt64 × String)
@[extern "lean_tg_context_free"] opaque contextFree (handle : UInt64) : IO UInt64
@[extern "lean_tg_session_new"] opaque sessionNew (context : UInt64)
  (verifyName : @& String) : IO (UInt64 × String)
@[extern "lean_tg_session_free"] opaque sessionFree (handle : UInt64) : IO UInt64
@[extern "lean_tg_handshake"] opaque handshake (handle : UInt64) : IO (UInt64 × String)
@[extern "lean_tg_feed"] opaque feed (handle : UInt64) (cipher : @& ByteArray) : IO (UInt64 × String)
@[extern "lean_tg_drain"] opaque drain (handle : UInt64) : IO (UInt64 × (ByteArray × String))
@[extern "lean_tg_read"] opaque read (handle : UInt64) (maximum : UInt32) : IO (UInt64 × (ByteArray × String))
@[extern "lean_tg_write"] opaque write (handle : UInt64) (plain : @& ByteArray) : IO (UInt64 × String)
@[extern "lean_tg_clean"] opaque clean (handle : UInt64) : IO UInt64
@[extern "lean_tg_cipher_pending"] opaque cipherPending (handle : UInt64) : IO UInt64
@[extern "lean_tg_shutdown"] opaque shutdown (handle : UInt64) : IO (UInt64 × String)

end LeanNetTLS.FFI.Gateway
