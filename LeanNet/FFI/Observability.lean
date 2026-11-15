namespace LeanNet.FFI.Observability

@[extern "lean_ob_new"]
opaque create (workers capacity : UInt32) (path helper : @& String)
  (fileBytes : UInt64) (files pollMs : UInt32) : IO UInt64
@[extern "lean_ob_emit"]
opaque emit (handle : UInt64) (worker : UInt32) (timestampMs durationUs bytesSent : UInt64)
  (status protocol outcome : UInt32) (method target remote trace : @& ByteArray) : IO UInt64
@[extern "lean_ob_publish"]
opaque publish (handle : UInt64) (worker : UInt32) (fields : @& Array UInt64) : IO UInt64
@[extern "lean_ob_snapshot"]
opaque snapshot (handle : UInt64) : IO (UInt64 × Array UInt64)
@[extern "lean_ob_ready"] opaque ready (handle : UInt64) : IO UInt64
@[extern "lean_ob_check"] opaque check (handle : UInt64) : IO UInt64
@[extern "lean_ob_last_error"] opaque lastError (handle : UInt64) : IO UInt64
@[extern "lean_ob_stop"] opaque stop (handle timeoutMs : UInt64) : IO UInt64
@[extern "lean_ob_join"] opaque join (handle : UInt64) : IO UInt64
@[extern "lean_ob_free"] opaque free (handle : UInt64) : IO UInt64

end LeanNet.FFI.Observability
