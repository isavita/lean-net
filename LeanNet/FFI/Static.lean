namespace LeanNet.FFI.Static

@[extern "lean_sc_builder_new"]
opaque create (root : @& String) (maxFileBytes maxPackBytes : UInt64)
  (maxEntries : UInt32) (minCompressBytes : UInt64)
  (gzipLevel brotliQuality : UInt32) : IO UInt64
@[extern "lean_sc_builder_prepare"] opaque prepare (handle : UInt64) : IO UInt64
@[extern "lean_sc_builder_begin_path"]
opaque beginPath (handle : UInt64) (path : @& ByteArray) (compression : UInt32) : IO UInt64
@[extern "lean_sc_builder_begin_bytes"]
opaque beginBytes (handle : UInt64) (bytes : @& ByteArray) (compression : UInt32) : IO UInt64
@[extern "lean_sc_builder_check_directory"]
opaque checkDirectory (handle : UInt64) (path : @& ByteArray) : IO UInt64
@[extern "lean_sc_builder_read_directory"]
opaque readDirectory (handle : UInt64) (path : @& ByteArray) (limit : UInt32) :
  IO (UInt64 × Array (ByteArray × UInt32))
@[extern "lean_sc_builder_step"] opaque step (handle : UInt64) (budget : UInt32) : IO UInt64
@[extern "lean_sc_builder_field"]
opaque field (handle : UInt64) (entry field : UInt32) : IO UInt64
@[extern "lean_sc_builder_finish"] opaque finish (handle budget : UInt64) : IO UInt64
@[extern "lean_sc_builder_free"] opaque free (handle : UInt64) : IO UInt64

@[extern "shim_file_source_retain"] opaque sourceRetain (handle : UInt64) : IO UInt64
@[extern "shim_file_source_release"] opaque sourceRelease (handle : UInt64) : IO UInt64
@[extern "shim_file_source_size"] opaque sourceSize (handle : UInt64) : IO UInt64
@[extern "shim_file_prepare_residency"] opaque prepareResidency (budget : UInt64) : IO UInt64

end LeanNet.FFI.Static
