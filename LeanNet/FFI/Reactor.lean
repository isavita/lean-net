namespace LeanNet.FFI.Reactor

/-- Scalar completion record; its layout is shared with reactor_ffi.h. -/
structure NativeEvent where
  connection : UInt64
  operation : UInt64
  buffer : UInt64
  result : UInt64
  kind : UInt32
  flags : UInt32
  offset : UInt32
  length : UInt32

@[extern "shim_reactor_new"]
opaque create (connections events writes buffers4k buffers16k buffers64k tickMs : UInt32) : IO UInt64
@[extern "shim_reactor_free"] opaque free (handle : UInt64) : IO UInt64
@[extern "shim_reactor_set_accept_targets"]
opaque setAcceptTargets (handle : UInt64) (workers : @& Array UInt64) (queueCapacity : UInt32) : IO UInt64
@[extern "shim_reactor_socket_new"] opaque socketNew (handle : UInt64) : IO UInt64
@[extern "shim_reactor_bind"] opaque bind (handle token : UInt64) (host : @& String) (port : UInt16) (reusePort : UInt8) : IO UInt64
@[extern "shim_reactor_start_listening"] opaque startListening (handle token : UInt64) (backlog : UInt32) : IO UInt64
@[extern "shim_reactor_listen"]
opaque listen (handle : UInt64) (host : @& String) (port : UInt16) (reusePort : UInt8) : IO UInt64
@[extern "shim_reactor_step"] opaque step (handle : UInt64) (timeout : Int32) : IO UInt64
@[extern "shim_reactor_event"] opaque event (handle : UInt64) (index : UInt32) : IO NativeEvent
@[extern "shim_reactor_write"]
opaque write (handle connection buffer : UInt64) (offset length : UInt32) (operation : UInt64) : IO UInt64
@[extern "shim_reactor_read_enabled"]
opaque readEnabled (handle connection : UInt64) (enabled : UInt8) : IO UInt64
@[extern "shim_reactor_connection_live"]
opaque connectionLive (handle connection : UInt64) : IO UInt64
@[extern "shim_reactor_acquire"] opaque acquire (handle : UInt64) (minimum : UInt32) : IO UInt64
@[extern "shim_reactor_buffer"] opaque buffer (handle token : UInt64) : IO (UInt64 × ByteArray)
@[extern "shim_reactor_release"] opaque release (handle token : UInt64) : IO UInt64
@[extern "shim_reactor_copy"] opaque copy (handle token : UInt64) (bytes : @& ByteArray) : IO UInt64
@[extern "shim_reactor_copy_slice"]
opaque copySlice (handle token : UInt64) (bytes : @& ByteArray) (offset length : UInt32) : IO UInt64
@[extern "shim_reactor_arm_timer"]
opaque armTimer (handle connection : UInt64) (kind : UInt32) (deadline : UInt64) : IO UInt64
@[extern "shim_reactor_cancel_timer"]
opaque cancelTimer (handle connection : UInt64) (kind : UInt32) : IO UInt64
@[extern "shim_reactor_close"] opaque close (handle connection : UInt64) : IO UInt64
@[extern "shim_reactor_close_after_writes"] opaque closeAfterWrites (handle connection : UInt64) : IO UInt64
@[extern "shim_reactor_wake"] opaque wake (handle : UInt64) : IO UInt64
@[extern "shim_reactor_now"] opaque now : IO UInt64

@[extern "shim_reactor_group_new"] opaque groupNew (handles : @& Array UInt64) : IO UInt64
@[extern "shim_reactor_group_install"] opaque groupInstall (handle : UInt64) : IO UInt64
@[extern "shim_reactor_group_stop"] opaque groupStop (handle : UInt64) : IO UInt64
@[extern "shim_reactor_group_stopping"] opaque groupStopping (handle : UInt64) : IO UInt64
@[extern "shim_reactor_group_wake_error"] opaque groupWakeError (handle : UInt64) : IO UInt64
@[extern "shim_reactor_group_uninstall"] opaque groupUninstall (handle : UInt64) : IO UInt64
@[extern "shim_reactor_group_free"] opaque groupFree (handle : UInt64) : IO UInt64
@[extern "shim_reactor_cpu_count"] opaque cpuCount : IO UInt64

@[extern "shim_reactor_endpoint_acquire"] opaque endpointAcquire (port : UInt16) : IO UInt64
@[extern "shim_reactor_endpoint_release"] opaque endpointRelease (handle : UInt64) : IO UInt64


@[extern "shim_reactor_transport_claim"] opaque transportClaim (handle connection : UInt64) : IO UInt64
@[extern "shim_reactor_transport_mode"] opaque transportMode (handle connection capability : UInt64) : IO UInt64
@[extern "shim_reactor_transport_ready"] opaque transportReady (handle connection capability : UInt64) : IO UInt64
@[extern "shim_reactor_transport_write"]
opaque transportWrite (handle connection capability buffer : UInt64) (offset length : UInt32) (operation : UInt64) : IO UInt64
@[extern "shim_reactor_transport_read_enabled"]
opaque transportReadEnabled (handle connection capability : UInt64) (enabled : UInt8) : IO UInt64
@[extern "shim_reactor_transport_arm_timer"]
opaque transportArmTimer (handle connection capability : UInt64) (kind : UInt32) (deadline : UInt64) : IO UInt64
@[extern "shim_reactor_transport_cancel_timer"]
opaque transportCancelTimer (handle connection capability : UInt64) (kind : UInt32) : IO UInt64
@[extern "shim_reactor_transport_drain"] opaque transportDrain (handle connection capability : UInt64) : IO UInt64
@[extern "shim_reactor_transport_abort"] opaque transportAbort (handle connection capability : UInt64) : IO UInt64
@[extern "shim_reactor_waker_acquire"] opaque wakerAcquire (handle : UInt64) : IO UInt64
@[extern "shim_reactor_waker_wake"] opaque wakerWake (handle : UInt64) : IO UInt64
@[extern "shim_reactor_waker_release"] opaque wakerRelease (handle : UInt64) : IO UInt64

end LeanNet.FFI.Reactor
