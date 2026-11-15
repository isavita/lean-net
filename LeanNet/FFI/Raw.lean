namespace LeanNet.FFI

/-- Raw POSIX wrappers.  Do not use directly from application code;
    go through `LeanNet.Socket` / `LeanNet.TCP`, which interpret the
    integer encoding and surface typed outcomes. -/

@[extern "shim_tcp_listen"]
opaque rawTcpListen (host : @& String) (port : UInt16) : IO UInt64
-- Positive -> fd; negative (as Int64) -> -errno, or -(100000 + EAI_*) for
-- getaddrinfo failures.

@[extern "shim_tcp_accept"]
opaque rawTcpAccept (listenFd : Int64) : IO UInt64

/-- fd or -errno paired with stage: 0 success, 1 accept, 2 option setup,
    3 cleanup close, 4 option setup with a peer error confirmed by SO_ERROR. -/
@[extern "shim_tcp_accept_staged"]
opaque acceptStaged (listenFd : Int64) : IO (UInt64 × UInt8)

@[extern "shim_tcp_recv"]
opaque rawTcpRecv (fd : Int64) (maxLen : USize) : IO (UInt64 × ByteArray)
-- Pair.1 as Int64: >0 count, =0 EOF, <0 -errno.  Pair.2 is empty unless count > 0.

@[extern "shim_tcp_send"]
opaque rawTcpSend (fd : Int64) (buf : @& ByteArray) (len : USize) : IO UInt64
-- As Int64: >=0 bytes sent (may be < len), <0 -errno.

@[extern "shim_close"]
opaque rawClose (fd : Int64) : IO UInt64
-- As Int64: 0 ok, <0 -errno.  Do NOT retry -EBADF; it's a library bug.

@[extern "shim_errno_name"]
opaque rawErrnoName (errno : Int32) : IO String

end LeanNet.FFI

namespace LeanNet.FFI

@[extern "shim_errno_eintr"] opaque errnoEintr : IO UInt64
@[extern "shim_errno_eagain"] opaque errnoEagain : IO UInt64
@[extern "shim_errno_ewouldblock"] opaque errnoEwouldblock : IO UInt64
@[extern "shim_errno_ebadf"] opaque errnoEbadf : IO UInt64

@[extern "shim_interrupt_begin"] opaque interruptBegin : IO UInt64
@[extern "shim_interrupt_end"] opaque interruptEnd : IO UInt64
@[extern "shim_interrupt_requested"] opaque interruptRequested : IO UInt64
@[extern "shim_interruptible_accept"] opaque interruptibleAccept (fd : Int64) : IO UInt64
@[extern "shim_interruptible_recv"] opaque interruptibleRecv (fd : Int64) (maxLen : USize) : IO (UInt64 × ByteArray)
@[extern "shim_interruptible_send"] opaque interruptibleSend (fd : Int64) (buf : @& ByteArray) (len : USize) : IO UInt64

end LeanNet.FFI

namespace LeanNet.FFI
@[extern "shim_errno_epipe"] opaque errnoEpipe : IO UInt64
@[extern "shim_errno_econnreset"] opaque errnoEconnreset : IO UInt64
@[extern "shim_errno_econnaborted"] opaque errnoEconnaborted : IO UInt64
@[extern "shim_errno_etimedout"] opaque errnoEtimedout : IO UInt64
@[extern "shim_errno_enetreset"] opaque errnoEnetreset : IO UInt64
@[extern "shim_errno_enetdown"] opaque errnoEnetdown : IO UInt64
@[extern "shim_errno_enetunreach"] opaque errnoEnetunreach : IO UInt64
@[extern "shim_errno_ehostunreach"] opaque errnoEhostunreach : IO UInt64
@[extern "shim_errno_econnrefused"] opaque errnoEconnrefused : IO UInt64
@[extern "shim_errno_enotconn"] opaque errnoEnotconn : IO UInt64
-- Zero means the platform does not define the optional error code.
@[extern "shim_errno_enonet"] opaque errnoEnonet : IO UInt64
@[extern "shim_errno_eproto"] opaque errnoEproto : IO UInt64
@[extern "shim_errno_enoprotoopt"] opaque errnoEnoprotoopt : IO UInt64
@[extern "shim_errno_ehostdown"] opaque errnoEhostdown : IO UInt64
@[extern "shim_errno_eopnotsupp"] opaque errnoEopnotsupp : IO UInt64
@[extern "shim_errno_emfile"] opaque errnoEmfile : IO UInt64
@[extern "shim_errno_enfile"] opaque errnoEnfile : IO UInt64
@[extern "shim_errno_enobufs"] opaque errnoEnobufs : IO UInt64
@[extern "shim_errno_enomem"] opaque errnoEnomem : IO UInt64

/-- Toggle O_NONBLOCK on an existing socket; success is zero, failure -errno. -/
@[extern "shim_set_nonblocking"] opaque setNonblocking (fd : Int64) (enabled : UInt8) : IO UInt64

/-- Entries use five bytes each: a little-endian UInt32 fd, then an interest
    mask (read=1, write=2). On success one result mask per fd is returned
    (read=1, write=2, hangup=4, error=8, invalid=16). On error the count is
    -errno and the result is empty. A scoped SIGINT handler is required. -/
@[extern "shim_poll"] opaque poll (entries : @& ByteArray) (timeoutMs : Int32) : IO (UInt64 × ByteArray)

/-- Send a bounded slice from a borrowed ByteArray, returning count or -errno. -/
@[extern "shim_tcp_send_offset"] opaque sendOffset (fd : Int64) (bytes : @& ByteArray)
    (offset length : USize) : IO UInt64
end LeanNet.FFI
