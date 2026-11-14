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
