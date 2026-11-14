/*
 * socket_shim.h — Lean-facing FFI surface for lean-net's TCP shim.
 *
 * All functions return `lean_object *` encoding an `IO` result.
 * Lean does not read this header; it exists as a single source of truth
 * for the contract, and so C test harnesses can link against it if needed.
 *
 * Contract:
 *   - Failures are encoded as negative Int64 (bitcast from UInt64):
 *       -errno                     POSIX failure
 *       -(100000 + EAI_code)       getaddrinfo failure (listen only)
 *   - No syscall is retried on EINTR inside C.  Retry policy belongs to Lean.
 *   - close() is not retryable on Linux: the fd is released even on error.
 *     -EBADF from shim_close indicates a library bug (double-close / corrupt fd).
 *
 * Ownership:
 *   - b_lean_obj_arg arguments are borrowed; C must not store or consume them.
 *   - ByteArray results are freshly allocated; the caller owns them.
 *   - shim_tcp_recv returns exactly the bytes read, never padded.
 */

#ifndef LEAN_NET_SOCKET_SHIM_H
#define LEAN_NET_SOCKET_SHIM_H

#include <lean/lean.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* listen(host, port) -> IO UInt64
 *   >= 0                  file descriptor
 *   -(100000 + EAI_*)     getaddrinfo failure
 *   -errno                any POSIX failure (bind, listen, socket, setsockopt) */
lean_object *shim_tcp_listen(b_lean_obj_arg host_lean, uint16_t port);

/* accept(listen_fd) -> IO UInt64
 *   >= 0                  accepted fd (SO_NOSIGPIPE + TCP_NODELAY applied)
 *   -errno                POSIX failure (incl. -EAGAIN if listener is non-blocking,
 *                         -EINTR if interrupted; caller decides retry) */
lean_object *shim_tcp_accept(int64_t listen_fd);

/* recv(fd, max_len) -> IO (UInt64 × ByteArray)
 *   count > 0             ByteArray holds exactly `count` bytes
 *   count = 0             EOF (orderly peer close); ByteArray empty
 *   count < 0             -errno; ByteArray empty */
lean_object *shim_tcp_recv(int64_t fd, size_t max_len);

/* send(fd, buf, len) -> IO UInt64
 *   >= 0                  bytes written (may be < len; caller must loop)
 *   -errno                POSIX failure (incl. -EPIPE if peer closed; SIGPIPE suppressed) */
lean_object *shim_tcp_send(int64_t fd, b_lean_obj_arg buf, size_t len);

/* close(fd) -> IO UInt64
 *   0                     success
 *   -errno                failure; fd is gone either way.  Never retry. */
lean_object *shim_close(int64_t fd);

/* errno_name(errno) -> IO String
 * Human-readable strerror() message, for logging. */
lean_object *shim_errno_name(int32_t errno_);

#ifdef __cplusplus
}
#endif

#endif /* LEAN_NET_SOCKET_SHIM_H */
