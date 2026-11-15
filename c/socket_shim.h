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

/* Event-loop accept distinguishes the failing stage while preserving the
 * usual fd-or-negative-errno first component: 0=success, 1=accept syscall,
 * 2=socket-option setup, 3=cleanup close, 4=option setup with a verified
 * pending peer/network error in SO_ERROR. No syscall is retried. */
lean_object *shim_tcp_accept_staged(int64_t listen_fd);

/* recv(fd, max_len) -> IO (UInt64 × ByteArray)
 *   count > 0             ByteArray holds exactly `count` bytes
 *   count = 0             EOF (orderly peer close); ByteArray empty
 *   count < 0             -errno; ByteArray empty (EINVAL when max_len=0) */
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

/* Native errno constants, returned as non-negative IO UInt64 values. */
lean_object *shim_errno_eintr(void);
lean_object *shim_errno_eagain(void);
lean_object *shim_errno_ewouldblock(void);
lean_object *shim_errno_ebadf(void);
lean_object *shim_errno_epipe(void);
lean_object *shim_errno_econnreset(void);
lean_object *shim_errno_econnaborted(void);
lean_object *shim_errno_etimedout(void);
lean_object *shim_errno_enetreset(void);
lean_object *shim_errno_enetdown(void);
lean_object *shim_errno_enetunreach(void);
lean_object *shim_errno_ehostunreach(void);
lean_object *shim_errno_econnrefused(void);
lean_object *shim_errno_enotconn(void);
/* Zero means this optional platform errno constant does not exist. */
lean_object *shim_errno_enonet(void);
lean_object *shim_errno_eproto(void);
lean_object *shim_errno_enoprotoopt(void);
lean_object *shim_errno_ehostdown(void);
lean_object *shim_errno_emfile(void);
lean_object *shim_errno_enfile(void);
lean_object *shim_errno_enobufs(void);
lean_object *shim_errno_enomem(void);
lean_object *shim_errno_eopnotsupp(void);

/* Scoped single-threaded SIGINT wakeup and interruptible blocking I/O.
 * Begin/end return 0 or -errno. Begin must be paired with end in a bracket.
 * Begin rejects an already blocked SIGINT with EINVAL.
 * The I/O functions return the same results as their ordinary counterparts,
 * with -EINTR on SIGINT and potentially -EAGAIN on stale readiness. */
lean_object *shim_interrupt_begin(void);
lean_object *shim_interrupt_end(void);
lean_object *shim_interrupt_requested(void);
lean_object *shim_interruptible_accept(int64_t listen_fd);
lean_object *shim_interruptible_recv(int64_t fd, size_t max_len);
lean_object *shim_interruptible_send(int64_t fd, b_lean_obj_arg buf, size_t len);

/* Event-loop primitives: no operation retries EINTR. Socket descriptors are
 * encoded in poll entries as little-endian uint32 plus an interest byte (bit
 * 0 = read, bit 1 = write). Successful poll returns one result byte per
 * entry (read, write, hangup, error, invalid in bits 0..4), with the count
 * of entries having any result. An active scoped interrupt handler is
 * required; SIGINT wakes poll and returns -EINTR. timeout_ms is -1 or >= 0. */
lean_object *shim_set_nonblocking(int64_t fd, uint8_t enabled);
lean_object *shim_poll(b_lean_obj_arg entries, int32_t timeout_ms);

/* Send a borrowed slice. Reject out-of-bounds offsets or lengths with EINVAL. */
lean_object *shim_tcp_send_offset(int64_t fd, b_lean_obj_arg buf,
                                  size_t offset, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* LEAN_NET_SOCKET_SHIM_H */
