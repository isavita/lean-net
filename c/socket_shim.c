/*
 * socket_shim.c — POSIX TCP shim for lean-net.
 *
 * Contract (uniform across all functions that can fail):
 *   - Success values are non-negative Int64 (fd, byte count, 0 for close).
 *   - Failures are negative: -errno (POSIX).  getaddrinfo failures are
 *     encoded as -(100000 + EAI_code) so they're distinguishable from errno.
 *   - Nothing is retried on EINTR here.  The Lean layer decides policy.
 *   - close() is NOT retryable on Linux: the fd is released even on error.
 *     -EBADF from close indicates a double-close / corrupt-fd bug in the library.
 *
 * Byte order / ownership:
 *   - ByteArray arguments are borrowed (@&).  C must not store or consume them.
 *   - ByteArray results are freshly allocated; the caller owns them.
 *   - Buffers returned to Lean are exactly the number of bytes read,
 *     never padded to the requested max_len.
 */

#define _POSIX_C_SOURCE 200809L

#include <lean/lean.h>

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* --------------------------------------------------------------------- */
/* Helpers                                                               */
/* --------------------------------------------------------------------- */

/* Encode an Int64 (fd / count / close result) as IO UInt64.
 * Lean side bitcasts to Int64 to recover the sign. */
static lean_object *mk_i64_ok(int64_t v) {
    return lean_io_result_mk_ok(lean_box_uint64((uint64_t)v));
}

/* Encode an (Int64, ByteArray) pair as IO (UInt64 × ByteArray). */
static lean_object *mk_count_ba_ok(int64_t count, lean_object *ba) {
    lean_object *pair = lean_alloc_ctor(0, 2, 0);
    lean_ctor_set(pair, 0, lean_box_uint64((uint64_t)count));
    lean_ctor_set(pair, 1, ba);
    return lean_io_result_mk_ok(pair);
}

/* Allocate a fresh empty ByteArray. */
static lean_object *empty_ba(void) {
    return lean_alloc_sarray(1, 0, 0);
}

/* Platform socket send flags: suppress SIGPIPE where supported. */
#ifdef MSG_NOSIGNAL
#  define WS_SEND_FLAGS MSG_NOSIGNAL
#else
#  define WS_SEND_FLAGS 0
#endif

/* Best-effort per-socket SIGPIPE suppression (macOS/BSD). */
static void suppress_sigpipe(int fd) {
#ifdef SO_NOSIGPIPE
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#else
    (void)fd;
#endif
}

/* --------------------------------------------------------------------- */
/* listen                                                                */
/* --------------------------------------------------------------------- */

/* shim_tcp_listen(host, port) -> fd >= 0 | -errno | -(100000 + EAI_*) */
lean_object *shim_tcp_listen(b_lean_obj_arg host_lean, uint16_t port) {
    const char *host = lean_string_cstr(host_lean);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    const char *node = (host[0] == '\0') ? NULL : host;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(node, port_str, &hints, &res);
    if (rc != 0) {
        return mk_i64_ok(-(int64_t)(100000 + rc));
    }

    int fd = -1;
    int last_errno = EADDRNOTAVAIL;

    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) { last_errno = errno; continue; }

        suppress_sigpipe(fd);

        int one = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
            last_errno = errno; close(fd); fd = -1; continue;
        }

        if (bind(fd, ai->ai_addr, ai->ai_addrlen) < 0) {
            last_errno = errno; close(fd); fd = -1; continue;
        }

        if (listen(fd, SOMAXCONN) < 0) {
            last_errno = errno; close(fd); fd = -1; continue;
        }

        break; /* success */
    }

    freeaddrinfo(res);

    if (fd < 0) return mk_i64_ok(-(int64_t)last_errno);
    return mk_i64_ok((int64_t)fd);
}

/* --------------------------------------------------------------------- */
/* accept                                                                */
/* --------------------------------------------------------------------- */

/* shim_tcp_accept(listen_fd) -> fd >= 0 | -errno */
lean_object *shim_tcp_accept(int64_t listen_fd) {
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);

    int fd = accept((int)listen_fd, (struct sockaddr *)&addr, &addrlen);
    if (fd < 0) {
        return mk_i64_ok(-(int64_t)errno);
    }

    suppress_sigpipe(fd);

    /* Latency-oriented default; can be made configurable later. */
    int one = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    return mk_i64_ok((int64_t)fd);
}

/* --------------------------------------------------------------------- */
/* recv                                                                  */
/* --------------------------------------------------------------------- */

/* shim_tcp_recv(fd, max_len) -> (count | -errno, ByteArray)
 *   count > 0 : ByteArray has exactly `count` bytes
 *   count = 0 : EOF (ByteArray is empty)
 *   count < 0 : -errno (ByteArray is empty) */
lean_object *shim_tcp_recv(int64_t fd, size_t max_len) {
    if (max_len == 0) {
        /* Nothing to read into; treat as EOF-ish no-op. */
        return mk_count_ba_ok(0, empty_ba());
    }

    uint8_t *tmp = (uint8_t *)malloc(max_len);
    if (tmp == NULL) {
        return mk_count_ba_ok(-(int64_t)ENOMEM, empty_ba());
    }

    ssize_t n = read((int)fd, tmp, max_len);
    if (n < 0) {
        int e = errno;
        free(tmp);
        return mk_count_ba_ok(-(int64_t)e, empty_ba());
    }

    lean_object *ba = lean_alloc_sarray(1, (size_t)n, (size_t)n);
    if (n > 0) {
        memcpy(lean_sarray_cptr(ba), tmp, (size_t)n);
    }
    free(tmp);

    return mk_count_ba_ok((int64_t)n, ba);
}

/* --------------------------------------------------------------------- */
/* send                                                                  */
/* --------------------------------------------------------------------- */

/* shim_tcp_send(fd, buf, len) -> count >= 0 | -errno
 * Partial sends are reported honestly (count < len); the caller must loop. */
lean_object *shim_tcp_send(int64_t fd, b_lean_obj_arg buf, size_t len) {
    lean_object *ba = (lean_object *)buf;
    size_t ba_size = lean_sarray_size(ba);
    size_t to_write = (len < ba_size) ? len : ba_size;

    const uint8_t *data = lean_sarray_cptr(ba);

    ssize_t n = send((int)fd, data, to_write, WS_SEND_FLAGS);
    if (n < 0) {
        return mk_i64_ok(-(int64_t)errno);
    }
    return mk_i64_ok((int64_t)n);
}

/* --------------------------------------------------------------------- */
/* close                                                                 */
/* --------------------------------------------------------------------- */

/* shim_close(fd) -> 0 | -errno
 * Never retry on failure: on Linux close() releases the fd even on error,
 * and retrying risks closing a reused descriptor. */
lean_object *shim_close(int64_t fd) {
    if (close((int)fd) < 0) {
        return mk_i64_ok(-(int64_t)errno);
    }
    return mk_i64_ok(0);
}

/* --------------------------------------------------------------------- */
/* errno -> human-readable name                                          */
/* --------------------------------------------------------------------- */

/* shim_errno_name(errno) -> IO String
 * Thread safety: strerror is not thread-safe on all platforms; acceptable
 * for the single-threaded phase, swap to strerror_r when threading lands. */
lean_object *shim_errno_name(int32_t errno_) {
    const char *msg = strerror((int)errno_);
    if (msg == NULL) msg = "unknown errno";
    return lean_io_result_mk_ok(lean_mk_string(msg));
}
