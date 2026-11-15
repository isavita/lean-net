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

#if defined(_WIN32)
#include "socket_windows.c"
#else
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L

#include "socket_shim.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
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

static lean_object *mk_result_stage_ok(int64_t result, uint8_t stage) {
    lean_object *pair = lean_alloc_ctor(0, 2, 0);
    lean_ctor_set(pair, 0, lean_box_uint64((uint64_t)result));
    lean_ctor_set(pair, 1, lean_box(stage));
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

/* Per-socket SIGPIPE suppression on platforms that require it. */
static int suppress_sigpipe(int fd) {
#ifdef SO_NOSIGPIPE
    int one = 1;
    return setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#elif defined(MSG_NOSIGNAL)
    (void)fd;
    return 0;
#else
    (void)fd;
    errno = ENOTSUP;
    return -1;
#endif
}

/* Never retry close, including when it reports EINTR. Prefer a cleanup error
 * over the original failure: the caller must know ownership is uncertain. */
static int close_after_failure(int fd, int *error) {
    if (close(fd) < 0) {
        *error = errno;
        return -1;
    }
    return 0;
}

/* On some systems a peer RST races option setup and setsockopt reports
 * EINVAL. Only downgrade the setup failure when SO_ERROR independently
 * confirms a connection-local failure; unrelated setup failures remain fatal. */
static int pending_peer_error(int fd) {
    int error = 0;
    socklen_t length = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) < 0 || length != sizeof(error)) return 0;
    if (error == ECONNRESET || error == ECONNABORTED || error == EPIPE ||
        error == ENOTCONN || error == ETIMEDOUT || error == ENETUNREACH ||
        error == EHOSTUNREACH || error == ENETDOWN || error == ECONNREFUSED)
        return error;
    return 0;
}

static void close_pair_after_failure(const int fds[2], int *error) {
    int first_error = 0;
    if (close(fds[0]) < 0) first_error = errno;
    if (close(fds[1]) < 0 && first_error == 0) first_error = errno;
    if (first_error != 0) *error = first_error;
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
        if (fd < 0) {
            last_errno = errno;
            if (last_errno == EINTR) break;
            continue;
        }

        if (suppress_sigpipe(fd) < 0) {
            last_errno = errno;
            int closed = close_after_failure(fd, &last_errno);
            fd = -1;
            if (closed < 0 || last_errno == EINTR) break;
            continue;
        }

        int one = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
            last_errno = errno;
            int closed = close_after_failure(fd, &last_errno);
            fd = -1;
            if (closed < 0 || last_errno == EINTR) break;
            continue;
        }

        if (bind(fd, ai->ai_addr, ai->ai_addrlen) < 0) {
            last_errno = errno;
            int closed = close_after_failure(fd, &last_errno);
            fd = -1;
            if (closed < 0 || last_errno == EINTR) break;
            continue;
        }

        if (listen(fd, SOMAXCONN) < 0) {
            last_errno = errno;
            int closed = close_after_failure(fd, &last_errno);
            fd = -1;
            if (closed < 0 || last_errno == EINTR) break;
            continue;
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
    if (listen_fd < 0 || listen_fd > INT_MAX) return mk_i64_ok(-EBADF);
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);

    int fd = accept((int)listen_fd, (struct sockaddr *)&addr, &addrlen);
    if (fd < 0) {
        return mk_i64_ok(-(int64_t)errno);
    }

    if (suppress_sigpipe(fd) < 0) {
        int e = errno;
        close_after_failure(fd, &e);
        return mk_i64_ok(-(int64_t)e);
    }

    /* Latency-oriented default; can be made configurable later. */
    int one = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) {
        int e = errno;
        close_after_failure(fd, &e);
        return mk_i64_ok(-(int64_t)e);
    }

    return mk_i64_ok((int64_t)fd);
}

lean_object *shim_tcp_accept_staged(int64_t listen_fd) {
    if (listen_fd < 0 || listen_fd > INT_MAX) return mk_result_stage_ok(-EBADF, 1);
    int fd = accept((int)listen_fd, NULL, NULL);
    if (fd < 0) return mk_result_stage_ok(-errno, 1);
    if (suppress_sigpipe(fd) < 0) {
        int e = errno;
        int peer = pending_peer_error(fd);
        /* EINVAL is observed for the Darwin reset race. An unrelated setup
         * error, such as ENOPROTOOPT, must remain fatal even if a peer error
         * happens to be pending at the same time. */
        if (e != EINVAL && e != peer) peer = 0;
        if (peer != 0) e = peer;
        int stage = close_after_failure(fd, &e) < 0 ? 3 : peer != 0 ? 4 : 2;
        return mk_result_stage_ok(-e, (uint8_t)stage);
    }
    int one = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) {
        int e = errno;
        int peer = pending_peer_error(fd);
        if (e != EINVAL && e != peer) peer = 0;
        if (peer != 0) e = peer;
        int stage = close_after_failure(fd, &e) < 0 ? 3 : peer != 0 ? 4 : 2;
        return mk_result_stage_ok(-e, (uint8_t)stage);
    }
    return mk_result_stage_ok(fd, 0);
}

/* --------------------------------------------------------------------- */
/* recv                                                                  */
/* --------------------------------------------------------------------- */

/* shim_tcp_recv(fd, max_len) -> (count | -errno, ByteArray)
 *   count > 0 : ByteArray has exactly `count` bytes
 *   count = 0 : EOF (ByteArray is empty)
 *   count < 0 : -errno (ByteArray is empty) */
lean_object *shim_tcp_recv(int64_t fd, size_t max_len) {
    if (fd < 0 || fd > INT_MAX) return mk_count_ba_ok(-EBADF, empty_ba());
    if (max_len == 0) {
        /* A zero-sized read cannot establish EOF. */
        return mk_count_ba_ok(-EINVAL, empty_ba());
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
    if (fd < 0 || fd > INT_MAX) return mk_i64_ok(-EBADF);
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
    if (fd < 0 || fd > INT_MAX) return mk_i64_ok(-EBADF);
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

/* Expose platform constants without assuming that errno values are portable. */
lean_object *shim_errno_eintr(void) { return mk_i64_ok(EINTR); }
lean_object *shim_errno_eagain(void) { return mk_i64_ok(EAGAIN); }
lean_object *shim_errno_ewouldblock(void) { return mk_i64_ok(EWOULDBLOCK); }
lean_object *shim_errno_ebadf(void) { return mk_i64_ok(EBADF); }
lean_object *shim_errno_epipe(void) { return mk_i64_ok(EPIPE); }
lean_object *shim_errno_econnreset(void) { return mk_i64_ok(ECONNRESET); }
lean_object *shim_errno_econnaborted(void) { return mk_i64_ok(ECONNABORTED); }
lean_object *shim_errno_etimedout(void) { return mk_i64_ok(ETIMEDOUT); }
lean_object *shim_errno_enetreset(void) { return mk_i64_ok(ENETRESET); }
lean_object *shim_errno_enetdown(void) { return mk_i64_ok(ENETDOWN); }
lean_object *shim_errno_enetunreach(void) { return mk_i64_ok(ENETUNREACH); }
lean_object *shim_errno_ehostunreach(void) { return mk_i64_ok(EHOSTUNREACH); }
lean_object *shim_errno_econnrefused(void) { return mk_i64_ok(ECONNREFUSED); }
lean_object *shim_errno_enotconn(void) { return mk_i64_ok(ENOTCONN); }

/* Some Linux accept errors do not exist on all supported POSIX platforms.
 * Zero is a sentinel for an unavailable constant, never an errno failure. */
lean_object *shim_errno_enonet(void) {
#ifdef ENONET
    return mk_i64_ok(ENONET);
#else
    return mk_i64_ok(0);
#endif
}
lean_object *shim_errno_eproto(void) {
#ifdef EPROTO
    return mk_i64_ok(EPROTO);
#else
    return mk_i64_ok(0);
#endif
}
lean_object *shim_errno_enoprotoopt(void) {
#ifdef ENOPROTOOPT
    return mk_i64_ok(ENOPROTOOPT);
#else
    return mk_i64_ok(0);
#endif
}
lean_object *shim_errno_ehostdown(void) {
#ifdef EHOSTDOWN
    return mk_i64_ok(EHOSTDOWN);
#else
    return mk_i64_ok(0);
#endif
}
lean_object *shim_errno_emfile(void) { return mk_i64_ok(EMFILE); }
lean_object *shim_errno_enfile(void) { return mk_i64_ok(ENFILE); }
lean_object *shim_errno_enobufs(void) { return mk_i64_ok(ENOBUFS); }
lean_object *shim_errno_enomem(void) { return mk_i64_ok(ENOMEM); }
lean_object *shim_errno_eopnotsupp(void) {
#ifdef EOPNOTSUPP
    return mk_i64_ok(EOPNOTSUPP);
#else
    return mk_i64_ok(0);
#endif
}

/*
 * Scoped SIGINT wakeup for single-threaded applications. The handler does no
 * Lean work: a nonblocking self-pipe wakes poll even if SIGINT arrives just
 * before the wait. The application restores the old handler in a bracket.
 */
static volatile sig_atomic_t interrupt_requested = 0;
/* Accessed in the handler; setup/teardown occur with SIGINT blocked. This
 * facility is only valid in a single-threaded process. */
static volatile sig_atomic_t interrupt_write_fd = -1;
static int interrupt_pipe[2] = {-1, -1};
static struct sigaction old_sigint_action;

static void interrupt_handler(int signo) {
    (void)signo;
    int saved_errno = errno;
    interrupt_requested = 1;
    const unsigned char byte = 1;
    if (interrupt_write_fd >= 0) {
        /* EAGAIN is harmless: a full pipe is already readable. */
        ssize_t ignored = write((int)interrupt_write_fd, &byte, 1);
        (void)ignored;
    }
    errno = saved_errno;
}

lean_object *shim_interrupt_begin(void) {
    if (interrupt_pipe[0] >= 0) return mk_i64_ok(-EBUSY);

    int fds[2];
    if (pipe(fds) < 0) return mk_i64_ok(-errno);
    for (int i = 0; i < 2; ++i) {
        int flags = fcntl(fds[i], F_GETFL);
        if (flags < 0) {
            int e = errno;
            close_pair_after_failure(fds, &e);
            return mk_i64_ok(-e);
        }
        int fdflags = fcntl(fds[i], F_GETFD);
        if (fdflags < 0 ||
            fcntl(fds[i], F_SETFL, flags | O_NONBLOCK) < 0 ||
            fcntl(fds[i], F_SETFD, fdflags | FD_CLOEXEC) < 0) {
            int e = errno;
            close_pair_after_failure(fds, &e);
            return mk_i64_ok(-e);
        }
    }

    sigset_t set, oldmask;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    if (sigprocmask(SIG_BLOCK, &set, &oldmask) < 0) {
        int e = errno;
        close_pair_after_failure(fds, &e);
        return mk_i64_ok(-e);
    }
    /* A blocked SIGINT could never wake poll. Do not silently change the
     * caller's signal mask or claim interruptible behavior in that case. */
    int was_blocked = sigismember(&oldmask, SIGINT);
    if (was_blocked != 0) {
        int e = was_blocked < 0 ? errno : EINVAL;
        close_pair_after_failure(fds, &e);
        if (sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0) e = errno;
        return mk_i64_ok(-e);
    }
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = interrupt_handler;
    /* No other handler may interrupt the one-byte nonblocking pipe write. */
    sigfillset(&action.sa_mask);
    interrupt_requested = 0;
    interrupt_pipe[0] = fds[0];
    interrupt_pipe[1] = fds[1];
    interrupt_write_fd = fds[1];
    if (sigaction(SIGINT, &action, &old_sigint_action) < 0) {
        int e = errno;
        interrupt_write_fd = -1;
        interrupt_pipe[0] = interrupt_pipe[1] = -1;
        close_pair_after_failure(fds, &e);
        if (sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0) e = errno;
        return mk_i64_ok(-e);
    }
    if (sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0) {
        int e = errno;
        (void)sigaction(SIGINT, &old_sigint_action, NULL);
        interrupt_write_fd = -1;
        interrupt_pipe[0] = interrupt_pipe[1] = -1;
        close_pair_after_failure(fds, &e);
        return mk_i64_ok(-e);
    }
    return mk_i64_ok(0);
}

lean_object *shim_interrupt_requested(void) {
    return mk_i64_ok(interrupt_requested ? 1 : 0);
}

lean_object *shim_interrupt_end(void) {
    if (interrupt_pipe[0] < 0) return mk_i64_ok(-EINVAL);
    sigset_t set, oldmask;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    if (sigprocmask(SIG_BLOCK, &set, &oldmask) < 0) return mk_i64_ok(-errno);
    if (sigaction(SIGINT, &old_sigint_action, NULL) < 0) {
        int e = errno;
        (void)sigprocmask(SIG_SETMASK, &oldmask, NULL);
        return mk_i64_ok(-e);
    }
    int read_fd = interrupt_pipe[0], write_fd = interrupt_pipe[1];
    interrupt_write_fd = -1;
    interrupt_pipe[0] = interrupt_pipe[1] = -1;
    int e = 0;
    if (close(read_fd) < 0) e = errno;
    if (close(write_fd) < 0 && e == 0) e = errno;
    interrupt_requested = 0;
    if (sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0 && e == 0) e = errno;
    return mk_i64_ok(-e);
}

/* One wait per invocation: EINTR is reported and never retried in C. */
static int wait_interruptible(int fd, short events) {
    if (interrupt_pipe[0] < 0) return -EINVAL;
    if (interrupt_requested) return -EINTR;
    struct pollfd fds[2] = {{fd, events, 0}, {interrupt_pipe[0], POLLIN, 0}};
    int rc = poll(fds, 2, -1);
    if (rc < 0) return -errno;
    if (interrupt_requested) return -EINTR;
    if (fds[1].revents & POLLNVAL) return -EBADF;
    if (fds[1].revents) return -EIO;
    if (fds[0].revents & POLLNVAL) return -EBADF;
    return 0;
}

lean_object *shim_interruptible_accept(int64_t listen_fd) {
    if (listen_fd < 0 || listen_fd > INT_MAX) return mk_i64_ok(-EBADF);
    int fd = (int)listen_fd;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return mk_i64_ok(-errno);
    if (!(flags & O_NONBLOCK) && fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return mk_i64_ok(-errno);
    int rc = wait_interruptible(fd, POLLIN);
    int accepted = -1;
    if (rc == 0) {
        accepted = accept(fd, NULL, NULL);
        if (accepted < 0) rc = -errno;
    }
    if (!(flags & O_NONBLOCK) && fcntl(fd, F_SETFL, flags) < 0) {
        int e = errno;
        if (accepted >= 0) close_after_failure(accepted, &e);
        return mk_i64_ok(-e);
    }
    if (rc < 0) return mk_i64_ok(rc);
    /* Some systems inherit the listener's temporary nonblocking flag. */
    int accepted_flags = fcntl(accepted, F_GETFL);
    if (accepted_flags < 0 ||
        ((accepted_flags & O_NONBLOCK) &&
         fcntl(accepted, F_SETFL, accepted_flags & ~O_NONBLOCK) < 0)) {
        int e = errno; close_after_failure(accepted, &e); return mk_i64_ok(-e);
    }
    if (suppress_sigpipe(accepted) < 0) {
        int e = errno; close_after_failure(accepted, &e); return mk_i64_ok(-e);
    }
    int one = 1;
    if (setsockopt(accepted, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) {
        int e = errno; close_after_failure(accepted, &e); return mk_i64_ok(-e);
    }
    return mk_i64_ok(accepted);
}

lean_object *shim_interruptible_recv(int64_t fd, size_t max_len) {
    if (fd < 0 || fd > INT_MAX) return mk_count_ba_ok(-EBADF, empty_ba());
    if (max_len == 0) return mk_count_ba_ok(-EINVAL, empty_ba());
    int flags = fcntl((int)fd, F_GETFL);
    if (flags < 0) return mk_count_ba_ok(-errno, empty_ba());
    if (!(flags & O_NONBLOCK) && fcntl((int)fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return mk_count_ba_ok(-errno, empty_ba());
    int rc = wait_interruptible((int)fd, POLLIN);
    uint8_t *tmp = NULL;
    ssize_t n = -1;
    if (rc == 0) {
        tmp = malloc(max_len);
        if (tmp == NULL) rc = -ENOMEM;
        else {
            n = recv((int)fd, tmp, max_len, 0);
            if (n < 0) rc = -errno;
        }
    }
    if (!(flags & O_NONBLOCK) && fcntl((int)fd, F_SETFL, flags) < 0) rc = -errno;
    if (rc < 0) { free(tmp); return mk_count_ba_ok(rc, empty_ba()); }
    lean_object *ba = lean_alloc_sarray(1, (size_t)n, (size_t)n);
    if (n > 0) memcpy(lean_sarray_cptr(ba), tmp, (size_t)n);
    free(tmp);
    return mk_count_ba_ok((int64_t)n, ba);
}

lean_object *shim_interruptible_send(int64_t fd, b_lean_obj_arg buf, size_t len) {
    if (fd < 0 || fd > INT_MAX) return mk_i64_ok(-EBADF);
    size_t size = lean_sarray_size((lean_object *)buf);
    size_t count = len < size ? len : size;
    if (count == 0) return mk_i64_ok(0);
    int flags = fcntl((int)fd, F_GETFL);
    if (flags < 0) return mk_i64_ok(-errno);
    if (!(flags & O_NONBLOCK) && fcntl((int)fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return mk_i64_ok(-errno);
    int rc = wait_interruptible((int)fd, POLLOUT);
    ssize_t n = -1;
    if (rc == 0) {
        n = send((int)fd, lean_sarray_cptr((lean_object *)buf), count, WS_SEND_FLAGS);
        if (n < 0) rc = -errno;
    }
    if (!(flags & O_NONBLOCK) && fcntl((int)fd, F_SETFL, flags) < 0) rc = -errno;
    if (rc < 0) return mk_i64_ok(rc);
    return mk_i64_ok((int64_t)n);
}

lean_object *shim_set_nonblocking(int64_t fd, uint8_t enabled) {
    if (fd < 0 || fd > INT_MAX) return mk_i64_ok(-EBADF);
    if (enabled > 1) return mk_i64_ok(-EINVAL);
    int flags = fcntl((int)fd, F_GETFL);
    if (flags < 0) return mk_i64_ok(-errno);
    int updated = enabled ? flags | O_NONBLOCK : flags & ~O_NONBLOCK;
    if (updated != flags && fcntl((int)fd, F_SETFL, updated) < 0)
        return mk_i64_ok(-errno);
    return mk_i64_ok(0);
}

lean_object *shim_tcp_send_offset(int64_t fd, b_lean_obj_arg buf,
                                  size_t offset, size_t len) {
    if (fd < 0 || fd > INT_MAX) return mk_i64_ok(-EBADF);
    size_t size = lean_sarray_size((lean_object *)buf);
    if (offset > size || len > size - offset) return mk_i64_ok(-EINVAL);
    if (len == 0) return mk_i64_ok(0);
    const uint8_t *data = lean_sarray_cptr((lean_object *)buf);
    ssize_t n = send((int)fd, data + offset, len, WS_SEND_FLAGS);
    if (n < 0) return mk_i64_ok(-errno);
    return mk_i64_ok((int64_t)n);
}

lean_object *shim_poll(b_lean_obj_arg entries, int32_t timeout_ms) {
    size_t size = lean_sarray_size((lean_object *)entries);
    if (size % 5 != 0 || timeout_ms < -1)
        return mk_count_ba_ok(-EINVAL, empty_ba());
    if (interrupt_pipe[0] < 0) return mk_count_ba_ok(-EINVAL, empty_ba());
    if (interrupt_requested) return mk_count_ba_ok(-EINTR, empty_ba());
    size_t count = size / 5;
    if (count > (SIZE_MAX / sizeof(struct pollfd)) - 1 ||
        (size_t)(nfds_t)(count + 1) != count + 1)
        return mk_count_ba_ok(-EINVAL, empty_ba());
    struct pollfd *fds = calloc(count + 1, sizeof(*fds));
    if (fds == NULL) return mk_count_ba_ok(-ENOMEM, empty_ba());
    const uint8_t *input = lean_sarray_cptr((lean_object *)entries);
    for (size_t i = 0; i < count; ++i) {
        const uint8_t *entry = input + i * 5;
        uint32_t fd = (uint32_t)entry[0] | ((uint32_t)entry[1] << 8) |
                      ((uint32_t)entry[2] << 16) | ((uint32_t)entry[3] << 24);
        if (fd > INT_MAX || (entry[4] & (uint8_t)~3u) != 0) {
            free(fds);
            return mk_count_ba_ok(-EINVAL, empty_ba());
        }
        fds[i].fd = (int)fd;
        if (entry[4] & 1u) fds[i].events |= POLLIN;
        if (entry[4] & 2u) fds[i].events |= POLLOUT;
    }
    fds[count].fd = interrupt_pipe[0];
    fds[count].events = POLLIN;
    int rc = poll(fds, (nfds_t)(count + 1), timeout_ms);
    if (rc < 0) {
        int e = errno;
        free(fds);
        return mk_count_ba_ok(-e, empty_ba());
    }
    if (interrupt_requested) {
        free(fds);
        return mk_count_ba_ok(-EINTR, empty_ba());
    }
    if (fds[count].revents != 0) {
        int e = (fds[count].revents & POLLNVAL) ? EBADF : EIO;
        free(fds);
        return mk_count_ba_ok(-e, empty_ba());
    }
    lean_object *result = lean_alloc_sarray(1, count, count);
    uint8_t *output = lean_sarray_cptr(result);
    int64_t ready = 0;
    for (size_t i = 0; i < count; ++i) {
        short events = fds[i].revents;
        uint8_t mask = 0;
        if (events & POLLIN) mask |= 1;
        if (events & POLLOUT) mask |= 2;
        if (events & POLLHUP) mask |= 4;
        if (events & POLLERR) mask |= 8;
        if (events & POLLNVAL) mask |= 16;
        output[i] = mask;
        if (mask != 0) ++ready;
    }
    free(fds);
    return mk_count_ba_ok(ready, result);
}

#endif /* POSIX compatibility shim */
#include "reactor_ffi.h"
#include "gateway_resolve.h"
