/* Test-only socket fault injection; active only in the launched test process. */
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int injected_accept;
static int injected_option;
static int cleanup_fd = -1;
#ifdef SO_NOSIGPIPE
static int nosigpipe_calls;
#endif
static int mode_is(const char *wanted) {
    const char *mode = getenv("LEAN_NET_TEST_SOCKET_FAULT");
    return mode && strcmp(mode, wanted) == 0;
}
static void marker(const char *text) { (void)write(STDERR_FILENO, text, strlen(text)); }
static int accept_fault(void) {
    if (injected_accept || (!mode_is("accept_abort") && !mode_is("accept_proto"))) return 0;
    injected_accept = 1;
    marker("TEST_ACCEPT_FAULT\n");
    errno = mode_is("accept_abort") ? ECONNABORTED : ENOPROTOOPT;
    return 1;
}
static int option_fault(int fd, int level, int name) {
#ifdef SO_NOSIGPIPE
    if (!injected_option && (mode_is("tls_option_einval_peer") || mode_is("tls_option_proto_peer")) &&
        level == SOL_SOCKET && name == SO_NOSIGPIPE) {
        ++nosigpipe_calls;
        /* Listener, accepted socket, then TLS session socket preparation. */
        if (nosigpipe_calls == 3) {
            injected_option = 1;
            cleanup_fd = fd;
            marker("TEST_TLS_OPTION_FAULT\n");
            errno = mode_is("tls_option_einval_peer") ? EINVAL : ENOPROTOOPT;
            return 1;
        }
    }
#endif
    if (injected_option || (!mode_is("option_proto") && !mode_is("cleanup_fail") &&
        !mode_is("option_proto_peer") && !mode_is("option_einval_peer")) ||
        level != IPPROTO_TCP || name != TCP_NODELAY) return 0;
    injected_option = 1;
    cleanup_fd = fd;
    marker("TEST_OPTION_FAULT\n");
    errno = mode_is("option_einval_peer") ? EINVAL : ENOPROTOOPT;
    return 1;
}
static int peer_error_fault(int fd, int level, int name, void *value, socklen_t *length) {
    if ((!mode_is("option_proto_peer") && !mode_is("option_einval_peer") &&
         !mode_is("tls_option_proto_peer") && !mode_is("tls_option_einval_peer")) ||
        fd != cleanup_fd || level != SOL_SOCKET || name != SO_ERROR || *length < sizeof(int)) return 0;
    *(int *)value = ECONNRESET;
    *length = sizeof(int);
    marker("TEST_PENDING_PEER_ERROR\n");
    return 1;
}

#ifdef __APPLE__
static int injected_accept_fn(int fd, struct sockaddr *addr, socklen_t *len) {
    if (accept_fault()) return -1;
    return accept(fd, addr, len);
}
static int injected_setsockopt_fn(int fd, int level, int name, const void *value, socklen_t len) {
    if (option_fault(fd, level, name)) return -1;
    return setsockopt(fd, level, name, value, len);
}
static int injected_getsockopt_fn(int fd, int level, int name, void *value, socklen_t *length) {
    if (peer_error_fault(fd, level, name, value, length)) return 0;
    return getsockopt(fd, level, name, value, length);
}
static int injected_close_fn(int fd) {
    if (mode_is("cleanup_fail") && fd == cleanup_fd) {
        cleanup_fd = -1;
        (void)close(fd);
        marker("TEST_CLEANUP_FAULT\n");
        errno = EIO;
        return -1;
    }
    return close(fd);
}
#define INTERPOSE(replacement, original) \
    __attribute__((used, section("__DATA,__interpose"))) \
    static const struct { const void *replacement_fn; const void *original_fn; } \
    interpose_##replacement = {(const void *)replacement, (const void *)original}
INTERPOSE(injected_accept_fn, accept);
INTERPOSE(injected_setsockopt_fn, setsockopt);
INTERPOSE(injected_getsockopt_fn, getsockopt);
INTERPOSE(injected_close_fn, close);
#else
#include <dlfcn.h>
#define LOAD_NEXT(name, pointer) do { \
    void *symbol = dlsym(RTLD_NEXT, name); \
    memcpy(&(pointer), &symbol, sizeof(pointer)); \
    if (!(pointer)) { errno = ENOSYS; return -1; } \
} while (0)
int accept(int fd, struct sockaddr *addr, socklen_t *len) {
    if (accept_fault()) return -1;
    int (*next)(int, struct sockaddr *, socklen_t *);
    LOAD_NEXT("accept", next);
    return next(fd, addr, len);
}
int setsockopt(int fd, int level, int name, const void *value, socklen_t len) {
    if (option_fault(fd, level, name)) return -1;
    int (*next)(int, int, int, const void *, socklen_t);
    LOAD_NEXT("setsockopt", next);
    return next(fd, level, name, value, len);
}
int getsockopt(int fd, int level, int name, void *value, socklen_t *length) {
    if (peer_error_fault(fd, level, name, value, length)) return 0;
    int (*next)(int, int, int, void *, socklen_t *);
    LOAD_NEXT("getsockopt", next);
    return next(fd, level, name, value, length);
}
int close(int fd) {
    int (*next)(int);
    LOAD_NEXT("close", next);
    if (mode_is("cleanup_fail") && fd == cleanup_fd) {
        cleanup_fd = -1;
        (void)next(fd);
        marker("TEST_CLEANUP_FAULT\n");
        errno = EIO;
        return -1;
    }
    return next(fd);
}
#endif
