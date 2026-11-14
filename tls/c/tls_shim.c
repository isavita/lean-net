/* OpenSSL server adapter. Socket descriptors are borrowed and are never closed
 * here. Every entry point returns a Lean IO result; syscall errors are -errno.
 * OpenSSL WANT_READ/WANT_WRITE are distinct non-error statuses. */
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#if defined(_WIN32) && !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif
#include <lean/lean.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include "../../c/windows_error.h"
#include "../../c/socket_windows_bridge.h"
#else
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#if defined(MSG_NOSIGNAL)
#define TLS_SEND_FLAGS MSG_NOSIGNAL
#else
#define TLS_SEND_FLAGS 0
#endif

typedef struct {
    SSL_CTX *ctx;
    BIO_METHOD *method;
} tls_context;

typedef struct {
    SSL *ssl;
    unsigned char *read_buffer;
    size_t read_capacity;
    size_t read_pending_size;
    int read_pending;
} tls_session;

static lean_object *pair(lean_object *a, lean_object *b) {
    lean_object *p = lean_alloc_ctor(0, 2, 0);
    lean_ctor_set(p, 0, a);
    lean_ctor_set(p, 1, b);
    return p;
}

static lean_object *number(int64_t n) { return lean_box_uint64((uint64_t)n); }
static lean_object *empty_bytes(void) { return lean_alloc_sarray(1, 0, 0); }

static lean_object *diagnostic(const char *fallback) {
    unsigned long error = ERR_get_error();
    if (error == 0) return lean_mk_string(fallback);
    char buffer[256];
    ERR_error_string_n(error, buffer, sizeof(buffer));
    ERR_clear_error();
    return lean_mk_string(buffer);
}

/* IO (UInt64 × String) */
static lean_object *handle_result(int64_t n, lean_object *message) {
    return lean_io_result_mk_ok(pair(number(n), message));
}
/* IO ((UInt64 × UInt8) × String) */
static lean_object *step_result(int64_t n, uint8_t status, lean_object *message) {
    return lean_io_result_mk_ok(pair(pair(number(n), lean_box(status)), message));
}
/* IO ((UInt64 × UInt8) × (ByteArray × String)) */
static lean_object *read_result(int64_t n, uint8_t status, lean_object *bytes, lean_object *message) {
    return lean_io_result_mk_ok(pair(pair(number(n), lean_box(status)), pair(bytes, message)));
}

/* BIO callbacks perform exactly one syscall and never take fd ownership. */
static int socket_create(BIO *bio) {
    BIO_set_init(bio, 0);
    BIO_set_data(bio, NULL);
    BIO_set_shutdown(bio, 0);
    return 1;
}
static int socket_destroy(BIO *bio) {
    if (bio == NULL) return 0;
    BIO_set_data(bio, NULL);
    BIO_set_init(bio, 0);
    return 1;
}
static int bio_fd(BIO *bio) { return (int)((intptr_t)BIO_get_data(bio) - 1); }
static int socket_read(BIO *bio, char *out, int len) {
    if (out == NULL || len <= 0) return 0;
    BIO_clear_retry_flags(bio);
#if defined(_WIN32)
    uintptr_t borrowed = 0;
    int error = ln_windows_socket_borrow(bio_fd(bio), &borrowed, NULL);
    if (error) { errno = -error; return -1; }
    int n = recv((SOCKET)borrowed, out, len, 0);
    if (n == SOCKET_ERROR) errno = ln_windows_errno((DWORD)WSAGetLastError());
#else
    ssize_t n = recv(bio_fd(bio), out, (size_t)len, 0);
#endif
    if (n < 0) {
        int e = errno;
        if (e == EAGAIN || e == EWOULDBLOCK) BIO_set_retry_read(bio);
        errno = e;
    }
    return n < 0 ? -1 : (int)n;
}
static int socket_write(BIO *bio, const char *in, int len) {
    if (in == NULL || len <= 0) return 0;
    BIO_clear_retry_flags(bio);
#if defined(_WIN32)
    uintptr_t borrowed = 0;
    int error = ln_windows_socket_borrow(bio_fd(bio), &borrowed, NULL);
    if (error) { errno = -error; return -1; }
    int n = send((SOCKET)borrowed, in, len, TLS_SEND_FLAGS);
    if (n == SOCKET_ERROR) errno = ln_windows_errno((DWORD)WSAGetLastError());
#else
    ssize_t n = send(bio_fd(bio), in, (size_t)len, TLS_SEND_FLAGS);
#endif
    if (n < 0) {
        int e = errno;
        if (e == EAGAIN || e == EWOULDBLOCK) BIO_set_retry_write(bio);
        errno = e;
    }
    return n < 0 ? -1 : (int)n;
}
static long socket_ctrl(BIO *bio, int cmd, long arg, void *ptr) {
    (void)bio; (void)arg; (void)ptr;
    return cmd == BIO_CTRL_FLUSH ? 1 : 0;
}

/* Prefer h2; unknown ALPN lists are rejected rather than silently downgraded. */
static int alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl; (void)arg;
    const unsigned char *h2 = NULL, *http1 = NULL;
    for (unsigned int pos = 0; pos < inlen;) {
        unsigned int n = in[pos++];
        if (n == 0 || n > inlen - pos) return SSL_TLSEXT_ERR_ALERT_FATAL;
        if (n == 2 && memcmp(in + pos, "h2", 2) == 0) h2 = in + pos;
        if (n == 8 && memcmp(in + pos, "http/1.1", 8) == 0) http1 = in + pos;
        pos += n;
    }
    if (h2 != NULL) { *out = h2; *outlen = 2; return SSL_TLSEXT_ERR_OK; }
    if (http1 != NULL) { *out = http1; *outlen = 8; return SSL_TLSEXT_ERR_OK; }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

/* Encrypted keys require an explicit future credential API; never prompt in a
 * headless server process during startup. */
static int no_password(char *buffer, int size, int writing, void *arg) {
    (void)buffer; (void)size; (void)writing; (void)arg;
    return 0;
}

static int pending_peer_error(int fd) {
    int error = 0;
#if defined(_WIN32)
    uintptr_t borrowed = 0;
    if (ln_windows_socket_borrow(fd, &borrowed, NULL)) return 0;
    int length = sizeof(error);
    if (getsockopt((SOCKET)borrowed, SOL_SOCKET, SO_ERROR, (char *)&error, &length) < 0 || length != sizeof(error)) return 0;
    error = ln_windows_errno((DWORD)error);
#else
    socklen_t length = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) < 0 || length != sizeof(error)) return 0;
#endif
    if (error == ECONNRESET || error == ECONNABORTED || error == EPIPE ||
        error == ENOTCONN || error == ETIMEDOUT || error == ENETUNREACH ||
        error == EHOSTUNREACH || error == ENETDOWN || error == ECONNREFUSED)
        return error;
    return 0;
}

lean_object *lean_tls_context_new(b_lean_obj_arg cert, b_lean_obj_arg key) {
    ERR_clear_error();
#if !defined(_WIN32) && !defined(MSG_NOSIGNAL) && !defined(SO_NOSIGPIPE)
    (void)cert; (void)key;
    return handle_result(-ENOTSUP, lean_mk_string("platform lacks per-socket SIGPIPE suppression"));
#else
    tls_context *context = calloc(1, sizeof(*context));
    if (context == NULL) return handle_result(-ENOMEM, lean_mk_string("allocating TLS context"));
    context->ctx = SSL_CTX_new(TLS_server_method());
    context->method = BIO_meth_new(BIO_TYPE_SOURCE_SINK | BIO_get_new_index(), "lean-net borrowed socket");
    if (context->ctx != NULL) SSL_CTX_set_default_passwd_cb(context->ctx, no_password);
    int setup_errno = EINVAL;
    if (context->ctx == NULL || context->method == NULL ||
        BIO_meth_set_create(context->method, socket_create) != 1 ||
        BIO_meth_set_destroy(context->method, socket_destroy) != 1 ||
        BIO_meth_set_read(context->method, socket_read) != 1 ||
        BIO_meth_set_write(context->method, socket_write) != 1 ||
        BIO_meth_set_ctrl(context->method, socket_ctrl) != 1 ||
        SSL_CTX_set_min_proto_version(context->ctx, TLS1_2_VERSION) != 1 ||
        SSL_CTX_set_cipher_list(context->ctx,
          "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
          "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
          "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305") != 1) {
        goto setup_failed;
    }
    errno = 0;
    if (SSL_CTX_use_certificate_chain_file(context->ctx, lean_string_cstr(cert)) != 1) {
        if (errno != 0) setup_errno = errno;
        goto setup_failed;
    }
    errno = 0;
    if (SSL_CTX_use_PrivateKey_file(context->ctx, lean_string_cstr(key), SSL_FILETYPE_PEM) != 1) {
        if (errno != 0) setup_errno = errno;
        goto setup_failed;
    }
    if (SSL_CTX_check_private_key(context->ctx) != 1) {
        goto setup_failed;
    }
    SSL_CTX_set_options(context->ctx, SSL_OP_NO_COMPRESSION);
#ifdef SSL_OP_NO_RENEGOTIATION
    SSL_CTX_set_options(context->ctx, SSL_OP_NO_RENEGOTIATION);
#endif
    SSL_CTX_set_mode(context->ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_CTX_set_alpn_select_cb(context->ctx, alpn_select, NULL);
    if ((uintptr_t)context > INT64_MAX) {
        SSL_CTX_free(context->ctx); BIO_meth_free(context->method); free(context);
        return handle_result(-EOVERFLOW, lean_mk_string("TLS context pointer out of range"));
    }
    return handle_result((int64_t)(uintptr_t)context, lean_mk_string(""));

setup_failed:
    {
        lean_object *message = diagnostic("TLS context setup failed");
        SSL_CTX_free(context->ctx);
        BIO_meth_free(context->method);
        free(context);
        return handle_result(-(int64_t)setup_errno, message);
    }
#endif
}

lean_object *lean_tls_context_free(uint64_t handle) {
    if (handle == 0) return lean_io_result_mk_ok(number(-EINVAL));
    tls_context *context = (tls_context *)(uintptr_t)handle;
    SSL_CTX_free(context->ctx);
    BIO_meth_free(context->method);
    free(context);
    return lean_io_result_mk_ok(number(0));
}

lean_object *lean_tls_session_new(uint64_t handle, int64_t fd) {
    if (handle == 0 || fd < 0 || fd > INT_MAX)
        return step_result(-EINVAL, 1, lean_mk_string("invalid TLS context or socket"));
#if defined(_WIN32)
    uintptr_t borrowed = 0; int nonblocking = 0;
    int error = ln_windows_socket_borrow(fd, &borrowed, &nonblocking);
    if (error) return step_result(error, 1, lean_mk_string("checking socket flags failed"));
    if (!nonblocking) return step_result(-EINVAL, 1, lean_mk_string("TLS socket must be nonblocking"));
#else
    int flags = fcntl((int)fd, F_GETFL);
    if (flags < 0) return step_result(-errno, 1, lean_mk_string("checking socket flags failed"));
    if (!(flags & O_NONBLOCK)) return step_result(-EINVAL, 1, lean_mk_string("TLS socket must be nonblocking"));
#endif
#ifdef SO_NOSIGPIPE
    int one = 1;
    if (setsockopt((int)fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) < 0) {
        int error = errno;
        int peer = pending_peer_error((int)fd);
        if (error != EINVAL && error != peer) peer = 0;
        if (peer != 0) return step_result(-peer, 2, lean_mk_string("peer failed during TLS socket setup"));
        return step_result(-error, 1, lean_mk_string("setting SO_NOSIGPIPE failed"));
    }
#else
    (void)pending_peer_error;
#endif
    ERR_clear_error();
    tls_context *context = (tls_context *)(uintptr_t)handle;
    tls_session *session = calloc(1, sizeof(*session));
    if (session == NULL) return step_result(-ENOMEM, 1, lean_mk_string("allocating TLS session"));
    session->ssl = SSL_new(context->ctx);
    BIO *bio = BIO_new(context->method);
    if (session->ssl == NULL || bio == NULL) {
        lean_object *message = diagnostic("TLS session setup failed");
        SSL_free(session->ssl); BIO_free(bio); free(session);
        return step_result(-ENOMEM, 1, message);
    }
    BIO_set_data(bio, (void *)(intptr_t)(fd + 1));
    BIO_set_init(bio, 1);
    SSL_set_bio(session->ssl, bio, bio);
    SSL_set_accept_state(session->ssl);
    if ((uintptr_t)session > INT64_MAX) {
        SSL_free(session->ssl); free(session);
        return step_result(-EOVERFLOW, 1, lean_mk_string("TLS session pointer out of range"));
    }
    return step_result((int64_t)(uintptr_t)session, 0, lean_mk_string(""));
}

lean_object *lean_tls_session_free(uint64_t handle) {
    if (handle == 0) return lean_io_result_mk_ok(number(-EINVAL));
    tls_session *session = (tls_session *)(uintptr_t)handle;
    SSL_free(session->ssl);
    free(session->read_buffer);
    free(session);
    return lean_io_result_mk_ok(number(0));
}

/* status: 0 success/failure, 1 WANT_READ, 2 WANT_WRITE, 3 clean EOF. */
static void classify(SSL *ssl, int result, int saved_errno, int64_t *value, uint8_t *status,
                     lean_object **message) {
    int error = SSL_get_error(ssl, result);
    *status = 0;
    if (error == SSL_ERROR_WANT_READ) { *value = 0; *status = 1; *message = lean_mk_string(""); return; }
    if (error == SSL_ERROR_WANT_WRITE) { *value = 0; *status = 2; *message = lean_mk_string(""); return; }
    if (error == SSL_ERROR_ZERO_RETURN) { *value = 0; *status = 3; *message = lean_mk_string(""); return; }
    if (error == SSL_ERROR_SYSCALL && saved_errno != 0) {
        *value = -(int64_t)saved_errno;
        *message = diagnostic("TLS socket operation failed");
        return;
    }
    /* Do not misclassify OpenSSL's own allocation/internal failures as bad
     * peer traffic: the Lean layer treats protocol errors as connection-local. */
    unsigned long detail = ERR_peek_last_error();
    int reason = detail == 0 ? 0 : ERR_GET_REASON(detail);
    if (reason == ERR_R_MALLOC_FAILURE) *value = -ENOMEM;
#ifdef ERR_R_INTERNAL_ERROR
    else if (reason == ERR_R_INTERNAL_ERROR) *value = -EIO;
#endif
    else *value = -EPROTO;
    *message = diagnostic("TLS protocol operation failed");
}

lean_object *lean_tls_handshake(uint64_t handle) {
    if (handle == 0) return step_result(-EINVAL, 0, lean_mk_string("invalid session"));
    tls_session *session = (tls_session *)(uintptr_t)handle;
    ERR_clear_error(); errno = 0;
    int rc = SSL_accept(session->ssl);
    int saved_errno = errno;
    if (rc == 1) return step_result(0, 0, lean_mk_string(""));
    int64_t value; uint8_t status; lean_object *message;
    classify(session->ssl, rc, saved_errno, &value, &status, &message);
    return step_result(value, status, message);
}

lean_object *lean_tls_read(uint64_t handle, size_t max_len) {
    if (handle == 0 || max_len == 0 || max_len > INT_MAX)
        return read_result(-EINVAL, 0, empty_bytes(), lean_mk_string("invalid TLS read size"));
    tls_session *session = (tls_session *)(uintptr_t)handle;
    if (session->read_pending && max_len != session->read_pending_size)
        return read_result(-EINVAL, 0, empty_bytes(), lean_mk_string("TLS read retry changed size"));
    if (session->read_capacity < max_len) {
        unsigned char *buffer = realloc(session->read_buffer, max_len);
        if (buffer == NULL) return read_result(-ENOMEM, 0, empty_bytes(), lean_mk_string("allocating TLS read"));
        session->read_buffer = buffer;
        session->read_capacity = max_len;
    }
    ERR_clear_error(); errno = 0;
    size_t count = 0;
    int rc = SSL_read_ex(session->ssl, session->read_buffer, max_len, &count);
    int saved_errno = errno;
    if (rc == 1) {
        lean_object *bytes = lean_alloc_sarray(1, count, count);
        if (count > 0) memcpy(lean_sarray_cptr(bytes), session->read_buffer, count);
        session->read_pending = 0;
        return read_result((int64_t)count, 0, bytes, lean_mk_string(""));
    }
    int64_t value; uint8_t status; lean_object *message;
    classify(session->ssl, rc, saved_errno, &value, &status, &message);
    session->read_pending = status == 1 || status == 2 || value == -EINTR;
    if (session->read_pending) session->read_pending_size = max_len;
    return read_result(value, status, empty_bytes(), message);
}

lean_object *lean_tls_write(uint64_t handle, b_lean_obj_arg data, size_t offset, size_t len) {
    size_t size = lean_sarray_size((lean_object *)data);
    if (handle == 0 || offset > size || len > size - offset || len > INT_MAX)
        return step_result(-EINVAL, 0, lean_mk_string("invalid TLS write range"));
    if (len == 0) return step_result(0, 0, lean_mk_string(""));
    tls_session *session = (tls_session *)(uintptr_t)handle;
    ERR_clear_error(); errno = 0;
    size_t count = 0;
    int rc = SSL_write_ex(session->ssl, lean_sarray_cptr((lean_object *)data) + offset, len, &count);
    int saved_errno = errno;
    if (rc == 1) return step_result((int64_t)count, 0, lean_mk_string(""));
    int64_t value; uint8_t status; lean_object *message;
    classify(session->ssl, rc, saved_errno, &value, &status, &message);
    return step_result(value, status, message);
}

lean_object *lean_tls_alpn(uint64_t handle) {
    if (handle == 0) return read_result(-EINVAL, 0, empty_bytes(), lean_mk_string("invalid session"));
    tls_session *session = (tls_session *)(uintptr_t)handle;
    const unsigned char *selected = NULL; unsigned int length = 0;
    SSL_get0_alpn_selected(session->ssl, &selected, &length);
    lean_object *bytes = lean_alloc_sarray(1, length, length);
    if (length > 0) memcpy(lean_sarray_cptr(bytes), selected, length);
    return read_result((int64_t)length, 0, bytes, lean_mk_string(""));
}

lean_object *lean_tls_shutdown(uint64_t handle) {
    if (handle == 0) return step_result(-EINVAL, 0, lean_mk_string("invalid session"));
    tls_session *session = (tls_session *)(uintptr_t)handle;
    ERR_clear_error(); errno = 0;
    int rc = SSL_shutdown(session->ssl);
    int saved_errno = errno;
    if (rc == 1) return step_result(0, 0, lean_mk_string(""));
    if (rc == 0) return step_result(0, 1, lean_mk_string(""));
    int64_t value; uint8_t status; lean_object *message;
    classify(session->ssl, rc, saved_errno, &value, &status, &message);
    return step_result(value, status, message);
}

/* OpenSSL can buffer multiple complete records, including encrypted records
 * not reflected in SSL_pending. SSL_has_pending can also report a partial
 * record: after an attempted read returns WANT, suppress this hint until the
 * caller observes actual socket readiness and retries, preventing a spin. */
lean_object *lean_tls_pending(uint64_t handle) {
    if (handle == 0) return lean_io_result_mk_ok(number(-EINVAL));
    tls_session *session = (tls_session *)(uintptr_t)handle;
    if (session->read_pending) return lean_io_result_mk_ok(number(0));
    if (SSL_pending(session->ssl) > 0 || SSL_has_pending(session->ssl) == 1)
        return lean_io_result_mk_ok(number(1));
    return lean_io_result_mk_ok(number(0));
}
