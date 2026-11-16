/* Nonblocking upstream TLS client. OpenSSL owns memory BIOs, never a socket.
 * The gateway reactor owner feeds ciphertext and queues drained ciphertext;
 * every entry point is bounded and executes on that owner thread. */
#include <lean/lean.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum { TG_MAX_CHUNK = 65536, TG_MAX_PENDING = 262144 };

typedef struct { SSL_CTX *ssl; } tg_context;
typedef struct { SSL *ssl; BIO *read_bio, *write_bio; int ready, failed; } tg_session;

static lean_object *tg_pair(lean_object *left, lean_object *right) {
  lean_object *value = lean_alloc_ctor(0, 2, 0);
  lean_ctor_set(value, 0, left); lean_ctor_set(value, 1, right); return value;
}
static lean_object *tg_code(int64_t code, const char *message) {
  return lean_io_result_mk_ok(tg_pair(lean_box_uint64((uint64_t)code), lean_mk_string(message)));
}
static lean_object *tg_bytes(int64_t code, lean_object *bytes, const char *message) {
  return lean_io_result_mk_ok(tg_pair(lean_box_uint64((uint64_t)code),
    tg_pair(bytes, lean_mk_string(message))));
}
static lean_object *tg_empty(void) { return lean_alloc_sarray(1, 0, 0); }
static const char *tg_error(char buffer[256], const char *fallback) {
  unsigned long code = ERR_get_error();
  if (!code) return fallback;
  ERR_error_string_n(code, buffer, 256); ERR_clear_error(); return buffer;
}

/* A worker creates one context. Empty ca_file uses OpenSSL's configured trust
 * store; a supplied CA PEM replaces it and must load successfully. */
lean_object *lean_tg_context_new(b_lean_obj_arg ca_file) {
  const char *path = lean_string_cstr(ca_file);
  size_t size = lean_string_size(ca_file) - 1;
  if (strlen(path) != size) return tg_code(-1, "CA path contains NUL");
  ERR_clear_error();
  tg_context *context = calloc(1, sizeof(*context));
  if (!context) return tg_code(-1, "TLS context allocation failed");
  context->ssl = SSL_CTX_new(TLS_client_method());
  if (!context->ssl || SSL_CTX_set_min_proto_version(context->ssl, TLS1_2_VERSION) != 1 ||
      (size ? SSL_CTX_load_verify_locations(context->ssl, path, NULL) != 1 :
              SSL_CTX_set_default_verify_paths(context->ssl) != 1)) {
    char detail[256]; const char *error = tg_error(detail, "TLS trust store unavailable");
    lean_object *result = tg_code(-1, error);
    SSL_CTX_free(context->ssl); free(context); return result;
  }
  SSL_CTX_set_verify(context->ssl, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_options(context->ssl, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
  SSL_CTX_set_mode(context->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
  return tg_code((int64_t)(uintptr_t)context, "");
}

lean_object *lean_tg_context_free(uint64_t raw) {
  tg_context *context = (tg_context *)(uintptr_t)raw;
  if (!context) return lean_io_result_mk_ok(lean_box_uint64((uint64_t)-1));
  SSL_CTX_free(context->ssl); free(context);
  return lean_io_result_mk_ok(lean_box_uint64(0));
}

static int tg_valid_name(const char *name, size_t length) {
  if (!length || length > 253 || name[0] == '.' || name[length - 1] == '.') return 0;
  size_t label = 0;
  for (size_t i = 0; i < length; ++i) {
    unsigned char c = (unsigned char)name[i];
    if (c == '.') {
      if (i == label || i - label > 63 || name[i - 1] == '-') return 0;
      label = i + 1;
    } else if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                 (c >= '0' && c <= '9') || c == '-') ||
               (c == '-' && i == label)) return 0;
  }
  return length - label <= 63 && name[length - 1] != '-';
}

/* IP literals use iPAddress SAN verification and no SNI. Other names require
 * dNSName SAN/CN verification and send SNI. */
static int tg_ipv4_literal(const char *name) {
  int dots = 0, digits = 0, value = 0;
  for (const unsigned char *p = (const unsigned char *)name; *p; ++p) {
    if (*p == '.') {
      if (!digits || value > 255) return 0;
      ++dots; digits = 0; value = 0;
    } else if (*p >= '0' && *p <= '9') {
      if (digits == 3 || (!digits && *p == '0' && p[1] >= '0' && p[1] <= '9')) return 0;
      value = value * 10 + (*p - '0'); ++digits;
    } else return 0;
  }
  return dots == 3 && digits && value <= 255;
}

/* OpenSSL 4 separates DNS and IP reference identifiers and deprecates
 * SSL_set1_host. Numeric IPs take the dedicated verification path below. */
static int tg_set_dns_name(SSL *ssl, const char *name) {
#if OPENSSL_VERSION_NUMBER >= 0x40000000L
  return SSL_set1_dnsname(ssl, name);
#else
  return SSL_set1_host(ssl, name);
#endif
}

lean_object *lean_tg_session_new(uint64_t raw_context, b_lean_obj_arg verify_name) {
  tg_context *context = (tg_context *)(uintptr_t)raw_context;
  const char *name = lean_string_cstr(verify_name);
  size_t length = lean_string_size(verify_name) - 1;
  int ipv6 = memchr(name, ':', length) != NULL;
  if (!context || !length || length > 253 || strlen(name) != length ||
      (!ipv6 && !tg_valid_name(name, length)))
    return tg_code(-1, "invalid upstream TLS verification name");
  ERR_clear_error();
  tg_session *session = calloc(1, sizeof(*session));
  if (!session) return tg_code(-1, "TLS session allocation failed");
  session->ssl = SSL_new(context->ssl);
  BIO *read_bio = BIO_new(BIO_s_mem()), *write_bio = BIO_new(BIO_s_mem());
  if (!session->ssl || !read_bio || !write_bio) goto fail;
  BIO_set_mem_eof_return(read_bio, -1);
  session->read_bio = read_bio; session->write_bio = write_bio;
  SSL_set_bio(session->ssl, read_bio, write_bio);
  read_bio = write_bio = NULL; /* SSL now owns both BIOs. */
  SSL_set_connect_state(session->ssl);
  X509_VERIFY_PARAM *param = SSL_get0_param(session->ssl);
  X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
  if (ipv6 || tg_ipv4_literal(name)) {
    if (X509_VERIFY_PARAM_set1_ip_asc(param, name) != 1) goto fail;
  } else if (tg_set_dns_name(session->ssl, name) != 1 ||
             SSL_set_tlsext_host_name(session->ssl, name) != 1) goto fail;
  static const unsigned char alpn[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
  if (SSL_set_alpn_protos(session->ssl, alpn, sizeof(alpn)) != 0) goto fail;
  return tg_code((int64_t)(uintptr_t)session, "");
fail:
  {
    char detail[256]; const char *error = tg_error(detail, "upstream TLS session setup failed");
    lean_object *result = tg_code(-1, error);
    BIO_free(read_bio); BIO_free(write_bio); SSL_free(session->ssl); free(session); return result;
  }
}

lean_object *lean_tg_session_free(uint64_t raw) {
  tg_session *session = (tg_session *)(uintptr_t)raw;
  if (!session) return lean_io_result_mk_ok(lean_box_uint64((uint64_t)-1));
  SSL_free(session->ssl); free(session);
  return lean_io_result_mk_ok(lean_box_uint64(0));
}

/* 0 = needs more ciphertext/output drain; 1 = verified and ready; negative =
 * fatal. A peer that sends no certificate can never be considered ready. */
lean_object *lean_tg_handshake(uint64_t raw) {
  tg_session *session = (tg_session *)(uintptr_t)raw;
  if (!session || session->failed) return tg_code(-1, "invalid upstream TLS session");
  if (session->ready) return tg_code(1, "");
  ERR_clear_error();
  int rc = SSL_connect(session->ssl);
  if (rc == 1) {
    const unsigned char *alpn = NULL; unsigned int length = 0;
    SSL_get0_alpn_selected(session->ssl, &alpn, &length);
    /* SSL_get_peer_certificate is the reference-owning spelling shared by
     * the package's OpenSSL 1.1.1 minimum and OpenSSL 3.x. */
    X509 *peer = SSL_get_peer_certificate(session->ssl);
    int verified = peer && SSL_get_verify_result(session->ssl) == X509_V_OK &&
      (!length || (length == 8 && memcmp(alpn, "http/1.1", 8) == 0));
    X509_free(peer);
    if (!verified) { session->failed = 1; return tg_code(-1, "upstream TLS peer or ALPN verification failed"); }
    session->ready = 1; return tg_code(1, "");
  }
  int error = SSL_get_error(session->ssl, rc);
  if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) return tg_code(0, "");
  session->failed = 1;
  char detail[256]; return tg_code(-1, tg_error(detail, "upstream TLS handshake failed"));
}

lean_object *lean_tg_feed(uint64_t raw, b_lean_obj_arg bytes) {
  tg_session *session = (tg_session *)(uintptr_t)raw;
  if (!session || session->failed) return tg_code(-1, "invalid upstream TLS session");
  size_t length = lean_sarray_size(bytes);
  if (!length || length > TG_MAX_CHUNK || BIO_ctrl_pending(session->read_bio) > TG_MAX_PENDING - length) {
    session->failed = 1;
    return tg_code(-1, "upstream TLS ciphertext feed exceeds bound");
  }
  if (BIO_write(session->read_bio, lean_sarray_cptr(bytes), (int)length) != (int)length) {
    session->failed = 1;
    return tg_code(-1, "upstream TLS ciphertext feed failed");
  }
  return tg_code((int64_t)length, "");
}

lean_object *lean_tg_drain(uint64_t raw) {
  tg_session *session = (tg_session *)(uintptr_t)raw;
  if (!session || session->failed) return tg_bytes(-1, tg_empty(), "invalid upstream TLS session");
  size_t pending = BIO_ctrl_pending(session->write_bio);
  if (!pending) return tg_bytes(0, tg_empty(), "");
  size_t length = pending < TG_MAX_CHUNK ? pending : TG_MAX_CHUNK;
  lean_object *bytes = lean_alloc_sarray(1, length, length);
  int count = BIO_read(session->write_bio, lean_sarray_cptr(bytes), (int)length);
  if (count <= 0) { session->failed = 1; lean_dec(bytes); return tg_bytes(-1, tg_empty(), "upstream TLS ciphertext drain failed"); }
  lean_sarray_set_size(bytes, (size_t)count);
  return tg_bytes(count, bytes, "");
}

/* 0 = authenticated close_notify, -2 = WANT_READ/WRITE, -1 = fatal. */
lean_object *lean_tg_read(uint64_t raw, uint32_t maximum) {
  tg_session *session = (tg_session *)(uintptr_t)raw;
  if (!session || !session->ready || session->failed || !maximum || maximum > TG_MAX_CHUNK)
    return tg_bytes(-1, tg_empty(), "invalid upstream TLS plaintext read");
  lean_object *bytes = lean_alloc_sarray(1, maximum, maximum);
  ERR_clear_error();
  int count = SSL_read(session->ssl, lean_sarray_cptr(bytes), (int)maximum);
  if (count > 0) {
    lean_sarray_set_size(bytes, (size_t)count); return tg_bytes(count, bytes, "");
  }
  lean_dec(bytes);
  int error = SSL_get_error(session->ssl, count);
  if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) return tg_bytes(-2, tg_empty(), "");
  if (error == SSL_ERROR_ZERO_RETURN) return tg_bytes(0, tg_empty(), "");
  session->failed = 1;
  char detail[256]; return tg_bytes(-1, tg_empty(), tg_error(detail, "upstream TLS read failed"));
}

lean_object *lean_tg_write(uint64_t raw, b_lean_obj_arg bytes) {
  tg_session *session = (tg_session *)(uintptr_t)raw;
  size_t length = lean_sarray_size(bytes);
  if (!session || !session->ready || session->failed || !length || length > 16384 ||
      BIO_ctrl_pending(session->write_bio) > TG_MAX_PENDING - 16384) {
    if (session) session->failed = 1;
    return tg_code(-1, "invalid or overflowing upstream TLS write");
  }
  ERR_clear_error();
  int count = SSL_write(session->ssl, lean_sarray_cptr(bytes), (int)length);
  if (count > 0) return tg_code(count, "");
  int error = SSL_get_error(session->ssl, count);
  if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) return tg_code(-2, "");
  session->failed = 1;
  char detail[256]; return tg_code(-1, tg_error(detail, "upstream TLS write failed"));
}

/* Reuse is safe only after a complete HTTP response and this TLS state check.
 * The caller also checks parser bytes and reactor socket liveness. */
lean_object *lean_tg_clean(uint64_t raw) {
  tg_session *session = (tg_session *)(uintptr_t)raw;
  int clean = session && session->ready && !session->failed &&
    !(SSL_get_shutdown(session->ssl) & SSL_RECEIVED_SHUTDOWN) &&
    !SSL_has_pending(session->ssl) &&
    BIO_ctrl_pending(session->read_bio) == 0 && BIO_ctrl_pending(session->write_bio) == 0;
  return lean_io_result_mk_ok(lean_box_uint64(clean ? 1 : 0));
}

lean_object *lean_tg_cipher_pending(uint64_t raw) {
  tg_session *session = (tg_session *)(uintptr_t)raw;
  if (!session || session->failed) return lean_io_result_mk_ok(lean_box_uint64((uint64_t)-1));
  return lean_io_result_mk_ok(lean_box_uint64((uint64_t)BIO_ctrl_pending(session->write_bio)));
}

lean_object *lean_tg_shutdown(uint64_t raw) {
  tg_session *session = (tg_session *)(uintptr_t)raw;
  if (!session || !session->ready || session->failed) return tg_code(-1, "invalid upstream TLS shutdown");
  ERR_clear_error();
  int rc = SSL_shutdown(session->ssl);
  if (rc == 1) return tg_code(1, "");
  if (rc == 0) return tg_code(0, "");
  int error = SSL_get_error(session->ssl, rc);
  if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) return tg_code(0, "");
  session->failed = 1;
  char detail[256]; return tg_code(-1, tg_error(detail, "upstream TLS shutdown failed"));
}
