/* Optional OpenSSL transport. All SSL/BIO operations run on one dedicated
 * native thread. Only the bridge below may touch Lean and the reactor. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#include "tls_worker.h"
#include "../../c/reactor.h"
#include "../../c/reactor_lean.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <errno.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#endif

#define TW_NONE UINT32_MAX
#define TW_MAX_SESSIONS 1000000u
#define TW_MAX_QUEUE 256u
#define TW_MAX_CERTS 256u
#define TW_BIO_CAPACITY 17408u
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "TLS byte lanes need lock-free indices");

typedef struct tw_context {
  SSL_CTX *ssl;
  char *name;
  unsigned char identity[SHA256_DIGEST_LENGTH];
} tw_context;
typedef struct tw_bundle {
  atomic_uint references;
  uint32_t count;
  tw_context *contexts;
} tw_bundle;
typedef struct tw_cell {
  uint64_t operation, fence;
  uint32_t length;
  unsigned char bytes[TLSW_CELL_SIZE];
} tw_cell;
typedef struct tw_lane {
  atomic_uint head, tail;
  uint32_t capacity;
  tw_cell *cells;
} tw_lane;
enum tw_state { TW_FREE, TW_OPEN, TW_ACTIVE, TW_DONE };
typedef struct tw_session {
  /* Owner publishes OPEN; thread publishes ACTIVE/DONE; owner recycles FREE
   * only after DONE and all lane ownership has returned. */
  atomic_uint state;
  atomic_int cancel, peer_eof, shutdown, ready, ready_ack, eof;
  atomic_uint_fast64_t close_deadline;
  uint32_t generation;
  tw_lane cipher_in, plain_in, cipher_out, plain_out, fences;
  SSL *ssl;
  BIO *network;
  uint64_t started, produced, close_fence, handshake_fence, fatal_deadline;
  uint32_t plain_offset, bio_count;
  int write_complete, read_want_write, eof_applied, handshake_complete,
      fatal, shutdown_sent;
  int error, protocol;
  char diagnostic[256];
  uint32_t seen_cipher, seen_plain, seen_cipher_tail, seen_plain_tail,
      seen_fence_tail;
  int more;
} tw_session;
typedef struct tw_engine {
  tw_bundle *bundle;
  rn_waker *reactor_waker;
  uint32_t count, queue_capacity;
  uint64_t handshake_ms, shutdown_ms;
  tw_session *sessions;
  atomic_int stop, wake_error;
  atomic_uint notifications, running;
  atomic_uint_fast64_t ssl_calls, owner_violations;
  atomic_uint live_ssl, live_bios;
#ifdef _WIN32
  HANDLE thread, wake;
  DWORD thread_id;
#else
  pthread_t thread;
  int wake_read, wake_write, thread_started;
#endif
} tw_engine;
typedef struct tw_bridge_session {
  uint64_t connection, capability, cipher_buffer, plain_buffer, cipher_operation;
  uint64_t cipher_ack;
  uint32_t generation, cipher_length;
  int used, ready_sent, eof_sent, error_sent, aborted, reading,
      native_closed, drain_sent, plain_borrowed;
} tw_bridge_session;
typedef struct tw_bridge {
  tw_engine *engine;
  rn_reactor *reactor;
  lean_object *reactor_record;
  tw_bridge_session *sessions;
  rn_event *events;
  unsigned char *event_claimed;
  uint32_t event_count, event_capacity;
  uint64_t serial;
} tw_bridge;
static _Thread_local tw_engine *tw_current_engine;
static void tw_note_ssl(tw_engine *engine) {
  atomic_fetch_add(&engine->ssl_calls, 1);
  if (tw_current_engine != engine) atomic_fetch_add(&engine->owner_violations, 1);
}

static lean_object *tw_number(int64_t n) { return lean_box_uint64((uint64_t)n); }
static lean_object *tw_result(int64_t n) { return lean_io_result_mk_ok(tw_number(n)); }
static lean_object *tw_handle(int64_t n, const char *message) {
  lean_object *pair = lean_alloc_ctor(0, 2, 0);
  lean_ctor_set(pair, 0, tw_number(n));
  lean_ctor_set(pair, 1, lean_mk_string(message));
  return lean_io_result_mk_ok(pair);
}
static void tw_diagnostic(char out[256], const char *fallback) {
  unsigned long detail = ERR_get_error();
  if (detail) ERR_error_string_n(detail, out, 256);
  else { size_t n = strlen(fallback); if (n > 255) n = 255; memcpy(out, fallback, n); out[n] = 0; }
  ERR_clear_error();
}
static uint64_t tw_token(uint32_t i, uint32_t generation) {
  return ((uint64_t)generation << 32) | ((uint64_t)i + 1);
}
static tw_cell *tw_producer(tw_lane *lane) {
  uint32_t head = atomic_load_explicit(&lane->head, memory_order_relaxed);
  uint32_t tail = atomic_load_explicit(&lane->tail, memory_order_acquire);
  uint32_t count = head >= tail ? head - tail : head + 2u * lane->capacity - tail;
  return count < lane->capacity ? &lane->cells[head % lane->capacity] : NULL;
}
static tw_cell *tw_consumer(tw_lane *lane) {
  uint32_t tail = atomic_load_explicit(&lane->tail, memory_order_relaxed);
  uint32_t head = atomic_load_explicit(&lane->head, memory_order_acquire);
  return head != tail ? &lane->cells[tail % lane->capacity] : NULL;
}
static void tw_publish(tw_lane *lane) {
  uint32_t head = atomic_load_explicit(&lane->head, memory_order_relaxed);
  atomic_store_explicit(&lane->head, head + 1 == 2u * lane->capacity ? 0 : head + 1, memory_order_release);
}
static void tw_consume(tw_lane *lane) {
  uint32_t tail = atomic_load_explicit(&lane->tail, memory_order_relaxed);
  atomic_store_explicit(&lane->tail, tail + 1 == 2u * lane->capacity ? 0 : tail + 1, memory_order_release);
}
static int tw_lane_new(tw_lane *lane, uint32_t capacity) {
  atomic_init(&lane->head, 0); atomic_init(&lane->tail, 0);
  lane->capacity = capacity;
  lane->cells = calloc(capacity, sizeof(*lane->cells));
  return lane->cells ? 0 : -ENOMEM;
}
static void tw_lane_reset(tw_lane *lane) {
  atomic_store(&lane->head, 0); atomic_store(&lane->tail, 0);
}
static void tw_bundle_release(tw_bundle *bundle) {
  if (atomic_fetch_sub(&bundle->references, 1) != 1) return;
  for (uint32_t i = 0; bundle->contexts && i < bundle->count; ++i) {
    SSL_CTX_free(bundle->contexts[i].ssl); free(bundle->contexts[i].name);
  }
  free(bundle->contexts); free(bundle);
}
static int tw_password(char *buffer, int size, int writing, void *argument) {
  (void)buffer; (void)size; (void)writing; (void)argument; return 0;
}
static int tw_hostname(const unsigned char *name, size_t length, char out[254]) {
  if (!length || length > 253) return 0;
  for (size_t i = 0; i < length; ++i) {
    unsigned char c = name[i];
    if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + ('a' - 'A'));
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.')) return 0;
    out[i] = (char)c;
  }
  out[length] = 0; return 1;
}
static int tw_client_hello(SSL *ssl, int *alert, void *argument) {
  tw_bundle *bundle = argument;
  const unsigned char *extension = NULL; size_t length = 0;
  char host[254] = {0}; size_t host_length = 0;
  if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &extension, &length)) {
    if (length < 5 || (((size_t)extension[0] << 8) | extension[1]) != length - 2 || extension[2] != TLSEXT_NAMETYPE_host_name) goto invalid;
    host_length = ((size_t)extension[3] << 8) | extension[4];
    if (host_length != length - 5 || !tw_hostname(extension + 5, host_length, host)) goto invalid;
  }
  uint32_t selected = 0;
  for (uint32_t i = 1; i < bundle->count; ++i)
    if (strcmp(host, bundle->contexts[i].name) == 0) { selected = i; break; }
  tw_context *context = &bundle->contexts[selected];
  if (SSL_set_SSL_CTX(ssl, context->ssl) == NULL) goto invalid;
  unsigned char identity[SHA256_DIGEST_LENGTH + 253], digest[SHA256_DIGEST_LENGTH];
  memcpy(identity, context->identity, SHA256_DIGEST_LENGTH);
  memcpy(identity + SHA256_DIGEST_LENGTH, host, host_length);
  if (SHA256(identity, SHA256_DIGEST_LENGTH + host_length, digest) == NULL ||
      SSL_set_session_id_context(ssl, digest, sizeof(digest)) != 1) goto invalid;
  return SSL_CLIENT_HELLO_SUCCESS;
invalid:
  *alert = SSL_AD_DECODE_ERROR; return SSL_CLIENT_HELLO_ERROR;
}
static int tw_servername(SSL *ssl, int *alert, void *argument) {
  (void)alert; (void)argument;
  return SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name) ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_NOACK;
}
static int tw_alpn(SSL *ssl, const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int length, void *argument) {
  (void)ssl; (void)argument;
  const unsigned char *h2 = NULL, *http1 = NULL;
  for (unsigned int i = 0; i < length;) {
    unsigned int n = in[i++];
    if (!n || n > length - i) return SSL_TLSEXT_ERR_ALERT_FATAL;
    if (n == 2 && memcmp(in + i, "h2", 2) == 0) h2 = in + i;
    if (n == 8 && memcmp(in + i, "http/1.1", 8) == 0) http1 = in + i;
    i += n;
  }
  if (h2) { *out = h2; *outlen = 2; return SSL_TLSEXT_ERR_OK; }
  if (http1) { *out = http1; *outlen = 8; return SSL_TLSEXT_ERR_OK; }
  return SSL_TLSEXT_ERR_ALERT_FATAL;
}
lean_object *lean_tlsw_bundle_new(b_lean_obj_arg cert, b_lean_obj_arg key,
    b_lean_obj_arg names, b_lean_obj_arg certs, b_lean_obj_arg keys, uint8_t tickets) {
  size_t extra = lean_array_size(names);
  if (extra >= TW_MAX_CERTS || extra != lean_array_size(certs) || extra != lean_array_size(keys) || tickets > 1)
    return tw_handle(-EINVAL, "invalid TLS certificate table");
  tw_bundle *bundle = calloc(1, sizeof(*bundle));
  if (!bundle) return tw_handle(-ENOMEM, "allocating TLS contexts");
  atomic_init(&bundle->references, 1); bundle->count = (uint32_t)extra + 1;
  bundle->contexts = calloc(bundle->count, sizeof(*bundle->contexts));
  if (!bundle->contexts) { free(bundle); return tw_handle(-ENOMEM, "allocating TLS contexts"); }
  char message[256] = "TLS context setup failed"; int error = EINVAL;
  ERR_clear_error();
  for (uint32_t i = 0; i < bundle->count; ++i) {
    tw_context *context = &bundle->contexts[i];
    lean_object *certificate = i ? lean_array_uget_borrowed(certs, i - 1) : (lean_object *)cert;
    lean_object *private_key = i ? lean_array_uget_borrowed(keys, i - 1) : (lean_object *)key;
    if (i) {
      lean_object *name = lean_array_uget_borrowed(names, i - 1); char hostname[254];
      size_t n = lean_string_size(name) - 1;
      if (!tw_hostname((const unsigned char *)lean_string_cstr(name), n, hostname)) goto failure;
      context->name = malloc(n + 1); if (!context->name) { error = ENOMEM; goto failure; }
      memcpy(context->name, hostname, n + 1);
      for (uint32_t previous = 1; previous < i; ++previous)
        if (strcmp(bundle->contexts[previous].name, context->name) == 0) goto failure;
    }
    if (strlen(lean_string_cstr(certificate)) + 1 != lean_string_size(certificate) ||
        strlen(lean_string_cstr(private_key)) + 1 != lean_string_size(private_key)) goto failure;
    context->ssl = SSL_CTX_new(TLS_server_method());
    if (!context->ssl) { error = ENOMEM; goto failure; }
    SSL_CTX_set_default_passwd_cb(context->ssl, tw_password);
    if (SSL_CTX_set_min_proto_version(context->ssl, TLS1_2_VERSION) != 1 ||
        SSL_CTX_use_certificate_chain_file(context->ssl, lean_string_cstr(certificate)) != 1 ||
        SSL_CTX_use_PrivateKey_file(context->ssl, lean_string_cstr(private_key), SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(context->ssl) != 1) goto failure;
    unsigned int digest_length = 0;
    if (X509_digest(SSL_CTX_get0_certificate(context->ssl), EVP_sha256(), context->identity, &digest_length) != 1 || digest_length != sizeof(context->identity)) goto failure;
    uint64_t options = SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION;
#ifdef SSL_OP_SERVER_PREFERENCE
    options |= SSL_OP_SERVER_PREFERENCE;
#else
    options |= SSL_OP_CIPHER_SERVER_PREFERENCE;
#endif
    if (!tickets) options |= SSL_OP_NO_TICKET;
    SSL_CTX_set_options(context->ssl, options);
    SSL_CTX_set_mode(context->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_CTX_set_session_cache_mode(context->ssl, SSL_SESS_CACHE_SERVER);
    SSL_CTX_sess_set_cache_size(context->ssl, 4096);
    SSL_CTX_set_timeout(context->ssl, 300);
    if (SSL_CTX_set_session_id_context(context->ssl, context->identity, sizeof(context->identity)) != 1 ||
        SSL_CTX_set_num_tickets(context->ssl, tickets ? 2 : 0) != 1) goto failure;
    SSL_CTX_set_alpn_select_cb(context->ssl, tw_alpn, bundle);
    SSL_CTX_set_client_hello_cb(context->ssl, tw_client_hello, bundle);
    SSL_CTX_set_tlsext_servername_callback(context->ssl, tw_servername);
    SSL_CTX_set_tlsext_servername_arg(context->ssl, bundle);
  }
  if ((uintptr_t)bundle > INT64_MAX) { error = EOVERFLOW; goto failure; }
  return tw_handle((int64_t)(uintptr_t)bundle, "");
failure:
  tw_diagnostic(message, "invalid TLS certificate, key or server name");
  tw_bundle_release(bundle); return tw_handle(-error, message);
}
lean_object *lean_tlsw_bundle_free(uint64_t handle) {
  if (!handle) return tw_result(-EINVAL);
  tw_bundle_release((tw_bundle *)(uintptr_t)handle); return tw_result(0);
}

static void tw_notify_thread(tw_engine *engine) {
  atomic_fetch_add_explicit(&engine->notifications, 1, memory_order_release);
#ifdef _WIN32
  if (!SetEvent(engine->wake)) { int expected = 0; (void)atomic_compare_exchange_strong(&engine->wake_error, &expected, -EIO); }
#else
  unsigned char byte = 1; ssize_t result = write(engine->wake_write, &byte, 1);
  if (result < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
    int expected = 0; (void)atomic_compare_exchange_strong(&engine->wake_error, &expected, -errno);
  }
#endif
}
static void tw_notify_reactor(tw_engine *engine) {
  int result = rn_waker_wake(engine->reactor_waker);
  if (result && result != -ECANCELED) { int expected = 0; (void)atomic_compare_exchange_strong(&engine->wake_error, &expected, result); }
}
static void tw_finish(tw_engine *engine, tw_session *session, int error, const char *reason) {
  tw_note_ssl(engine);
  session->error = error;
  if (error && !session->fatal) tw_diagnostic(session->diagnostic, reason);
  if (session->ssl) atomic_fetch_sub(&engine->live_ssl, 1);
  SSL_free(session->ssl); session->ssl = NULL;
  BIO_free(session->network); session->network = NULL;
  if (session->bio_count) atomic_fetch_sub(&engine->live_bios, session->bio_count);
  session->bio_count = 0;
  atomic_store_explicit(&session->state, TW_DONE, memory_order_release);
  tw_notify_reactor(engine);
}
static int tw_classify(tw_session *session, int result) {
  int error = SSL_get_error(session->ssl, result);
  if (error == SSL_ERROR_WANT_READ) return 1;
  if (error == SSL_ERROR_WANT_WRITE) return 2;
  if (error == SSL_ERROR_ZERO_RETURN) return 3;
  unsigned long detail = ERR_peek_last_error();
  int reason = detail ? ERR_GET_REASON(detail) : 0;
  if (reason == ERR_R_MALLOC_FAILURE) return -ENOMEM;
#ifdef ERR_R_INTERNAL_ERROR
  if (reason == ERR_R_INTERNAL_ERROR) return -EIO;
#endif
  return -EPROTO;
}
static int tw_feed_bio(tw_session *session) {
  int progress = 0; tw_cell *cell;
  while ((cell = tw_consumer(&session->cipher_in)) != NULL) {
    size_t count = 0;
    if (BIO_write_ex(session->network, cell->bytes + cell->fence, cell->length - (size_t)cell->fence, &count) != 1 || !count) break;
    cell->fence += count; progress = 1;
    if (cell->fence == cell->length) tw_consume(&session->cipher_in);
  }
  if (atomic_load(&session->peer_eof) && !session->eof_applied && !tw_consumer(&session->cipher_in)) {
    (void)BIO_shutdown_wr(session->network); session->eof_applied = 1; progress = 1;
  }
  return progress;
}
static int tw_drain_bio(tw_engine *engine, tw_session *session) {
  int progress = 0; tw_cell *cell;
  while (BIO_ctrl_pending(session->network) && (cell = tw_producer(&session->cipher_out)) != NULL) {
    size_t count = 0;
    if (BIO_read_ex(session->network, cell->bytes, sizeof(cell->bytes), &count) != 1 || !count) break;
    if (session->produced > INT64_MAX - count) return -EOVERFLOW;
    session->produced += count; cell->length = (uint32_t)count; cell->fence = session->produced;
    tw_publish(&session->cipher_out); progress = 1; tw_notify_reactor(engine);
  }
  return progress;
}
static void tw_fail(tw_engine *engine, tw_session *session, int error, const char *reason) {
  if (!session->fatal) {
    session->fatal = 1; session->error = error;
    session->fatal_deadline = rn_now_ms() + engine->shutdown_ms;
    tw_diagnostic(session->diagnostic, reason);
  }
  int drained = session->network ? tw_drain_bio(engine, session) : 0;
  if (drained < 0 || rn_now_ms() >= session->fatal_deadline || !session->network || !BIO_ctrl_pending(session->network)) {
    session->close_fence = session->produced;
    tw_finish(engine, session, session->error, reason);
  }
}
static int tw_open_session(tw_engine *engine, tw_session *session) {
  tw_note_ssl(engine);
  session->ssl = NULL; session->network = NULL; session->bio_count = 0;
  session->fatal = session->error = 0; session->diagnostic[0] = 0;
  ERR_clear_error(); session->ssl = SSL_new(engine->bundle->contexts[0].ssl);
  if (session->ssl) atomic_fetch_add(&engine->live_ssl, 1);
  BIO *internal = NULL;
  if (!session->ssl || BIO_new_bio_pair(&internal, TW_BIO_CAPACITY, &session->network, TW_BIO_CAPACITY) != 1) {
    BIO_free(internal); tw_finish(engine, session, -ENOMEM, "allocating TLS session"); return 0;
  }
  session->bio_count = 2; atomic_fetch_add(&engine->live_bios, 2);
  SSL_set_bio(session->ssl, internal, internal); SSL_set_accept_state(session->ssl);
  session->started = rn_now_ms(); session->produced = session->close_fence = session->handshake_fence = session->fatal_deadline = 0;
  session->plain_offset = 0; session->write_complete = session->read_want_write = session->eof_applied = 0;
  session->handshake_complete = session->fatal = session->shutdown_sent = 0;
  session->error = session->protocol = 0; session->diagnostic[0] = 0;
  session->more = 1;
  atomic_store_explicit(&session->state, TW_ACTIVE, memory_order_release); return 1;
}
static void tw_drive(tw_engine *engine, tw_session *session) {
  if (atomic_load_explicit(&session->state, memory_order_acquire) == TW_OPEN && !tw_open_session(engine, session)) return;
  if (atomic_load(&session->state) != TW_ACTIVE) return;
  if (atomic_load(&session->cancel)) { tw_finish(engine, session, 0, ""); return; }
  if (session->fatal) { tw_fail(engine, session, session->error, "TLS protocol operation failed"); return; }
  uint64_t now = rn_now_ms();
  if (!atomic_load(&session->ready_ack) && now - session->started >= engine->handshake_ms) { tw_fail(engine, session, -ETIMEDOUT, "TLS handshake timed out"); return; }
  if (atomic_load(&session->shutdown) && now >= atomic_load(&session->close_deadline)) {
    session->close_fence = session->produced;
    tw_finish(engine, session, 0, ""); return;
  }
  uint32_t cipher = atomic_load(&session->cipher_in.head), plain = atomic_load(&session->plain_in.head),
      cipher_tail = atomic_load(&session->cipher_out.tail), plain_tail = atomic_load(&session->plain_out.tail),
      fence_tail = atomic_load(&session->fences.tail);
  int changed = session->more || cipher != session->seen_cipher || plain != session->seen_plain ||
      cipher_tail != session->seen_cipher_tail || plain_tail != session->seen_plain_tail || fence_tail != session->seen_fence_tail ||
      (atomic_load(&session->peer_eof) && !session->eof_applied) ||
      (atomic_load(&session->shutdown) && !session->shutdown_sent);
  session->seen_cipher = cipher; session->seen_plain = plain; session->seen_cipher_tail = cipher_tail;
  session->seen_plain_tail = plain_tail; session->seen_fence_tail = fence_tail; session->more = 0;
  if (!changed) return;
  for (unsigned budget = 0; budget < 16; ++budget) {
    int input = tw_feed_bio(session), output = tw_drain_bio(engine, session);
    if (input) tw_notify_reactor(engine);
    if (output < 0) { tw_fail(engine, session, output, "TLS ciphertext counter exhausted"); return; }
    if (BIO_ctrl_pending(session->network)) return;
    if (session->handshake_complete && !atomic_load(&session->ready)) {
      session->handshake_fence = session->produced;
      atomic_store_explicit(&session->ready, 1, memory_order_release);
      tw_notify_reactor(engine);
    }
    if (session->write_complete) {
      tw_cell *fence = tw_producer(&session->fences), *source = tw_consumer(&session->plain_in);
      if (!fence || !source) return;
      fence->operation = source->operation; fence->length = source->length; fence->fence = session->produced;
      tw_publish(&session->fences); tw_consume(&session->plain_in);
      session->write_complete = 0; session->plain_offset = 0; tw_notify_reactor(engine);
    }
    int rc, status; size_t count = 0;
    ERR_clear_error();
    tw_note_ssl(engine);
    if (!session->handshake_complete) {
      rc = SSL_accept(session->ssl);
      if (rc == 1) {
        const unsigned char *protocol = NULL; unsigned int n = 0;
        SSL_get0_alpn_selected(session->ssl, &protocol, &n);
        session->protocol = n == 2 && memcmp(protocol, "h2", 2) == 0 ? 2 : 1;
        session->handshake_complete = 1; session->more = 1; continue;
      }
      status = tw_classify(session, rc);
    } else if (tw_consumer(&session->plain_in) && !session->read_want_write) {
      tw_cell *source = tw_consumer(&session->plain_in);
      if (source->length == 0) { session->write_complete = 1; session->more = 1; continue; }
      rc = SSL_write_ex(session->ssl, source->bytes + session->plain_offset, source->length - session->plain_offset, &count);
      if (rc == 1) {
        if (!count || count > source->length - session->plain_offset) { tw_fail(engine, session, -EIO, "invalid TLS write count"); return; }
        session->plain_offset += (uint32_t)count;
        if (session->plain_offset == source->length) session->write_complete = 1;
        session->more = 1; continue;
      }
      status = tw_classify(session, rc);
    } else if (atomic_load(&session->shutdown) && !tw_consumer(&session->plain_in) && !session->read_want_write) {
      rc = SSL_shutdown(session->ssl);
      if (rc >= 0) {
        output = tw_drain_bio(engine, session);
        if (output < 0) { tw_fail(engine, session, output, "TLS ciphertext counter exhausted"); return; }
        session->shutdown_sent = (SSL_get_shutdown(session->ssl) & SSL_SENT_SHUTDOWN) != 0;
        if (rc == 1 && !BIO_ctrl_pending(session->network)) {
          session->close_fence = session->produced; tw_finish(engine, session, 0, ""); return;
        }
        return;
      }
      status = tw_classify(session, rc);
    } else {
      tw_cell *destination = tw_producer(&session->plain_out);
      if (!destination || atomic_load(&session->eof)) return;
      rc = SSL_read_ex(session->ssl, destination->bytes, sizeof(destination->bytes), &count);
      if (rc == 1) {
        session->read_want_write = 0;
        if (!count || count > sizeof(destination->bytes)) { tw_fail(engine, session, -EIO, "invalid TLS read count"); return; }
        destination->length = (uint32_t)count; tw_publish(&session->plain_out); tw_notify_reactor(engine); session->more = 1; continue;
      }
      status = tw_classify(session, rc); session->read_want_write = status == 2;
      if (status == 3) { atomic_store(&session->eof, 1); tw_notify_reactor(engine); return; }
    }
    if (status < 0 || status == 3) { tw_fail(engine, session, status < 0 ? status : -EPROTO, "TLS protocol operation failed"); return; }
    output = tw_drain_bio(engine, session);
    if (output < 0) { tw_fail(engine, session, output, "TLS ciphertext counter exhausted"); return; }
    if (input || output) { session->more = 1; continue; }
    session->more = 0; return;
  }
  session->more = 1;
}
static void tw_run(tw_engine *engine) {
  tw_current_engine = engine;
  atomic_store(&engine->running, 1);
  while (!atomic_load_explicit(&engine->stop, memory_order_acquire)) {
    uint32_t notification = atomic_load_explicit(&engine->notifications, memory_order_acquire);
    int more = 0;
    for (uint32_t i = 0; i < engine->count; ++i) { tw_drive(engine, &engine->sessions[i]); if (engine->sessions[i].more && atomic_load(&engine->sessions[i].state) == TW_ACTIVE) more = 1; }
    if (more) continue;
#ifdef _WIN32
    (void)ResetEvent(engine->wake);
    if (notification == atomic_load_explicit(&engine->notifications, memory_order_acquire) && !atomic_load(&engine->stop)) (void)WaitForSingleObject(engine->wake, 20);
#else
    unsigned char bytes[128]; while (read(engine->wake_read, bytes, sizeof(bytes)) > 0) {}
    if (notification == atomic_load_explicit(&engine->notifications, memory_order_acquire) && !atomic_load(&engine->stop)) { struct pollfd fd = {engine->wake_read, POLLIN, 0}; (void)poll(&fd, 1, 20); }
#endif
  }
  for (uint32_t i = 0; i < engine->count; ++i) {
    tw_session *session = &engine->sessions[i];
    if (session->ssl || session->network) tw_finish(engine, session, 0, "");
  }
  OPENSSL_thread_stop(); atomic_store(&engine->running, 0); tw_current_engine = NULL;
}
#ifdef _WIN32
static DWORD WINAPI tw_entry(LPVOID argument) { tw_run(argument); return 0; }
#else
static void *tw_entry(void *argument) { tw_run(argument); return NULL; }
#endif

static void tw_engine_delete(tw_engine *engine) {
  if (!engine) return;
  for (uint32_t i = 0; engine->sessions && i < engine->count; ++i) {
    tw_session *session = &engine->sessions[i];
    free(session->cipher_in.cells); free(session->plain_in.cells); free(session->cipher_out.cells);
    free(session->plain_out.cells); free(session->fences.cells);
  }
#ifdef _WIN32
  if (engine->thread) CloseHandle(engine->thread);
  if (engine->wake) CloseHandle(engine->wake);
#else
  if (engine->wake_read >= 0) (void)close(engine->wake_read);
  if (engine->wake_write >= 0) (void)close(engine->wake_write);
#endif
  if (engine->reactor_waker) (void)rn_waker_release(engine->reactor_waker);
  if (engine->bundle) tw_bundle_release(engine->bundle);
  free(engine->sessions); free(engine);
}
static void tw_release_events(tw_bridge *bridge) {
  for (uint32_t i = 0; i < bridge->event_count; ++i) {
    rn_event *event = &bridge->events[i]; uint32_t index = (uint32_t)event->connection - 1;
    if (event->kind == TLSW_READ && !bridge->event_claimed[i] && index < bridge->engine->count &&
        bridge->sessions[index].generation == (uint32_t)(event->connection >> 32))
      bridge->sessions[index].plain_borrowed = 0;
  }
  bridge->event_count = 0;
}
static int tw_bridge_delete(tw_bridge *bridge) {
  if (!bridge) return 0;
  tw_engine *engine = bridge->engine; int error = 0;
  if (engine) {
    atomic_store_explicit(&engine->stop, 1, memory_order_release); tw_notify_thread(engine);
#ifdef _WIN32
    if (engine->thread && WaitForSingleObject(engine->thread, INFINITE) != WAIT_OBJECT_0) return -EIO;
#else
    if (engine->thread_started && pthread_join(engine->thread, NULL) != 0) return -EIO;
#endif
    if (atomic_load(&engine->live_ssl) || atomic_load(&engine->live_bios)) error = -EIO;
  }
  tw_release_events(bridge);
  if (bridge->sessions) for (uint32_t i = 0; engine && i < engine->count; ++i) {
    if (bridge->sessions[i].cipher_buffer) {
      int result = rn_buffer_release(bridge->reactor, bridge->sessions[i].cipher_buffer);
      if (result && !error) error = result;
    }
    if (bridge->sessions[i].plain_buffer) {
      int result = rn_buffer_release(bridge->reactor, bridge->sessions[i].plain_buffer);
      if (result && !error) error = result;
    }
  }
  /* Returned READ leases belong to the Lean dispatcher, not this bridge. */
  if (bridge->reactor_record) lean_dec(bridge->reactor_record);
  tw_engine_delete(engine); free(bridge->sessions); free(bridge->events); free(bridge->event_claimed); free(bridge); return error;
}
lean_object *lean_tlsw_worker_new(uint64_t bundle_handle, b_lean_obj_arg reactor,
    uint32_t count, uint32_t capacity, uint64_t handshake_ms, uint64_t shutdown_ms) {
  if (!bundle_handle || !count || count > TW_MAX_SESSIONS || !capacity || capacity > TW_MAX_QUEUE || !handshake_ms || !shutdown_ms || handshake_ms > INT64_MAX || shutdown_ms > INT64_MAX)
    return tw_handle(-EINVAL, "invalid TLS worker limits");
  rn_reactor *native = NULL; int error = rn_bridge_reactor(reactor, &native);
  if (error) return tw_handle(error, "invalid TLS reactor");
  tw_bridge *bridge = calloc(1, sizeof(*bridge)); tw_engine *engine = calloc(1, sizeof(*engine));
  if (!bridge || !engine) { free(bridge); free(engine); return tw_handle(-ENOMEM, "allocating TLS worker"); }
  bridge->engine = engine; bridge->reactor = native;
  atomic_init(&engine->stop, 0); atomic_init(&engine->wake_error, 0); atomic_init(&engine->notifications, 0); atomic_init(&engine->running, 0);
  atomic_init(&engine->ssl_calls, 0); atomic_init(&engine->owner_violations, 0);
  atomic_init(&engine->live_ssl, 0); atomic_init(&engine->live_bios, 0);
#ifndef _WIN32
  engine->wake_read = engine->wake_write = -1;
#endif
  engine->count = count; engine->queue_capacity = capacity; engine->handshake_ms = handshake_ms; engine->shutdown_ms = shutdown_ms;
  engine->bundle = (tw_bundle *)(uintptr_t)bundle_handle; atomic_fetch_add(&engine->bundle->references, 1);
  bridge->reactor_record = (lean_object *)reactor; lean_inc(bridge->reactor_record);
  engine->sessions = calloc(count, sizeof(*engine->sessions)); bridge->sessions = calloc(count, sizeof(*bridge->sessions));
  bridge->event_capacity = count > UINT32_MAX / 8 ? 0 : count * 8;
  bridge->events = calloc(bridge->event_capacity, sizeof(*bridge->events));
  bridge->event_claimed = calloc(bridge->event_capacity, 1);
  if (!engine->sessions || !bridge->sessions || !bridge->events || !bridge->event_claimed) { error = -ENOMEM; goto failure; }
  error = rn_waker_acquire(native, &engine->reactor_waker); if (error) goto failure;
  for (uint32_t i = 0; i < count; ++i) {
    tw_session *session = &engine->sessions[i];
    atomic_init(&session->state, TW_FREE); atomic_init(&session->cancel, 0); atomic_init(&session->peer_eof, 0);
    atomic_init(&session->shutdown, 0); atomic_init(&session->ready, 0); atomic_init(&session->ready_ack, 0); atomic_init(&session->eof, 0); atomic_init(&session->close_deadline, 0);
    if (tw_lane_new(&session->cipher_in, capacity) || tw_lane_new(&session->plain_in, capacity) ||
        tw_lane_new(&session->cipher_out, capacity) || tw_lane_new(&session->plain_out, capacity) || tw_lane_new(&session->fences, capacity)) { error = -ENOMEM; goto failure; }
    error = rn_acquire_buffer(native, TLSW_CELL_SIZE, &bridge->sessions[i].cipher_buffer); if (error) goto failure;
    error = rn_acquire_buffer(native, TLSW_CELL_SIZE, &bridge->sessions[i].plain_buffer); if (error) goto failure;
  }
#ifdef _WIN32
  engine->wake = CreateEventW(NULL, TRUE, FALSE, NULL); if (!engine->wake) { error = -EIO; goto failure; }
  engine->thread = CreateThread(NULL, 0, tw_entry, engine, 0, &engine->thread_id); if (!engine->thread) { error = -EIO; goto failure; }
#else
  int descriptors[2]; if (pipe(descriptors) < 0) { error = -errno; goto failure; }
  engine->wake_read = descriptors[0]; engine->wake_write = descriptors[1];
  for (unsigned i = 0; i < 2; ++i) {
    int flags = fcntl(descriptors[i], F_GETFL);
    if (flags < 0 || fcntl(descriptors[i], F_SETFL, flags | O_NONBLOCK) < 0 || fcntl(descriptors[i], F_SETFD, FD_CLOEXEC) < 0) { error = -errno; goto failure; }
  }
  error = pthread_create(&engine->thread, NULL, tw_entry, engine); if (error) { error = -error; goto failure; } engine->thread_started = 1;
#endif
  if ((uintptr_t)bridge > INT64_MAX) { error = -EOVERFLOW; goto failure; }
  return tw_handle((int64_t)(uintptr_t)bridge, "");
failure:
  (void)tw_bridge_delete(bridge); return tw_handle(error, "TLS worker setup failed");
}
lean_object *lean_tlsw_worker_free(uint64_t handle) {
  return tw_result(handle ? tw_bridge_delete((tw_bridge *)(uintptr_t)handle) : -EINVAL);
}
static tw_bridge_session *tw_find(tw_bridge *bridge, uint64_t token, tw_session **out) {
  uint32_t i = (uint32_t)token - 1;
  if (!token || i >= bridge->engine->count) return NULL;
  tw_bridge_session *session = &bridge->sessions[i];
  if (!session->used || session->generation != (uint32_t)(token >> 32)) return NULL;
  *out = &bridge->engine->sessions[i]; return session;
}
lean_object *lean_tlsw_attach(uint64_t handle, b_lean_obj_arg wire) {
  if (!handle) return tw_result(-EINVAL);
  tw_bridge *bridge = (tw_bridge *)(uintptr_t)handle; rn_reactor *reactor = NULL; uint64_t connection, capability;
  int error = rn_bridge_wire(wire, &reactor, &connection, &capability);
  if (error || reactor != bridge->reactor) return tw_result(error ? error : -EINVAL);
  for (uint32_t i = 0; i < bridge->engine->count; ++i)
    if (bridge->sessions[i].used && bridge->sessions[i].connection == connection) return tw_result(-EALREADY);
  for (uint32_t i = 0; i < bridge->engine->count; ++i) {
    tw_bridge_session *owner = &bridge->sessions[i]; tw_session *session = &bridge->engine->sessions[i];
    if (owner->used || atomic_load_explicit(&session->state, memory_order_acquire) != TW_FREE || owner->generation == INT32_MAX) continue;
    uint64_t cipher_buffer = owner->cipher_buffer, plain_buffer = owner->plain_buffer; uint32_t generation = owner->generation + 1;
    memset(owner, 0, sizeof(*owner)); owner->generation = generation; owner->cipher_buffer = cipher_buffer;
    owner->plain_buffer = plain_buffer;
    owner->connection = connection; owner->capability = capability; owner->used = owner->reading = 1;
    tw_lane_reset(&session->cipher_in); tw_lane_reset(&session->plain_in); tw_lane_reset(&session->cipher_out); tw_lane_reset(&session->plain_out); tw_lane_reset(&session->fences);
    session->generation = generation; session->seen_cipher = session->seen_plain = session->seen_cipher_tail = session->seen_plain_tail = session->seen_fence_tail = 0;
    atomic_store(&session->cancel, 0); atomic_store(&session->peer_eof, 0); atomic_store(&session->shutdown, 0); atomic_store(&session->ready, 0); atomic_store(&session->ready_ack, 0); atomic_store(&session->eof, 0);
    atomic_store_explicit(&session->state, TW_OPEN, memory_order_release); tw_notify_thread(bridge->engine);
    return tw_result((int64_t)tw_token(i, generation));
  }
  return tw_result(-EAGAIN);
}
static int tw_input(tw_bridge *bridge, uint64_t token, b_lean_obj_arg buffer,
    uint32_t offset, uint32_t length, uint64_t operation, int plain) {
  tw_session *session = NULL; tw_bridge_session *owner = tw_find(bridge, token, &session);
  if (!owner) return -EINVAL;
  if (owner->aborted || atomic_load(&session->state) == TW_DONE) return plain ? 1 : 0;
  if (plain && (!atomic_load_explicit(&session->ready, memory_order_acquire) || atomic_load(&session->shutdown))) return -EINVAL;
  uint64_t lease; int error = rn_bridge_buffer(buffer, bridge->reactor, &lease); if (error) return error;
  lean_object *bytes = NULL; error = rn_buffer_view(bridge->reactor, lease, &bytes); if (error) return error;
  size_t size = lean_sarray_size(bytes);
  if (offset > size || length > size - offset || (plain && length > TLSW_CELL_SIZE)) return -EINVAL;
  tw_lane *lane = plain ? &session->plain_in : &session->cipher_in;
  tw_cell *cell = tw_producer(lane); if (!cell) return plain ? 1 : 0;
  uint32_t count = length < TLSW_CELL_SIZE ? length : TLSW_CELL_SIZE;
  memcpy(cell->bytes, lean_sarray_cptr(bytes) + offset, count); cell->length = count; cell->operation = operation; cell->fence = 0;
  tw_publish(lane); tw_notify_thread(bridge->engine); return plain ? 0 : (int)count;
}
lean_object *lean_tlsw_feed(uint64_t handle, uint64_t session, b_lean_obj_arg buffer, uint32_t offset, uint32_t length) {
  return tw_result(handle ? tw_input((tw_bridge *)(uintptr_t)handle, session, buffer, offset, length, 0, 0) : -EINVAL);
}
lean_object *lean_tlsw_write(uint64_t handle, uint64_t session, b_lean_obj_arg buffer, uint32_t offset, uint32_t length, uint64_t operation) {
  return tw_result(handle ? tw_input((tw_bridge *)(uintptr_t)handle, session, buffer, offset, length, operation, 1) : -EINVAL);
}
lean_object *lean_tlsw_peer_eof(uint64_t handle, uint64_t token) {
  if (!handle) return tw_result(-EINVAL);
  tw_bridge *bridge = (tw_bridge *)(uintptr_t)handle; tw_session *session = NULL;
  if (!tw_find(bridge, token, &session)) return tw_result(-EINVAL);
  atomic_store(&session->peer_eof, 1); tw_notify_thread(bridge->engine); return tw_result(0);
}
lean_object *lean_tlsw_shutdown(uint64_t handle, uint64_t token) {
  if (!handle) return tw_result(-EINVAL);
  tw_bridge *bridge = (tw_bridge *)(uintptr_t)handle; tw_session *session = NULL;
  if (!tw_find(bridge, token, &session)) return tw_result(-EINVAL);
  if (!atomic_load(&session->shutdown)) {
    uint64_t now = rn_now_ms(); atomic_store(&session->close_deadline, now + bridge->engine->shutdown_ms);
    atomic_store(&session->shutdown, 1);
  }
  tw_notify_thread(bridge->engine); return tw_result(0);
}
lean_object *lean_tlsw_abort(uint64_t handle, uint64_t token) {
  if (!handle) return tw_result(-EINVAL);
  tw_bridge *bridge = (tw_bridge *)(uintptr_t)handle; tw_session *session = NULL;
  tw_bridge_session *owner = tw_find(bridge, token, &session);
  if (!owner) return tw_result(0);
  if (owner->aborted) return tw_result(0);
  owner->aborted = 1;
  atomic_store(&session->cancel, 1); tw_notify_thread(bridge->engine);
  int live = rn_connection_live(bridge->reactor, owner->connection);
  int result = live > 0 ? rn_transport_abort(bridge->reactor, owner->connection, owner->capability) : 0;
  return tw_result(result);
}
lean_object *lean_tlsw_native_closed(uint64_t handle, uint64_t token) {
  if (!handle) return tw_result(-EINVAL);
  tw_bridge *bridge = (tw_bridge *)(uintptr_t)handle; tw_session *session = NULL;
  tw_bridge_session *owner = tw_find(bridge, token, &session); if (!owner) return tw_result(0);
  owner->aborted = owner->native_closed = 1;
  owner->cipher_operation = 0; owner->cipher_length = 0;
  atomic_store(&session->cancel, 1); tw_notify_thread(bridge->engine); return tw_result(0);
}
lean_object *lean_tlsw_release_plain(uint64_t handle, uint64_t token) {
  if (!handle) return tw_result(-EINVAL);
  tw_bridge *bridge = (tw_bridge *)(uintptr_t)handle; tw_session *session = NULL;
  tw_bridge_session *owner = tw_find(bridge, token, &session); if (!owner) return tw_result(0);
  owner->plain_borrowed = 0; tw_notify_thread(bridge->engine); return tw_result(0);
}
lean_object *lean_tlsw_read_enabled(uint64_t handle, uint64_t token, uint8_t enabled) {
  if (!handle || enabled > 1) return tw_result(-EINVAL);
  tw_bridge *bridge = (tw_bridge *)(uintptr_t)handle; tw_session *session = NULL;
  tw_bridge_session *owner = tw_find(bridge, token, &session); if (!owner) return tw_result(-EINVAL);
  owner->reading = enabled; tw_notify_thread(bridge->engine); return tw_result(0);
}
static int tw_emit(tw_bridge *bridge, uint32_t index, uint32_t kind, uint64_t operation, uint64_t buffer, int64_t result, uint32_t flags, uint32_t length) {
  if (bridge->event_count == bridge->event_capacity) return 0;
  tw_bridge_session *owner = &bridge->sessions[index];
  bridge->event_claimed[bridge->event_count] = 0;
  bridge->events[bridge->event_count++] = (rn_event){tw_token(index, owner->generation), operation, buffer, result, kind, flags, 0, length}; return 1;
}
static int tw_would_block(int error) { return error == -EAGAIN || error == -EWOULDBLOCK || error == -EBUSY; }
lean_object *lean_tlsw_pump(uint64_t handle) {
  if (!handle) return tw_result(-EINVAL);
  tw_bridge *bridge = (tw_bridge *)(uintptr_t)handle; tw_release_events(bridge); tw_engine *engine = bridge->engine;
  int wake_error = atomic_exchange(&engine->wake_error, 0); if (wake_error) return tw_result(wake_error);
  for (uint32_t i = 0; i < engine->count; ++i) {
    tw_bridge_session *owner = &bridge->sessions[i]; tw_session *session = &engine->sessions[i]; if (!owner->used) continue;
    uint32_t state = atomic_load_explicit(&session->state, memory_order_acquire);
    if (owner->aborted) {
      while (tw_consumer(&session->cipher_out)) tw_consume(&session->cipher_out);
      while (tw_consumer(&session->plain_out)) tw_consume(&session->plain_out);
      while (tw_consumer(&session->fences)) tw_consume(&session->fences);
      if (state == TW_DONE && owner->native_closed && !owner->plain_borrowed) { owner->used = 0; atomic_store_explicit(&session->state, TW_FREE, memory_order_release); }
      continue;
    }
    /* The permanent plaintext lease cannot be consumed by raw native reads.
     * Lean delivery borrows it until the explicit generation-checked ACK. */
    if (atomic_load_explicit(&session->ready, memory_order_acquire) && !owner->ready_sent && owner->cipher_ack >= session->handshake_fence) {
      if (tw_emit(bridge, i, TLSW_READY, 0, 0, 0, (uint32_t)session->protocol, 0)) {
        owner->ready_sent = 1; atomic_store(&session->ready_ack, 1); tw_notify_thread(engine);
      }
    }
    tw_cell *cell = tw_consumer(&session->cipher_out);
    if (cell && !owner->cipher_operation) {
      int error = rn_buffer_copy(bridge->reactor, owner->cipher_buffer, cell->bytes, cell->length);
      if (!error) {
        if (bridge->serial == (UINT64_C(1) << 43) - 1) return tw_result(-EOVERFLOW);
        uint64_t operation = TLSW_CIPHER_OPERATION | (++bridge->serial << 20) | ((uint64_t)i + 1);
        error = rn_transport_write(bridge->reactor, owner->connection, owner->capability, owner->cipher_buffer, 0, cell->length, operation);
        if (!error) { owner->cipher_operation = operation; owner->cipher_length = cell->length; tw_consume(&session->cipher_out); tw_notify_thread(engine); }
      }
      if (error && !tw_would_block(error)) {
        uint32_t flags = error == -EACCES || error == -EINVAL || error == -ENOMEM || error == -EIO || error == -EOVERFLOW ? RN_SETUP_ERROR : 0;
        if (tw_emit(bridge, i, TLSW_ERROR, 0, 0, error, flags, 0)) owner->error_sent = 1;
        /* The owning dispatcher calls abort after observing ERROR. Keep that
         * first abort actionable so it still closes the physical capability. */
        atomic_store(&session->cancel, 1); tw_notify_thread(engine); continue;
      }
    }
    while (owner->ready_sent && owner->reading && (cell = tw_consumer(&session->plain_out)) != NULL && bridge->event_count < bridge->event_capacity) {
      if (owner->plain_borrowed) break;
      uint64_t buffer = owner->plain_buffer;
      lean_object *view = NULL;
      int viewed = rn_buffer_view(bridge->reactor, buffer, &view);
      if (viewed) return tw_result(viewed);
      if (!lean_is_exclusive(view)) break;
      int error = rn_buffer_copy(bridge->reactor, buffer, cell->bytes, cell->length);
      if (tw_would_block(error)) break;
      if (error) return tw_result(error);
      if (!tw_emit(bridge, i, TLSW_READ, 0, buffer, cell->length, 0, cell->length)) break;
      owner->plain_borrowed = 1;
      tw_consume(&session->plain_out); tw_notify_thread(engine);
    }
    while ((cell = tw_consumer(&session->fences)) != NULL && cell->fence <= owner->cipher_ack) {
      if (!tw_emit(bridge, i, TLSW_WRITTEN, cell->operation, 0, cell->length, 0, cell->length)) break;
      tw_consume(&session->fences); tw_notify_thread(engine);
    }
    if (atomic_load(&session->eof) && !owner->eof_sent && !tw_consumer(&session->plain_out)) {
      if (tw_emit(bridge, i, TLSW_EOF, 0, 0, 0, 0, 0)) owner->eof_sent = 1;
    }
    if (state == TW_DONE) {
      if (session->error && !owner->error_sent &&
          (owner->cipher_ack >= session->close_fence || rn_now_ms() >= session->fatal_deadline)) {
        uint32_t flags = session->error == -ENOMEM || session->error == -EIO || session->error == -EOVERFLOW ? RN_SETUP_ERROR : 0;
        if (tw_emit(bridge, i, TLSW_ERROR, 0, 0, session->error, flags, 0)) owner->error_sent = 1;
      }
      if (!session->error && !owner->drain_sent && !owner->cipher_operation && !tw_consumer(&session->cipher_out) && !tw_consumer(&session->plain_out) && !tw_consumer(&session->fences) &&
          !owner->plain_borrowed && owner->cipher_ack >= session->close_fence) {
        int error = rn_transport_drain(bridge->reactor, owner->connection, owner->capability);
        if (error) return tw_result(error);
        owner->drain_sent = 1;
      }
    }
  }
  return tw_result(bridge->event_count);
}
lean_object *lean_tlsw_event(uint64_t handle, uint32_t index) {
  rn_event invalid = {0}; invalid.kind = TLSW_ERROR; invalid.result = -EINVAL;
  tw_bridge *bridge = (tw_bridge *)(uintptr_t)handle;
  const rn_event *event = bridge && index < bridge->event_count ? &bridge->events[index] : &invalid;
  lean_object *result = lean_alloc_ctor(0, 0, 48);
  lean_ctor_set_uint64(result, 0, event->connection); lean_ctor_set_uint64(result, 8, event->operation);
  lean_ctor_set_uint64(result, 16, event->buffer); lean_ctor_set_uint64(result, 24, (uint64_t)event->result);
  lean_ctor_set_uint32(result, 32, event->kind); lean_ctor_set_uint32(result, 36, event->flags);
  lean_ctor_set_uint32(result, 40, event->offset); lean_ctor_set_uint32(result, 44, event->length);
  return lean_io_result_mk_ok(result);
}
lean_object *lean_tlsw_event_buffer(uint64_t handle, uint32_t index) {
  tw_bridge *bridge = (tw_bridge *)(uintptr_t)handle;
  if (!bridge || index >= bridge->event_count || bridge->events[index].kind != TLSW_READ || bridge->event_claimed[index])
    return lean_io_result_mk_error(lean_mk_io_user_error(lean_mk_string("invalid TLS READ event")));
  lean_object *buffer = NULL; int error = rn_bridge_make_buffer(bridge->reactor_record, bridge->events[index].buffer, &buffer);
  if (error) return lean_io_result_mk_error(lean_mk_io_user_error(lean_mk_string("TLS READ lease is stale")));
  bridge->event_claimed[index] = 1;
  return lean_io_result_mk_ok(buffer);
}
lean_object *lean_tlsw_on_written(uint64_t handle, uint64_t operation, uint64_t count) {
  if (!handle || !(operation & TLSW_CIPHER_OPERATION)) return tw_result(-EINVAL);
  tw_bridge *bridge = (tw_bridge *)(uintptr_t)handle; uint32_t i = (uint32_t)(operation & ((UINT64_C(1) << 20) - 1)) - 1;
  if (i >= bridge->engine->count) return tw_result(-EINVAL);
  tw_bridge_session *owner = &bridge->sessions[i];
  if (!owner->used || owner->aborted || owner->cipher_operation != operation) return tw_result(0);
  if (count != owner->cipher_length) return tw_result(-EIO);
  owner->cipher_ack += count; owner->cipher_operation = 0; owner->cipher_length = 0;
  tw_notify_thread(bridge->engine); return tw_result(0);
}
lean_object *lean_tlsw_has_work(uint64_t handle) {
  if (!handle) return tw_result(-EINVAL);
  tw_bridge *bridge = (tw_bridge *)(uintptr_t)handle;
  if (atomic_load(&bridge->engine->wake_error)) return tw_result(1);
  for (uint32_t i = 0; i < bridge->engine->count; ++i) {
    tw_bridge_session *owner = &bridge->sessions[i]; tw_session *session = &bridge->engine->sessions[i]; if (!owner->used) continue;
    if (!owner->plain_borrowed && owner->reading && tw_consumer(&session->plain_out)) {
      lean_object *bytes = NULL;
      if (rn_buffer_view(bridge->reactor, owner->plain_buffer, &bytes) == 0 && lean_is_exclusive(bytes)) return tw_result(1);
    }
    if ((atomic_load(&session->ready) && !owner->ready_sent && owner->cipher_ack >= session->handshake_fence) ||
        (tw_consumer(&session->cipher_out) && !owner->cipher_operation) ||
        (atomic_load(&session->eof) && !owner->eof_sent && !tw_consumer(&session->plain_out)) ||
        (atomic_load(&session->state) == TW_DONE && ((!owner->error_sent && session->error &&
          (owner->cipher_ack >= session->close_fence || rn_now_ms() >= session->fatal_deadline)) || (owner->aborted && owner->native_closed)))) return tw_result(1);
    tw_cell *fence = tw_consumer(&session->fences); if (fence && fence->fence <= owner->cipher_ack) return tw_result(1);
  }
  return tw_result(0);
}
lean_object *lean_tlsw_stats(uint64_t handle) {
  if (!handle) return lean_io_result_mk_error(lean_mk_io_user_error(lean_mk_string("invalid TLS worker")));
  tw_engine *engine = ((tw_bridge *)(uintptr_t)handle)->engine;
  lean_object *result = lean_alloc_ctor(0, 0, 24);
  lean_ctor_set_uint64(result, 0, atomic_load(&engine->ssl_calls));
  lean_ctor_set_uint64(result, 8, atomic_load(&engine->owner_violations));
  lean_ctor_set_uint64(result, 16, atomic_load(&engine->running));
  return lean_io_result_mk_ok(result);
}
