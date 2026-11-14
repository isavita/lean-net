/* Actual native worker/bridge ownership under ASan and the Lean allocator. */
#include "../../c/reactor_posix.c"
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdio.h>
static int fail_join;
static int fail_cipher;
static void (*ssl_error_hook)(SSL *, int);
static int test_ssl_get_error(SSL *ssl, int result) {
  int error = SSL_get_error(ssl, result);
  if (ssl_error_hook) ssl_error_hook(ssl, error);
  return error;
}
static int test_join(pthread_t thread, void **result) {
  if (fail_join) { fail_join = 0; return EDEADLK; }
  return pthread_join(thread, result);
}
static int test_cipher_write(rn_reactor *reactor, uint64_t connection, uint64_t capability,
    uint64_t buffer, uint32_t offset, uint32_t length, uint64_t operation) {
  if (fail_cipher) { fail_cipher = 0; return -ENOMEM; }
  return rn_transport_write(reactor, connection, capability, buffer, offset, length, operation);
}
#define pthread_join test_join
#define rn_transport_write test_cipher_write
#define SSL_get_error test_ssl_get_error
#include "../c/tls_worker.c"
#undef pthread_join
#undef rn_transport_write
#undef SSL_get_error
void lean_initialize_runtime_module(void);

static void check(int condition, const char *message) {
  if (!condition) { fprintf(stderr, "TLS worker native: %s\n", message); exit(1); }
}
static int64_t result(lean_object *value) {
  check(lean_io_result_is_ok(value), "native scalar IO result");
  int64_t n = (int64_t)lean_unbox_uint64(lean_io_result_get_value(value)); lean_dec(value); return n;
}
static uint64_t handle(lean_object *value) {
  check(lean_io_result_is_ok(value), "native handle IO result");
  lean_object *pair = lean_io_result_get_value(value);
  int64_t n = (int64_t)lean_unbox_uint64(lean_ctor_get(pair, 0));
  if (n <= 0) fprintf(stderr, "%s\n", lean_string_cstr(lean_ctor_get(pair, 1)));
  check(n > 0, "native handle creation"); lean_dec(value); return (uint64_t)n;
}
static lean_object *reactor_record(rn_reactor *reactor) {
  lean_object *record = lean_alloc_ctor(0, 1, 8);
  lean_ctor_set(record, 0, lean_st_mk_ref(lean_box(1)));
  lean_ctor_set_uint64(record, sizeof(void *), (uint64_t)(uintptr_t)reactor); return record;
}
static lean_object *wire_record(lean_object *reactor, uint64_t connection, uint64_t capability) {
  lean_object *socket = lean_alloc_ctor(0, 1, 8); lean_inc(reactor); lean_ctor_set(socket, 0, reactor);
  lean_ctor_set_uint64(socket, sizeof(void *), connection);
  lean_object *record = lean_alloc_ctor(0, 1, 9); lean_ctor_set(record, 0, socket);
  lean_ctor_set_uint64(record, sizeof(void *), capability);
  lean_ctor_set_uint8(record, sizeof(void *) + 8, 1); return record;
}
static void queue_wrap(void) {
  tw_lane lane = {0}; check(tw_lane_new(&lane, 3) == 0, "allocate queue3");
  /* Every six publications wraps a bounded cursor, including non-powers2. */
  for (uint32_t round = 0; round < 10000; ++round) {
    for (uint32_t i = 0; i < 3; ++i) {
      tw_cell *cell = tw_producer(&lane); check(cell != NULL, "queue3 credit");
      cell->operation = (uint64_t)round * 3 + i; tw_publish(&lane);
    }
    check(tw_producer(&lane) == NULL, "queue3 bounded pressure");
    for (uint32_t i = 0; i < 3; ++i) {
      tw_cell *cell = tw_consumer(&lane);
      check(cell && cell->operation == (uint64_t)round * 3 + i, "queue3 wrap preserves FIFO"); tw_consume(&lane);
    }
    check(tw_consumer(&lane) == NULL, "queue3 empties");
  }
  free(lane.cells);
}
static tw_engine *wrap_engine;
static tw_session *wrap_session;
static unsigned char wrap_cipher[TLSW_CELL_SIZE];
static size_t wrap_cipher_length;
static int wrap_injected;
/* Deterministically interleave the reactor producer after SSL_read has already
 * reported WANT_READ, but before the drive decides whether it made progress. */
static void publish_wrapped_input(SSL *ssl, int error) {
  if (ssl != wrap_session->ssl || error != SSL_ERROR_WANT_READ) return;
  ssl_error_hook = NULL;
  uint32_t head = atomic_load(&wrap_session->cipher_in.head);
  tw_cell *cell = tw_producer(&wrap_session->cipher_in);
  check(cell != NULL && wrap_cipher_length > 1, "prepare forced queue1 wrap");
  cell->bytes[0] = wrap_cipher[0]; cell->length = 1; cell->fence = 0;
  tw_publish(&wrap_session->cipher_in); tw_notify_session(wrap_engine, wrap_session);
  check(tw_feed_bio(wrap_session) && !tw_consumer(&wrap_session->cipher_in), "first wrapped input reaches real BIO");
  cell = tw_producer(&wrap_session->cipher_in);
  check(cell != NULL, "first queue1 credit returned during drive");
  memcpy(cell->bytes, wrap_cipher + 1, wrap_cipher_length - 1);
  cell->length = (uint32_t)(wrap_cipher_length - 1); cell->fence = 0;
  tw_publish(&wrap_session->cipher_in); tw_notify_session(wrap_engine, wrap_session);
  check(atomic_load(&wrap_session->cipher_in.head) == head &&
      tw_consumer(&wrap_session->cipher_in) != NULL, "bounded input cursor returns to its snapshot with data pending");
  wrap_injected = 1;
}
static void drive_notification_wrap(const char *certificate, const char *key) {
  lean_object *cert = lean_mk_string(certificate), *secret = lean_mk_string(key), *empty = lean_mk_empty_array();
  uint64_t bundle = handle(lean_tlsw_bundle_new(cert, secret, empty, empty, empty, 1));
  lean_dec(cert); lean_dec(secret); lean_dec(empty);
  rn_config config = {1, 8, 1, 2, 0, 0, 1}; rn_reactor *reactor = NULL;
  check(rn_new(&config, &reactor) == 0, "create forced-wrap reactor");
  tw_engine engine = {0}; tw_session session = {0};
  atomic_init(&engine.stop, 0); atomic_init(&engine.wake_error, 0);
  atomic_init(&engine.notifications, 0); atomic_init(&engine.running, 0);
  atomic_init(&engine.ssl_calls, 0); atomic_init(&engine.owner_violations, 0);
  atomic_init(&engine.live_ssl, 0); atomic_init(&engine.live_bios, 0);
  engine.bundle = (tw_bundle *)(uintptr_t)bundle; engine.sessions = &session; engine.count = engine.queue_capacity = 1;
  engine.handshake_ms = 5000; engine.shutdown_ms = 1000;
  check(rn_waker_acquire(reactor, &engine.reactor_waker) == 0, "forced-wrap reactor waker");
  int wake[2]; check(pipe(wake) == 0 && rn_nonblocking(wake[0]) == 0 && rn_nonblocking(wake[1]) == 0, "forced-wrap worker wake pipe");
  engine.wake_read = wake[0]; engine.wake_write = wake[1];
  atomic_init(&session.state, TW_OPEN); atomic_init(&session.notifications, 0);
  atomic_init(&session.cancel, 0); atomic_init(&session.peer_eof, 0);
  atomic_init(&session.shutdown, 0); atomic_init(&session.ready, 0); atomic_init(&session.ready_ack, 0);
  atomic_init(&session.eof, 0); atomic_init(&session.close_deadline, 0);
  check(tw_lane_new(&session.cipher_in, 1) == 0 && tw_lane_new(&session.plain_in, 1) == 0 &&
      tw_lane_new(&session.cipher_out, 1) == 0 && tw_lane_new(&session.plain_out, 1) == 0 &&
      tw_lane_new(&session.fences, 1) == 0, "forced-wrap one-cell lanes");
  SSL_CTX *client_context = SSL_CTX_new(TLS_client_method());
  SSL *client = client_context ? SSL_new(client_context) : NULL;
  BIO *input = BIO_new(BIO_s_mem()), *output = BIO_new(BIO_s_mem());
  check(client && input && output, "forced-wrap client memory BIOs");
  SSL_set_bio(client, input, output); SSL_set_connect_state(client);
  tw_current_engine = &engine;
  int client_ready = 0, server_ready = 0;
  for (unsigned iteration = 0; iteration < 10000; ++iteration) {
    if (!client_ready) {
      ERR_clear_error(); int rc = SSL_do_handshake(client);
      if (rc == 1) client_ready = 1;
      else { int e = SSL_get_error(client, rc); check(e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE, "forced-wrap client handshake"); }
    }
    tw_cell *cell = tw_producer(&session.cipher_in);
    if (cell && BIO_ctrl_pending(output)) {
      int n = BIO_read(output, cell->bytes, sizeof(cell->bytes)); check(n > 0, "forced-wrap client handshake output");
      cell->length = (uint32_t)n; cell->fence = 0; tw_publish(&session.cipher_in); tw_notify_session(&engine, &session);
    }
    tw_drive(&engine, &session);
    while ((cell = tw_consumer(&session.cipher_out)) != NULL) {
      check(BIO_write(input, cell->bytes, cell->length) == (int)cell->length, "forced-wrap server handshake output");
      tw_consume(&session.cipher_out); tw_notify_session(&engine, &session);
    }
    if (atomic_load(&session.ready)) { atomic_store(&session.ready_ack, 1); server_ready = 1; }
    if (client_ready && server_ready && !tw_consumer(&session.cipher_in) && !BIO_ctrl_pending(output) &&
        !BIO_ctrl_pending(session.network)) break;
  }
  check(client_ready && server_ready, "forced-wrap handshake completes");
  tw_drive(&engine, &session); tw_drive(&engine, &session);
  const unsigned char expected[] = "queue1-notification-wrap"; size_t count = 0;
  check(SSL_write_ex(client, expected, sizeof(expected), &count) == 1 && count == sizeof(expected), "forced-wrap real encrypted record");
  int encrypted = BIO_read(output, wrap_cipher, sizeof(wrap_cipher));
  check(encrypted > 1 && !BIO_ctrl_pending(output), "forced-wrap encrypted record fits one lane cell");
  wrap_cipher_length = (size_t)encrypted; wrap_engine = &engine; wrap_session = &session; wrap_injected = 0;
  atomic_store(&engine.notifications, UINT32_MAX - 1);
  atomic_store(&session.notifications, UINT32_MAX - 1); session.more = 1;
  ssl_error_hook = publish_wrapped_input;
  tw_drive(&engine, &session);
  check(wrap_injected && !session.more && tw_consumer(&session.cipher_in), "forced wrap lands at no-progress WANT_READ return");
  tw_drive(&engine, &session);
  tw_cell *plain = tw_consumer(&session.plain_out);
  check(!tw_consumer(&session.cipher_in) && plain && plain->length == sizeof(expected) &&
      memcmp(plain->bytes, expected, sizeof(expected)) == 0, "notification drives queued ciphertext after queue1 cursor ABA");
  tw_consume(&session.plain_out); tw_notify_session(&engine, &session);
  tw_drive(&engine, &session); tw_drive(&engine, &session);
  check(SSL_write_ex(client, expected, sizeof(expected), &count) == 1 && count == sizeof(expected), "prepare partial-record idle check");
  encrypted = BIO_read(output, wrap_cipher, sizeof(wrap_cipher));
  check(encrypted > 3, "partial encrypted record contains more than its prefix");
  tw_cell *partial = tw_producer(&session.cipher_in); check(partial != NULL, "partial-record input credit");
  memcpy(partial->bytes, wrap_cipher, 3); partial->length = 3; partial->fence = 0;
  tw_publish(&session.cipher_in); tw_notify_session(&engine, &session);
  tw_drive(&engine, &session); tw_drive(&engine, &session);
  uint64_t calls = atomic_load(&engine.ssl_calls);
  for (unsigned iteration = 0; iteration < 100; ++iteration) tw_drive(&engine, &session);
  check(atomic_load(&engine.ssl_calls) == calls && !session.more, "idle partial-record reads do not spin after notification progress");
  tw_notify_thread(&engine);
  tw_drive(&engine, &session);
  check(atomic_load(&engine.ssl_calls) == calls, "another session's engine wake does not retry idle SSL reads");
  tw_finish(&engine, &session, 0, ""); tw_current_engine = NULL;
  SSL_free(client); SSL_CTX_free(client_context);
  free(session.cipher_in.cells); free(session.plain_in.cells); free(session.cipher_out.cells);
  free(session.plain_out.cells); free(session.fences.cells);
  check(close(wake[0]) == 0 && close(wake[1]) == 0, "close forced-wrap worker pipe");
  rn_waker_release(engine.reactor_waker); check(rn_free(reactor) == 0, "free forced-wrap reactor");
  check(result(lean_tlsw_bundle_free(bundle)) == 0, "free forced-wrap context");
}
typedef struct pending { uint64_t lease; uint32_t offset, length; } pending;
static void exercise(const char *certificate, const char *key, uint32_t capacity) {
  lean_object *cert = lean_mk_string(certificate), *secret = lean_mk_string(key), *empty = lean_mk_empty_array();
  uint64_t bundle = handle(lean_tlsw_bundle_new(cert, secret, empty, empty, empty, 1));
  lean_dec(cert); lean_dec(secret); lean_dec(empty);
  rn_config config = {1, 32, 8, 4, 0, 0, 1}; rn_reactor *reactor = NULL;
  check(rn_new(&config, &reactor) == 0, "create four-cell reactor");
  int peers[2]; check(socketpair(AF_UNIX, SOCK_STREAM, 0, peers) == 0 && rn_nonblocking(peers[0]) == 0 && rn_nonblocking(peers[1]) == 0, "create nonblocking native transport");
  uint64_t connection = 0, capability = 0;
  check(rn_socket_new(reactor, &connection) == 0, "create connection token");
  reactor->connections[rn_index(connection)].fd = peers[0]; reactor->connections[rn_index(connection)].state = 4;
  check(rn_interest(reactor, rn_index(connection), 1) == 0 && rn_transport_claim(reactor, connection, &capability) == 0, "claim socketpair transport");
  lean_object *record = reactor_record(reactor), *wire = wire_record(record, connection, capability);
  for (unsigned overflow = 0; overflow < 2; ++overflow) {
    lean_object *bad = lean_tlsw_worker_new(bundle, record, 1, capacity, overflow ? 1000 : UINT64_MAX, overflow ? UINT64_MAX : 1000);
    check(lean_io_result_is_ok(bad) && (int64_t)lean_unbox_uint64(lean_ctor_get(lean_io_result_get_value(bad), 0)) == -EINVAL, "overflowing TLS deadlines rejected before thread creation"); lean_dec(bad);
  }
  uint64_t worker = handle(lean_tlsw_worker_new(bundle, record, 1, capacity, 5000, 1000));
  rn_reactor *checked_reactor = NULL; uint64_t checked_connection = 0, checked_capability = 0;
  int wire_check = rn_bridge_wire(wire, &checked_reactor, &checked_connection, &checked_capability);
  check(wire_check == 0, "native opaque wire fixture ABI");
  int64_t attached = result(lean_tlsw_attach(worker, wire)); check(attached > 0, "attach TLS session"); uint64_t session = (uint64_t)attached; lean_dec(wire);
  tw_bridge *bridge = (tw_bridge *)(uintptr_t)worker;
  SSL_CTX *client_context = SSL_CTX_new(TLS_client_method()); check(client_context != NULL, "create client context");
  SSL *client = SSL_new(client_context); check(client && SSL_set_fd(client, peers[1]) == 1, "bind client BIO");
  const unsigned char alpn[] = {8, 'h','t','t','p','/','1','.','1'};
  check(SSL_set_alpn_protos(client, alpn, sizeof(alpn)) == 0, "client ALPN");
  unsigned char payload[131072], incoming[8192]; for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (unsigned char)(i * 73);
  size_t sent = 0, received = 0, written = 0; int client_ready = 0, server_ready = 0;
  pending inputs[32] = {{0}}; uint32_t input_count = 0;
  lean_object *plain = NULL, *retained = NULL; uint32_t plain_length = 0; unsigned hold_rounds = 0;
  uint64_t end = rn_now_ms() + 10000;
  while ((received < sizeof(payload) || written < sizeof(payload)) && rn_now_ms() < end) {
    if (!client_ready) {
      ERR_clear_error(); int rc = SSL_connect(client);
      if (rc == 1) client_ready = 1;
      else { int e = SSL_get_error(client, rc); check(e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE, "client handshake progress"); }
    }
    if (client_ready && server_ready && sent < sizeof(payload)) {
      size_t count = 0, n = sizeof(payload) - sent; if (n > 4096) n = 4096;
      ERR_clear_error(); int rc = SSL_write_ex(client, payload + sent, n, &count);
      if (rc == 1) sent += count;
      else { int e = SSL_get_error(client, rc); check(e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE, "client binary write progress"); }
    }
    int native = rn_step(reactor, 0); check(native >= 0, "native transport step");
    for (int n = 0; n < native; ++n) {
      const rn_event *event = rn_event_at(reactor, (uint32_t)n);
      if (event->kind == RN_READ) { check(input_count < 32, "bounded retained native input"); inputs[input_count++] = (pending){event->buffer, event->offset, event->length}; }
      else if (event->kind == RN_WRITTEN) check(result(lean_tlsw_on_written(worker, event->operation, (uint64_t)event->result)) == 0, "ciphertext wire acknowledgement");
      else check(event->kind == RN_WAKE, "no native error/close during echo");
    }
    for (uint32_t n = 0; n < input_count;) {
      pending *input = &inputs[n]; lean_object *buffer = NULL;
      check(rn_bridge_make_buffer(record, input->lease, &buffer) == 0, "wrap raw input lease");
      int64_t copied = result(lean_tlsw_feed(worker, session, buffer, input->offset, input->length)); lean_dec(buffer);
      if (copied < 0 || (uint64_t)copied > input->length) fprintf(stderr,"copy%lld length%u offset%u session%llu state%u error%d %s\n",(long long)copied,input->length,input->offset,(unsigned long long)session,atomic_load(&bridge->engine->sessions[0].state),bridge->engine->sessions[0].error,bridge->engine->sessions[0].diagnostic);
      check(copied >= 0 && (uint64_t)copied <= input->length, "bounded cipher input copy");
      if (!copied) break;
      input->offset += (uint32_t)copied; input->length -= (uint32_t)copied;
      if (!input->length) { check(rn_buffer_release(reactor, input->lease) == 0, "release raw input"); memmove(input, input + 1, (--input_count - n) * sizeof(*input)); }
      else ++n;
    }
    if (plain) {
      int64_t queued = result(lean_tlsw_write(worker, session, plain, 0, plain_length, 123));
      check(queued == 0 || queued == 1, "bounded plaintext queue submission");
      if (!queued) { lean_dec(plain); plain = NULL; check(result(lean_tlsw_release_plain(worker, session)) == 0, "return plaintext borrow credit"); }
    }
    int64_t events = result(lean_tlsw_pump(worker)); check(events >= 0, "bridge pump");
    for (int64_t n = 0; n < events; ++n) {
      rn_event *event = &bridge->events[n];
      if (event->kind == TLSW_READY) { check(!server_ready && event->flags == 1, "one handshake READY"); check(rn_transport_ready(reactor, connection, capability) == 0, "native TLS-ready transition"); server_ready = 1; }
      else if (event->kind == TLSW_READ) {
        check(!plain, "one permanent plaintext loan"); plain = lean_io_result_take_value(lean_tlsw_event_buffer(worker, (uint32_t)n)); plain_length = event->length;
        lean_object *bytes = NULL; check(rn_buffer_view(reactor, event->buffer, &bytes) == 0, "view plaintext");
        if (!retained && !hold_rounds) { retained = bytes; lean_inc(retained); hold_rounds = 1; }
      } else if (event->kind == TLSW_WRITTEN) { check(event->operation == 123 && event->result > 0, "logical operation completion"); written += (size_t)event->result; }
      else { fprintf(stderr,"unexpected TLS event kind%u error%lld\n",event->kind,(long long)event->result); check(0,"no TLS errors during binary echo"); }
    }
    if (client_ready) {
      size_t count = 0; ERR_clear_error(); int rc = SSL_read_ex(client, incoming, sizeof(incoming), &count);
      if (rc == 1) { check(count <= sizeof(payload) - received && memcmp(incoming, payload + received, count) == 0, "exact binary stream"); received += count; }
      else { int e = SSL_get_error(client, rc); check(e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE, "client binary read progress"); }
    }
    if (retained && ++hold_rounds > 20 && received > 0) { lean_dec(retained); retained = NULL; }
    struct timespec pause = {0, 100000}; (void)nanosleep(&pause, NULL);
  }
  check(sent == sizeof(payload) && received == sizeof(payload) && written == sizeof(payload), "four-cell queues complete binary echo and wire fences");
  if (retained) lean_dec(retained);
  if (plain) { lean_dec(plain); check(result(lean_tlsw_release_plain(worker, session)) == 0, "release final plaintext loan"); }
  check(atomic_load(&bridge->engine->owner_violations) == 0 && atomic_load(&bridge->engine->ssl_calls) > 0, "exclusive off-loop SSL ownership");
  uint64_t fault_lease = 0; lean_object *fault_buffer = NULL;
  check(rn_acquire_buffer(reactor, 1, &fault_lease) == 0 && rn_buffer_copy(reactor, fault_lease, (const uint8_t *)"x", 1) == 0 && rn_bridge_make_buffer(record, fault_lease, &fault_buffer) == 0, "prepare ciphertext submit fault");
  fail_cipher = 1; check(result(lean_tlsw_write(worker, session, fault_buffer, 0, 1, 456)) == 0, "queue submit-fault plaintext"); lean_dec(fault_buffer);
  check(rn_buffer_release(reactor, fault_lease) == 0, "release submit-fault source");
  int saw_error = 0; end = rn_now_ms() + 1000;
  while (!saw_error && rn_now_ms() < end) {
    int64_t count = result(lean_tlsw_pump(worker)); check(count >= 0, "pump submit fault");
    for (int64_t n = 0; n < count; ++n) if (bridge->events[n].kind == TLSW_ERROR) {
      check(bridge->events[n].result == -ENOMEM && bridge->events[n].flags == RN_SETUP_ERROR, "infrastructure fault retains fatal classification");
      check(result(lean_tlsw_abort(worker, session)) == 0 && rn_connection_live(reactor, connection) == 0, "observed submit fault still aborts physical connection"); saw_error = 1;
    }
    struct timespec pause = {0, 100000}; (void)nanosleep(&pause, NULL);
  }
  check(saw_error && result(lean_tlsw_abort(worker, session)) == 0, "submit fault and repeated abort are bounded");
  for (uint32_t n = 0; n < input_count; ++n) check(rn_buffer_release(reactor, inputs[n].lease) == 0, "release canceled retained input");
  SSL_free(client); SSL_CTX_free(client_context); check(close(peers[1]) == 0, "close client descriptor");
  /* An injected failed join must retain the worker, lanes and callback owner. */
  fail_join = 1; check(result(lean_tlsw_worker_free(worker)) == -EIO, "join failure preserves live storage");
  check(bridge->engine != NULL && bridge->reactor_record == record, "failed join retains ownership graph");
  check(result(lean_tlsw_worker_free(worker)) == 0, "join retry frees all SSL/BIO objects");
  check(result(lean_tlsw_bundle_free(bundle)) == 0, "free sealed context bundle");
  lean_dec(record); check(rn_free(reactor) == 0, "free reactor after TLS join");
}
int main(int argc, char **argv) {
  check(argc == 3, "certificate/key arguments"); lean_initialize_runtime_module();
  queue_wrap(); drive_notification_wrap(argv[1], argv[2]);
  exercise(argv[1], argv[2], 1); exercise(argv[1], argv[2], 3);
  puts("TLS worker queue, wire fences and lifecycle tests passed"); return 0;
}
