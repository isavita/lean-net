/* Actual native worker/bridge ownership under ASan and the Lean allocator. */
#include "../../c/reactor_posix.c"
#include <pthread.h>
#include <stdio.h>
static int fail_join;
static int test_join(pthread_t thread, void **result) {
  if (fail_join) { fail_join = 0; return EDEADLK; }
  return pthread_join(thread, result);
}
#define pthread_join test_join
#include "../c/tls_worker.c"
#undef pthread_join
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
  if (retained) lean_dec(retained); if (plain) { lean_dec(plain); check(result(lean_tlsw_release_plain(worker, session)) == 0, "release final plaintext loan"); }
  check(atomic_load(&bridge->engine->owner_violations) == 0 && atomic_load(&bridge->engine->ssl_calls) > 0, "exclusive off-loop SSL ownership");
  check(result(lean_tlsw_abort(worker, session)) == 0, "abort pending native receive");
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
  queue_wrap(); exercise(argv[1], argv[2], 1); exercise(argv[1], argv[2], 3);
  puts("TLS worker queue, wire fences and lifecycle tests passed"); return 0;
}
