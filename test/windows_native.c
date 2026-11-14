/* Real IOCP/Winsock integration and lifetime regression fixture. Including the
 * production units permits checking pending operation ownership and ephemeral
 * ports without widening the public API merely for tests. */
#ifndef _WIN32
#error This fixture must run on Windows
#endif
#include "../c/reactor_group.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
static atomic_int track_native_allocations, native_allocations;
static atomic_uint transport_send_limit, transport_send_calls, transport_max_vectors;
static int WSAAPI transport_test_WSASend(SOCKET socket, LPWSABUF buffers, DWORD count,
                                        LPDWORD sent, DWORD flags, LPWSAOVERLAPPED overlapped,
                                        LPWSAOVERLAPPED_COMPLETION_ROUTINE callback) {
  atomic_fetch_add(&transport_send_calls, 1);
  unsigned previous = atomic_load(&transport_max_vectors);
  while (previous < count && !atomic_compare_exchange_weak(&transport_max_vectors, &previous, count)) {}
  unsigned limit = atomic_load(&transport_send_limit);
  if (!limit) return WSASend(socket, buffers, count, sent, flags, overlapped, callback);
  /* Shorten the stable production descriptor array before submission. The
   * next operation rebuilds it from logical offsets after this completion. */
  DWORD used = 0;
  for (DWORD i = 0; i < count && limit; ++i) {
    if (used >= 16) abort();
    if (buffers[i].len > limit) buffers[i].len = limit;
    limit -= buffers[i].len; ++used;
  }
  return WSASend(socket, buffers, used, sent, flags, overlapped, callback);
}
static void *tracked_malloc(size_t size) {
  if (atomic_load(&track_native_allocations))
    atomic_fetch_add(&native_allocations, 1);
  return malloc(size);
}
static void *tracked_calloc(size_t count, size_t size) {
  if (atomic_load(&track_native_allocations))
    atomic_fetch_add(&native_allocations, 1);
  return calloc(count, size);
}
#define malloc tracked_malloc
#define calloc tracked_calloc
#define WSASend(...) transport_test_WSASend(__VA_ARGS__)
#include "../c/reactor_windows.c"
#undef malloc
#undef calloc
#undef WSASend
#include "../c/socket_windows.c"

void lean_initialize_runtime_module(void);
void lean_initialize_thread(void);
void lean_finalize_thread(void);
static void check(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "Windows native test: %s (WSA=%d)\n", message,
            WSAGetLastError());
    exit(1);
  }
}
static int64_t result_i64(lean_object *result) {
  check(lean_io_result_is_ok(result), "unexpected Lean IO exception");
  int64_t value = (int64_t)lean_unbox_uint64(lean_io_result_get_value(result));
  lean_dec(result);
  return value;
}
static int64_t result_count(lean_object *result, uint8_t *data,
                            size_t capacity) {
  check(lean_io_result_is_ok(result), "unexpected Lean IO pair exception");
  lean_object *pair = lean_io_result_get_value(result);
  int64_t value = (int64_t)lean_unbox_uint64(lean_ctor_get(pair, 0));
  lean_object *bytes = lean_ctor_get(pair, 1);
  if (value >= 0 && data) {
    size_t count = lean_sarray_size(bytes);
    check(count <= capacity, "receive exceeds test buffer");
    memcpy(data, lean_sarray_cptr(bytes), count);
  }
  lean_dec(result);
  return value;
}
static rn_config config(void) { return (rn_config){8, 16, 8, 2, 1, 1, 1}; }
static uint16_t listener_port(rn_reactor *reactor, uint64_t listener) {
  struct sockaddr_in address;
  int length = sizeof(address);
  check(getsockname(reactor->connections[rn_index(listener)].socket,
                    (struct sockaddr *)&address, &length) == 0,
        "listener address");
  return ntohs(address.sin_port);
}
static SOCKET connect_client(uint16_t port) {
  SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  check(client != INVALID_SOCKET, "create client");
  struct sockaddr_in address;
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(port);
  check(connect(client, (const struct sockaddr *)&address, sizeof(address)) ==
            0,
        "connect client");
  DWORD timeout = 3000;
  check(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout,
                   sizeof(timeout)) == 0,
        "client receive timeout");
  return client;
}
static uint64_t accept_client(rn_reactor *reactor) {
  uint64_t end = rn_now_ms() + 3000;
  while (rn_now_ms() < end) {
    int count = rn_step(reactor, 10);
    check(count >= 0, "accept step");
    for (int i = 0; i < count; ++i) {
      const rn_event *event = rn_event_at(reactor, (uint32_t)i);
      check(event->kind != RN_ERROR, "accept completion error");
      if (event->kind == RN_ACCEPTED)
        return event->connection;
    }
  }
  check(0, "accept deadline");
  return 0;
}
static void test_pool_and_timer(void) {
  rn_reactor *reactor;
  rn_config options = config();
  check(rn_new(&options, &reactor) == 0, "create reactor");
  uint64_t buffer, replacement, connection, stale;
  check(rn_acquire_buffer(reactor, 65536, &buffer) == 0,
        "acquire large pool class");
  const uint8_t payload[] = {0, 255, 17, 0, 42};
  check(rn_buffer_copy(reactor, buffer, payload, sizeof(payload)) == 0,
        "copy binary payload");
  lean_object *view;
  check(rn_buffer_view(reactor, buffer, &view) == 0, "borrow pooled view");
  lean_inc(view);
  check(rn_buffer_release(reactor, buffer) == 0, "release retained buffer");
  check(rn_acquire_buffer(reactor, 65536, &replacement) == -EAGAIN,
        "retained Lean view prevents storage reuse");
  check(memcmp(lean_sarray_cptr(view), payload, sizeof(payload)) == 0,
        "retained view remains intact");
  lean_dec(view);
  check(rn_acquire_buffer(reactor, 65536, &replacement) == 0 &&
            replacement != buffer,
        "released storage receives fresh generation");
  check(rn_buffer_release(reactor, buffer) == -EINVAL, "stale lease rejected");
  check(rn_buffer_release(reactor, replacement) == 0,
        "release replacement lease");
  check(rn_socket_new(reactor, &connection) == 0, "create logical socket");
  uint64_t deadline = rn_now_ms() + 5;
  check(rn_arm_timer(reactor, connection, 3, deadline) == 0, "arm timer");
  check(rn_arm_timer(reactor, connection, 4, deadline) == 0,
        "arm canceled timer");
  check(rn_cancel_timer(reactor, connection, 4) == 0, "cancel timer");
  int fired = 0;
  uint64_t end = deadline + 1000;
  while (!fired && rn_now_ms() < end) {
    int count = rn_step(reactor, 10);
    check(count >= 0, "timer step");
    for (int i = 0; i < count; ++i) {
      const rn_event *event = rn_event_at(reactor, (uint32_t)i);
      check(event->kind == RN_TIMER && event->operation == 3 &&
                event->result == (int64_t)deadline,
            "timer kind and absolute deadline");
      ++fired;
    }
  }
  check(fired == 1, "timer fires once");
  stale = connection;
  check(rn_close_connection(reactor, connection) == 0, "close fresh socket");
  check(rn_socket_new(reactor, &connection) == 0 && stale != connection,
        "connection generation changes");
  check(rn_close_connection(reactor, stale) == -EINVAL,
        "stale socket rejected");
  check(rn_wake(reactor) == 0, "post wake");
  check(rn_step(reactor, 0) >= 1, "drain wake and close");
  check(rn_free(reactor) == 0, "free pooled reactor");
}
static void test_echo_and_cancellation(void) {
  rn_reactor *reactor;
  rn_config options = config();
  check(rn_new(&options, &reactor) == 0, "create echo reactor");
  uint64_t listener;
  check(rn_listen(reactor, "127.0.0.1", 0, 0, &listener) == 0,
        "start IOCP listener");
  uint16_t port = listener_port(reactor, listener);
  SOCKET client = connect_client(port);
  uint64_t connection = accept_client(reactor);
  uint8_t payload[4000], echoed[8000], expected[8000];
  size_t expected_size = 0;
  for (size_t i = 0; i < sizeof(payload); ++i)
    payload[i] = (uint8_t)i;
  check(send(client, (const char *)payload, sizeof(payload), 0) ==
            sizeof(payload),
        "send binary echo payload");
  size_t consumed = 0;
  unsigned written = 0, issued = 0;
  uint64_t end = rn_now_ms() + 3000;
  while ((consumed != sizeof(payload) || written != issued) &&
         rn_now_ms() < end) {
    int count = rn_step(reactor, 10);
    check(count >= 0, "echo step");
    for (int i = 0; i < count; ++i) {
      const rn_event *event = rn_event_at(reactor, (uint32_t)i);
      check(event->kind != RN_ERROR, "echo completion error");
      if (event->kind == RN_READ) {
        lean_object *bytes;
        check(rn_buffer_view(reactor, event->buffer, &bytes) == 0,
              "read pooled view");
        check(consumed + event->length <= sizeof(payload) &&
                  memcmp(lean_sarray_cptr(bytes) + event->offset,
                         payload + consumed, event->length) == 0,
              "received binary bytes");
        consumed += event->length;
        for (unsigned n = 0; n < 2; ++n) {
          memcpy(expected + expected_size,
                 lean_sarray_cptr(bytes) + event->offset, event->length);
          expected_size += event->length;
        }
        for (unsigned n = 0; n < 2; ++n)
          check(rn_queue_write(reactor, connection, event->buffer,
                               event->offset, event->length, ++issued) == 0,
                "queue pinned echo");
        check(rn_buffer_copy(reactor, event->buffer, payload, 1) == -EBUSY,
              "queued writes freeze buffer");
        check(rn_buffer_release(reactor, event->buffer) == 0,
              "release queued buffer owner");
      } else if (event->kind == RN_WRITTEN) {
        check(event->operation == ++written, "write completion order");
      }
    }
  }
  check(consumed == sizeof(payload) && written == issued && issued > 0,
        "all binary reads and writes complete");
  size_t received = 0;
  while (received < sizeof(echoed)) {
    int count = recv(client, (char *)echoed + received,
                     (int)(sizeof(echoed) - received), 0);
    check(count > 0, "receive doubled echo");
    received += (size_t)count;
  }
  check(expected_size == sizeof(echoed) &&
            memcmp(echoed, expected, sizeof(echoed)) == 0,
        "echo wire content");
  const char tail[] = "drain this queued tail before FIN";
  check(send(client, tail, sizeof(tail), 0) == sizeof(tail),
        "send drain payload");
  check(shutdown(client, SD_SEND) == 0, "half-close client");
  int closed = 0;
  end = rn_now_ms() + 3000;
  while (!closed && rn_now_ms() < end) {
    int count = rn_step(reactor, 10);
    check(count >= 0, "half-close step");
    for (int i = 0; i < count; ++i) {
      const rn_event *event = rn_event_at(reactor, (uint32_t)i);
      check(event->kind != RN_ERROR, "half-close completion error");
      if (event->kind == RN_READ) {
        check(rn_queue_write(reactor, connection, event->buffer, event->offset,
                             event->length, 700) == 0,
              "queue tail while peer has half-closed");
        check(rn_buffer_release(reactor, event->buffer) == 0,
              "release tail lease");
      }
      if (event->kind == RN_EOF)
        check(rn_close_after_writes(reactor, connection) == 0,
              "drain writes on EOF");
      if (event->kind == RN_CLOSED && event->connection == connection)
        closed = 1;
    }
  }
  check(closed, "drained close completion");
  received = 0;
  while (received < sizeof(tail)) {
    int count = recv(client, (char *)echoed + received,
                     (int)(sizeof(tail) - received), 0);
    check(count > 0, "half-closed peer receives queued tail");
    received += (size_t)count;
  }
  check(memcmp(echoed, tail, sizeof(tail)) == 0 &&
            recv(client, (char *)echoed, 1, 0) == 0,
        "queued tail reaches peer before FIN");
  check(closesocket(client) == 0, "close echo client");

  client = connect_client(port);
  connection = accept_client(reactor);
  check(reactor->connections[rn_index(connection)].read.pending,
        "receive posted before forced close");
  uint64_t buffer;
  check(rn_acquire_buffer(reactor, 65536, &buffer) == 0,
        "acquire canceled-write buffer");
  uint8_t large[65536];
  memset(large, 31, sizeof(large));
  check(rn_buffer_copy(reactor, buffer, large, sizeof(large)) == 0,
        "fill canceled-write buffer");
  check(rn_queue_write(reactor, connection, buffer, 0, sizeof(large), 99) == 0,
        "submit write before cancellation");
  /* Submit without draining IOCP, so even synchronous completion retains the
   * exact operation record until the following forced-close/drain sequence. */
  rn_post_write(reactor, rn_index(connection));
  check(reactor->writes[reactor->connections[rn_index(connection)].write_head]
            .op.pending,
        "submitted send remains owned until completion dequeue");
  check(rn_buffer_release(reactor, buffer) == 0,
        "release canceled-write buffer owner");
  check(rn_close_connection(reactor, connection) == 0,
        "cancel pending receive and send");
  check(reactor->connections[rn_index(connection)].pending != 0,
        "operation slots retained before cancellation completion");
  closed = 0;
  end = rn_now_ms() + 3000;
  while (!closed && rn_now_ms() < end) {
    int count = rn_step(reactor, 10);
    check(count >= 0, "cancel completion step");
    for (int i = 0; i < count; ++i) {
      const rn_event *event = rn_event_at(reactor, (uint32_t)i);
      if (event->kind == RN_CLOSED && event->connection == connection)
        closed = 1;
      check(event->kind != RN_READ && event->kind != RN_WRITTEN,
            "canceled nonterminal completions suppressed");
    }
  }
  check(closed && reactor->outstanding == 1,
        "only listener AcceptEx remains after cancel drain");
  check(closesocket(client) == 0, "close canceled client");
  check(rn_free(reactor) == 0, "destructor drains pending AcceptEx");
}
static void test_legacy_and_handles(void) {
  lean_object *host = lean_mk_string("127.0.0.1");
  int64_t listener = result_i64(shim_tcp_listen(host, 0));
  lean_dec(host);
  check(listener > 0 && listener <= INT_MAX,
        "legacy descriptor preserves poll ABI");
  SOCKET native;
  check(ln_socket_lookup(listener, &native, NULL) == 0,
        "legacy socket mapping");
  struct sockaddr_in address;
  int length = sizeof(address);
  check(getsockname(native, (struct sockaddr *)&address, &length) == 0,
        "legacy listener port");
  SOCKET client = connect_client(ntohs(address.sin_port));
  int64_t connection = result_i64(shim_tcp_accept(listener));
  check(connection > 0, "legacy accept");
  const char payload[] = "legacy binary\0payload";
  check(send(client, payload, sizeof(payload), 0) == sizeof(payload),
        "legacy peer send");
  uint8_t received[sizeof(payload)];
  check(result_count(shim_tcp_recv(connection, sizeof(payload)), received,
                     sizeof(received)) == sizeof(payload) &&
            memcmp(payload, received, sizeof(payload)) == 0,
        "legacy receive exact bytes");
  check(result_i64(shim_set_nonblocking(connection, 1)) == 0,
        "legacy nonblocking");
  check(result_count(shim_tcp_recv(connection, 1), NULL, 0) == -EAGAIN,
        "legacy would-block errno");
  check(result_i64(shim_close(connection)) == 0, "legacy close");
  check(result_i64(shim_close(connection)) == -EBADF,
        "legacy stale token cannot close reused socket");
  check(result_i64(shim_close(listener)) == 0, "legacy listener close");
  check(closesocket(client) == 0, "legacy peer close");

  DWORD before = 0, after = 0;
  check(GetProcessHandleCount(GetCurrentProcess(), &before),
        "baseline handle count");
  for (unsigned n = 0; n < 1000; ++n) {
    rn_reactor *reactor;
    rn_config options = config();
    uint64_t token;
    check(rn_new(&options, &reactor) == 0, "churn reactor create");
    check(rn_listen(reactor, "127.0.0.1", 0, 0, &token) == 0,
          "churn pending accept");
    check(rn_free(reactor) == 0, "churn cancel-drain-free");
  }
  check(GetProcessHandleCount(GetCurrentProcess(), &after),
        "final handle count");
  check(after <= before + 1, "1000 pending accepts leave handle count flat");
}
static void test_transport_pause_vectors(void) {
  for (unsigned mode = 0; mode < 2; ++mode) {
    rn_config options = {4, mode ? 32u : 2u, 32, 4, 0, 0, 1};
    rn_reactor *r = NULL; uint64_t listener = 0;
    check(rn_new(&options, &r) == 0 && rn_listen(r, "127.0.0.1", 0, 0, &listener) == 0, "create vector reactor");
    SOCKET peer = connect_client(listener_port(r, listener));
    uint64_t connection = accept_client(r);
    rn_connection *c = &r->connections[rn_index(connection)];
    atomic_store(&native_allocations, 0); atomic_store(&track_native_allocations, 1);
    check(rn_set_read_enabled(r, listener, 0) == -EINVAL && rn_set_read_enabled(r, connection, 2) == -EINVAL, "validate read enable state");
    check(c->read.pending && rn_set_read_enabled(r, connection, 0) == 0, "pause one outstanding read");
    for (unsigned marker = 0; marker < 3; ++marker) {
      char byte = (char)('A' + marker);
      if (marker == 1) {
        check(send(peer, &byte, 1, 0) == 1, "send input during user pause");
        for (unsigned tick = 0; tick < 3; ++tick) {
          int count = rn_step(r, 1); check(count >= 0, "poll paused input");
          for (int i = 0; i < count; ++i) check(rn_event_at(r, (uint32_t)i)->kind != RN_READ, "paused IOCP does not post another receive");
        }
        check(rn_set_read_enabled(r, connection, 1) == 0, "resume user-paused read");
      } else {
        if (marker == 2) check(rn_set_read_enabled(r, connection, 0) == 0, "pause returned read batch with next receive outstanding");
        check(send(peer, &byte, 1, 0) == 1, "complete outstanding paused receive");
      }
      int received = 0; uint64_t end = rn_now_ms() + 3000;
      while (!received && rn_now_ms() < end) {
        int count = rn_step(r, 10); check(count >= 0, "poll controlled receive");
        for (int i = 0; i < count; ++i) {
          const rn_event *event = rn_event_at(r, (uint32_t)i);
          if (event->kind == RN_READ) {
            lean_object *view;
            check(rn_buffer_view(r, event->buffer, &view) == 0 && lean_sarray_size(view) == 1 && lean_sarray_cptr(view)[0] == (uint8_t)byte, "read pause preserves exact input and lease");
            check(rn_buffer_release(r, event->buffer) == 0, "release controlled receive"); ++received;
          } else check(event->kind != RN_ERROR, "controlled receive has no error");
        }
      }
      check(received == 1 && (marker == 1 || !c->read.pending), "only an already-posted receive completes under pause");
    }
    check(rn_set_read_enabled(r, connection, 1) == 0 && !c->read.pending && rn_connection_live(r, connection) == 1, "resume defers receive submission and failure until next native step");
    check(rn_set_read_enabled(r, connection, 0) == 0 && !c->read.pending, "pause cancels deferred resume without posting IO");
    uint64_t pressure[4];
    for (unsigned b = 0; b < 4; ++b) check(rn_acquire_buffer(r, 4096, &pressure[b]) == 0, "exhaust read pool under pause");
    check(rn_set_read_enabled(r, connection, 1) == 0 && rn_step(r, 0) == 0 && c->read_paused && !c->read.pending, "pool pause remains independent of user pause");
    check(rn_set_read_enabled(r, connection, 0) == 0, "disable a pool-paused IOCP receive");
    for (unsigned b = 0; b < 4; ++b) check(rn_buffer_release(r, pressure[b]) == 0, "restore exhausted read pool");
    check(rn_step(r, 1) == 0 && !c->read.pending, "pool recovery does not override user pause");
    check(shutdown(peer, SD_SEND) == 0 && rn_step(r, 1) == 0, "paused read delays EOF without blocking writes");
    check(rn_set_read_enabled(r, connection, 1) == 0, "resume to observe EOF");
    unsigned saw_eof = 0; uint64_t end = rn_now_ms() + 3000;
    while (!saw_eof && rn_now_ms() < end) {
      int count = rn_step(r, 10); check(count >= 0, "poll resumed EOF");
      for (int i = 0; i < count; ++i) {
        const rn_event *event = rn_event_at(r, (uint32_t)i);
        if (event->kind == RN_EOF) ++saw_eof;
        check(event->kind != RN_ERROR, "resumed EOF has no error");
      }
    }
    check(saw_eof == 1 && rn_set_read_enabled(r, connection, 0) == 0 && rn_set_read_enabled(r, connection, 1) == 0 && !c->read.pending, "EOF cannot be reopened by resume");
    uint8_t block[4096], expected[20 * 4096], received[20 * 4096]; size_t size = 0, got = 0;
    uint64_t buffers[4]; lean_object *retained;
    for (unsigned b = 0; b < 4; ++b) {
      for (size_t i = 0; i < sizeof(block); ++i) block[i] = (uint8_t)(i * 13 + b);
      check(rn_acquire_buffer(r, 4096, &buffers[b]) == 0 && rn_buffer_copy(r, buffers[b], block, sizeof(block)) == 0, "prepare scatter buffers");
    }
    check(rn_buffer_view(r, buffers[0], &retained) == 0, "retain scatter source view"); lean_inc(retained);
    for (unsigned op = 0; op < 20; ++op) {
      unsigned b = op % 4, offset = op % 19, length = op % 5 == 0 ? 0 : 4096 - offset;
      lean_object *view;
      check(rn_buffer_view(r, buffers[b], &view) == 0 && rn_queue_write(r, connection, buffers[b], offset, length, op + 1) == 0, "queue ordered scatter slice");
      memcpy(expected + size, lean_sarray_cptr(view) + offset, length); size += length;
    }
    for (unsigned b = 0; b < 4; ++b) check(rn_buffer_release(r, buffers[b]) == 0, "release pinned scatter lease");
    check(rn_close_after_writes(r, connection) == 0, "drain queued vectors after EOF");
    u_long nonblocking = 1; check(ioctlsocket(peer, FIONBIO, &nonblocking) == 0, "nonblocking scatter client");
    atomic_store(&transport_send_limit, 97); atomic_store(&transport_send_calls, 0); atomic_store(&transport_max_vectors, 0);
    unsigned written = 0, closed = 0; int eof = 0; end = rn_now_ms() + 10000;
    while ((!closed || !eof) && rn_now_ms() < end) {
      int count = rn_step(r, 1); check(count >= 0 && (unsigned)count <= options.max_events, "scatter completion count bounded");
      for (int i = 0; i < count; ++i) {
        const rn_event *event = rn_event_at(r, (uint32_t)i);
        if (event->kind == RN_WRITTEN) {
          check(event->operation == ++written && written <= 20, "scatter writes complete once in queue order");
          unsigned op = written - 1, length = op % 5 == 0 ? 0 : 4096 - op % 19;
          check(event->result == length && event->length == length, "scatter completion reports logical operation length");
        }
        else if (event->kind == RN_CLOSED) { check(written == 20, "scatter completions precede CLOSED"); ++closed; }
        else check(event->kind != RN_ERROR && event->kind != RN_READ, "scatter writes have no peer/ownership error");
      }
      uint8_t extra;
      int n = recv(peer, (char *)(got < sizeof(received) ? received + got : &extra), (int)(got < sizeof(received) ? sizeof(received) - got : 1), 0);
      if (n > 0) got += (size_t)n;
      else if (!n) eof = 1;
      else check(WSAGetLastError() == WSAEWOULDBLOCK, "receive scatter bytes");
    }
    check(closed == 1 && eof && got == size && memcmp(expected, received, size) == 0, "partial scatter sends preserve all binary bytes");
    check(atomic_load(&transport_send_calls) > 20 && atomic_load(&transport_max_vectors) == (mode ? 16u : 2u), "scatter operation coalescing respects completion budget");
    atomic_store(&transport_send_limit, 0);
    uint64_t held[4];
    for (unsigned b = 0; b < 3; ++b) check(rn_acquire_buffer(r, 4096, &held[b]) == 0, "completed unaliased scatter cell recycled");
    uint64_t unavailable; check(rn_acquire_buffer(r, 4096, &unavailable) == -EAGAIN, "retained scatter view prevents reuse");
    check(lean_sarray_cptr(retained)[17] == (uint8_t)(17 * 13), "retained scatter content unchanged"); lean_dec(retained);
    check(rn_acquire_buffer(r, 4096, &held[3]) == 0, "scatter alias cell recycled after release");
    for (unsigned b = 0; b < 4; ++b) check(rn_buffer_release(r, held[b]) == 0, "release scatter test cell");
    check(closesocket(peer) == 0, "close scatter client");

    peer = connect_client(listener_port(r, listener)); connection = accept_client(r); c = &r->connections[rn_index(connection)];
    check(rn_set_read_enabled(r, connection, 0) == 0 && c->read.pending, "retain outstanding read for forced cancellation");
    for (unsigned b = 0; b < 3; ++b) {
      check(rn_acquire_buffer(r, 4096, &buffers[b]) == 0 && rn_buffer_copy(r, buffers[b], block, sizeof(block)) == 0 && rn_queue_write(r, connection, buffers[b], 0, sizeof(block), 1001 + b) == 0, "queue independent cancellation vector");
      check(rn_buffer_release(r, buffers[b]) == 0, "release cancellation lease");
    }
    rn_post_write(r, rn_index(connection)); uint32_t head = c->write_head;
    check(head != RN_NONE && r->writes[head].op.pending && r->writes[head].vector_count == (mode ? 3u : 2u), "multiple buffers share stable pending OVERLAPPED");
    unsigned submitted = r->writes[head].vector_count;
    check(rn_close_connection(r, connection) == 0, "cancel pending scatter operation");
    for (unsigned b = 0; b < submitted; ++b) check(r->buffers[rn_index(buffers[b])].io_refs == 1, "each submitted vector stays pinned until cancellation drains");
    closed = 0; end = rn_now_ms() + 3000;
    while (!closed && rn_now_ms() < end) {
      int count = rn_step(r, 10); check(count >= 0, "drain scatter cancellations");
      for (int i = 0; i < count; ++i) if (rn_event_at(r, (uint32_t)i)->kind == RN_CLOSED && rn_event_at(r, (uint32_t)i)->connection == connection) ++closed;
    }
    check(closed == 1, "scatter cancellation closes after all OVERLAPPED operations drain");
    for (unsigned b = 0; b < 4; ++b) check(rn_acquire_buffer(r, 4096, &held[b]) == 0, "all canceled scatter cells reclaimed");
    for (unsigned b = 0; b < 4; ++b) check(rn_buffer_release(r, held[b]) == 0, "release canceled scatter cell");
    check(closesocket(peer) == 0, "close canceled scatter peer");
    peer = connect_client(listener_port(r, listener)); connection = accept_client(r);
    check(send(peer, "lease", 5, 0) == 5, "send close-after-returned-read payload");
    uint64_t returned = 0; end = rn_now_ms() + 3000;
    while (!returned && rn_now_ms() < end) {
      int count = rn_step(r, 10); check(count >= 0, "poll close-after-returned-read");
      for (int i = 0; i < count; ++i) if (rn_event_at(r, (uint32_t)i)->kind == RN_READ) returned = rn_event_at(r, (uint32_t)i)->buffer;
    }
    check(returned && rn_set_read_enabled(r, connection, 0) == 0 && rn_close_connection(r, connection) == 0, "pause and close returned read batch");
    lean_object *view;
    check(rn_buffer_view(r, returned, &view) == 0 && lean_sarray_size(view) == 5 && memcmp(lean_sarray_cptr(view), "lease", 5) == 0 && rn_buffer_release(r, returned) == 0, "returned read lease survives IOCP cancellation");
    closed = 0; end = rn_now_ms() + 3000;
    while (!closed && rn_now_ms() < end) {
      int count = rn_step(r, 10); check(count >= 0, "drain returned-read close");
      for (int i = 0; i < count; ++i) if (rn_event_at(r, (uint32_t)i)->kind == RN_CLOSED && rn_event_at(r, (uint32_t)i)->connection == connection) ++closed;
    }
    check(closed == 1 && closesocket(peer) == 0, "returned-read connection closes once");
    atomic_store(&track_native_allocations, 0);
    check(atomic_load(&native_allocations) == 0 && rn_free(r) == 0, "scatter and pause path has no hot native allocations");
  }
}
static void test_historical_write_liveness(void) {
  rn_config options = {4, 1, 4, 4, 0, 0, 1}; rn_reactor *r = NULL; uint64_t listener = 0;
  check(rn_new(&options, &r) == 0 && rn_listen(r, "127.0.0.1", 0, 0, &listener) == 0, "create single-event liveness reactor");
  SOCKET peer = connect_client(listener_port(r, listener)); uint64_t connection = accept_client(r);
  atomic_store(&native_allocations, 0); atomic_store(&track_native_allocations, 1);
  check(rn_connection_live(NULL, connection) == -EINVAL && rn_connection_live(r, 0) == 0 && rn_connection_live(r, listener) == 0, "liveness excludes invalid/listening identities");
  check(rn_set_read_enabled(r, connection, 0) == 0 && rn_connection_live(r, connection) == 1, "IOCP paused connection remains live");
  uint64_t buffer;
  check(rn_acquire_buffer(r, 3, &buffer) == 0 && rn_buffer_copy(r, buffer, (const uint8_t *)"bye", 3) == 0 && rn_queue_write(r, connection, buffer, 0, 3, 9001) == 0 && rn_buffer_release(r, buffer) == 0, "queue liveness write");
  check(rn_close_after_writes(r, connection) == 0 && rn_connection_live(r, connection) == 1, "IOCP liveness includes pending drain");
  int written = 0, closed = 0; uint64_t end = rn_now_ms() + 3000;
  while (!closed && rn_now_ms() < end) {
    int count = rn_step(r, 10); check(count >= 0 && count <= 1, "liveness completion budget");
    if (!count) continue;
    const rn_event *event = rn_event_at(r, 0);
    if (event->kind == RN_WRITTEN) {
      check(!written && !closed && event->operation == 9001 && rn_connection_live(r, connection) == 0, "historical write reports dead identity before CLOSED"); written = 1;
    } else if (event->kind == RN_CLOSED) {
      check(written && rn_connection_live(r, connection) == 0, "CLOSED follows historical write"); closed = 1;
    } else check(event->kind != RN_ERROR, "liveness drain has no error");
  }
  check(written && closed, "single-event liveness drain completes");
  uint64_t fresh;
  check(rn_socket_new(r, &fresh) == 0 && fresh != connection && rn_connection_live(r, fresh) == 0 && rn_connection_live(r, connection) == 0, "IOCP liveness rejects reused generations");
  atomic_store(&track_native_allocations, 0);
  check(atomic_load(&native_allocations) == 0 && closesocket(peer) == 0 && rn_free(r) == 0, "liveness has no hot native allocations");
}
static void test_generation_retirement(void) {
  rn_config options = {1, 1, 1, 1, 0, 0, 1}; rn_reactor *r = NULL;
  check(rn_new(&options, &r) == 0, "create generation boundary reactor");
  atomic_store(&native_allocations, 0); atomic_store(&track_native_allocations, 1);
  uint64_t stale, last, unavailable = 0;
  check(rn_socket_new(r, &stale) == 0 && rn_close_connection(r, stale) == 0 && rn_step(r, 0) == 1, "recycle IOCP slot before boundary");
  r->connections[rn_index(stale)].generation = RN_GENERATION_MAX - 1;
  check(rn_socket_new(r, &last) == 0 && (int64_t)last > 0 && (last >> 32) == INT32_MAX, "final IOCP socket token remains signed-positive");
  check(rn_arm_timer(r, stale, 0, 0) == -EINVAL && rn_close_connection(r, stale) == -EINVAL, "old IOCP socket alias cannot address final generation");
  check(rn_close_connection(r, last) == 0 && rn_step(r, 0) == 1 && rn_event_at(r, 0)->connection == last, "final IOCP socket closes with original identity");
  check(r->free_connection_count == 0 && rn_socket_new(r, &unavailable) == -ENOBUFS && unavailable == 0, "exhausted IOCP connection slot is retired");
  check(rn_close_connection(r, last) == -EINVAL && rn_arm_timer(r, last, 0, 0) == -EINVAL && rn_arm_timer(r, stale, 0, 0) == -EINVAL, "all retired IOCP socket aliases remain stale");
  check(rn_acquire_buffer(r, 1, &stale) == 0 && rn_buffer_release(r, stale) == 0, "recycle IOCP buffer before boundary");
  r->buffers[rn_index(stale)].generation = RN_GENERATION_MAX - 1;
  check(rn_acquire_buffer(r, 1, &last) == 0 && (int64_t)last > 0 && (last >> 32) == INT32_MAX, "final IOCP buffer token remains signed-positive");
  const uint8_t binary[] = {0, 255, 17}; lean_object *view = NULL;
  check(rn_buffer_copy(r, last, binary, sizeof(binary)) == 0 && rn_buffer_view(r, last, &view) == 0, "use final IOCP buffer generation"); lean_inc(view);
  check(rn_buffer_release(r, last) == 0 && r->free_buffer_count[0] == 0 && !r->buffers[rn_index(last)].in_free, "exhausted IOCP buffer excluded from free candidates");
  lean_object *invalid = NULL;
  check(rn_buffer_view(r, stale, &invalid) == -EINVAL && rn_buffer_view(r, last, &invalid) == -EINVAL && rn_buffer_release(r, last) == -EINVAL, "retired IOCP buffer aliases cannot reacquire ownership");
  check(lean_sarray_size(view) == sizeof(binary) && memcmp(lean_sarray_cptr(view), binary, sizeof(binary)) == 0, "retired IOCP buffer view immutable"); lean_dec(view);
  for (unsigned i = 0; i < 8; ++i) check(rn_acquire_buffer(r, 1, &unavailable) == -EAGAIN && unavailable == 0 && rn_socket_new(r, &unavailable) == -ENOBUFS && rn_step(r, 1) == 0, "retired IOCP exhaustion returns without a completion spin");
  atomic_store(&track_native_allocations, 0);
  check(atomic_load(&native_allocations) == 0 && rn_free(r) == 0, "generation retirement has no hot allocation or leaked port");
}
typedef struct dispatch_loop {
  rn_reactor *reactor;
  rn_group *group;
  int acceptor;
  atomic_uint accepted, errors, thread_id;
} dispatch_loop;
static void loop_error(dispatch_loop *loop) {
  atomic_fetch_add(&loop->errors, 1);
  if (rn_group_request_stop(loop->group))
    atomic_fetch_add(&loop->errors, 1);
}
static DWORD WINAPI dispatch_thread(LPVOID argument) {
  dispatch_loop *loop = argument;
  lean_initialize_thread();
  atomic_store(&loop->thread_id, GetCurrentThreadId());
  while (rn_group_stopping(loop->group) == 0) {
    int count = rn_step(loop->reactor, 20);
    if (count < 0) {
      loop_error(loop);
      break;
    }
    for (int i = 0; i < count; ++i) {
      const rn_event *event = rn_event_at(loop->reactor, (uint32_t)i);
      if (event->kind == RN_ACCEPTED) {
        if (loop->acceptor)
          loop_error(loop);
        atomic_fetch_add(&loop->accepted, 1);
      } else if (event->kind == RN_READ) {
        int queued =
            rn_queue_write(loop->reactor, event->connection, event->buffer,
                           event->offset, event->length, 1);
        int released = rn_buffer_release(loop->reactor, event->buffer);
        if (queued || released || loop->acceptor)
          loop_error(loop);
      } else if (event->kind == RN_EOF) {
        if (rn_close_after_writes(loop->reactor, event->connection))
          loop_error(loop);
      } else if (event->kind == RN_ERROR)
        loop_error(loop);
    }
  }
  lean_finalize_thread();
  return 0;
}
static void receive_exact_echo(SOCKET socket, const uint8_t *payload,
                               size_t size) {
  uint8_t received[128];
  check(size <= sizeof(received), "dispatch test payload bound");
  size_t count = 0;
  while (count < size) {
    int read = recv(socket, (char *)received + count, (int)(size - count), 0);
    check(read > 0, "full handoff queue does not lose an accepted connection");
    count += (size_t)read;
  }
  check(memcmp(received, payload, size) == 0,
        "worker echo bytes remain private and ordered");
  check(recv(socket, (char *)received, 1, 0) == 0,
        "worker drains writes before FIN");
}
static void test_dispatch_validation(void) {
  rn_config options = config();
  rn_reactor *acceptor, *worker, *other;
  check(rn_new(&options, &acceptor) == 0 && rn_new(&options, &worker) == 0 &&
            rn_new(&options, &other) == 0,
        "create dispatch validation reactors");
  rn_reactor *duplicates[] = {worker, worker};
  check(rn_set_accept_targets(acceptor, &worker, 0, 1) == -EINVAL,
        "reject empty worker set");
  check(rn_set_accept_targets(acceptor, &worker, 1, 0) == -EINVAL,
        "reject zero queue capacity");
  check(rn_set_accept_targets(acceptor, &worker, 1, 1000001) == -EINVAL,
        "reject excessive queue capacity");
  check(rn_set_accept_targets(acceptor, &acceptor, 1, 1) == -EINVAL,
        "reject self handoff");
  check(rn_set_accept_targets(acceptor, duplicates, 2, 1) == -EINVAL,
        "reject duplicate consumer");
  check(rn_set_accept_targets(acceptor, &worker, 1, 3) == 0,
        "configure non-power-of-two queue");
  check(rn_set_accept_targets(acceptor, &other, 1, 1) == -EBUSY,
        "reject second source configuration");
  check(rn_set_accept_targets(other, &worker, 1, 1) == -EBUSY,
        "reject second producer");
  check(rn_step(other, 0) >= 0, "start unconfigured reactor");
  check(rn_set_accept_targets(other, &acceptor, 1, 1) == -EBUSY,
        "reject configuration after first step");
  check(rn_free(worker) == 0 && rn_free(acceptor) == 0 && rn_free(other) == 0,
        "free validated setup endpoints");
}
static void test_dispatch_capacity_one(void) {
  rn_config accept_options = {4, 16, 1, 1, 0, 0, 1};
  rn_config worker_options = {1, 16, 1, 1, 0, 0, 1};
  rn_reactor *acceptor, *worker;
  check(rn_new(&accept_options, &acceptor) == 0 &&
            rn_new(&worker_options, &worker) == 0,
        "create single-credit handoff endpoints");
  check(rn_set_accept_targets(acceptor, &worker, 1, 1) == 0,
        "configure capacity-one queue");
  uint64_t listener;
  check(rn_listen(acceptor, "127.0.0.1", 0, 0, &listener) == 0,
        "single-credit listener");
  SOCKET clients[3];
  clients[0] = connect_client(listener_port(acceptor, listener));
  uint64_t end = rn_now_ms() + 3000;
  while (atomic_load(&worker->incoming_accepts->head) ==
             atomic_load(&worker->incoming_accepts->tail) &&
         rn_now_ms() < end)
    check(rn_step(acceptor, 10) >= 0, "handoff first single-credit client");
  uint64_t first = accept_client(worker);
  for (unsigned i = 1; i < 3; ++i)
    clients[i] = connect_client(listener_port(acceptor, listener));
  end = rn_now_ms() + 3000;
  while (acceptor->connections[rn_index(listener)].dispatch_pending ==
             RN_NONE &&
         rn_now_ms() < end)
    check(rn_step(acceptor, 10) >= 0, "fill queue behind full worker");
  check(acceptor->connections[rn_index(listener)].dispatch_pending != RN_NONE,
        "full worker leaves one queued socket and one retained accept");
  check(rn_step(worker, 0) >= 0 &&
            rn_channel_count(worker->incoming_accepts,
                             atomic_load(&worker->incoming_accepts->head),
                             atomic_load(&worker->incoming_accepts->tail)) == 1,
        "consumer does not pop without a free native connection slot");
  check(rn_close_connection(worker, first) == 0,
        "release full worker's connection credit");
  unsigned adopted = 0;
  end = rn_now_ms() + 3000;
  while (!adopted && rn_now_ms() < end) {
    int count = rn_step(worker, 10);
    check(count >= 0, "drain cancellation and adopt next queued socket");
    for (int i = 0; i < count; ++i)
      if (rn_event_at(worker, (uint32_t)i)->kind == RN_ACCEPTED)
        ++adopted;
  }
  check(adopted == 1, "new connection adopts exactly once when credit returns");
  end = rn_now_ms() + 3000;
  while (acceptor->connections[rn_index(listener)].dispatch_pending !=
             RN_NONE &&
         rn_now_ms() < end)
    check(rn_step(acceptor, 10) >= 0,
          "worker capacity wake resumes retained accept");
  check(acceptor->connections[rn_index(listener)].dispatch_pending == RN_NONE &&
            rn_channel_count(worker->incoming_accepts,
                             atomic_load(&worker->incoming_accepts->head),
                             atomic_load(&worker->incoming_accepts->tail)) == 1,
        "retained accepted socket reaches the worker queue without loss");
  check(rn_free(worker) == 0 && rn_free(acceptor) == 0,
        "free full capacity-one endpoints");
  for (unsigned i = 0; i < 3; ++i)
    check(closesocket(clients[i]) == 0, "close single-credit peer");
}
static void test_dispatch_threads(void) {
  enum { WORKERS = 3, INITIAL = 24, SEQUENTIAL = 12 };
  rn_config options = {32, 32, 64, 32, 2, 1, 1};
  rn_config accept_options = {4, 64, 1, 1, 0, 0, 1};
  rn_reactor *acceptor, *workers[WORKERS], *members[WORKERS + 1];
  check(rn_new(&accept_options, &acceptor) == 0, "create dedicated acceptor");
  members[0] = acceptor;
  for (unsigned i = 0; i < WORKERS; ++i) {
    check(rn_new(&options, &workers[i]) == 0, "create dedicated worker");
    members[i + 1] = workers[i];
  }
  check(rn_set_accept_targets(acceptor, workers, WORKERS, 3) == 0,
        "configure bounded worker channels");
  uint64_t listener;
  check(rn_listen(acceptor, "127.0.0.1", 0, 0, &listener) == 0,
        "listen only on acceptor");
  uint16_t port = listener_port(acceptor, listener);
  rn_group *group;
  check(rn_group_new(members, WORKERS + 1, &group) == 0 &&
            rn_group_install(group) == 0,
        "stop group includes acceptor and workers");
  dispatch_loop loops[WORKERS + 1];
  HANDLE threads[WORKERS + 1];
  memset(loops, 0, sizeof(loops));
  for (unsigned i = 0; i <= WORKERS; ++i) {
    loops[i].reactor = members[i];
    loops[i].group = group;
    loops[i].acceptor = i == 0;
    atomic_init(&loops[i].accepted, 0);
    atomic_init(&loops[i].errors, 0);
    atomic_init(&loops[i].thread_id, 0);
  }
  atomic_store(&native_allocations, 0);
  atomic_store(&track_native_allocations, 1);
  threads[0] = CreateThread(NULL, 0, dispatch_thread, &loops[0], 0, NULL);
  check(threads[0] != NULL, "start dedicated acceptor thread");
  SOCKET clients[INITIAL];
  uint8_t payloads[INITIAL][64];
  for (unsigned i = 0; i < INITIAL; ++i) {
    clients[i] = connect_client(port);
    memset(payloads[i], (int)i, sizeof(payloads[i]));
    payloads[i][0] = 255;
    check(send(clients[i], (const char *)payloads[i], sizeof(payloads[i]), 0) ==
                  sizeof(payloads[i]) &&
              shutdown(clients[i], SD_SEND) == 0,
          "queue clients before any worker runs");
  }
  uint64_t end = rn_now_ms() + 3000;
  int all_full = 0;
  while (!all_full && rn_now_ms() < end) {
    all_full = 1;
    for (unsigned i = 0; i < WORKERS; ++i) {
      rn_accept_channel *channel = workers[i]->incoming_accepts;
      if (rn_channel_count(channel, atomic_load(&channel->head),
                           atomic_load(&channel->tail)) != 3)
        all_full = 0;
    }
    if (!all_full)
      Sleep(1);
  }
  check(all_full, "all bounded queues reach capacity with workers paused");
  for (unsigned i = 1; i <= WORKERS; ++i) {
    threads[i] = CreateThread(NULL, 0, dispatch_thread, &loops[i], 0, NULL);
    check(threads[i] != NULL, "start dedicated IOCP worker thread");
  }
  for (unsigned i = 0; i < INITIAL; ++i) {
    receive_exact_echo(clients[i], payloads[i], sizeof(payloads[i]));
    check(closesocket(clients[i]) == 0, "close backpressure client");
  }
  unsigned baseline[WORKERS];
  for (unsigned i = 0; i < WORKERS; ++i)
    baseline[i] = atomic_load(&loops[i + 1].accepted);
  for (unsigned i = 0; i < SEQUENTIAL; ++i) {
    SOCKET client = connect_client(port);
    uint8_t payload[] = {0, 1, 255, (uint8_t)i, 17};
    check(send(client, (const char *)payload, sizeof(payload), 0) ==
                  sizeof(payload) &&
              shutdown(client, SD_SEND) == 0,
          "sequential RR client");
    receive_exact_echo(client, payload, sizeof(payload));
    check(closesocket(client) == 0, "close RR client");
  }
  check(rn_group_request_stop(group) == 0, "stop every dedicated loop");
  check(WaitForMultipleObjects(WORKERS + 1, threads, TRUE, 5000) ==
            WAIT_OBJECT_0,
        "join acceptor and all IOCP workers");
  atomic_store(&track_native_allocations, 0);
  unsigned accepted = 0;
  for (unsigned i = 0; i <= WORKERS; ++i) {
    check(CloseHandle(threads[i]), "close joined thread handle");
    check(atomic_load(&loops[i].errors) == 0,
          "worker/native event has no error");
    if (i) {
      unsigned total = atomic_load(&loops[i].accepted);
      check(total >= 3 && total - baseline[i - 1] == SEQUENTIAL / WORKERS,
            "exact round robin when every worker has capacity");
      accepted += total;
    }
    for (unsigned j = 0; j < i; ++j)
      check(atomic_load(&loops[i].thread_id) !=
                atomic_load(&loops[j].thread_id),
            "one distinct OS thread per loop");
  }
  check(atomic_load(&loops[0].accepted) == 0 &&
            accepted == INITIAL + SEQUENTIAL,
        "each accepted socket reaches exactly one worker");
  check(atomic_load(&native_allocations) == 0,
        "no native heap allocation after setup");
  check(rn_group_free(group) == 0, "unregister group after join");
  check(rn_free(acceptor) == 0, "free acceptor before workers after join");
  for (unsigned i = 0; i < WORKERS; ++i)
    check(rn_free(workers[i]) == 0, "free IOCP worker");
}
static void dispatch_free_order(int producer_first) {
  rn_config options = config();
  rn_reactor *acceptor, *worker;
  check(rn_new(&options, &acceptor) == 0 && rn_new(&options, &worker) == 0,
        "create free-order endpoints");
  check(rn_set_accept_targets(acceptor, &worker, 1, 3) == 0,
        "configure nonpower queue for free-order test");
  uint64_t listener;
  check(rn_listen(acceptor, "127.0.0.1", 0, 0, &listener) == 0,
        "free-order listener");
  SOCKET clients[4];
  for (unsigned i = 0; i < 4; ++i)
    clients[i] = connect_client(listener_port(acceptor, listener));
  uint64_t end = rn_now_ms() + 3000;
  while (rn_now_ms() < end) {
    check(rn_step(acceptor, 10) >= 0, "fill free-order handoff queue");
    if (rn_channel_count(worker->incoming_accepts,
                         atomic_load(&worker->incoming_accepts->head),
                         atomic_load(&worker->incoming_accepts->tail)) == 3 &&
        acceptor->connections[rn_index(listener)].dispatch_pending != RN_NONE)
      break;
  }
  check(acceptor->connections[rn_index(listener)].dispatch_pending != RN_NONE,
        "acceptor retains one socket when all queues are full");
  if (producer_first) {
    check(rn_free(acceptor) == 0,
          "free producer with queued and retained accepted sockets");
    unsigned accepted = 0;
    end = rn_now_ms() + 3000;
    while (accepted < 3 && rn_now_ms() < end) {
      int count = rn_step(worker, 10);
      check(count >= 0, "worker may safely repoll after acceptor free");
      for (int i = 0; i < count; ++i) {
        const rn_event *event = rn_event_at(worker, (uint32_t)i);
        if (event->kind == RN_ACCEPTED)
          ++accepted;
        check(event->kind != RN_ERROR, "no wake through freed producer handle");
      }
    }
    check(accepted == 3 && rn_free(worker) == 0,
          "worker adopts queued sockets after producer free");
  } else {
    check(rn_free(worker) == 0, "free consumer closes all queued sockets");
    int saw_closed_target = 0;
    for (unsigned attempt = 0; attempt < 10 && !saw_closed_target; ++attempt) {
      int count = rn_step(acceptor, 0);
      check(count >= 0, "acceptor safely repolls after consumer free");
      for (int i = 0; i < count; ++i) {
        const rn_event *event = rn_event_at(acceptor, (uint32_t)i);
        if (event->kind == RN_ERROR && event->result == -EPIPE)
          saw_closed_target = 1;
      }
    }
    check(saw_closed_target && rn_free(acceptor) == 0,
          "closed consumers fail cleanly without reactor dereference");
  }
  for (unsigned i = 0; i < 4; ++i)
    check(closesocket(clients[i]) == 0, "close free-order clients");
}
static void test_dispatch_lifetime(void) {
  dispatch_free_order(0);
  dispatch_free_order(1);
  DWORD before, after;
  check(GetProcessHandleCount(GetCurrentProcess(), &before),
        "handoff handle baseline");
  for (unsigned cycle = 0; cycle < 64; ++cycle)
    dispatch_free_order((int)(cycle & 1));
  check(GetProcessHandleCount(GetCurrentProcess(), &after) &&
            after <= before + 1,
        "queue sockets and shared IOCP port references do not leak");
}
static void test_console(int legacy) {
  if (legacy) {
    check(result_i64(shim_interrupt_begin()) == 0, "legacy console setup");
    puts("READY");
    fflush(stdout);
    lean_object *entries = empty_ba();
    check(result_count(shim_poll(entries, -1), NULL, 0) == -EINTR,
          "console event wakes legacy poll");
    lean_dec(entries);
    check(result_i64(shim_interrupt_end()) == 0, "legacy console teardown");
  } else {
    rn_reactor *reactor;
    rn_config options = config();
    rn_group *group;
    check(rn_new(&options, &reactor) == 0, "console reactor create");
    check(rn_group_new(&reactor, 1, &group) == 0 &&
              rn_group_install(group) == 0,
          "console group setup");
    puts("READY");
    fflush(stdout);
    uint64_t end = rn_now_ms() + 5000;
    while (rn_group_stopping(group) == 0 && rn_now_ms() < end)
      check(rn_step(reactor, -1) >= 0, "console IOCP wait");
    check(rn_group_stopping(group) == 1 && rn_group_take_wake_error(group) == 0,
          "console event stops and wakes IOCP group");
    check(rn_group_free(group) == 0, "console group lifetime barrier");
    check(rn_free(reactor) == 0, "console reactor free after barrier");
  }
}
int main(int argc, char **argv) {
  lean_initialize_runtime_module();
  lean_io_mark_end_initialization();
  if (argc == 2 && strcmp(argv[1], "--transport") == 0) {
    test_transport_pause_vectors();
    test_historical_write_liveness();
    test_generation_retirement();
  } else if (argc == 2 && strcmp(argv[1], "--dispatch") == 0) {
    test_dispatch_validation();
    test_dispatch_capacity_one();
    test_dispatch_threads();
    test_dispatch_lifetime();
  } else if (argc == 2)
    test_console(strcmp(argv[1], "--legacy-console") == 0);
  else {
    test_pool_and_timer();
    test_echo_and_cancellation();
    test_legacy_and_handles();
  }
  puts("Windows IOCP, Winsock, buffer and cancellation tests passed");
  return 0;
}
