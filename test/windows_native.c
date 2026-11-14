/* Real IOCP/Winsock integration and lifetime regression fixture. Including the
 * production units permits checking pending operation ownership and ephemeral
 * ports without widening the public API merely for tests. */
#ifndef _WIN32
#error This fixture must run on Windows
#endif
#include "../c/reactor_group.h"
#include <stdatomic.h>
#include <stdlib.h>
static atomic_int track_native_allocations, native_allocations;
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
#include "../c/reactor_windows.c"
#undef malloc
#undef calloc
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
  if (argc == 2 && strcmp(argv[1], "--dispatch") == 0) {
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
