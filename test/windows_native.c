/* Real IOCP/Winsock integration and lifetime regression fixture. Including the
 * production units permits checking pending operation ownership and ephemeral
 * ports without widening the public API merely for tests. */
#ifndef _WIN32
#error This fixture must run on Windows
#endif
#include "../c/reactor_group.h"
#include "../c/reactor_windows.c"
#include "../c/socket_windows.c"

void lean_initialize_runtime_module(void);
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
  if (argc == 2)
    test_console(strcmp(argv[1], "--legacy-console") == 0);
  else {
    test_pool_and_timer();
    test_echo_and_cancellation();
    test_legacy_and_handles();
  }
  puts("Windows IOCP, Winsock, buffer and cancellation tests passed");
  return 0;
}
