/* Compile the real backend into this test so libc and Lean heap calls in that
 * translation unit can be counted during established I/O. Startup allocations
 * are allowed; the measured path includes accept, reads, writes and closure. */
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#include "../c/reactor.h"
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/epoll.h>
#else
#include <sys/event.h>
#endif
static unsigned hot_path;
static unsigned allocation_attempts;
static int injected_wait_error;
static unsigned native_wait_calls;
static int injected_read_error;
static unsigned native_read_calls;
static ssize_t rn_test_read(int fd, void *bytes, size_t size) {
    ++native_read_calls;
    if (injected_read_error) { errno = injected_read_error; injected_read_error = 0; return -1; }
    return read(fd, bytes, size);
}
#define read(...) rn_test_read(__VA_ARGS__)
#if defined(__linux__)
static int rn_test_epoll_wait(int fd, struct epoll_event *events, int count, int timeout) {
    ++native_wait_calls;
    if (injected_wait_error) { errno = injected_wait_error; injected_wait_error = 0; return -1; }
    return epoll_wait(fd, events, count, timeout);
}
#define epoll_wait(...) rn_test_epoll_wait(__VA_ARGS__)
#else
static int rn_test_kevent(int fd, const struct kevent *changes, int change_count,
                          struct kevent *events, int event_count, const struct timespec *timeout) {
    if (change_count == 0) {
        ++native_wait_calls;
        if (injected_wait_error) { errno = injected_wait_error; injected_wait_error = 0; return -1; }
    }
    return kevent(fd, changes, change_count, events, event_count, timeout);
}
#define kevent(...) rn_test_kevent(__VA_ARGS__)
#endif
#define malloc(size) (allocation_attempts += hot_path, malloc(size))
#define calloc(count, size) (allocation_attempts += hot_path, calloc(count, size))
#define realloc(ptr, size) (allocation_attempts += hot_path, realloc(ptr, size))
#define lean_alloc_sarray(elem, size, cap) (allocation_attempts += hot_path, lean_alloc_sarray(elem, size, cap))
#include "../c/reactor_posix.c"
#undef malloc
#undef calloc
#undef realloc
#undef lean_alloc_sarray
#undef read
#if defined(__linux__)
#undef epoll_wait
#else
#undef kevent
#endif

void lean_initialize_runtime_module(void);

static void check(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "reactor POSIX test: %s (errno %d)\n", message, errno); exit(1); }
}
static void dispatch_echo(rn_reactor *r, int count) {
    check(count >= 0, "step succeeds");
    for (int i = 0; i < count; ++i) {
        rn_event event = *rn_event_at(r, (uint32_t)i);
        if (event.kind == RN_READ) {
            check(rn_queue_write(r, event.connection, event.buffer, event.offset, event.length, 1) == 0, "queue echo");
            check(rn_buffer_release(r, event.buffer) == 0, "release receive lease");
        } else if (event.kind == RN_EOF) {
            check(rn_close_after_writes(r, event.connection) == 0, "drain half-close");
        } else if (event.kind == RN_ERROR) {
            check(event.result == -ECONNRESET || event.result == -EPIPE, "ordinary peer error only");
            check(event.flags == 0 || event.flags == RN_ACCEPT_ERROR, "no setup/close error");
        }
    }
}
static void drain_completion_regression(rn_reactor *r, const struct sockaddr_in *address) {
    int client = socket(AF_INET, SOCK_STREAM, 0);
    check(client >= 0 && connect(client, (const struct sockaddr *)address, sizeof(*address)) == 0, "connect drain completion peer");
    check(send(client, "end", 3, 0) == 3 && shutdown(client, SHUT_WR) == 0, "send drain completion payload");
    uint64_t connection = 0; int written = 0, closed = 0, same_batch = 0;
    for (unsigned tick = 0; tick < 100 && !closed; ++tick) {
        int count = rn_step(r, 10); int batch_written = 0;
        check(count >= 0, "poll drain completion");
        for (int i = 0; i < count; ++i) {
            rn_event event = *rn_event_at(r, (uint32_t)i);
            if (event.kind == RN_ACCEPTED) connection = event.connection;
            else if (event.kind == RN_READ) {
                check(event.length == 3, "drain completion read length");
                check(rn_queue_write(r, event.connection, event.buffer, 0, 3, 12345) == 0, "queue final write");
                check(rn_buffer_release(r, event.buffer) == 0, "release final write lease");
            } else if (event.kind == RN_EOF) {
                check(rn_close_after_writes(r, event.connection) == 0, "drain final write");
                uint64_t late;
                check(rn_acquire_buffer(r, 3, &late) == 0 && rn_buffer_copy(r, late, (const uint8_t *)"bad", 3) == 0, "acquire late-write lease");
                unsigned free_writes = r->free_write_count;
                check(rn_queue_write(r, event.connection, late, 0, 3, 67890) == -EPIPE, "new writes rejected after drain-close");
                lean_object *view = NULL;
                check(r->free_write_count == free_writes && rn_buffer_view(r, late, &view) == 0 && lean_sarray_size(view) == 3, "rejected drain write preserves lease and credits");
                check(rn_buffer_release(r, late) == 0, "release preserved late-write lease");
            } else if (event.kind == RN_WRITTEN) {
                check(event.connection == connection && event.operation == 12345 && event.result == 3, "final write completion identity");
                check(!written && !closed, "final write completes once before close");
                written = 1; batch_written = 1;
            } else if (event.kind == RN_CLOSED) {
                check(event.connection == connection && written, "successful final write is delivered before CLOSED");
                closed = 1; same_batch = batch_written;
            } else check(event.kind != RN_ERROR, "drain completion has no error");
        }
    }
    check(written && closed && same_batch, "WRITTEN survives closing in the same batch");
    char bytes[4];
    check(recv(client, bytes, sizeof(bytes), 0) == 3 && memcmp(bytes, "end", 3) == 0, "final write reaches peer");
    check(recv(client, bytes, sizeof(bytes), 0) == 0 && close(client) == 0, "drained completion peer EOF");
}
static void committed_wait_error_regression(rn_reactor *r) {
    const int errors[] = {EINTR, EIO};
    for (unsigned i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        uint64_t socket;
        check(rn_socket_new(r, &socket) == 0 && rn_close_connection(r, socket) == 0, "commit close before wait error");
        unsigned calls = native_wait_calls;
        injected_wait_error = errors[i];
        check(rn_step(r, 0) == 1 && rn_event_at(r, 0)->kind == RN_CLOSED, "committed CLOSED survives wait error");
        check(native_wait_calls == calls + 1, "failed native wait is not retried");
        check(rn_step(r, 0) == -errors[i] && native_wait_calls == calls + 1, "wait error is surfaced on next poll");
        check(rn_step(r, 0) == 0 && native_wait_calls == calls + 2, "wait error is surfaced exactly once");

        check(rn_socket_new(r, &socket) == 0, "create due timer socket");
        check(rn_arm_timer(r, socket, 3, rn_now_ms() + 1) == 0, "arm timer before wait error");
        const struct timespec pause = {0, 3000000};
        check(nanosleep(&pause, NULL) == 0, "wait for timer deadline");
        calls = native_wait_calls; injected_wait_error = errors[i];
        check(rn_step(r, 0) == 1, "committed TIMER survives wait error");
        const rn_event *event = rn_event_at(r, 0);
        check(event->kind == RN_TIMER && event->connection == socket && event->operation == 3, "due timer identity survives wait error");
        check(native_wait_calls == calls + 1, "timer wait error is not retried");
        check(rn_step(r, 0) == -errors[i] && native_wait_calls == calls + 1, "timer wait error surfaced next poll");
        check(rn_close_connection(r, socket) == 0 && rn_step(r, 0) == 1, "close timer regression socket");
    }
}
static void interrupted_wake_regression(rn_reactor *r) {
    check(rn_wake(r) == 0, "publish wake before interrupted read");
    unsigned calls = native_read_calls;
    injected_read_error = EINTR;
    check(rn_step(r, 0) == 1, "interrupted wake still delivers completion");
    const rn_event *wake = rn_event_at(r, 0);
    check(wake->kind == RN_WAKE && wake->result == 0, "wake has a valid success result");
    check(native_read_calls == calls + 1, "interrupted wake read is not retried");
    check(rn_step(r, 0) == -EINTR && native_read_calls == calls + 1, "wake interruption surfaces next poll");
    check(rn_step(r, 0) == 1 && rn_event_at(r, 0)->kind == RN_WAKE, "unconsumed wake survives interruption");
    check(rn_step(r, 0) == 0, "wake interruption surfaced exactly once");
}
static void half_close_idle_regression(rn_reactor *r) {
#if defined(__linux__)
    int pair[2];
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "create half-close idle pair");
    check(rn_nonblocking(pair[0]) == 0 && shutdown(pair[1], SHUT_WR) == 0, "half-close idle peer");
    int capacity = 4096;
    check(setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &capacity, sizeof(capacity)) == 0, "bound idle send capacity");
    unsigned char bytes[4096] = {0};
    for (;;) {
        ssize_t n = send(pair[0], bytes, sizeof(bytes), 0);
        if (n < 0) { check(errno == EAGAIN || errno == EWOULDBLOCK, "fill idle send buffer"); break; }
        check(n > 0, "idle send makes progress");
    }
    uint64_t token;
    check(rn_socket_new(r, &token) == 0, "allocate idle connection");
    rn_conn *connection = &r->connections[rn_index(token)];
    connection->fd = pair[0]; connection->state = 4; connection->eof = 1;
    check(rn_interest(r, rn_index(token), 2) == 0, "watch write-only half-closed socket");
    struct epoll_event events[7];
    check(epoll_wait(r->queue_fd, events, 7, 30) == 0, "half-close must sleep while writes are blocked");
    check(rn_close_connection(r, token) == 0 && close(pair[1]) == 0, "close idle pair");
    check(rn_step(r, 0) == 1 && rn_event_at(r, 0)->kind == RN_CLOSED, "idle pair closes once");
#else
    (void)r;
#endif
}
int main(void) {
    lean_initialize_runtime_module();
    const rn_config config = {16, 7, 32, 2, 1, 1, 1};
    rn_reactor *r = NULL;
    check(rn_new(&config, &r) == 0, "create reactor");
    uint64_t listener;
    check(rn_listen(r, "127.0.0.1", 0, 0, &listener) == 0, "listen on ephemeral port");
    struct sockaddr_in address; socklen_t address_length = sizeof(address);
    check(getsockname(r->connections[rn_index(listener)].fd, (struct sockaddr *)&address, &address_length) == 0, "listener address");
    unsigned char payload[65536], received[65536];
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (unsigned char)(i * 17u + (i >> 8));
    hot_path = 1;
    drain_completion_regression(r, &address);
    committed_wait_error_regression(r);
    interrupted_wake_regression(r);
    half_close_idle_regression(r);
    for (unsigned iteration = 0; iteration < 500; ++iteration) {
        int client = socket(AF_INET, SOCK_STREAM, 0);
        check(client >= 0 && connect(client, (struct sockaddr *)&address, sizeof(address)) == 0, "connect peer");
        size_t sent = 0;
        while (sent < sizeof(payload)) {
            ssize_t n = send(client, payload + sent, sizeof(payload) - sent, 0);
            check(n > 0, "send peer payload"); sent += (size_t)n;
        }
        if (iteration % 10u == 0) {
            struct linger reset = {1, 0};
            check(setsockopt(client, SOL_SOCKET, SO_LINGER, &reset, sizeof(reset)) == 0 && close(client) == 0, "reset peer");
            for (unsigned tick = 0; tick < 8; ++tick) dispatch_echo(r, rn_step(r, 0));
            continue;
        }
        check(shutdown(client, SHUT_WR) == 0 && rn_nonblocking(client) == 0, "half-close peer");
        size_t got = 0; int eof = 0;
        for (unsigned tick = 0; tick < 10000u && !eof; ++tick) {
            dispatch_echo(r, rn_step(r, 0));
            unsigned char extra;
            ssize_t n = recv(client, got < sizeof(received) ? received + got : &extra,
                             got < sizeof(received) ? sizeof(received) - got : 1u, 0);
            if (n > 0) { check(got + (size_t)n <= sizeof(received), "no extra bytes"); got += (size_t)n; }
            else if (n == 0) eof = 1;
            else check(errno == EAGAIN || errno == EWOULDBLOCK, "receive echo");
        }
        check(eof && got == sizeof(payload) && memcmp(payload, received, got) == 0, "binary echo drained before EOF");
        check(close(client) == 0, "close peer");
    }
    /* All pool cells must return once no application alias or write owns them. */
    for (unsigned tick = 0; tick < 8; ++tick) dispatch_echo(r, rn_step(r, 0));
    uint64_t leases[4];
    for (unsigned i = 0; i < 4; ++i) check(rn_acquire_buffer(r, 4096, &leases[i]) == 0, "all pooled cells reclaimed");
    uint64_t excess;
    check(rn_acquire_buffer(r, 4096, &excess) == -EAGAIN, "pool exhaustion bounded");
    for (unsigned i = 0; i < 4; ++i) check(rn_buffer_release(r, leases[i]) == 0, "release reclaimed cell");
    check(rn_close_connection(r, listener) == 0, "close listener");
    check(rn_step(r, 0) == 1 && rn_event_at(r, 0)->kind == RN_CLOSED, "listener closed once");
    hot_path = 0;
    check(allocation_attempts == 0, "no backend native or Lean buffer allocations during established I/O");
    check(rn_free(r) == 0, "free reactor");
    puts("reactor POSIX ASan lifecycle and zero-allocation tests passed (500 peers, 50 resets)");
    return 0;
}
