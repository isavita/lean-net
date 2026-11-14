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
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
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
static size_t injected_recv_prefix;
static size_t vector_send_limit;
static unsigned native_vector_calls, max_vector_count;
static int vector_prefix(const struct iovec *input, int count, struct iovec *output) {
    ++native_vector_calls;
    if ((unsigned)count > max_vector_count) max_vector_count = (unsigned)count;
    size_t remaining = vector_send_limit ? vector_send_limit : SIZE_MAX;
    int used = 0;
    for (int i = 0; i < count && remaining; ++i) {
        output[used] = input[i];
        if (output[used].iov_len > remaining) output[used].iov_len = remaining;
        remaining -= output[used].iov_len;
        ++used;
    }
    return used;
}
#if defined(__linux__)
static ssize_t rn_test_sendmsg(int fd, const struct msghdr *message, int flags) {
    struct iovec vectors[16]; struct msghdr prefix = *message;
    prefix.msg_iovlen = (size_t)vector_prefix(message->msg_iov, (int)message->msg_iovlen, vectors);
    prefix.msg_iov = vectors;
    return sendmsg(fd, &prefix, flags);
}
#define sendmsg(...) rn_test_sendmsg(__VA_ARGS__)
#else
static ssize_t rn_test_writev(int fd, const struct iovec *vectors, int count) {
    struct iovec prefix[16];
    return writev(fd, prefix, vector_prefix(vectors, count, prefix));
}
#define writev(...) rn_test_writev(__VA_ARGS__)
#endif
static ssize_t rn_test_read(int fd, void *bytes, size_t size) {
    ++native_read_calls;
    if (injected_read_error) { errno = injected_read_error; injected_read_error = 0; return -1; }
    return read(fd, bytes, size);
}
#define read(...) rn_test_read(__VA_ARGS__)
static ssize_t rn_test_recv(int fd, void *bytes, size_t size, int flags) {
    if (injected_recv_prefix) {
        if (size > injected_recv_prefix) size = injected_recv_prefix;
        injected_recv_prefix = 0;
    }
    return recv(fd, bytes, size, flags);
}
#define recv(...) rn_test_recv(__VA_ARGS__)
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
#undef recv
#if defined(__linux__)
#undef sendmsg
#else
#undef writev
#endif
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
                int live = rn_connection_live(r, event.connection);
                int late_result = rn_queue_write(r, event.connection, late, 0, 3, 67890);
                check(late_result == (live ? -EPIPE : -EBADF), "new writes rejected during drain or after immediate close");
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
static uint64_t connected_peer(rn_reactor *r, uint64_t listener, int *peer) {
    struct sockaddr_in address; socklen_t length = sizeof(address);
    check(getsockname(r->connections[rn_index(listener)].fd, (struct sockaddr *)&address, &length) == 0, "transport listener address");
    *peer = socket(AF_INET, SOCK_STREAM, 0);
    check(*peer >= 0 && connect(*peer, (struct sockaddr *)&address, sizeof(address)) == 0, "connect transport peer");
    for (unsigned tick = 0; tick < 100; ++tick) {
        int count = rn_step(r, 10); check(count >= 0, "accept transport peer");
        for (int i = 0; i < count; ++i) {
            const rn_event *event = rn_event_at(r, (uint32_t)i);
            if (event->kind == RN_ACCEPTED) return event->connection;
        }
    }
    check(0, "transport accept timeout"); return 0;
}
static size_t collect_large_reads(rn_reactor *r, int count, uint64_t connection,
    const unsigned char *expected, size_t total, size_t *received,
    uint64_t *held, unsigned *held_count, int *eof) {
    check(count >= 0, "poll large-buffer receive burst");
    size_t batch_bytes = 0;
    for (int i = 0; i < count; ++i) {
        const rn_event *event = rn_event_at(r, (uint32_t)i);
        check(event->connection == connection, "large-buffer completion identity");
        if (event->kind == RN_READ) {
            lean_object *view = NULL;
            check(rn_buffer_view(r, event->buffer, &view) == 0 &&
                r->buffers[rn_index(event->buffer)].capacity == 65536,
                "receive uses fallback 64K pool class");
            check(event->length <= total - *received && event->offset == 0 &&
                lean_sarray_size(view) == event->length &&
                memcmp(lean_sarray_cptr(view), expected + *received, event->length) == 0,
                "bounded receive burst preserves exact binary order");
            *received += event->length; batch_bytes += event->length;
            if (held) {
                check(*held_count < 16, "bounded first-batch leases");
                held[(*held_count)++] = event->buffer;
            } else check(rn_buffer_release(r, event->buffer) == 0, "return resumed large-buffer lease");
        } else {
            check(event->kind == RN_EOF && *received == total && !*eof,
                "large-buffer EOF follows every payload byte once");
            *eof = 1;
        }
    }
    check(batch_bytes <= 65536, "one connection returns at most 64KiB per poll even with 64K buffers");
    return batch_bytes;
}
static void large_read_budget_regression(void) {
    hot_path = 0;
    rn_config config = {1, 32, 1, 0, 0, 20, 1}; rn_reactor *r = NULL;
    check(rn_new(&config, &r) == 0, "create 64K-only receive pool");
    int pair[2]; check(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "create large receive burst pair");
    int capacity = 262144;
    check(setsockopt(pair[1], SOL_SOCKET, SO_SNDBUF, &capacity, sizeof(capacity)) == 0 &&
        rn_nonblocking(pair[0]) == 0 && rn_nonblocking(pair[1]) == 0,
        "reserve socket capacity for preloaded receive burst");
    uint64_t connection = 0; check(rn_socket_new(r, &connection) == 0, "allocate large burst connection");
    rn_conn *native = &r->connections[rn_index(connection)]; native->fd = pair[0]; native->state = 4;
    check(rn_interest(r, rn_index(connection), 1) == 0, "watch preloaded receive burst");
    unsigned char payload[2 * 65536 + 137];
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (unsigned char)(i * 29u + (i >> 7));
    unsigned allocations = allocation_attempts; hot_path = 1;
    size_t sent = 0;
    while (sent < sizeof(payload)) {
        ssize_t n = send(pair[1], payload + sent, sizeof(payload) - sent, 0);
        check(n > 0, "preload more than 64KiB before native poll"); sent += (size_t)n;
    }
    check(shutdown(pair[1], SHUT_WR) == 0, "half-close preloaded binary burst");
    size_t received = 0; uint64_t held[16]; unsigned held_count = 0; int eof = 0;
    /* A short first recv forces the following 64K cell to use only the
     * remaining quantum rather than overshooting before checking a counter. */
    injected_recv_prefix = 17;
    size_t first = collect_large_reads(r, rn_step(r, 10), connection, payload,
        sizeof(payload), &received, held, &held_count, &eof);
    check(first > 0 && received < sizeof(payload) && !eof && rn_connection_live(r, connection) == 1,
        "first receive quantum leaves unread data and live socket");
    check(rn_set_read_enabled(r, connection, 0) == 0, "pause after returned large-buffer batch");
    for (unsigned i = 0; i < 4; ++i) check(rn_step(r, 1) == 0, "application pause prevents further large reads and EOF");
    size_t offset = 0;
    for (unsigned i = 0; i < held_count; ++i) {
        lean_object *view = NULL;
        check(rn_buffer_view(r, held[i], &view) == 0 &&
            memcmp(lean_sarray_cptr(view), payload + offset, lean_sarray_size(view)) == 0,
            "pause leaves already-returned leases intact");
        offset += lean_sarray_size(view);
        check(rn_buffer_release(r, held[i]) == 0, "return paused large-buffer lease");
    }
    check(offset == first && rn_set_read_enabled(r, connection, 1) == 0,
        "resume preserves independent user read control");
    for (unsigned i = 0; i < 100 && !eof; ++i)
        (void)collect_large_reads(r, rn_step(r, 10), connection, payload,
            sizeof(payload), &received, NULL, NULL, &eof);
    check(eof && received == sizeof(payload) && allocation_attempts == allocations,
        "resumed 64K quanta deliver all bytes without native or Lean-buffer allocation");
    check(rn_close_connection(r, connection) == 0 && rn_step(r, 0) == 1 &&
        rn_event_at(r, 0)->kind == RN_CLOSED, "large-buffer connection closes once");
    hot_path = 0; check(close(pair[1]) == 0 && rn_free(r) == 0, "free large receive budget fixture");
}
static void pause_and_vectors_regression(void) {
    for (unsigned mode = 0; mode < 2; ++mode) {
        hot_path = 0;
        rn_config config = {4, mode ? 32u : 2u, 32, 4, 0, 0, 1};
        rn_reactor *r = NULL; uint64_t listener = 0;
        check(rn_new(&config, &r) == 0 && rn_listen(r, "127.0.0.1", 0, 0, &listener) == 0, "create transport reactor");
        int peer; uint64_t connection = connected_peer(r, listener, &peer);
        hot_path = 1;
        check(rn_set_read_enabled(r, listener, 0) == -EINVAL && rn_set_read_enabled(r, connection, 2) == -EINVAL, "validate read control");
        check(rn_set_read_enabled(r, connection, 0) == 0, "pause transport reads");
        check(send(peer, "abc", 3, 0) == 3 && rn_step(r, 1) == 0, "paused reads do not consume input");
        uint64_t held[4];
        for (unsigned i = 0; i < 4; ++i) check(rn_acquire_buffer(r, 4096, &held[i]) == 0, "hold pool under user pause");
        check(rn_set_read_enabled(r, connection, 1) == 0 && rn_step(r, 0) == 0, "pool pressure pauses an enabled read");
        check(r->connections[rn_index(connection)].paused, "resource pause tracked separately");
        check(rn_set_read_enabled(r, connection, 0) == 0, "user pause while pool paused");
        for (unsigned i = 0; i < 4; ++i) check(rn_buffer_release(r, held[i]) == 0, "return pool cells");
        check(rn_step(r, 1) == 0, "pool recovery cannot override user pause");
        check(rn_set_read_enabled(r, connection, 1) == 0, "resume pooled reads");
        int saw_read = 0;
        for (unsigned tick = 0; tick < 100 && !saw_read; ++tick) {
            int count = rn_step(r, 1); check(count >= 0, "poll resumed input");
            for (int i = 0; i < count; ++i) {
                const rn_event *event = rn_event_at(r, (uint32_t)i);
                if (event->kind == RN_READ) {
                    lean_object *view; check(rn_buffer_view(r, event->buffer, &view) == 0 && lean_sarray_size(view) == 3 && memcmp(lean_sarray_cptr(view), "abc", 3) == 0, "resumed input remains exact");
                    check(rn_set_read_enabled(r, connection, 0) == 0 && rn_buffer_release(r, event->buffer) == 0, "pause preserves returned read lease");
                    saw_read = 1;
                }
            }
        }
        check(saw_read, "resumed read delivered");
        unsigned char block[4096], expected[20 * 4096], received[20 * 4096]; size_t size = 0;
        uint64_t buffers[4]; lean_object *retained;
        for (unsigned b = 0; b < 4; ++b) {
            for (size_t i = 0; i < sizeof(block); ++i) block[i] = (unsigned char)(i * 13 + b);
            check(rn_acquire_buffer(r, 4096, &buffers[b]) == 0 && rn_buffer_copy(r, buffers[b], block, sizeof(block)) == 0, "prepare vector pool cells");
        }
        check(rn_buffer_view(r, buffers[0], &retained) == 0, "retain vector source view"); lean_inc(retained);
        for (unsigned op = 0; op < 20; ++op) {
            unsigned b = op % 4, offset = op % 19, length = op % 5 == 0 ? 0 : 4096 - offset;
            check(rn_queue_write(r, connection, buffers[b], offset, length, op + 1) == 0, "queue ordered vector slice");
            lean_object *view; check(rn_buffer_view(r, buffers[b], &view) == 0, "view vector source");
            memcpy(expected + size, lean_sarray_cptr(view) + offset, length); size += length;
        }
        for (unsigned b = 0; b < 4; ++b) check(rn_buffer_release(r, buffers[b]) == 0, "release vector lease while pinned");
        check(rn_close_after_writes(r, connection) == 0 && rn_nonblocking(peer) == 0, "drain vectors while reads paused");
        vector_send_limit = 97; native_vector_calls = max_vector_count = 0;
        size_t got = 0; unsigned written = 0, closed = 0; int eof = 0;
        for (unsigned tick = 0; tick < 10000 && (!eof || !closed); ++tick) {
            int count = rn_step(r, 0); check(count >= 0 && (unsigned)count <= config.max_events, "bounded vector completion count");
            for (int i = 0; i < count; ++i) {
                const rn_event *event = rn_event_at(r, (uint32_t)i);
                if (event->kind == RN_WRITTEN) {
                    check(event->operation == ++written && written <= 20, "vector operations complete in order once");
                    unsigned op = written - 1, length = op % 5 == 0 ? 0 : 4096 - op % 19;
                    check(event->result == length && event->length == length, "vector completion reports its whole logical slice");
                } else if (event->kind == RN_CLOSED) { check(written == 20, "all vector completions precede close"); closed = 1; }
                else check(event->kind != RN_ERROR && event->kind != RN_READ, "paused vector transport has no error/read");
            }
            unsigned char extra;
            ssize_t n = recv(peer, got < sizeof(received) ? received + got : &extra, got < sizeof(received) ? sizeof(received) - got : 1, 0);
            if (n > 0) got += (size_t)n;
            else if (!n) eof = 1;
            else check(errno == EAGAIN || errno == EWOULDBLOCK, "receive vector bytes");
        }
        check(eof && closed && got == size && memcmp(expected, received, size) == 0, "partial binary vectors remain exact");
        check(native_vector_calls > 20 && max_vector_count == (mode ? 16u : 2u), "writes coalesce within native event credits");
        vector_send_limit = 0;
        for (unsigned b = 0; b < 3; ++b) check(rn_acquire_buffer(r, 4096, &held[b]) == 0, "unaliased vector cells recycled");
        uint64_t unavailable; check(rn_acquire_buffer(r, 4096, &unavailable) == -EAGAIN, "retained vector view blocks its cell reuse");
        check(lean_sarray_cptr(retained)[17] == (uint8_t)(17 * 13), "retained vector bytes immutable"); lean_dec(retained);
        check(rn_acquire_buffer(r, 4096, &held[3]) == 0, "vector alias cell recyclable after release");
        for (unsigned b = 0; b < 4; ++b) check(rn_buffer_release(r, held[b]) == 0, "release transport test cells");
        check(close(peer) == 0, "close vector peer");
        connection = connected_peer(r, listener, &peer);
        check(rn_set_read_enabled(r, connection, 0) == 0, "pause cancellation reads");
        for (unsigned b = 0; b < 3; ++b) {
            check(rn_acquire_buffer(r, 4096, &buffers[b]) == 0 && rn_buffer_copy(r, buffers[b], block, sizeof(block)) == 0 && rn_queue_write(r, connection, buffers[b], 0, sizeof(block), 1001 + b) == 0, "queue cancellation vectors");
        }
        check(rn_buffer_view(r, buffers[0], &retained) == 0, "retain canceled vector source"); lean_inc(retained);
        for (unsigned b = 0; b < 3; ++b) check(rn_buffer_release(r, buffers[b]) == 0, "release canceled vector owner");
        vector_send_limit = 97; r->event_count = 0;
        check(rn_write_ready(r, rn_index(connection)) == 0 && r->writes[r->connections[rn_index(connection)].head_write].sent > 0, "force partial multi-buffer write before cancellation");
        check(rn_close_connection(r, connection) == 0 && r->free_write_count == config.max_writes, "cancel queued vectors releases every write credit");
        for (unsigned b = 0; b < 3; ++b) check(r->buffers[rn_index(buffers[b])].writes == 0, "canceled vectors release every native buffer pin");
        check(lean_sarray_size(retained) == sizeof(block) && memcmp(lean_sarray_cptr(retained), block, sizeof(block)) == 0, "canceled vector alias stays immutable"); lean_dec(retained);
        vector_send_limit = 0;
        check(rn_step(r, 0) == 1 && rn_event_at(r, 0)->kind == RN_CLOSED && close(peer) == 0, "canceled vector closes exactly once");
        connection = connected_peer(r, listener, &peer);
        check(send(peer, "lease", 5, 0) == 5, "send returned-batch lease");
        uint64_t returned = 0;
        for (unsigned tick = 0; tick < 100 && !returned; ++tick) {
            int count = rn_step(r, 1); check(count >= 0, "poll returned-batch lease");
            for (int i = 0; i < count; ++i) if (rn_event_at(r, (uint32_t)i)->kind == RN_READ) returned = rn_event_at(r, (uint32_t)i)->buffer;
        }
        check(returned && rn_set_read_enabled(r, connection, 0) == 0 && rn_close_connection(r, connection) == 0, "pause and close after READ batch returned");
        lean_object *view;
        check(rn_buffer_view(r, returned, &view) == 0 && lean_sarray_size(view) == 5 && memcmp(lean_sarray_cptr(view), "lease", 5) == 0 && rn_buffer_release(r, returned) == 0, "returned read lease survives connection close");
        check(rn_step(r, 0) == 1 && close(peer) == 0, "returned-batch close cleanup");
        hot_path = 0;
        check(rn_free(r) == 0, "free transport reactor");
    }
}
static void historical_write_liveness(void) {
    hot_path = 0;
    rn_config config = {4, 1, 4, 4, 0, 0, 1}; rn_reactor *r = NULL; uint64_t listener = 0;
    check(rn_new(&config, &r) == 0 && rn_listen(r, "127.0.0.1", 0, 0, &listener) == 0, "create liveness reactor");
    int peer; uint64_t connection = connected_peer(r, listener, &peer);
    hot_path = 1;
    check(rn_connection_live(NULL, connection) == -EINVAL && rn_connection_live(r, 0) == 0 && rn_connection_live(r, listener) == 0, "liveness rejects non-connection identities");
    check(rn_connection_live(r, connection) == 1 && rn_set_read_enabled(r, connection, 0) == 0 && rn_connection_live(r, connection) == 1, "paused live connection remains live");
    uint64_t buffer; check(rn_acquire_buffer(r, 3, &buffer) == 0 && rn_buffer_copy(r, buffer, (const uint8_t *)"bye", 3) == 0, "prepare liveness output");
    check(rn_queue_write(r, connection, buffer, 0, 3, 9001) == 0 && rn_buffer_release(r, buffer) == 0 && rn_close_after_writes(r, connection) == 0 && rn_connection_live(r, connection) == 1, "live query includes active drain");
    check(rn_step(r, 10) == 1 && rn_event_at(r, 0)->kind == RN_WRITTEN && rn_event_at(r, 0)->operation == 9001, "single-event batch returns historical write first");
    check(rn_connection_live(r, connection) == 0, "historical write identity is already closed before CLOSED delivery");
    check(rn_step(r, 0) == 1 && rn_event_at(r, 0)->kind == RN_CLOSED && rn_connection_live(r, connection) == 0, "queued CLOSED preserves dead liveness");
    uint64_t fresh; check(rn_socket_new(r, &fresh) == 0 && fresh != connection && rn_connection_live(r, fresh) == 0 && rn_connection_live(r, connection) == 0, "liveness cannot alias a recycled generation");
    check(close(peer) == 0, "close liveness peer"); hot_path = 0;
    check(rn_free(r) == 0, "free liveness reactor");
}
static void generation_retirement(void) {
    hot_path = 0;
    rn_config config = {1, 1, 1, 1, 0, 0, 1}; rn_reactor *r = NULL;
    check(rn_new(&config, &r) == 0, "create generation boundary reactor");
    hot_path = 1;
    uint64_t stale, last, unavailable = 0;
    check(rn_socket_new(r, &stale) == 0 && rn_close_connection(r, stale) == 0 && rn_step(r, 0) == 1, "recycle socket before boundary");
    r->connections[rn_index(stale)].generation = RN_GENERATION_MAX - 1;
    check(rn_socket_new(r, &last) == 0 && (int64_t)last > 0 && (last >> 32) == INT32_MAX, "final socket generation remains FFI-positive");
    check(rn_arm_timer(r, stale, 0, 0) == -EBADF && rn_close_connection(r, stale) == -EBADF, "old socket alias cannot reach final generation");
    check(rn_close_connection(r, last) == 0 && rn_step(r, 0) == 1 && rn_event_at(r, 0)->connection == last, "final socket closes with original positive identity");
    check(r->free_connection_count == 0 && rn_socket_new(r, &unavailable) == -EAGAIN && unavailable == 0, "exhausted socket slot retired without a wrapped token");
    check(rn_arm_timer(r, last, 0, 0) == -EBADF && rn_close_connection(r, last) == -EBADF && rn_arm_timer(r, stale, 0, 0) == -EBADF, "all socket aliases remain stale after retirement");
    check(rn_acquire_buffer(r, 1, &stale) == 0 && rn_buffer_release(r, stale) == 0, "recycle buffer before boundary");
    r->buffers[rn_index(stale)].generation = RN_GENERATION_MAX - 1;
    check(rn_acquire_buffer(r, 1, &last) == 0 && (int64_t)last > 0 && (last >> 32) == INT32_MAX, "final buffer generation remains FFI-positive");
    const uint8_t binary[] = {0, 255, 17}; lean_object *view = NULL;
    check(rn_buffer_copy(r, last, binary, sizeof(binary)) == 0 && rn_buffer_view(r, last, &view) == 0, "use final buffer generation"); lean_inc(view);
    check(rn_buffer_release(r, last) == 0 && r->free_buffer_count == 0 && !r->buffers[rn_index(last)].on_free, "final buffer retires outside free candidates");
    lean_object *invalid = NULL;
    check(rn_buffer_view(r, stale, &invalid) == -EINVAL && rn_buffer_view(r, last, &invalid) == -EINVAL && rn_buffer_release(r, last) == -EINVAL, "retired buffer aliases cannot reacquire ownership");
    check(lean_sarray_size(view) == sizeof(binary) && memcmp(lean_sarray_cptr(view), binary, sizeof(binary)) == 0, "retired buffer retained view is immutable"); lean_dec(view);
    unsigned calls = native_wait_calls;
    for (unsigned i = 0; i < 8; ++i) {
        check(rn_acquire_buffer(r, 1, &unavailable) == -EAGAIN && unavailable == 0 && rn_socket_new(r, &unavailable) == -EAGAIN, "retired resource exhaustion stays bounded");
        check(rn_step(r, 1) == 0, "retired reactor has no readiness spin");
    }
    check(native_wait_calls == calls + 8, "resource exhaustion performs one native wait per poll");
    hot_path = 0; check(rn_free(r) == 0, "free retired reactor");
}

static void claimed_transport_regression(void) {
    hot_path = 0;
    rn_config config = {4, 8, 4, 4, 0, 0, 1}; rn_reactor *r = NULL; uint64_t listener = 0;
    check(rn_new(&config, &r) == 0 && rn_listen(r, "127.0.0.1", 0, 0, &listener) == 0, "create claimed transport reactor");
    int peer; uint64_t connection = connected_peer(r, listener, &peer), capability = 0;
    check(send(peer, "TLS", 3, 0) == 3, "send before transport claim");
    uint64_t buffer = 0;
    for (unsigned n = 0; n < 100 && !buffer; ++n) {
        int count = rn_step(r, 10); check(count >= 0, "poll preclaim returned batch");
        for (int i = 0; i < count; ++i) if (rn_event_at(r, (uint32_t)i)->kind == RN_READ) buffer = rn_event_at(r, (uint32_t)i)->buffer;
    }
    check(buffer != 0, "preclaim read is returned"); hot_path = 1;
    check(rn_transport_state(r,connection) == 0 && rn_transport_claim(r,connection,&capability) == 0 && capability != 0, "claim connected generation");
    uint64_t duplicate = 0; unsigned credits = r->free_write_count;
    check(rn_transport_claim(r,connection,&duplicate) == -EALREADY && rn_transport_claim(r,listener,&duplicate) == -EINVAL, "duplicate and listener claims rejected");
    check(rn_queue_write(r,connection,buffer,0,3,1) == -EACCES && rn_set_read_enabled(r,connection,0) == -EACCES && rn_arm_timer(r,connection,0,0) == -EACCES && rn_cancel_timer(r,connection,0) == -EACCES && rn_close_after_writes(r,connection) == -EACCES && rn_close_connection(r,connection) == -EACCES, "all stale plaintext alias operations rejected");
    check(r->free_write_count == credits && rn_transport_write(r,connection,capability + 1,buffer,0,3,1) == -EACCES, "bad capability consumes no write credits");
    check(rn_transport_mode(r,connection,capability) == 1 && rn_transport_read_enabled(r,connection,capability,0) == 0 && rn_transport_arm_timer(r,connection,capability,3,rn_now_ms()+1000) == 0 && rn_transport_cancel_timer(r,connection,capability,3) == 0, "handshaking capability controls wire and timers");
    check(rn_transport_ready(r,connection,capability) == 0 && rn_transport_mode(r,connection,capability) == 2 && rn_transport_ready(r,connection,capability) == -EALREADY, "ready transition is one-way");
    check(rn_transport_write(r,connection,capability,buffer,0,3,991) == 0 && rn_buffer_release(r,buffer) == 0 && rn_transport_drain(r,connection,capability) == 0, "claimed ciphertext drain retains returned lease");
    int written = 0, closed = 0;
    for (unsigned n = 0; n < 100 && !closed; ++n) {
        int count = rn_step(r,10); check(count >= 0, "poll claimed drain");
        for (int i = 0; i < count; ++i) { const rn_event *event = rn_event_at(r,(uint32_t)i);
            if (event->kind == RN_WRITTEN) { check(event->operation == 991 && !closed, "claimed write precedes close"); ++written; }
            if (event->kind == RN_CLOSED && event->connection == connection) { check(written == 1, "claimed closure follows full write"); ++closed; }
        }
    }
    char received[3]; check(closed == 1 && recv(peer,received,3,MSG_WAITALL) == 3 && memcmp(received,"TLS",3) == 0, "only guarded ciphertext reaches peer");
    check(rn_transport_abort(r,connection,capability) < 0, "closed capability rejected");
    hot_path = 0; check(close(peer) == 0 && rn_free(r) == 0, "free claimed transport reactor");
}
typedef struct waker_race { rn_waker *waker; atomic_uint calls, canceled, stop; } waker_race;
static void *wake_until_stopped(void *argument) {
    waker_race *race = argument;
    while (!atomic_load(&race->stop)) {
        int result = rn_waker_wake(race->waker);
        check(result == 0 || result == -ECANCELED, "retained wake has a defined outcome during free");
        if (result == -ECANCELED) atomic_store(&race->canceled,1);
        atomic_fetch_add(&race->calls,1); sched_yield();
    }
    check(rn_waker_release(race->waker) == 0, "thread releases waker reference"); return NULL;
}
static void retained_waker_regression(void) {
    hot_path = 0;
    rn_config config = {1, 2, 1, 1, 0, 0, 1}; rn_reactor *r = NULL; rn_waker *w = NULL;
    check(rn_new(&config,&r) == 0 && rn_waker_acquire(r,&w) == 0 && rn_waker_retain(w) == 0, "retain loop-independent waker");
    check(rn_waker_wake(w) == 0 && rn_step(r,0) == 1 && rn_event_at(r,0)->kind == RN_WAKE, "retained waker reaches live reactor");
    int read_fd = w->read_fd, write_fd = w->write_fd;
    waker_race race = { .waker = w }; pthread_t thread;
    check(pthread_create(&thread,NULL,wake_until_stopped,&race) == 0, "start native wake race");
    while (atomic_load(&race.calls) < 50) sched_yield();
    check(rn_free(r) == 0 && fcntl(read_fd,F_GETFD) >= 0 && fcntl(write_fd,F_GETFD) >= 0, "reactor free retains both pipe endpoints");
    while (!atomic_load(&race.canceled)) sched_yield();
    atomic_store(&race.stop,1); check(pthread_join(thread,NULL) == 0, "join late wake thread");
    check(rn_waker_wake(w) == -ECANCELED && rn_waker_release(w) == 0, "late wake canceled then release last reference");
    check(fcntl(read_fd,F_GETFD) < 0 && errno == EBADF && fcntl(write_fd,F_GETFD) < 0 && errno == EBADF, "last waker reference closes pipe exactly once");
}

int main(void) {
    lean_initialize_runtime_module();
    large_read_budget_regression();
    pause_and_vectors_regression();
    historical_write_liveness();
    generation_retirement();
    claimed_transport_regression();
    retained_waker_regression();
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
