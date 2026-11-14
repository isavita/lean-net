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
#include <stdlib.h>
static unsigned hot_path;
static unsigned allocation_attempts;
#define malloc(size) (allocation_attempts += hot_path, malloc(size))
#define calloc(count, size) (allocation_attempts += hot_path, calloc(count, size))
#define realloc(ptr, size) (allocation_attempts += hot_path, realloc(ptr, size))
#define lean_alloc_sarray(elem, size, cap) (allocation_attempts += hot_path, lean_alloc_sarray(elem, size, cap))
#include "../c/reactor_posix.c"
#undef malloc
#undef calloc
#undef realloc
#undef lean_alloc_sarray

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
