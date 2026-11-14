/* Real macOS handoff channels, including bounded queues and both teardown
 * orders. Only the backend translation unit's hot heap calls are counted. */
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include "../c/reactor.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/event.h>
#include <unistd.h>
static _Atomic unsigned hot_path, allocation_attempts;
static _Atomic int injected_write_error, injected_write_fd, watched_wait_fd;
static _Atomic unsigned native_write_calls, native_wait_entered;
static ssize_t dispatch_test_write(int fd, const void *bytes, size_t size) {
    atomic_fetch_add(&native_write_calls, 1);
    if (fd == atomic_load(&injected_write_fd)) {
        int error = atomic_exchange(&injected_write_error, 0);
        if (error) { errno = error; return -1; }
    }
    return write(fd, bytes, size);
}
static int dispatch_test_kevent(int fd, const struct kevent *changes, int change_count,
                                struct kevent *events, int event_count, const struct timespec *timeout) {
    if (change_count == 0 && timeout == NULL && fd == atomic_load(&watched_wait_fd))
        atomic_store_explicit(&native_wait_entered, 1, memory_order_release);
    return kevent(fd, changes, change_count, events, event_count, timeout);
}
#define COUNT_ALLOCATION() atomic_fetch_add_explicit(&allocation_attempts, atomic_load_explicit(&hot_path, memory_order_relaxed), memory_order_relaxed)
#define malloc(size) (COUNT_ALLOCATION(), malloc(size))
#define calloc(count, size) (COUNT_ALLOCATION(), calloc(count, size))
#define realloc(ptr, size) (COUNT_ALLOCATION(), realloc(ptr, size))
#define lean_alloc_sarray(elem, size, cap) (COUNT_ALLOCATION(), lean_alloc_sarray(elem, size, cap))
#define write(...) dispatch_test_write(__VA_ARGS__)
#define kevent(...) dispatch_test_kevent(__VA_ARGS__)
#include "../c/reactor_posix.c"
#undef malloc
#undef calloc
#undef realloc
#undef lean_alloc_sarray
#undef write
#undef kevent

void lean_initialize_runtime_module(void);
void lean_initialize_thread(void);
void lean_finalize_thread(void);
static void check(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "reactor dispatch test: %s (errno %d)\n", message, errno); exit(1); }
}
static int fd_count(void) {
    int count = 0;
    for (int fd = 0; fd < 4096; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++count;
    return count;
}
static rn_reactor *make_reactor(uint32_t connections, uint32_t events) {
    rn_config config = {connections, events, 64, 32, 0, 0, 1};
    rn_reactor *r = NULL;
    check(rn_new(&config, &r) == 0, "create reactor"); return r;
}
static struct sockaddr_in start_listener(rn_reactor *r, uint64_t *token) {
    check(rn_listen(r, "127.0.0.1", 0, 0, token) == 0, "listen on ephemeral port");
    struct sockaddr_in address; socklen_t size = sizeof(address);
    check(getsockname(r->connections[rn_index(*token)].fd, (struct sockaddr *)&address, &size) == 0, "listener address");
    return address;
}
static int connect_peer(const struct sockaddr_in *address) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    check(fd >= 0 && connect(fd, (const struct sockaddr *)address, sizeof(*address)) == 0, "connect peer");
    int one = 1;
    check(setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) == 0, "suppress peer SIGPIPE");
    return fd;
}
static void validation(void) {
    rn_reactor *a = make_reactor(2, 8), *w = make_reactor(2, 8), *other = make_reactor(2, 8);
    rn_reactor *targets[2] = {w, w};
    check(rn_set_accept_targets(NULL, targets, 1, 1) == -EINVAL, "reject null acceptor");
    check(rn_set_accept_targets(a, NULL, 1, 1) == -EINVAL, "reject null targets");
    check(rn_set_accept_targets(a, targets, 0, 1) == -EINVAL && rn_set_accept_targets(a, targets, 1, 0) == -EINVAL, "reject zero bounds");
    check(rn_set_accept_targets(a, targets, 2, 1) == -EINVAL, "reject duplicate target");
    targets[0] = a;
    check(rn_set_accept_targets(a, targets, 1, 1) == -EINVAL, "reject self target");
    targets[0] = w;
    check(rn_step(other, 0) == 0, "poll unused reactor");
    targets[1] = other;
    check(rn_set_accept_targets(a, targets, 2, 1) == -EINVAL, "reject polled target");
    check(a->accept_targets == NULL && w->accept_source == NULL, "failed validation is atomic");
    check(rn_set_accept_targets(a, targets, 1, 3) == 0, "configure non-power-of-two queue capacity");
    check(rn_set_accept_targets(a, targets, 1, 3) == -EINVAL, "reject second configuration");
    uint64_t token;
    check(rn_socket_new(w, &token) == 0 && rn_bind(w, token, "127.0.0.1", 0, 0) == -EINVAL, "worker cannot bind a second listener");
    check(rn_free(a) == 0 && rn_free(w) == 0 && rn_free(other) == 0, "free validation reactors");
}
#define WORKERS 8u
#define PEERS 400u
#define TOKENS 128u
typedef struct worker_context {
    rn_reactor *reactor;
    _Atomic unsigned *stop;
    _Atomic unsigned accepted, closed;
    uint64_t thread, tokens[TOKENS];
    int acceptor, timeout_ms, close_on_read, delay;
} worker_context;
static void *worker_loop(void *argument) {
    worker_context *context = argument;
    lean_initialize_thread();
    check(pthread_threadid_np(NULL, &context->thread) == 0, "worker thread identity");
    while (!atomic_load_explicit(context->stop, memory_order_acquire)) {
        int count = rn_step(context->reactor, context->timeout_ms);
        if (count == -EINTR) continue;
        check(count >= 0, "threaded poll");
        for (int i = 0; i < count; ++i) {
            rn_event event = *rn_event_at(context->reactor, (uint32_t)i);
            if (event.kind == RN_ACCEPTED) {
                check(!context->acceptor && event.operation == 0, "only worker owns accepted identity");
                uint32_t index = rn_index(event.connection);
                check(index < TOKENS && context->tokens[index] == 0, "new worker-owned token");
                check(context->reactor->connections[index].interest == 1, "register before ACCEPTED");
                context->tokens[index] = event.connection;
                atomic_fetch_add_explicit(&context->accepted, 1, memory_order_release);
            } else if (event.kind == RN_READ) {
                check(!context->acceptor && context->tokens[rn_index(event.connection)] == event.connection, "ACCEPTED precedes READ on its owning worker");
                check(rn_queue_write(context->reactor, event.connection, event.buffer, event.offset, event.length, 123) == 0, "queue worker echo");
                check(rn_buffer_release(context->reactor, event.buffer) == 0, "release worker lease");
                if (context->close_on_read) check(rn_close_after_writes(context->reactor, event.connection) == 0, "close saturated echo");
            } else if (event.kind == RN_EOF) {
                check(rn_close_after_writes(context->reactor, event.connection) == 0, "drain worker echo");
            } else if (event.kind == RN_CLOSED) {
                context->tokens[rn_index(event.connection)] = 0;
                atomic_fetch_add_explicit(&context->closed, 1, memory_order_release);
            } else check(event.kind == RN_WAKE || event.kind == RN_WRITTEN, "no dispatch infrastructure or peer errors");
        }
        if (context->delay) { const struct timespec pause = {0, 1000000}; (void)nanosleep(&pause, NULL); }
    }
    lean_finalize_thread(); return NULL;
}
static void threaded_distribution(void) {
    int before = fd_count();
    rn_reactor *acceptor = make_reactor(1, 32), *workers[WORKERS];
    worker_context contexts[WORKERS + 1u]; memset(contexts, 0, sizeof(contexts));
    _Atomic unsigned stop = 0;
    for (unsigned i = 0; i < WORKERS; ++i) {
        workers[i] = make_reactor(TOKENS, 32); contexts[i].reactor = workers[i]; contexts[i].stop = &stop;
        contexts[i].timeout_ms = 100;
        atomic_init(&contexts[i].accepted, 0); atomic_init(&contexts[i].closed, 0);
    }
    check(rn_set_accept_targets(acceptor, workers, WORKERS, 127) == 0, "configure threaded channels");
    uint64_t listener; struct sockaddr_in address = start_listener(acceptor, &listener);
    contexts[WORKERS].reactor = acceptor; contexts[WORKERS].stop = &stop; contexts[WORKERS].acceptor = 1;
    contexts[WORKERS].timeout_ms = 100;
    atomic_init(&contexts[WORKERS].accepted, 0); atomic_init(&contexts[WORKERS].closed, 0);
    pthread_t threads[WORKERS + 1u]; int peers[PEERS];
    atomic_store(&hot_path, 1);
    for (unsigned i = 0; i <= WORKERS; ++i) check(pthread_create(&threads[i], NULL, worker_loop, &contexts[i]) == 0, "start dedicated reactor thread");
    unsigned char payload[64], received[64];
    for (unsigned i = 0; i < PEERS; ++i) {
        peers[i] = connect_peer(&address); memset(payload, (int)(i % 251u), sizeof(payload));
        check(send(peers[i], payload, sizeof(payload), 0) == (ssize_t)sizeof(payload), "send immediate peer payload");
        struct timeval timeout = {5, 0};
        check(setsockopt(peers[i], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "bound peer receive wait");
    }
    for (unsigned i = 0; i < PEERS; ++i) {
        size_t got = 0; memset(payload, (int)(i % 251u), sizeof(payload));
        while (got < sizeof(received)) {
            ssize_t n = recv(peers[i], received + got, sizeof(received) - got, 0);
            check(n > 0, "receive threaded echo"); got += (size_t)n;
        }
        check(memcmp(payload, received, sizeof(payload)) == 0, "threaded echo bytes");
        check(close(peers[i]) == 0, "close threaded peer");
    }
    uint64_t deadline = rn_now_ms() + 5000;
    for (;;) {
        unsigned closed = 0;
        for (unsigned i = 0; i < WORKERS; ++i) closed += atomic_load_explicit(&contexts[i].closed, memory_order_acquire);
        if (closed == PEERS) break;
        check(rn_now_ms() < deadline, "all threaded peer closes finish");
        const struct timespec pause = {0, 1000000}; (void)nanosleep(&pause, NULL);
    }
    atomic_store_explicit(&stop, 1, memory_order_release);
    for (unsigned i = 0; i <= WORKERS; ++i) check(rn_wake(contexts[i].reactor) == 0, "wake joined worker");
    for (unsigned i = 0; i <= WORKERS; ++i) check(pthread_join(threads[i], NULL) == 0, "join reactor thread");
    atomic_store(&hot_path, 0);
    fputs("worker accepts:", stdout);
    for (unsigned i = 0; i < WORKERS; ++i) {
        unsigned accepted = atomic_load(&contexts[i].accepted);
        check(accepted == PEERS / WORKERS, "deterministic equal round-robin distribution");
        check(contexts[i].thread != contexts[WORKERS].thread, "acceptor and workers use distinct threads");
        printf(" %u", accepted);
    }
    putchar('\n');
    check(rn_free(acceptor) == 0, "free acceptor before workers");
    for (unsigned i = 0; i < WORKERS; ++i) check(rn_free(workers[i]) == 0, "free joined worker");
    check(fd_count() == before, "threaded dispatch descriptor baseline restored");
}
static void tiny_dispatch(rn_reactor *worker, unsigned *accepted) {
    int count = rn_step(worker, 0); check(count >= 0, "tiny worker poll");
    for (int i = 0; i < count; ++i) {
        rn_event event = *rn_event_at(worker, (uint32_t)i);
        if (event.kind == RN_ACCEPTED) ++*accepted;
        else if (event.kind == RN_READ) {
            check(event.length == 1, "tiny receive payload");
            check(rn_queue_write(worker, event.connection, event.buffer, event.offset, 1, 7) == 0, "tiny echo write");
            check(rn_buffer_release(worker, event.buffer) == 0, "tiny release lease");
            check(rn_close_after_writes(worker, event.connection) == 0, "tiny echo drain close");
        } else check(event.kind == RN_CLOSED || event.kind == RN_WRITTEN || event.kind == RN_WAKE, "tiny dispatch has no error");
    }
}
static void full_queues(void) {
    int before = fd_count(); rn_reactor *acceptor = make_reactor(1, 1), *workers[2] = {make_reactor(1, 1), make_reactor(1, 1)};
    check(rn_set_accept_targets(acceptor, workers, 2, 1) == 0, "configure capacity-one channels");
    uint64_t listener; struct sockaddr_in address = start_listener(acceptor, &listener);
    int peers[6]; unsigned received[6] = {0}, eof[6] = {0}, accepted[2] = {0};
    for (unsigned i = 0; i < 6; ++i) {
        peers[i] = connect_peer(&address); unsigned char byte = (unsigned char)i;
        check(send(peers[i], &byte, 1, 0) == 1 && rn_nonblocking(peers[i]) == 0, "send tiny peer payload");
    }
    atomic_store(&hot_path, 1);
    check(rn_step(acceptor, 0) >= 0, "fill channels without polling workers");
    rn_conn *bound = &acceptor->connections[rn_index(listener)];
    check(bound->pending_accept_fd >= 0 && bound->interest == 0 && bound->paused, "full queues retain accepted fd and pause listener");
    for (unsigned i = 0; i < 2; ++i) {
        rn_accept_queue *q = workers[i]->accept_source;
        check(rn_accept_next(q, atomic_load(&q->head)) == atomic_load(&q->tail), "bounded queue is exactly full");
    }
    int retained = bound->pending_accept_fd; uint64_t started = rn_now_ms();
    check(rn_step(acceptor, 20) == 0 && rn_now_ms() - started >= 10, "paused acceptor sleeps without busy polling");
    check(bound->pending_accept_fd == retained && fcntl(retained, F_GETFD) >= 0, "full queue does not close or replace retained peer");
    unsigned completed = 0; uint64_t deadline = rn_now_ms() + 5000;
    while (completed != 6) {
        check(rn_step(acceptor, 0) >= 0, "resume acceptor after channel credit");
        for (unsigned i = 0; i < 2; ++i) tiny_dispatch(workers[i], &accepted[i]);
        for (unsigned i = 0; i < 6; ++i) if (!eof[i]) {
            unsigned char byte; ssize_t n = recv(peers[i], &byte, 1, 0);
            if (n > 0) { check(!received[i] && byte == i, "retained peers receive correct echo once"); received[i] = 1; }
            else if (n == 0) { check(received[i], "peer echo precedes EOF"); eof[i] = 1; ++completed; }
            else check(errno == EAGAIN || errno == EWOULDBLOCK, "no full-queue connection drop");
        }
        check(rn_now_ms() < deadline, "all queued and kernel-backlogged peers progress");
    }
    for (unsigned i = 0; i < 4; ++i) for (unsigned j = 0; j < 2; ++j) tiny_dispatch(workers[j], &accepted[j]);
    atomic_store(&hot_path, 0);
    check(accepted[0] + accepted[1] == 6 && accepted[0] && accepted[1], "all full-queue peers adopted exactly once");
    check(bound->pending_accept_fd == -1, "retained descriptor ownership transferred");
    for (unsigned i = 0; i < 6; ++i) check(close(peers[i]) == 0, "close tiny peer");
    check(rn_free(workers[0]) == 0 && rn_free(workers[1]) == 0 && rn_free(acceptor) == 0, "free workers before acceptor");
    check(fd_count() == before, "full-queue descriptor baseline restored");
}
static void retained_teardown(void) {
    int before = fd_count();
    for (unsigned iteration = 0; iteration < 20; ++iteration) {
        rn_reactor *acceptor = make_reactor(1, 2), *worker = make_reactor(1, 2), *targets[1] = {worker};
        check(rn_set_accept_targets(acceptor, targets, 1, 1) == 0, "configure teardown channel");
        uint64_t listener; struct sockaddr_in address = start_listener(acceptor, &listener); int peers[3];
        for (unsigned i = 0; i < 3; ++i) peers[i] = connect_peer(&address);
        atomic_store(&hot_path, 1);
        check(rn_step(acceptor, 0) >= 0 && acceptor->connections[rn_index(listener)].pending_accept_fd >= 0, "teardown owns queued and retained sockets");
        atomic_store(&hot_path, 0);
        check(rn_free(iteration % 2 ? worker : acceptor) == 0, "first teardown endpoint");
        int sentinel[2]; check(pipe(sentinel) == 0, "reuse freed descriptor numbers");
        check(rn_free(iteration % 2 ? acceptor : worker) == 0, "second teardown endpoint");
        check(fcntl(sentinel[0], F_GETFD) >= 0 && fcntl(sentinel[1], F_GETFD) >= 0, "teardown cannot close reused descriptor");
        check(close(sentinel[0]) == 0 && close(sentinel[1]) == 0, "close reuse sentinel");
        for (unsigned i = 0; i < 3; ++i) check(close(peers[i]) == 0, "close retained teardown peer");
        check(fd_count() == before, "retained teardown descriptor baseline restored");
    }
}
static void saturated_threads(void) {
    enum { total = 128 };
    int before = fd_count(), peers[total];
    rn_reactor *acceptor = make_reactor(1, 8), *worker = make_reactor(1, 1), *targets[1] = {worker};
    check(rn_set_accept_targets(acceptor, targets, 1, 1) == 0, "configure saturated threaded channel");
    uint64_t listener; struct sockaddr_in address = start_listener(acceptor, &listener);
    for (unsigned i = 0; i < total; ++i) {
        peers[i] = connect_peer(&address); unsigned char byte = (unsigned char)i;
        check(send(peers[i], &byte, 1, 0) == 1, "send saturated peer byte");
        const struct timeval timeout = {5, 0};
        check(setsockopt(peers[i], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "bound saturated peer wait");
    }
    _Atomic unsigned stop = 0;
    worker_context contexts[2]; memset(contexts, 0, sizeof(contexts));
    contexts[0].reactor = acceptor; contexts[0].stop = &stop; contexts[0].acceptor = 1; contexts[0].timeout_ms = -1;
    contexts[1].reactor = worker; contexts[1].stop = &stop; contexts[1].timeout_ms = -1;
    contexts[1].close_on_read = 1; contexts[1].delay = 1;
    for (unsigned i = 0; i < 2; ++i) { atomic_init(&contexts[i].accepted, 0); atomic_init(&contexts[i].closed, 0); }
    atomic_store(&hot_path, 1);
    check(rn_step(acceptor, 0) == 0 && acceptor->connections[rn_index(listener)].pending_accept_fd >= 0, "saturate before concurrent consumers start");
    pthread_t threads[2];
    for (unsigned i = 0; i < 2; ++i) check(pthread_create(&threads[i], NULL, worker_loop, &contexts[i]) == 0, "start saturated blocking loop");
    for (unsigned i = 0; i < total; ++i) {
        unsigned char byte;
        check(recv(peers[i], &byte, 1, 0) == 1 && byte == i, "blocked -1 polls resume for retained peers");
        check(recv(peers[i], &byte, 1, 0) == 0, "saturated echo drains before EOF");
        check(close(peers[i]) == 0, "close saturated peer");
    }
    uint64_t deadline = rn_now_ms() + 5000;
    while (atomic_load_explicit(&contexts[1].closed, memory_order_acquire) != total) {
        check(rn_now_ms() < deadline, "saturated closures complete");
        const struct timespec pause = {0, 1000000}; (void)nanosleep(&pause, NULL);
    }
    atomic_store_explicit(&stop, 1, memory_order_release);
    check(rn_wake(acceptor) == 0 && rn_wake(worker) == 0, "wake saturated blocking loops for shutdown");
    for (unsigned i = 0; i < 2; ++i) check(pthread_join(threads[i], NULL) == 0, "join saturated loop");
    atomic_store(&hot_path, 0);
    check(atomic_load(&contexts[1].accepted) == total, "saturated handoffs are delivered once");
    check(rn_free(worker) == 0 && rn_free(acceptor) == 0, "free saturated endpoints");
    check(fd_count() == before, "saturated descriptor baseline restored");
}
typedef struct once_context { rn_reactor *reactor; int result; } once_context;
static void *poll_once(void *argument) {
    once_context *context = argument;
    lean_initialize_thread(); context->result = rn_step(context->reactor, -1); lean_finalize_thread(); return NULL;
}
static pthread_t start_blocked_poll(once_context *context) {
    atomic_store(&watched_wait_fd, context->reactor->queue_fd); atomic_store(&native_wait_entered, 0);
    pthread_t thread;
    check(pthread_create(&thread, NULL, poll_once, context) == 0, "start watched infinite poll");
    uint64_t deadline = rn_now_ms() + 1000;
    while (!atomic_load_explicit(&native_wait_entered, memory_order_acquire)) {
        check(rn_now_ms() < deadline, "enter native infinite wait");
        const struct timespec pause = {0, 1000000}; (void)nanosleep(&pause, NULL);
    }
    return thread;
}
static void interrupted_channel_wakes(void) {
    int before = fd_count();
    for (unsigned direction = 0; direction < 2; ++direction) {
        rn_reactor *acceptor = make_reactor(1, 4), *worker = make_reactor(1, 4), *targets[1] = {worker};
        check(rn_set_accept_targets(acceptor, targets, 1, 1) == 0, "configure interrupted wake channel");
        uint64_t listener; struct sockaddr_in address = start_listener(acceptor, &listener);
        rn_accept_queue *q = worker->accept_source; int peers[3], peer_count = direction ? 3 : 1;
        for (int i = 0; i < peer_count; ++i) peers[i] = connect_peer(&address);
        atomic_store(&hot_path, 1);
        once_context waiting = {direction ? acceptor : worker, -999};
        if (direction) check(rn_step(acceptor, 0) == 0, "fill interrupted capacity queue");
        pthread_t thread = start_blocked_poll(&waiting);
        atomic_store(&injected_write_fd, direction ? q->producer_wake : q->consumer_wake);
        atomic_store(&injected_write_error, EINTR);
        unsigned calls = atomic_load(&native_write_calls);
        if (!direction) {
            check(rn_step(acceptor, 0) == -EINTR, "published socket wake surfaces EINTR");
            check(atomic_load(&native_write_calls) == calls + 1 && q->consumer_wake_pending, "consumer wake is attempted once and retained");
            check(rn_step(acceptor, 0) >= 0 && !q->consumer_wake_pending, "caller repoll retries pending consumer wake");
        } else {
            int count = rn_step(worker, 0); check(count > 0, "accepted event survives interrupted capacity wake");
            int accepted = 0;
            for (int i = 0; i < count; ++i) if (rn_event_at(worker, (uint32_t)i)->kind == RN_ACCEPTED) ++accepted;
            check(accepted == 1 && atomic_load(&native_write_calls) == calls + 1 && q->producer_wake_pending, "producer wake attempted once after ownership transfer");
            check(rn_step(worker, 0) == -EINTR && atomic_load(&native_write_calls) == calls + 1, "interrupted capacity wake is surfaced before retry");
            check(rn_step(worker, 0) >= 0 && !q->producer_wake_pending, "caller repoll retries pending producer wake");
        }
        check(pthread_join(thread, NULL) == 0 && waiting.result > 0, "infinite native wait resumes after explicit caller repoll");
        atomic_store(&watched_wait_fd, -1); atomic_store(&injected_write_fd, -1); atomic_store(&hot_path, 0);
        check(rn_free(acceptor) == 0 && rn_free(worker) == 0, "free interrupted wake endpoints");
        for (int i = 0; i < peer_count; ++i) check(close(peers[i]) == 0, "close interrupted wake peer");
        check(fd_count() == before, "interrupted wake descriptor baseline restored");
    }
}
static void interrupted_wake_preserves_records(void) {
    int before = fd_count();
    for (unsigned timer = 0; timer < 2; ++timer) {
        rn_reactor *acceptor = make_reactor(2, 8), *worker = make_reactor(1, 4), *targets[1] = {worker};
        check(rn_set_accept_targets(acceptor, targets, 1, 1) == 0, "configure committed-record wake regression");
        uint64_t listener; struct sockaddr_in address = start_listener(acceptor, &listener);
        int peers[3]; for (unsigned i = 0; i < 3; ++i) peers[i] = connect_peer(&address);
        atomic_store(&hot_path, 1);
        check(rn_step(acceptor, 0) == 0 && rn_step(worker, 0) > 0, "retain fd then release channel credit");
        uint64_t identity;
        check(rn_socket_new(acceptor, &identity) == 0, "create committed-record identity");
        if (timer) {
            check(rn_arm_timer(acceptor, identity, 2, rn_now_ms() + 1) == 0, "arm committed timer");
            const struct timespec pause = {0, 3000000}; check(nanosleep(&pause, NULL) == 0, "wait for committed timer");
        } else check(rn_close_connection(acceptor, identity) == 0, "commit close before wake interruption");
        rn_accept_queue *q = worker->accept_source;
        atomic_store(&injected_write_fd, q->consumer_wake); atomic_store(&injected_write_error, EINTR);
        unsigned calls = atomic_load(&native_write_calls);
        check(rn_step(acceptor, 0) == 1, "committed record survives forwarding wake EINTR");
        const rn_event *event = rn_event_at(acceptor, 0);
        check(event->kind == (timer ? RN_TIMER : RN_CLOSED) && event->connection == identity, "committed record identity retained");
        check(atomic_load(&native_write_calls) == calls + 1, "forwarding wake is not retried in native poll");
        check(rn_step(acceptor, 0) == -EINTR && atomic_load(&native_write_calls) == calls + 1, "forwarding interrupt is surfaced after committed record");
        check(rn_step(acceptor, 0) >= 0 && !q->consumer_wake_pending, "later explicit poll flushes retained wake");
        atomic_store(&hot_path, 0); atomic_store(&injected_write_fd, -1);
        check(rn_free(worker) == 0 && rn_free(acceptor) == 0, "free committed-record regression endpoints");
        for (unsigned i = 0; i < 3; ++i) check(close(peers[i]) == 0, "close committed-record peer");
        check(fd_count() == before, "committed-record descriptor baseline restored");
    }
}
int main(void) {
    lean_initialize_runtime_module();
    atomic_store(&injected_write_fd, -1); atomic_store(&watched_wait_fd, -1);
    validation(); threaded_distribution(); full_queues(); retained_teardown(); saturated_threads(); interrupted_channel_wakes(); interrupted_wake_preserves_records();
    check(atomic_load(&allocation_attempts) == 0, "no backend heap allocation during accept/handoff or established I/O");
    puts("macOS dispatch tests passed: bounded queues, retained sockets, both free orders, zero hot allocations");
    return 0;
}
