/* Real POSIX backend, real Lean allocator, deterministic sendfile fault points. */
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#include "../c/reactor.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/sendfile.h>
#else
extern int sendfile(int, int, off_t, off_t *, struct sf_hdtr *, int);
#endif
static unsigned hot_path, allocation_attempts, file_calls, unmap_calls, zero_file_calls;
static int injected_file_error, injected_eof, injected_lock_error;
static uint32_t injected_progress, file_limit = 97;
static uint64_t first_file_offset, last_file_offset;
static void *reused_core;
static void *test_calloc(size_t count, size_t size);
static void test_free(void *pointer);
static int test_mlock(const void *address, size_t length) {
    if (injected_lock_error) { errno = injected_lock_error; injected_lock_error = 0; return -1; }
    return mlock(address, length);
}
static int test_munmap(void *address, size_t length) { ++unmap_calls; return munmap(address, length); }
#if defined(__linux__)
static ssize_t test_sendfile(int output, int input, off_t *offset, size_t count) {
    if (!count) ++zero_file_calls;
    if (!file_calls++) first_file_offset = (uint64_t)*offset;
    last_file_offset = (uint64_t)*offset;
    if (injected_eof) { injected_eof = 0; return 0; }
    if (injected_file_error) { errno = injected_file_error; injected_file_error = 0; return -1; }
    if (file_limit && count > file_limit) count = file_limit;
    return sendfile(output, input, offset, count);
}
#else
static int test_sendfile(int input, int output, off_t offset, off_t *length,
                         struct sf_hdtr *headers, int flags) {
    if (!*length) ++zero_file_calls;
    if (!file_calls++) first_file_offset = (uint64_t)offset;
    last_file_offset = (uint64_t)offset;
    if (injected_eof) { injected_eof = 0; *length = 0; return 0; }
    int error = injected_file_error; injected_file_error = 0;
    if (error && !injected_progress) { *length = 0; errno = error; return -1; }
    off_t count = *length;
    if (error) { if (count > (off_t)injected_progress) count = (off_t)injected_progress; }
    else if (file_limit && count > (off_t)file_limit) count = (off_t)file_limit;
    injected_progress = 0;
    int result = sendfile(input, output, offset, &count, headers, flags);
    *length = count;
    if (result < 0) return result;
    if (error) { errno = error; return -1; }
    return 0;
}
#endif
#define sendfile(...) test_sendfile(__VA_ARGS__)
#define mlock(...) test_mlock(__VA_ARGS__)
#define munmap(...) test_munmap(__VA_ARGS__)
#define malloc(size) (allocation_attempts += hot_path, malloc(size))
#define calloc(count, size) (allocation_attempts += hot_path, test_calloc(count, size))
#define free(pointer) test_free(pointer)
#define realloc(ptr, size) (allocation_attempts += hot_path, realloc(ptr, size))
#define lean_alloc_sarray(elem, size, cap) (allocation_attempts += hot_path, lean_alloc_sarray(elem, size, cap))
#include "../c/reactor_posix.c"
#undef sendfile
#undef mlock
#undef munmap
#undef malloc
#undef calloc
#undef free
#undef realloc
#undef lean_alloc_sarray
/* Deterministically recycle the reactor's address while freeing all of its
 * real internal allocations. File namespaces must outlive raw pointer ABA. */
static void *test_calloc(size_t count, size_t size) {
    if (reused_core && count == 1 && size == sizeof(rn_reactor)) {
        memset(reused_core, 0, size); return reused_core;
    }
    return calloc(count, size);
}
static void test_free(void *pointer) {
    if (pointer == reused_core) return;
    free(pointer);
}
void lean_initialize_runtime_module(void);

static void check(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "reactor file test: %s (errno %d)\n", message, errno); exit(1); }
}
static uint8_t data[131072];
static int readonly_snapshot(size_t length) {
    char path[] = "/tmp/lean-net-file-test-XXXXXX";
    int writer = mkstemp(path); check(writer >= 0, "create private snapshot");
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(writer, data + offset, length - offset);
        check(written > 0, "populate snapshot"); offset += (size_t)written;
    }
    int reader = open(path, O_RDONLY | O_CLOEXEC);
    check(reader >= 0 && close(writer) == 0 && unlink(path) == 0, "publish only private read-only unlinked handle");
    check(access(path, F_OK) < 0 && errno == ENOENT, "snapshot has no mutable pathname");
    return reader;
}
static rn_file_source *source_new(size_t length) {
    rn_file_source *source = NULL;
    check(rn_file_source_publish((uintptr_t)readonly_snapshot(length), length, 1024u * 1024u, &source) == 0,
          "publish resident source");
    check(source && rn_file_source_size(source) == length, "source metadata");
    return source;
}
static rn_reactor *reactor_new(unsigned events, unsigned files) {
    const rn_config config = {4, events, 16, 4, 0, 0, 1};
    rn_reactor *r = NULL; check(rn_new(&config, &r) == 0, "new file reactor");
    check(rn_file_table_init(r, files) == 0, "initialize setup-only table"); return r;
}
static uint64_t adopt(rn_reactor *r, int *peer) {
    int pair[2]; check(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "create connected pair");
    check(rn_nonblocking(pair[0]) == 0 && rn_nonblocking(pair[1]) == 0 && rn_sigpipe(pair[0]) == 0,
          "configure nonblocking pair");
    uint64_t token; check(rn_socket_new(r, &token) == 0, "allocate connection slot");
    rn_conn *c = &r->connections[rn_index(token)]; c->fd = pair[0]; c->state = 4;
    *peer = pair[1]; return token;
}
static uint64_t buffer(rn_reactor *r, const char *text) {
    uint64_t token; size_t length = strlen(text);
    check(rn_acquire_buffer(r, (uint32_t)length, &token) == 0 &&
          rn_buffer_copy(r, token, (const uint8_t *)text, (uint32_t)length) == 0, "prepare byte operation");
    return token;
}
static void source_failures(void) {
    const long page = sysconf(_SC_PAGESIZE); check(page > 0, "page size");
    rn_file_source *source = NULL;
    int fd = readonly_snapshot(1);
    check(rn_file_source_publish((uintptr_t)fd, 1, (uint64_t)page - 1, &source) == -ENOMEM && !source,
          "page-rounded residency budget");
    check(fcntl(fd, F_GETFD) < 0 && errno == EBADF, "budget failure consumes owned handle");
    fd = readonly_snapshot(10);
    check(rn_file_source_publish((uintptr_t)fd, 11, (uint64_t)page, &source) == -EINVAL && !source,
          "source size must match descriptor");
    check(fcntl(fd, F_GETFD) < 0 && errno == EBADF, "stat failure consumes handle");
    unsigned unmapped = unmap_calls; fd = readonly_snapshot(10); injected_lock_error = ENOMEM;
    check(rn_file_source_publish((uintptr_t)fd, 10, (uint64_t)page, &source) == -ENOMEM && !source,
          "pin failure surfaced");
    check(unmap_calls == unmapped + 1 && fcntl(fd, F_GETFD) < 0 && errno == EBADF,
          "pin failure unmaps and closes");
    char path[] = "/tmp/lean-net-writable-test-XXXXXX";
    fd = mkstemp(path); check(fd >= 0 && unlink(path) == 0, "writable publication fixture");
    check(rn_file_source_publish((uintptr_t)fd, 0, 0, &source) == -EINVAL && !source &&
          fcntl(fd, F_GETFD) < 0 && errno == EBADF, "reject writable source and close handle");
    fd = readonly_snapshot(0);
    check(rn_file_source_publish((uintptr_t)fd, 0, 0, NULL) == -EINVAL &&
          fcntl(fd, F_GETFD) < 0 && errno == EBADF, "invalid output pointer still consumes valid source handle");
    source = source_new(0); const uint8_t *view = (const uint8_t *)1;
    check(rn_file_source_view(source, 0, 0, &view) == 0 && !view, "empty source is empty, never whole-file sentinel");
    check(rn_file_source_view(source, 1, 0, &view) == -EINVAL, "empty source bounds");
    fd = (int)rn_file_source_handle(source);
    check(rn_file_source_release(source) == 0 && fcntl(fd, F_GETFD) < 0 && errno == EBADF,
          "empty source closes exactly once");
}
static void fifo(rn_file_source *source, rn_file_source *empty, unsigned capacity) {
    rn_reactor *r = reactor_new(capacity, 2); uint64_t file, zero;
    check(rn_file_import(r, source, &file) == 0 && rn_file_import(r, empty, &zero) == 0, "import before first poll");
    uint64_t excess;
    check(rn_file_import(r, source, &excess) == -EAGAIN, "fixed file table exhaustion is bounded");
    int peer; uint64_t connection = adopt(r, &peer), owner = rn_file_owner(r);
    hot_path = 1;
    uint64_t head = buffer(r, "HEADER\r\n"), tail = buffer(r, "TRAILER");
    check(rn_queue_write(r, connection, head, 0, 8, 10) == 0 &&
          rn_queue_file(r, connection, owner, file, 17, 6000, 11) == 0 &&
          rn_queue_file(r, connection, owner, file, 333, 0, 12) == 0 &&
          rn_queue_file(r, connection, owner, zero, 0, 0, 13) == 0 &&
          rn_queue_write(r, connection, tail, 0, 7, 14) == 0, "queue mixed FIFO");
    check(rn_buffer_release(r, head) == 0 && rn_buffer_release(r, tail) == 0, "release queued buffer owners");
    check(rn_file_release(r, file) == -EBUSY && rn_file_release(r, zero) == -EBUSY,
          "queued source entries cannot be released");
    check(rn_close_after_writes(r, connection) == 0, "drain mixed FIFO");
    uint32_t available = r->free_write_count, pins = r->files.entries[rn_index(file)].writes;
    check(rn_queue_file(r, connection, owner, file, 0, 1, 99) == -EPIPE &&
          r->free_write_count == available && r->files.entries[rn_index(file)].writes == pins,
          "drain rejects new file writes without losing credits or pins");
    uint8_t received[6015]; size_t got = 0; unsigned completed = 0, closed = 0; int eof = 0;
    const unsigned lengths[] = {8, 6000, 0, 0, 7};
    unsigned calls = file_calls, zero_calls = zero_file_calls;
    for (unsigned turn = 0; turn < 10000 && (!closed || !eof); ++turn) {
        int count = rn_step(r, 0); check(count >= 0 && (unsigned)count <= capacity, "bounded completion capacity");
        if (!turn) {
            uint64_t extra;
            check(rn_file_import(r, source, &extra) == -EBUSY && rn_file_table_init(r, 1) == -EBUSY,
                  "publication is setup-only");
        }
        for (int i = 0; i < count; ++i) {
            const rn_event *event = rn_event_at(r, (uint32_t)i);
            if (event->kind == RN_WRITTEN) {
                check(completed < 5 && event->operation == 10 + completed &&
                      event->length == lengths[completed] && event->result == lengths[completed], "exact per-operation FIFO completions");
                ++completed;
            } else if (event->kind == RN_CLOSED) { check(completed == 5 && !closed, "CLOSED follows every successful completion"); ++closed; }
            else check(0, "unexpected mixed-operation event");
        }
        for (;;) {
            uint8_t extra; ssize_t n = recv(peer, got < sizeof(received) ? received + got : &extra,
                                            got < sizeof(received) ? sizeof(received) - got : 1, 0);
            if (n > 0) { check(got + (size_t)n <= sizeof(received), "no extra mixed bytes"); got += (size_t)n; }
            else if (n == 0) { eof = 1; break; }
            else { check(errno == EAGAIN || errno == EWOULDBLOCK, "read mixed bytes"); break; }
        }
    }
    check(closed && eof && completed == 5 && got == sizeof(received), "mixed operations terminate exactly");
    check(!memcmp(received, "HEADER\r\n", 8) && !memcmp(received + 8, data + 17, 6000) &&
          !memcmp(received + 6008, "TRAILER", 7), "mixed binary bytes exact");
    check(file_calls - calls >= (6000u + 96u) / 97u, "97-byte partial file sends exercised");
    check(zero_file_calls == zero_calls, "zero regions never invoke whole-file sendfile sentinel");
    check(rn_file_release(r, file) == 0 && rn_file_release(r, zero) == 0, "completed source entries release");
    check(close(peer) == 0 && rn_free(r) == 0, "mixed teardown"); hot_path = 0;
}
static void file_budget(rn_file_source *source) {
    rn_reactor *r = reactor_new(1, 1); uint64_t file;
    check(rn_file_import(r, source, &file) == 0, "import fairness source");
    int peer; uint64_t token = adopt(r, &peer); rn_conn *c = &r->connections[rn_index(token)];
    int capacity = 262144;
    check(setsockopt(c->fd, SOL_SOCKET, SO_SNDBUF, &capacity, sizeof(capacity)) == 0 &&
          setsockopt(peer, SOL_SOCKET, SO_RCVBUF, &capacity, sizeof(capacity)) == 0,
          "provide enough socket capacity to isolate the file fairness budget");
    check(rn_queue_file(r, token, rn_file_owner(r), file, 0, 100000, 33) == 0, "queue fairness file");
    uint32_t old_limit = file_limit; file_limit = 0;
    hot_path = 1;
    check(rn_write_ready(r, rn_index(token)) == 0 && c->head_write != RN_NONE,
          "fairness pass retains unfinished operation");
    uint32_t sent = r->writes[c->head_write].sent;
    check(sent == 65536 && r->event_count == 0, "file payload work stops at64KiB despite available socket capacity");
    check(rn_close_connection(r, token) == 0 && rn_file_release(r, file) == 0,
          "cancel fairness remainder releases source pins");
    check(close(peer) == 0 && rn_free(r) == 0, "fairness cancel cleanup");
    hot_path = 0; file_limit = old_limit;
}
static void ownership(rn_file_source *source) {
    rn_reactor *r = reactor_new(2, 1); uint64_t old = 0, file = 0;
    check(rn_file_import(r, source, &old) == 0 && rn_file_release(r, old) == 0 &&
          rn_file_import(r, source, &file) == 0 && old != file, "generation advances on reimport");
    int peer; uint64_t connection = adopt(r, &peer), owner = rn_file_owner(r);
    check(rn_queue_file(r, connection, owner, old, 0, 1, 1) == -EINVAL, "reject stale file token");
    check(rn_queue_file(r, connection, owner ^ 1u, file, 0, 1, 1) == -EACCES &&
          rn_queue_file(r, connection, UINT64_MAX, file, 0, 1, 1) == -EACCES, "foreign owner never dereferenced");
    check(rn_queue_file(r, connection, owner, file, UINT64_MAX, 1, 1) == -EINVAL &&
          rn_queue_file(r, connection, owner, file, 131072, 1, 1) == -EINVAL, "file range overflow rejected");
    rn_file_source *pin = NULL;
    check(rn_file_pin(r, owner ^ 1u, file, 0, 1, &pin) == -EACCES && !pin, "pin enforces reactor owner");
    check(rn_file_pin(r, owner, file, 5, 97, &pin) == 0 && pin == source, "retain native source pin");
    int imported_fd = (int)r->files.entries[rn_index(file)].handle;
    check(rn_file_release(r, file) == 0 && fcntl(imported_fd, F_GETFD) < 0 && errno == EBADF,
          "table release closes its duplicate while independent source pin survives");
    const uint8_t *view;
    check(rn_file_source_view(pin, 5, 97, &view) == 0 && !memcmp(view, data + 5, 97), "pinned bytes immutable");
    check(rn_file_source_release(pin) == 0 && rn_file_import(r, source, &file) == 0, "release pin and reimport");
    uint64_t cap; check(rn_transport_claim(r, connection, &cap) == 0, "claim file connection for TLS");
    check(rn_queue_file(r, connection, owner, file, 0, 1, 1) == -EACCES,
          "plain sendfile cannot bypass claimed TLS transport");
    check(rn_file_release(r, file) == 0 && rn_transport_abort(r, connection, cap) == 0 && close(peer) == 0,
          "claimed source cleanup");
    check(rn_free(r) == 0, "free ownership reactor");
    r = reactor_new(1, 1); r->files.entries[0].generation = INT32_MAX - 1u;
    check(rn_file_import(r, source, &file) == 0 && file <= INT64_MAX && rn_file_release(r, file) == 0,
          "last positive file generation");
    check(rn_file_import(r, source, &file) == -EAGAIN && rn_free(r) == 0, "exhausted file slot never wraps");
}
static void recycled_namespace(rn_file_source *source) {
    reused_core = calloc(1, sizeof(rn_reactor)); check(reused_core != NULL, "reserve recycled core address");
    rn_reactor *first = reactor_new(1, 1); uint64_t old_file = 0;
    uint64_t old_owner = rn_file_owner(first);
    check(first == reused_core && old_owner != 0 && rn_file_import(first, source, &old_file) == 0,
          "first owner at recycled core address");
    check(rn_free(first) == 0, "destroy first file namespace");
    rn_reactor *second = reactor_new(1, 1); uint64_t file = 0;
    uint64_t owner = rn_file_owner(second);
    check(second == first && owner && owner != old_owner && rn_file_import(second, source, &file) == 0 &&
          file == old_file, "new namespace survives identical pointer and numeric file token");
    int peer; uint64_t connection = adopt(second, &peer); rn_file_source *pin = NULL;
    check(rn_queue_file(second, connection, old_owner, old_file, 0, 10, 77) == -EACCES &&
          rn_file_pin(second, old_owner, old_file, 0, 10, &pin) == -EACCES && !pin,
          "retained old FileRegion cannot target recycled reactor file");
    check(rn_queue_file(second, connection, owner, file, 0, 0, 78) == 0 &&
          rn_close_connection(second, connection) == 0 && close(peer) == 0 && rn_free(second) == 0,
          "new namespace remains usable and cleans queued pins");
    void *block = reused_core; reused_core = NULL; free(block);
}
static void interrupted(rn_file_source *source, int error, unsigned progress) {
    rn_reactor *r = reactor_new(1, 1); uint64_t file; check(rn_file_import(r, source, &file) == 0, "import interruption source");
    int peer; uint64_t connection = adopt(r, &peer); rn_conn *c = &r->connections[rn_index(connection)];
    check(rn_queue_file(r, connection, rn_file_owner(r), file, 23, 200, 44) == 0, "queue interrupted file");
    file_calls = 0; injected_file_error = error; injected_progress = progress;
    check(rn_write_ready(r, rn_index(connection)) == 0 && file_calls == 1, "file syscall interruption is never retried");
#if defined(__linux__)
    progress = 0;
#endif
    check(r->writes[c->head_write].sent == progress && rn_file_release(r, file) == -EBUSY,
          "partial progress committed while source stays pinned");
    if (error == EINTR) check(r->event_count == 1 && r->events[0].kind == RN_ERROR && r->events[0].result == -EINTR,
                              "interruption surfaced exactly once");
    else check(r->event_count == 0, "EAGAIN is ordinary backpressure");
    r->event_count = 0; unsigned before = file_calls;
    check(rn_write_ready(r, rn_index(connection)) == 0 && r->event_count == 1 &&
          r->events[0].kind == RN_WRITTEN && r->events[0].operation == 44 && r->events[0].result == 200,
          "resumption completes original operation once");
    if (progress == 200) check(file_calls == before, "fully committed interrupted send does not repeat file IO");
    else check(last_file_offset >= 23 + progress && file_calls > before, "resume uses committed file cursor");
    uint8_t received[200]; size_t got = 0;
    while (got < sizeof(received)) {
        ssize_t n = recv(peer, received + got, sizeof(received) - got, 0);
        check(n > 0, "read resumed file bytes"); got += (size_t)n;
    }
    check(!memcmp(received, data + 23, sizeof(received)), "interrupted file has no duplicate or omitted bytes");
    check(rn_file_release(r, file) == 0 && rn_close_connection(r, connection) == 0 &&
          close(peer) == 0 && rn_free(r) == 0, "interrupted cleanup");
}
static void unexpected_eof(rn_file_source *source) {
    rn_reactor *r = reactor_new(2, 1); uint64_t file; check(rn_file_import(r, source, &file) == 0, "import EOF source");
    int peer; uint64_t connection = adopt(r, &peer);
    check(rn_queue_file(r, connection, rn_file_owner(r), file, 0, 10, 55) == 0, "queue EOF injection");
    injected_eof = 1; check(rn_write_ready(r, rn_index(connection)) == 0, "surface unexpected EOF");
    check(r->event_count == 1 && r->events[0].kind == RN_ERROR && r->events[0].result == -EIO &&
          r->events[0].operation == 55 && !rn_connection_live(r, connection), "unexpected EOF aborts, never completes short file");
    check(rn_file_release(r, file) == 0 && rn_step(r, 0) == 1 && rn_event_at(r, 0)->kind == RN_CLOSED,
          "EOF releases pins then CLOSED once");
    check(close(peer) == 0 && rn_free(r) == 0, "EOF cleanup");
}
static void retained_source_teardown(void) {
    rn_file_source *source = source_new(8192), *pin = NULL; int fd = (int)rn_file_source_handle(source);
    check((fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDONLY && write(fd, "x", 1) < 0 && errno == EBADF,
          "published descriptor is not writable");
    rn_reactor *r = reactor_new(1, 1); uint64_t file; check(rn_file_import(r, source, &file) == 0, "import teardown source");
    check(rn_file_pin(r, rn_file_owner(r), file, 0, 8192, &pin) == 0 && rn_file_source_release(source) == 0,
          "source pin outlives catalog reference");
    int peer; uint64_t connection = adopt(r, &peer);
    check(rn_queue_file(r, connection, rn_file_owner(r), file, 0, 8192, 66) == 0 &&
          rn_file_release(r, file) == -EBUSY, "queued teardown source busy");
    int imported_fd = (int)r->files.entries[rn_index(file)].handle;
    hot_path = 1;
    check(rn_free(r) == 0 && close(peer) == 0 && fcntl(fd, F_GETFD) >= 0 &&
          fcntl(imported_fd, F_GETFD) < 0 && errno == EBADF,
          "reactor teardown closes duplicate but retained source pin stays live");
    const uint8_t *view; check(rn_file_source_view(pin, 0, 8192, &view) == 0 && !memcmp(view, data, 8192),
                               "pin bytes survive reactor free");
    check(rn_file_source_release(pin) == 0 && fcntl(fd, F_GETFD) < 0 && errno == EBADF,
          "last pin closes source handle"); hot_path = 0;
}
#if defined(__linux__)
static void sigpipe_case(rn_file_source *source, unsigned mode) {
    pid_t pid = fork(); check(pid >= 0, "fork default SIGPIPE fixture");
    if (!pid) {
        signal(SIGPIPE, SIG_DFL); sigset_t only, before, pending;
        sigemptyset(&only); sigaddset(&only, SIGPIPE);
        check(pthread_sigmask(mode ? SIG_BLOCK : SIG_UNBLOCK, &only, &before) == 0, "set initial SIGPIPE mask");
        if (mode == 2) check(raise(SIGPIPE) == 0, "establish earlier pending SIGPIPE");
        int pair[2]; check(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0 && close(pair[1]) == 0,
                           "closed SIGPIPE peer");
        uint32_t sent; file_limit = 0; injected_file_error = 0;
        check(rn_send_file_once(pair[0], (int)rn_file_source_handle(source), 0, 10, &sent) == -EPIPE && sent == 0,
              "SIGPIPE becomes ordinary EPIPE");
        check(sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == (mode == 2),
              "preserve only caller's previously pending SIGPIPE");
        sigset_t after; check(pthread_sigmask(SIG_SETMASK, NULL, &after) == 0 &&
                              sigismember(&after, SIGPIPE) == (mode != 0), "restore original signal mask");
        if (mode == 2) { int caught; check(sigwait(&only, &caught) == 0 && caught == SIGPIPE, "consume preserved caller signal"); }
        check(pthread_sigmask(SIG_UNBLOCK, &only, NULL) == 0 && close(pair[0]) == 0, "later unblock survives");
        _exit(0);
    }
    int status; check(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                      "default-disposition child survives sendfile SIGPIPE");
}
#endif
int main(void) {
    lean_initialize_runtime_module();
    for (size_t i = 0; i < sizeof(data); ++i) data[i] = (uint8_t)(i * 19u + (i >> 8));
    source_failures(); rn_file_source *source = source_new(sizeof(data)), *empty = source_new(0);
    fifo(source, empty, 1); fifo(source, empty, 7); file_budget(source); ownership(source); recycled_namespace(source);
    interrupted(source, EINTR, 13); interrupted(source, EAGAIN, 13);
#if defined(__APPLE__)
    interrupted(source, EINTR, 200);
#endif
    unexpected_eof(source); retained_source_teardown();
#if defined(__linux__)
    for (unsigned mode = 0; mode < 3; ++mode) sigpipe_case(source, mode);
#endif
    check(rn_file_source_release(source) == 0 && rn_file_source_release(empty) == 0, "release catalog sources");
    check(allocation_attempts == 0, "no backend or Lean-buffer hot allocations");
    puts("reactor file ASan/UBSan FIFO, faults, ownership and zero-allocation tests passed"); return 0;
}
