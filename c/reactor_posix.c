/* POSIX completion reactor. Native storage is allocated at rn_new, never for
 * established I/O. Platform extensions expose SO_REUSEPORT/SO_NOSIGPIPE. */
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _WIN32
#include "reactor.h"
#include "reactor_file_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/epoll.h>
#include <sys/sendfile.h>
#else
#include <sys/event.h>
#include <sys/time.h>
#endif
#if defined(__APPLE__) && defined(_POSIX_C_SOURCE)
/* Darwin exposes sf_hdtr with its extensions but hides this prototype when
 * POSIX feature selection is also enabled. This is the SDK's sendfile ABI. */
extern int sendfile(int, int, off_t, off_t *, struct sf_hdtr *, int);
#endif
#include "reactor_file_impl.h"

#define RN_NONE UINT32_MAX
#define RN_WHEEL_SIZE 1024u
#define RN_READ_BUDGET 16u
#define RN_READ_BYTES_BUDGET 65536u
#define RN_WRITE_BUDGET 16u
#define RN_ACCEPT_BUDGET 64u
#define RN_GENERATION_MAX ((uint32_t)INT32_MAX)

struct rn_waker {
    atomic_uint references;
    atomic_int closed;
    int read_fd, write_fd;
};

typedef struct rn_conn {
    int fd;
    int pending_accept_fd;
    uint32_t generation;
    uint64_t transport_cap;
    uint8_t transport_mode;
    uint32_t head_write, tail_write;
    uint32_t next_closed;
    int close_error;
    uint8_t state; /* 0 free, 1 fresh, 2 bound, 3 listener, 4 connected, 5 closing */
    uint8_t interest;
    uint8_t paused;
    uint8_t eof;
    uint8_t drain_close;
    uint8_t read_disabled;
} rn_conn;
typedef struct rn_buffer {
    lean_object *bytes;
    uint32_t capacity, generation, writes;
    uint8_t owner, on_free;
} rn_buffer;
typedef struct rn_write {
    uint64_t connection, operation, buffer;
    uint32_t offset, length, sent, next;
    uint8_t active;
    uint8_t file_kind;
    uint64_t file, file_offset;
} rn_write;
typedef struct rn_timer {
    uint64_t connection, deadline_ms, deadline_tick;
    uint32_t next, previous, bucket;
    uint8_t active;
} rn_timer;
#if defined(__APPLE__)
/* A channel transfers only fd ownership. Each endpoint keeps its own wake
 * descriptor, so teardown of the other reactor cannot turn a late wake into a
 * write to a reused descriptor. All loops must be joined before destruction. */
typedef struct rn_accept_queue {
    _Atomic uint32_t head, tail, references;
    _Atomic uint32_t producer_waiting, producer_closed, consumer_closed;
    uint32_t slots;
    int producer_wake, consumer_wake;
    uint8_t producer_wake_pending, consumer_wake_pending;
    int *fds;
} rn_accept_queue;
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "accept channels require lock-free indices");
#endif
struct rn_reactor {
    rn_config config;
    int queue_fd, wake_read, wake_write;
    rn_waker *wake_owner;
    rn_file_table files;
    rn_conn *connections;
    uint32_t *free_connections, free_connection_count;
    uint32_t *paused_connections, paused_count;
    rn_buffer *buffers;
    uint32_t buffer_count, *free_buffers, free_buffer_count;
    rn_write *writes;
    uint32_t *free_writes, free_write_count;
    rn_timer *timers;
    uint32_t wheel[RN_WHEEL_SIZE];
    uint64_t tick;
    uint32_t active_timers;
    uint8_t timer_backlog;
    rn_event *events;
    uint32_t event_count;
    int pending_wait_error;
    uint32_t closed_head, closed_tail;
    uint8_t has_polled;
#if defined(__APPLE__)
    rn_accept_queue **accept_targets;
    uint32_t accept_target_count, next_accept_target;
    rn_accept_queue *accept_source;
#endif
#if defined(__linux__)
    struct epoll_event *native_events;
#else
    struct kevent *native_events;
#endif
};

uint64_t rn_now_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return 0;
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}
static uint64_t rn_token(uint32_t index, uint32_t generation) {
    return ((uint64_t)generation << 32) | ((uint64_t)index + 1u);
}
static uint32_t rn_index(uint64_t token) { return (uint32_t)token - 1u; }
static int rn_conn_get(rn_reactor *r, uint64_t token, rn_conn **out) {
    uint32_t i = rn_index(token);
    if (token == 0 || i >= r->config.max_connections) return -EBADF;
    rn_conn *c = &r->connections[i];
    if (c->state == 0 || c->state == 5 || c->generation != (uint32_t)(token >> 32)) return -EBADF;
    *out = c; return 0;
}
static int rn_buffer_get(rn_reactor *r, uint64_t token, rn_buffer **out) {
    uint32_t i = rn_index(token);
    if (token == 0 || i >= r->buffer_count) return -EINVAL;
    rn_buffer *b = &r->buffers[i];
    if ((!b->owner && b->writes == 0) || b->generation != (uint32_t)(token >> 32)) return -EINVAL;
    *out = b; return 0;
}
static uint32_t rn_generation(uint32_t old) {
    return old < RN_GENERATION_MAX ? old + 1u : 0;
}
static int rn_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return -errno;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -errno;
    int fdflags = fcntl(fd, F_GETFD);
    if (fdflags < 0) return -errno;
    if (fcntl(fd, F_SETFD, fdflags | FD_CLOEXEC) < 0) return -errno;
    return 0;
}
static int rn_sigpipe(int fd) {
#ifdef SO_NOSIGPIPE
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) < 0) return -errno;
#else
    (void)fd;
#endif
    return 0;
}
static int rn_close_fd(int fd) { return close(fd) < 0 ? -errno : 0; }
static int rn_wake_fd(int fd) {
    int saved_errno = errno;
    unsigned char value = 1;
    ssize_t n = write(fd, &value, 1);
    int result = n == 1 || (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) ? 0 : n < 0 ? -errno : -EIO;
    errno = saved_errno; return result;
}
int rn_waker_retain(rn_waker *w) {
    if (!w) return -EINVAL;
    unsigned refs = atomic_load(&w->references);
    do { if (!refs || refs == UINT_MAX) return -EOVERFLOW; }
    while (!atomic_compare_exchange_weak(&w->references, &refs, refs + 1));
    return 0;
}
int rn_waker_acquire(rn_reactor *r, rn_waker **out) {
    if (!r || !out || !r->wake_owner) return -EINVAL;
    int error = rn_waker_retain(r->wake_owner);
    if (!error) *out = r->wake_owner;
    return error;
}
int rn_waker_wake(rn_waker *w) {
    if (!w) return -EINVAL;
    if (atomic_load(&w->closed)) return -ECANCELED;
    /* A racing reactor free cannot close the read end while this retained
     * object exists, so write never raises SIGPIPE or targets a reused fd. */
    return rn_wake_fd(w->write_fd);
}
int rn_waker_release(rn_waker *w) {
    if (!w) return -EINVAL;
    if (atomic_fetch_sub(&w->references, 1) != 1) return 0;
    int error = rn_close_fd(w->write_fd), read_error = rn_close_fd(w->read_fd);
    free(w); return error ? error : read_error;
}
static int rn_emit(rn_reactor *r, uint32_t kind, uint64_t conn, uint64_t operation,
                   uint64_t buffer, uint32_t offset, uint32_t length, int64_t result, uint32_t flags) {
    if (r->event_count >= r->config.max_events) return -ENOBUFS;
    rn_event *e = &r->events[r->event_count++];
    *e = (rn_event){conn, operation, buffer, result, kind, flags, offset, length};
    return 0;
}
static int rn_interest(rn_reactor *r, uint32_t index, uint8_t mask) {
    rn_conn *c = &r->connections[index];
    if (c->interest == mask) return 0;
    uint64_t token = rn_token(index, c->generation);
#if defined(__linux__)
    struct epoll_event event;
    memset(&event, 0, sizeof(event));
    if (mask & 1u) event.events |= EPOLLIN | EPOLLRDHUP;
    if (mask & 2u) event.events |= EPOLLOUT;
    event.data.u64 = token;
    int operation = c->interest == 0 ? EPOLL_CTL_ADD : mask == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
    if (epoll_ctl(r->queue_fd, operation, c->fd, &event) < 0) return -errno;
#else
    struct kevent changes[2];
    int count = 0;
    if ((mask ^ c->interest) & 1u) {
        EV_SET(&changes[count++], (uintptr_t)c->fd, EVFILT_READ,
               (mask & 1u) ? EV_ADD | EV_ENABLE : EV_DELETE, 0, 0, (void *)(uintptr_t)token);
    }
    if ((mask ^ c->interest) & 2u) {
        EV_SET(&changes[count++], (uintptr_t)c->fd, EVFILT_WRITE,
               (mask & 2u) ? EV_ADD | EV_ENABLE : EV_DELETE, 0, 0, (void *)(uintptr_t)token);
    }
    if (count && kevent(r->queue_fd, changes, count, NULL, 0, NULL) < 0) return -errno;
#endif
    c->interest = mask; return 0;
}
static void rn_buffer_free_candidate(rn_reactor *r, uint32_t index) {
    rn_buffer *b = &r->buffers[index];
    if (!b->owner && b->writes == 0 && !b->on_free && b->generation < RN_GENERATION_MAX) {
        b->on_free = 1;
        r->free_buffers[r->free_buffer_count++] = index;
    }
}
int rn_acquire_buffer(rn_reactor *r, uint32_t minimum, uint64_t *out) {
    if (minimum == 0 || minimum > 65536u || out == NULL) return -EINVAL;
    uint32_t best = RN_NONE, best_position = RN_NONE, best_capacity = UINT32_MAX;
    uint32_t preferred = minimum <= 4096u ? 4096u : minimum <= 16384u ? 16384u : 65536u;
    for (uint32_t remaining = r->free_buffer_count; remaining > 0; --remaining) {
        uint32_t pos = remaining - 1u;
        uint32_t index = r->free_buffers[pos]; rn_buffer *b = &r->buffers[index];
        if (b->generation >= RN_GENERATION_MAX) {
            uint32_t last = --r->free_buffer_count;
            r->free_buffers[pos] = r->free_buffers[last]; b->on_free = 0;
            if (best_position == last) best_position = pos;
            continue;
        }
        if (b->capacity >= minimum && b->capacity < best_capacity && lean_is_exclusive(b->bytes)) {
            best = index; best_position = pos; best_capacity = b->capacity;
            if (best_capacity == preferred) break;
        }
    }
    if (best == RN_NONE) return -EAGAIN;
    r->free_buffers[best_position] = r->free_buffers[--r->free_buffer_count];
    rn_buffer *b = &r->buffers[best]; b->on_free = 0; b->owner = 1;
    b->generation = rn_generation(b->generation);
    lean_sarray_set_size(b->bytes, 0);
    *out = rn_token(best, b->generation); return 0;
}
int rn_buffer_view(rn_reactor *r, uint64_t token, lean_object **out) {
    rn_buffer *b; int error = rn_buffer_get(r, token, &b);
    if (error) return error;
    if (!b->owner || out == NULL) return -EINVAL;
    *out = b->bytes; return 0;
}
int rn_buffer_release(rn_reactor *r, uint64_t token) {
    rn_buffer *b; int error = rn_buffer_get(r, token, &b);
    if (error) return error;
    if (!b->owner) return -EINVAL;
    b->owner = 0; rn_buffer_free_candidate(r, rn_index(token)); return 0;
}
int rn_buffer_copy(rn_reactor *r, uint64_t token, const uint8_t *data, uint32_t length) {
    rn_buffer *b; int error = rn_buffer_get(r, token, &b);
    if (error) return error;
    if (!b->owner || b->writes != 0 || length > b->capacity || !lean_is_exclusive(b->bytes)) return -EINVAL;
    if (length && data == NULL) return -EINVAL;
    if (length) memcpy(lean_sarray_cptr(b->bytes), data, length);
    lean_sarray_set_size(b->bytes, length); return 0;
}
static void rn_timer_remove(rn_reactor *r, uint32_t index) {
    rn_timer *t = &r->timers[index];
    if (!t->active) return;
    if (t->previous != RN_NONE) r->timers[t->previous].next = t->next;
    else r->wheel[t->bucket] = t->next;
    if (t->next != RN_NONE) r->timers[t->next].previous = t->previous;
    t->active = 0; t->next = t->previous = RN_NONE;
    --r->active_timers;
}
static int rn_arm_timer_impl(rn_reactor *r, uint64_t token, uint32_t kind, uint64_t deadline) {
    rn_conn *c; int error = rn_conn_get(r, token, &c); (void)c;
    if (error) return error;
    if (kind >= RN_TIMER_KINDS || deadline > INT64_MAX) return -EINVAL;
    uint32_t index = rn_index(token) * RN_TIMER_KINDS + kind;
    rn_timer_remove(r, index);
    rn_timer *t = &r->timers[index];
    uint64_t tick = deadline / r->config.timer_tick_ms + (deadline % r->config.timer_tick_ms != 0);
    if (tick <= r->tick) tick = r->tick + 1u;
    uint32_t bucket = (uint32_t)(tick % RN_WHEEL_SIZE);
    *t = (rn_timer){token, deadline, tick, r->wheel[bucket], RN_NONE, bucket, 1};
    if (t->next != RN_NONE) r->timers[t->next].previous = index;
    r->wheel[bucket] = index; ++r->active_timers; return 0;
}
static int rn_cancel_timer_impl(rn_reactor *r, uint64_t token, uint32_t kind) {
    rn_conn *c; int error = rn_conn_get(r, token, &c); (void)c;
    if (error) return error;
    if (kind >= RN_TIMER_KINDS) return -EINVAL;
    rn_timer_remove(r, rn_index(token) * RN_TIMER_KINDS + kind); return 0;
}
static void rn_write_release(rn_reactor *r, uint32_t index) {
    rn_write *w = &r->writes[index];
    if (w->file_kind) {
        rn_file_entry *entry = NULL;
        if (!rn_files_get(&r->files, w->file, &entry) && entry->writes) --entry->writes;
    } else {
        rn_buffer *b = &r->buffers[rn_index(w->buffer)];
        if (b->writes) --b->writes;
        rn_buffer_free_candidate(r, rn_index(w->buffer));
    }
    w->active = 0; r->free_writes[r->free_write_count++] = index;
}
static int rn_close_connection_impl(rn_reactor *r, uint64_t token) {
    rn_conn *c; int error = rn_conn_get(r, token, &c);
    if (error) return error;
    uint32_t index = rn_index(token);
    if (c->pending_accept_fd >= 0) {
        error = rn_close_fd(c->pending_accept_fd);
        c->pending_accept_fd = -1;
    }
    for (uint32_t kind = 0; kind < RN_TIMER_KINDS; ++kind) rn_timer_remove(r, index * RN_TIMER_KINDS + kind);
    if (c->fd >= 0) {
        /* Last close removes registered filters even if explicit deletion failed. */
        int removed = rn_interest(r, index, 0);
        int closed = rn_close_fd(c->fd);
        if (!error) error = closed ? closed : removed;
    }
    c->fd = -1; c->interest = 0;
    while (c->head_write != RN_NONE) {
        uint32_t w = c->head_write; c->head_write = r->writes[w].next; rn_write_release(r, w);
    }
    c->tail_write = RN_NONE; c->state = 5; c->close_error = error; c->next_closed = RN_NONE;
    if (r->closed_tail == RN_NONE) r->closed_head = index;
    else r->connections[r->closed_tail].next_closed = index;
    r->closed_tail = index;
    return error;
}
int rn_socket_new(rn_reactor *r, uint64_t *out) {
    if (out == NULL) return -EINVAL;
    uint32_t index = 0, generation = 0;
    while (r->free_connection_count) {
        index = r->free_connections[--r->free_connection_count];
        generation = rn_generation(r->connections[index].generation);
        if (generation) break;
    }
    if (!generation) return -EAGAIN;
    rn_conn *c = &r->connections[index];
    memset(c, 0, sizeof(*c)); c->fd = c->pending_accept_fd = -1; c->generation = generation; c->state = 1;
    c->head_write = c->tail_write = c->next_closed = RN_NONE;
    *out = rn_token(index, generation); return 0;
}
int rn_bind(rn_reactor *r, uint64_t token, const char *host, uint16_t port, int reuse_port) {
    rn_conn *c; int error = rn_conn_get(r, token, &c);
    if (error) return error;
    if (c->state != 1 || host == NULL || (reuse_port != 0 && reuse_port != 1)) return -EINVAL;
#if defined(__APPLE__)
    if (r->accept_source != NULL) return -EINVAL;
#endif
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_PASSIVE;
    char service[6]; (void)snprintf(service, sizeof(service), "%u", (unsigned)port);
    struct addrinfo *addresses = NULL;
    int gai = getaddrinfo(host[0] ? host : NULL, service, &hints, &addresses);
    if (gai) return -(100000 + gai);
    error = -EADDRNOTAVAIL;
    for (struct addrinfo *ai = addresses; ai; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) { error = -errno; if (error == -EINTR) break; continue; }
        int one = 1;
        error = rn_nonblocking(fd);
        if (!error) error = rn_sigpipe(fd);
        if (!error && setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) error = -errno;
        if (!error && reuse_port) {
#ifdef SO_REUSEPORT
            if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0) error = -errno;
#else
            error = -ENOTSUP;
#endif
        }
        if (!error && bind(fd, ai->ai_addr, ai->ai_addrlen) < 0) error = -errno;
        if (!error) { c->fd = fd; c->state = 2; break; }
        int closed = rn_close_fd(fd);
        if (closed) { error = closed; break; }
        if (error == -EINTR || error == -ENOTSUP) break;
    }
    freeaddrinfo(addresses); return error;
}
int rn_start_listening(rn_reactor *r, uint64_t token, int backlog) {
    rn_conn *c; int error = rn_conn_get(r, token, &c);
    if (error) return error;
    if (c->state != 2 || backlog <= 0) return -EINVAL;
    if (listen(c->fd, backlog) < 0) return -errno;
    error = rn_interest(r, rn_index(token), 1);
    if (error) return error;
    c->state = 3; return 0;
}
int rn_listen(rn_reactor *r, const char *host, uint16_t port, int reuse_port, uint64_t *out) {
    uint64_t token; int error = rn_socket_new(r, &token);
    if (error) return error;
    error = rn_bind(r, token, host, port, reuse_port);
    if (!error) error = rn_start_listening(r, token, 4096);
    if (error) { int closed = rn_close_connection_impl(r, token); return closed ? closed : error; }
    *out = token; return 0;
}
static int rn_queue_write_impl(rn_reactor *r, uint64_t token, uint64_t buffer, uint32_t offset, uint32_t length, uint64_t operation) {
    rn_conn *c; rn_buffer *b;
    int error = rn_conn_get(r, token, &c); if (error) return error;
    error = rn_buffer_get(r, buffer, &b); if (error) return error;
    size_t size = lean_sarray_size(b->bytes);
    if (c->state != 4 || !b->owner || offset > size || length > size - offset) return -EINVAL;
    if (c->drain_close) return -EPIPE;
    if (r->free_write_count == 0) return -EAGAIN;
    uint32_t index = r->free_writes[--r->free_write_count];
    r->writes[index] = (rn_write){.connection=token, .operation=operation,
        .buffer=buffer, .offset=offset, .length=length, .next=RN_NONE, .active=1};
    ++b->writes;
    if (c->tail_write == RN_NONE) c->head_write = index;
    else r->writes[c->tail_write].next = index;
    c->tail_write = index;
    error = rn_interest(r, rn_index(token), (uint8_t)(c->interest | 2u));
    if (error) {
        if (c->head_write == index) c->head_write = c->tail_write = RN_NONE;
        else {
            uint32_t prior = c->head_write;
            while (r->writes[prior].next != index) prior = r->writes[prior].next;
            r->writes[prior].next = RN_NONE; c->tail_write = prior;
        }
        rn_write_release(r, index); return error;
    }
    return 0;
}

static int rn_queue_file_impl(rn_reactor *r, uint64_t token, uint64_t owner,
                             uint64_t file, uint64_t offset, uint32_t length,
                             uint64_t operation) {
    if (!owner || owner != r->files.owner) return -EACCES;
    rn_conn *c; int error = rn_conn_get(r, token, &c); if (error) return error;
    rn_file_entry *entry; error = rn_files_get(&r->files, file, &entry); if (error) return error;
    const uint8_t *bytes;
    error = rn_file_source_view(entry->source, offset, length, &bytes); if (error) return error;
    if (c->state != 4) return -EINVAL;
    if (c->drain_close) return -EPIPE;
    if (!r->free_write_count) return -EAGAIN;
    if (entry->writes == UINT32_MAX) return -EOVERFLOW;
    uint32_t index = r->free_writes[--r->free_write_count];
    r->writes[index] = (rn_write){.connection=token, .operation=operation,
        .length=length, .next=RN_NONE, .active=1, .file_kind=1,
        .file=file, .file_offset=offset};
    ++entry->writes;
    if (c->tail_write == RN_NONE) c->head_write = index;
    else r->writes[c->tail_write].next = index;
    c->tail_write = index;
    error = rn_interest(r, rn_index(token), (uint8_t)(c->interest | 2u));
    if (error) {
        if (c->head_write == index) c->head_write = c->tail_write = RN_NONE;
        else {
            uint32_t prior = c->head_write;
            while (r->writes[prior].next != index) prior = r->writes[prior].next;
            r->writes[prior].next = RN_NONE; c->tail_write = prior;
        }
        rn_write_release(r, index);
    }
    return error;
}

static int rn_close_after_writes_impl(rn_reactor *r, uint64_t token) {
    rn_conn *c; int error = rn_conn_get(r, token, &c);
    if (error) return error;
    if (c->state != 4) return -EINVAL;
    if (c->head_write == RN_NONE) return rn_close_connection_impl(r, token);
    c->drain_close = 1;
    return rn_interest(r, rn_index(token), 2);
}
static int rn_set_read_enabled_impl(rn_reactor *r, uint64_t token, int enabled) {
    if (r == NULL || (enabled != 0 && enabled != 1)) return -EINVAL;
    rn_conn *c; int error = rn_conn_get(r, token, &c);
    if (error) return error;
    if (c->state != 4) return -EINVAL;
    uint8_t interest = (uint8_t)(c->interest & 2u);
    if (enabled && !c->paused && !c->eof && !c->drain_close) interest |= 1u;
    error = rn_interest(r, rn_index(token), interest);
    if (!error) c->read_disabled = (uint8_t)!enabled;
    return error;
}
int rn_connection_live(rn_reactor *r, uint64_t token) {
    if (r == NULL) return -EINVAL;
    rn_conn *c;
    return rn_conn_get(r, token, &c) == 0 && c->state == 4;
}

static int rn_peer_error(int fd) {
    int value = 0; socklen_t length = sizeof(value);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &value, &length) < 0 || length != sizeof(value)) return 0;
    return value == ECONNRESET || value == ECONNABORTED || value == EPIPE || value == ENOTCONN ? value : 0;
}
static void rn_pause(rn_reactor *r, uint32_t index) {
    rn_conn *c = &r->connections[index];
    if (!c->paused) { c->paused = 1; r->paused_connections[r->paused_count++] = index; }
}
#if defined(__APPLE__)
static uint32_t rn_accept_next(const rn_accept_queue *q, uint32_t position) {
    return position + 1u == q->slots ? 0 : position + 1u;
}
static int rn_accept_discard(rn_accept_queue *q) {
    int first_error = 0;
    uint32_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
    uint32_t head = atomic_load_explicit(&q->head, memory_order_acquire);
    while (tail != head) {
        int error = rn_close_fd(q->fds[tail]);
        if (error && !first_error) first_error = error;
        q->fds[tail] = -1;
        tail = rn_accept_next(q, tail);
    }
    atomic_store_explicit(&q->tail, tail, memory_order_release);
    return first_error;
}
static int rn_accept_release(rn_accept_queue *q) {
    if (atomic_fetch_sub_explicit(&q->references, 1, memory_order_acq_rel) != 1) return 0;
    int first_error = rn_accept_discard(q);
    int error = q->producer_wake >= 0 ? rn_close_fd(q->producer_wake) : 0;
    if (error && !first_error) first_error = error;
    error = q->consumer_wake >= 0 ? rn_close_fd(q->consumer_wake) : 0;
    if (error && !first_error) first_error = error;
    free(q->fds); free(q); return first_error;
}
static int rn_accept_notify(rn_accept_queue *q, int consumer) {
    uint8_t *pending = consumer ? &q->consumer_wake_pending : &q->producer_wake_pending;
    if (!*pending) return 0;
    _Atomic uint32_t *closed = consumer ? &q->consumer_closed : &q->producer_closed;
    if (atomic_load_explicit(closed, memory_order_acquire)) { *pending = 0; return 0; }
    int error = rn_wake_fd(consumer ? q->consumer_wake : q->producer_wake);
    /* A failed syscall is surfaced without retry. The owning endpoint may
     * attempt this still-needed wake only when its caller polls again. */
    if (!error) *pending = 0;
    return error;
}
static int rn_accept_flush_wakes(rn_reactor *r) {
    for (uint32_t i = 0; i < r->accept_target_count; ++i) {
        int error = rn_accept_notify(r->accept_targets[i], 1);
        if (error) return error;
    }
    return r->accept_source ? rn_accept_notify(r->accept_source, 0) : 0;
}
static int rn_accept_target(rn_reactor *r, rn_accept_queue **out,
                            uint32_t *out_index, uint32_t *out_head) {
    /* The paired waiting/space operations are sequentially consistent: after
     * publishing waiting, either our recheck sees a consumer's freed slot or
     * that consumer sees waiting and wakes us. Mere release/acquire permits
     * both threads to read the old value on weakly ordered machines. */
    for (uint32_t pass = 0; pass < 2; ++pass) {
        int open = 0;
        for (uint32_t offset = 0; offset < r->accept_target_count; ++offset) {
            uint32_t index = (r->next_accept_target + offset) % r->accept_target_count;
            rn_accept_queue *q = r->accept_targets[index];
            if (atomic_load_explicit(&q->consumer_closed, memory_order_acquire)) continue;
            open = 1;
            uint32_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
            uint32_t tail = atomic_load_explicit(&q->tail, memory_order_seq_cst);
            if (rn_accept_next(q, head) != tail) {
                *out = q; *out_index = index; *out_head = head; return 0;
            }
        }
        if (!open) return -EPIPE;
        if (pass == 0) for (uint32_t i = 0; i < r->accept_target_count; ++i)
            atomic_store_explicit(&r->accept_targets[i]->producer_waiting, 1, memory_order_seq_cst);
    }
    return -EAGAIN;
}
static int rn_forward_accept(rn_reactor *r, rn_conn *listener) {
    rn_accept_queue *q; uint32_t index, head;
    int error = rn_accept_target(r, &q, &index, &head);
    if (error) return error;
    q->fds[head] = listener->pending_accept_fd;
    listener->pending_accept_fd = -1;
    atomic_store_explicit(&q->head, rn_accept_next(q, head), memory_order_release);
    r->next_accept_target = (index + 1u) % r->accept_target_count;
    q->consumer_wake_pending = 1;
    return rn_accept_notify(q, 1);
}
static int rn_adopt_accepts(rn_reactor *r) {
    rn_accept_queue *q = r->accept_source;
    if (q == NULL) return 0;
    for (uint32_t attempt = 0; attempt < RN_ACCEPT_BUDGET &&
         r->free_connection_count && r->event_count < r->config.max_events; ++attempt) {
        uint32_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
        if (tail == atomic_load_explicit(&q->head, memory_order_acquire)) break;
        uint64_t token;
        int error = rn_socket_new(r, &token);
        if (error) return error;
        rn_conn *c = &r->connections[rn_index(token)];
        c->fd = q->fds[tail]; c->state = 4;
        q->fds[tail] = -1;
        atomic_store_explicit(&q->tail, rn_accept_next(q, tail), memory_order_seq_cst);
        error = rn_interest(r, rn_index(token), 1);
        if (error) {
            int closed = rn_close_connection_impl(r, token);
            (void)rn_emit(r, RN_ERROR, token, 0, 0, 0, 0, closed ? closed : error,
                          closed ? RN_CLOSE_ERROR : RN_SETUP_ERROR);
        } else {
            /* The token and registration belong only to this worker. The
             * acceptor's listener identity must not escape into its namespace. */
            (void)rn_emit(r, RN_ACCEPTED, token, 0, 0, 0, 0, 0, 0);
        }
        if (atomic_exchange_explicit(&q->producer_waiting, 0, memory_order_seq_cst) &&
            !atomic_load_explicit(&q->producer_closed, memory_order_acquire)) {
            q->producer_wake_pending = 1;
            error = rn_accept_notify(q, 0);
            if (error) return error;
        }
    }
    return 0;
}
#endif
static int rn_accept_ready(rn_reactor *r, uint32_t index) {
    rn_conn *listener = &r->connections[index];
    uint64_t listener_token = rn_token(index, listener->generation);
    for (uint32_t attempt = 0; attempt < RN_ACCEPT_BUDGET && r->event_count < r->config.max_events; ++attempt) {
#if defined(__APPLE__)
        if (r->accept_target_count) {
            if (listener->pending_accept_fd >= 0) {
                int forwarded = rn_forward_accept(r, listener);
                if (forwarded == -EAGAIN) { rn_pause(r, index); return rn_interest(r, index, 0); }
                if (forwarded) return forwarded;
            }
        } else
#endif
        if (r->free_connection_count == 0) { rn_pause(r, index); return rn_interest(r, index, 0); }
        int fd = accept(listener->fd, NULL, NULL);
        if (fd < 0) {
            int e = errno;
            if (e == EAGAIN || e == EWOULDBLOCK) return 0;
            return rn_emit(r, RN_ERROR, listener_token, 0, 0, 0, 0, -e, RN_ACCEPT_ERROR);
        }
        int error = rn_nonblocking(fd);
        if (!error) error = rn_sigpipe(fd);
        int one = 1;
        if (!error && setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) error = -errno;
        if (error) {
            uint32_t flags = RN_SETUP_ERROR;
            int peer = rn_peer_error(fd);
            if (peer && (error == -EINVAL || error == -peer)) { error = -peer; flags = RN_ACCEPT_ERROR; }
            int closed = rn_close_fd(fd);
            if (closed) { error = closed; flags = RN_CLOSE_ERROR; }
            int emitted = rn_emit(r, RN_ERROR, listener_token, 0, 0, 0, 0, error, flags);
            if (emitted) return emitted;
            continue;
        }
#if defined(__APPLE__)
        if (r->accept_target_count) {
            listener->pending_accept_fd = fd;
            error = rn_forward_accept(r, listener);
            if (error == -EAGAIN) { rn_pause(r, index); return rn_interest(r, index, 0); }
            if (error) return error;
            continue;
        }
#endif
        uint64_t token;
        int allocated = rn_socket_new(r, &token);
        if (allocated) { int closed = rn_close_fd(fd); return closed ? closed : allocated; }
        rn_conn *c = &r->connections[rn_index(token)]; c->fd = fd; c->state = 4;
        error = rn_interest(r, rn_index(token), 1);
        if (error) { int closed = rn_close_connection_impl(r, token); return closed ? closed : error; }
        int emitted = rn_emit(r, RN_ACCEPTED, token, listener_token, 0, 0, 0, 0, 0);
        if (emitted) return emitted;
    }
    return 0;
}
static int rn_read_ready(rn_reactor *r, uint32_t index) {
    rn_conn *c = &r->connections[index]; uint64_t token = rn_token(index, c->generation);
    if (c->eof || c->drain_close || c->read_disabled) return 0;
    uint32_t remaining = RN_READ_BYTES_BUDGET;
    for (uint32_t attempt = 0; attempt < RN_READ_BUDGET && remaining && r->event_count < r->config.max_events; ++attempt) {
        uint64_t lease;
        int error = rn_acquire_buffer(r, 4096, &lease);
        if (error == -EAGAIN) { rn_pause(r, index); return rn_interest(r, index, (uint8_t)(c->interest & 2u)); }
        if (error) return error;
        rn_buffer *b = &r->buffers[rn_index(lease)];
        uint32_t length = b->capacity < remaining ? b->capacity : remaining;
        ssize_t n = recv(c->fd, lean_sarray_cptr(b->bytes), length, 0);
        if (n <= 0) {
            int e = errno;
            (void)rn_buffer_release(r, lease);
            if (n == 0) {
                c->eof = 1;
                error = rn_interest(r, index, (uint8_t)(c->interest & 2u));
                if (error) return error;
                return rn_emit(r, RN_EOF, token, 0, 0, 0, 0, 0, 0);
            }
            if (e == EAGAIN || e == EWOULDBLOCK) return 0;
            error = rn_emit(r, RN_ERROR, token, 0, 0, 0, 0, -e, 0);
            if (error) return error;
            if (e != EINTR) return rn_close_connection_impl(r, token);
            return 0;
        }
        remaining -= (uint32_t)n;
        lean_sarray_set_size(b->bytes, (size_t)n);
        error = rn_emit(r, RN_READ, token, 0, lease, 0, (uint32_t)n, n, 0);
        if (error) { (void)rn_buffer_release(r, lease); return error; }
    }
    return 0;
}
static int rn_send_file_once(int socket_fd, int file_fd, uint64_t offset,
                            uint32_t count, uint32_t *sent, uint32_t *flags) {
    *sent = 0; *flags = 0;
#if defined(__linux__)
    /* sendfile lacks MSG_NOSIGNAL. Preserve the caller's signal mask and any
     * previously pending SIGPIPE; consume only this call's newly raised one. */
    *flags = RN_SETUP_ERROR;
    sigset_t blocked, previous, pending;
    if (sigemptyset(&blocked) < 0 || sigaddset(&blocked, SIGPIPE) < 0) return -errno;
    int mask_error = pthread_sigmask(SIG_BLOCK, &blocked, &previous);
    if (mask_error) return -mask_error;
    if (sigpending(&pending) < 0) {
        int error = errno;
        mask_error = pthread_sigmask(SIG_SETMASK, &previous, NULL);
        return mask_error ? -mask_error : -error;
    }
    int had_pending = sigismember(&pending, SIGPIPE);
    if (had_pending < 0) {
        int error = errno;
        mask_error = pthread_sigmask(SIG_SETMASK, &previous, NULL);
        return mask_error ? -mask_error : -error;
    }
    off_t position = (off_t)offset;
    ssize_t result = sendfile(socket_fd, file_fd, &position, count);
    int error = result < 0 ? errno : 0;
    if (error == EPIPE && !had_pending) {
        /* One nonblocking wait, never a retry. It is safe if SIGPIPE was
         * ignored, or a concurrent host sigaction(SIG_IGN) discarded it:
         * EAGAIN proves there is currently no signal to consume. A blocking
         * sigwait after a pending query would race with that host action.
         *
         * An unexpected bookkeeping failure must leave SIGPIPE blocked:
         * restoring an unblocked mask with an unconsumed new SIGPIPE could
         * terminate the host process. RN_SETUP_ERROR makes the owning worker
         * retire even when this failure's actual errno is EINTR. */
        const struct timespec immediate = {0, 0};
        int caught = sigtimedwait(&blocked, NULL, &immediate);
        if (caught < 0) {
            int wait_error = errno;
            if (wait_error != EAGAIN) return -wait_error;
        } else if (caught != SIGPIPE) {
            return -EIO;
        }
    }
    mask_error = pthread_sigmask(SIG_SETMASK, &previous, NULL);
    if (result > 0) {
        if ((uint64_t)result > count) error = EIO;
        else *sent = (uint32_t)result;
    }
    if (mask_error) return -mask_error;
    *flags = 0;
    return error ? -error : 0;
#else
    off_t amount = (off_t)count;
    int result = sendfile(file_fd, socket_fd, (off_t)offset, &amount, NULL, 0);
    int error = result < 0 ? errno : 0;
    if (amount < 0 || (uint64_t)amount > count) return -EIO;
    *sent = (uint32_t)amount;
    return error ? -error : 0;
#endif
}

static int rn_complete_head_write(rn_reactor *r, rn_conn *c, uint64_t token) {
    uint32_t index = c->head_write; rn_write *write = &r->writes[index];
    int error = rn_emit(r, RN_WRITTEN, token, write->operation, 0, 0,
                        write->length, write->length, 0);
    if (error) return error;
    c->head_write = write->next;
    if (c->head_write == RN_NONE) c->tail_write = RN_NONE;
    rn_write_release(r, index); return 0;
}

static int rn_write_ready(rn_reactor *r, uint32_t index) {
    rn_conn *c = &r->connections[index]; uint64_t token = rn_token(index, c->generation);
    uint32_t budget = RN_WRITE_BUDGET;
    uint32_t file_budget = 65536u;
    for (uint32_t attempt = 0; attempt < RN_WRITE_BUDGET && budget && c->head_write != RN_NONE &&
         r->event_count < r->config.max_events; ++attempt) {
        rn_write *head = &r->writes[c->head_write];
        if (head->file_kind) {
            if (head->sent == head->length) {
                int error = rn_complete_head_write(r, c, token); if (error) return error;
                --budget; continue;
            }
            if (!file_budget) break;
            rn_file_entry *entry;
            int error = rn_files_get(&r->files, head->file, &entry);
            uint32_t count = head->length - head->sent;
            if (count > file_budget) count = file_budget;
            uint32_t sent = 0, flags = 0;
            if (!error) error = rn_send_file_once(c->fd, (int)entry->handle,
                head->file_offset + head->sent, count, &sent, &flags);
            if (sent > count) { sent = 0; error = -EIO; }
            head->sent += sent; file_budget -= sent;
            if (error && (flags || (error != -EAGAIN && error != -EWOULDBLOCK))) {
                int emitted = rn_emit(r, RN_ERROR, token, head->operation, 0, 0, 0, error, flags);
                if (emitted) return emitted;
                if (flags || error != -EINTR) return rn_close_connection_impl(r, token);
                return 0;
            }
            if (!error && !sent) {
                int emitted = rn_emit(r, RN_ERROR, token, head->operation, 0, 0, 0, -EIO, 0);
                return emitted ? emitted : rn_close_connection_impl(r, token);
            }
            if (head->sent == head->length) {
                int emitted = rn_complete_head_write(r, c, token); if (emitted) return emitted;
                --budget;
            }
            if (error) return 0;
            continue;
        }
        struct iovec vectors[16];
        uint32_t count = 0, wi = c->head_write;
        uint32_t limit = r->config.max_events - r->event_count;
        if (limit > budget) limit = budget;
        if (limit > 16u) limit = 16u;
        size_t total = 0;
        while (wi != RN_NONE && count < limit) {
            rn_write *w = &r->writes[wi];
            if (w->file_kind) break;
            rn_buffer *b = &r->buffers[rn_index(w->buffer)];
            vectors[count].iov_base = lean_sarray_cptr(b->bytes) + w->offset + w->sent;
            vectors[count].iov_len = w->length - w->sent;
            total += vectors[count].iov_len;
            ++count; wi = w->next;
        }
        ssize_t n;
        if (total == 0) n = 0;
        else {
#if defined(__linux__)
            struct msghdr message; memset(&message, 0, sizeof(message));
            message.msg_iov = vectors; message.msg_iovlen = count;
            n = sendmsg(c->fd, &message, MSG_NOSIGNAL);
#else
            n = writev(c->fd, vectors, (int)count);
#endif
        }
        if (n < 0) {
            int e = errno;
            if (e == EAGAIN || e == EWOULDBLOCK) return 0;
            rn_write *w = &r->writes[c->head_write];
            int error = rn_emit(r, RN_ERROR, token, w->operation, 0, 0, 0, -e, 0);
            if (error) return error;
            if (e != EINTR) return rn_close_connection_impl(r, token);
            return 0;
        }
        if ((total && n == 0) || (size_t)n > total) {
            rn_write *w = &r->writes[c->head_write];
            int error = rn_emit(r, RN_ERROR, token, w->operation, 0, 0, 0, -EIO, 0);
            if (error) return error;
            return rn_close_connection_impl(r, token);
        }
        size_t remaining = (size_t)n;
        for (uint32_t completed = 0; completed < count && c->head_write != RN_NONE; ++completed) {
            uint32_t write_index = c->head_write; rn_write *w = &r->writes[write_index];
            uint32_t length = w->length - w->sent;
            if (remaining < length) { w->sent += (uint32_t)remaining; break; }
            remaining -= length;
            int error = rn_emit(r, RN_WRITTEN, token, w->operation, 0, 0, w->length, w->length, 0);
            if (error) return error;
            c->head_write = w->next;
            if (c->head_write == RN_NONE) c->tail_write = RN_NONE;
            rn_write_release(r, write_index);
            --budget;
        }
    }
    if (c->head_write == RN_NONE) {
        if (c->drain_close) return rn_close_connection_impl(r, token);
        return rn_interest(r, index, (uint8_t)(c->interest & 1u));
    }
    return 0;
}
static int rn_closed_events(rn_reactor *r) {
    while (r->closed_head != RN_NONE && r->event_count < r->config.max_events) {
        uint32_t index = r->closed_head; rn_conn *c = &r->connections[index];
        int error = rn_emit(r, RN_CLOSED, rn_token(index, c->generation), 0, 0, 0, 0,
                            c->close_error, c->close_error ? RN_CLOSE_ERROR : 0);
        if (error) return error;
        r->closed_head = c->next_closed;
        if (r->closed_head == RN_NONE) r->closed_tail = RN_NONE;
        c->state = 0; c->next_closed = RN_NONE;
        if (c->generation < RN_GENERATION_MAX)
            r->free_connections[r->free_connection_count++] = index;
    }
    return 0;
}
static void rn_due_timers(rn_reactor *r, uint64_t now) {
    uint64_t target = now / r->config.timer_tick_ms;
    if (target <= r->tick && !r->timer_backlog) return;
    uint64_t count = target > r->tick ? target - r->tick : 0;
    if (count > RN_WHEEL_SIZE || r->timer_backlog) count = RN_WHEEL_SIZE;
    if (count > target + 1u) count = target + 1u;
    uint64_t first = target - count + 1u;
    r->timer_backlog = 0;
    for (uint64_t tick = first; tick <= target; ++tick) {
        uint32_t index = r->wheel[tick % RN_WHEEL_SIZE];
        while (index != RN_NONE) {
            rn_timer *t = &r->timers[index]; uint32_t next = t->next;
            if (t->deadline_tick <= target) {
                if (r->event_count == r->config.max_events) { r->timer_backlog = 1; r->tick = target; return; }
                uint32_t kind = index % RN_TIMER_KINDS;
                (void)rn_emit(r, RN_TIMER, t->connection, kind, 0, 0, 0, (int64_t)t->deadline_ms, 0);
                rn_timer_remove(r, index);
            }
            index = next;
        }
    }
    r->tick = target;
}
static int rn_has_read_buffer(rn_reactor *r) {
    for (uint32_t pos = 0; pos < r->free_buffer_count; ++pos) {
        rn_buffer *b = &r->buffers[r->free_buffers[pos]];
        if (b->generation < RN_GENERATION_MAX && lean_is_exclusive(b->bytes)) return 1;
    }
    return 0;
}
static int rn_resume_paused(rn_reactor *r) {
    int available = rn_has_read_buffer(r);
    uint32_t position = 0;
    while (position < r->paused_count) {
        uint32_t i = r->paused_connections[position]; rn_conn *c = &r->connections[i];
        if (!c->paused || c->state == 0 || c->state == 5 || c->eof || c->drain_close) {
            c->paused = 0; r->paused_connections[position] = r->paused_connections[--r->paused_count];
            continue;
        }
        int enabled = c->state == 3 ? r->free_connection_count != 0 : available && !c->read_disabled;
#if defined(__APPLE__)
        if (c->state == 3 && r->accept_target_count) {
            int error = c->pending_accept_fd >= 0 ? rn_forward_accept(r, c) : 0;
            if (error && error != -EAGAIN) return error;
            enabled = error == 0;
        }
#endif
        if (enabled) {
            int error = rn_interest(r, i, (uint8_t)(c->interest | 1u));
            if (error) return error;
            c->paused = 0; r->paused_connections[position] = r->paused_connections[--r->paused_count];
        } else ++position;
    }
    return 0;
}
/* A reset discovered after a successful read in the same kernel batch can
 * cancel that read before Lean has dispatched it. Never expose a canceled READ
 * whose token can no longer accept the echo action; release its lease here.
 * WRITTEN is historical operation accounting and remains valid after closure.
 * Explicit closes made by Lean after rn_step returns do not rewrite the batch. */
static void rn_compact_canceled_events(rn_reactor *r) {
    uint32_t written = 0;
    for (uint32_t i = 0; i < r->event_count; ++i) {
        rn_event event = r->events[i];
        if (event.kind == RN_ACCEPTED || event.kind == RN_READ ||
            event.kind == RN_EOF || event.kind == RN_TIMER) {
            rn_conn *c;
            if (rn_conn_get(r, event.connection, &c) != 0) {
                if (event.kind == RN_READ) (void)rn_buffer_release(r, event.buffer);
                continue;
            }
        }
        r->events[written++] = event;
    }
    r->event_count = written;
}
static int rn_step_failed(rn_reactor *r, int error) {
    rn_compact_canceled_events(r);
    /* Committed records and leased buffers must reach the caller before an
     * interrupted/failed syscall is surfaced. No syscall is retried here. */
    if (r->event_count) {
        r->pending_wait_error = error;
        return (int)r->event_count;
    }
    return error;
}
int rn_step(rn_reactor *r, int timeout_ms) {
    if (r == NULL || timeout_ms < -1) return -EINVAL;
    r->has_polled = 1;
    r->event_count = 0;
    if (r->pending_wait_error) {
        int pending = r->pending_wait_error;
        r->pending_wait_error = 0;
        return pending;
    }
#if defined(__APPLE__)
    int wake_error = rn_accept_flush_wakes(r);
    if (wake_error) return wake_error;
#endif
    int error = rn_closed_events(r); if (error) return rn_step_failed(r, error);
#if defined(__APPLE__)
    error = rn_adopt_accepts(r);
    if (error) return rn_step_failed(r, error);
#endif
    rn_due_timers(r, rn_now_ms());
    error = rn_resume_paused(r); if (error) return rn_step_failed(r, error);
    if (r->event_count) timeout_ms = 0;
    if (r->active_timers) {
        uint32_t tick_ms = r->config.timer_tick_ms;
        int until_tick = (int)(tick_ms - rn_now_ms() % tick_ms);
        if (timeout_ms < 0 || until_tick < timeout_ms) timeout_ms = until_tick;
    }
    if (r->event_count == r->config.max_events) return (int)r->event_count;
    int ready;
#if defined(__linux__)
    ready = epoll_wait(r->queue_fd, r->native_events, (int)r->config.max_events, timeout_ms);
#else
    struct timespec timeout = {0,0};
    if (timeout_ms >= 0) { timeout.tv_sec = timeout_ms / 1000; timeout.tv_nsec = (timeout_ms % 1000) * 1000000L; }
    ready = kevent(r->queue_fd, NULL, 0, r->native_events, (int)r->config.max_events, timeout_ms < 0 ? NULL : &timeout);
#endif
    if (ready < 0) return rn_step_failed(r, -errno);
    rn_due_timers(r, rn_now_ms());
    for (int n = 0; n < ready && r->event_count < r->config.max_events; ++n) {
        uint64_t token; int readable, writable, failed;
#if defined(__linux__)
        uint32_t flags = r->native_events[n].events;
        token = r->native_events[n].data.u64;
        readable = (flags & (EPOLLIN | EPOLLRDHUP | EPOLLHUP)) != 0;
        writable = (flags & EPOLLOUT) != 0;
        failed = (flags & EPOLLERR) != 0;
#else
        struct kevent *event = &r->native_events[n];
        token = (uint64_t)(uintptr_t)event->udata;
        readable = event->filter == EVFILT_READ;
        writable = event->filter == EVFILT_WRITE;
        failed = (event->flags & EV_ERROR) != 0;
#endif
        if (token == 0) {
            unsigned char bytes[256];
            ssize_t result = read(r->wake_read, bytes, sizeof(bytes));
            if (result < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return rn_step_failed(r, -errno);
            int interrupted = result < 0 && errno == EINTR;
            (void)rn_emit(r, RN_WAKE, 0, 0, 0, 0, 0, 0, 0);
            if (interrupted) return rn_step_failed(r, -EINTR);
#if defined(__APPLE__)
            error = rn_adopt_accepts(r);
            if (error) return rn_step_failed(r, error);
#endif
            continue;
        }
        rn_conn *c;
        if (rn_conn_get(r, token, &c)) continue; /* stale queued readiness after close */
        uint32_t index = rn_index(token);
        if (failed) {
            int e = 0; socklen_t length = sizeof(e);
            if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &e, &length) < 0) e = errno;
            if (e) {
                (void)rn_emit(r, RN_ERROR, token, 0, 0, 0, 0, -e, 0);
                error = rn_close_connection_impl(r, token); if (error) return rn_step_failed(r, error);
                continue;
            }
        }
        if (c->state == 3 && readable) error = rn_accept_ready(r, index);
        else if (c->state == 4) {
            if (readable) error = rn_read_ready(r, index);
            if (!error && c->state == 4 && writable && r->event_count < r->config.max_events) error = rn_write_ready(r, index);
        }
        if (error) return rn_step_failed(r, error);
    }
    error = rn_closed_events(r); if (error) return rn_step_failed(r, error);
    rn_compact_canceled_events(r);
    return (int)r->event_count;
}
const rn_event *rn_event_at(const rn_reactor *r, uint32_t index) {
    return r != NULL && index < r->event_count ? &r->events[index] : NULL;
}
int rn_wake(rn_reactor *r) {
    if (r == NULL) return -EINVAL;
    return rn_wake_fd(r->wake_write);
}
int rn_set_accept_targets(rn_reactor *acceptor, rn_reactor *const *workers,
                          uint32_t count, uint32_t queue_capacity) {
#if defined(__APPLE__)
    if (acceptor == NULL || workers == NULL || count == 0 || count > 256u ||
        queue_capacity == 0 || queue_capacity > 1000000u) return -EINVAL;
    if (acceptor->has_polled || acceptor->accept_source || acceptor->accept_targets ||
        acceptor->free_connection_count != acceptor->config.max_connections) return -EINVAL;
    for (uint32_t i = 0; i < count; ++i) {
        rn_reactor *worker = workers[i];
        if (worker == NULL || worker == acceptor || worker->has_polled ||
            worker->accept_source || worker->accept_targets ||
            worker->free_connection_count != worker->config.max_connections) return -EINVAL;
        for (uint32_t j = 0; j < i; ++j) if (workers[j] == worker) return -EINVAL;
    }
    rn_accept_queue **targets = calloc(count, sizeof(*targets));
    if (targets == NULL) return -ENOMEM;
    int error = 0;
    for (uint32_t i = 0; i < count; ++i) {
        rn_accept_queue *q = calloc(1, sizeof(*q));
        if (q == NULL) { error = -ENOMEM; break; }
        targets[i] = q; q->producer_wake = q->consumer_wake = -1;
        atomic_init(&q->head, 0); atomic_init(&q->tail, 0); atomic_init(&q->references, 1);
        atomic_init(&q->producer_waiting, 0); atomic_init(&q->producer_closed, 0); atomic_init(&q->consumer_closed, 0);
        q->slots = queue_capacity + 1u;
        q->fds = calloc(q->slots, sizeof(*q->fds));
        if (q->fds == NULL) { error = -ENOMEM; break; }
        q->producer_wake = fcntl(acceptor->wake_write, F_DUPFD_CLOEXEC, 0);
        if (q->producer_wake < 0) { error = -errno; break; }
        q->consumer_wake = fcntl(workers[i]->wake_write, F_DUPFD_CLOEXEC, 0);
        if (q->consumer_wake < 0) { error = -errno; break; }
    }
    if (error) {
        for (uint32_t i = 0; i < count; ++i) if (targets[i]) (void)rn_accept_release(targets[i]);
        free(targets); return error;
    }
    for (uint32_t i = 0; i < count; ++i) {
        atomic_store_explicit(&targets[i]->references, 2, memory_order_relaxed);
        workers[i]->accept_source = targets[i];
    }
    acceptor->accept_targets = targets; acceptor->accept_target_count = count;
    return 0;
#else
    (void)acceptor; (void)workers; (void)count; (void)queue_capacity;
    return -ENOTSUP;
#endif
}
int rn_free(rn_reactor *r) {
    if (r == NULL) return -EINVAL;
    int first_error = 0;
    if (r->wake_owner) atomic_store(&r->wake_owner->closed, 1);
#if defined(__APPLE__)
    if (r->accept_source) {
        rn_accept_queue *q = r->accept_source;
        atomic_store_explicit(&q->consumer_closed, 1, memory_order_release);
        int error = rn_accept_discard(q); if (error) first_error = error;
        error = rn_accept_release(q); if (error && !first_error) first_error = error;
    }
    for (uint32_t i = 0; i < r->accept_target_count; ++i) {
        rn_accept_queue *q = r->accept_targets[i];
        atomic_store_explicit(&q->producer_closed, 1, memory_order_release);
        int error = rn_accept_release(q); if (error && !first_error) first_error = error;
    }
    free(r->accept_targets);
#endif
    if (r->connections != NULL) {
        for (uint32_t i = 0; i < r->config.max_connections; ++i) {
            rn_conn *c = &r->connections[i];
            if (c->state && c->pending_accept_fd >= 0) {
                int error = rn_close_fd(c->pending_accept_fd); if (error && !first_error) first_error = error;
            }
            if (c->state && c->state != 5 && c->fd >= 0) {
                int error = rn_close_fd(c->fd); if (error && !first_error) first_error = error;
            }
        }
    }
    if (r->writes) {
        for (uint32_t i = 0; i < r->config.max_writes; ++i) {
            rn_write *write = &r->writes[i];
            if (write->active && write->file_kind) {
                rn_file_entry *entry = NULL;
                if (!rn_files_get(&r->files, write->file, &entry) && entry->writes) --entry->writes;
                write->active = 0;
            }
        }
    }
    int files_closed = rn_files_destroy(&r->files);
    if (files_closed && !first_error) first_error = files_closed;
    int fds[3] = {r->wake_owner ? -1 : r->wake_read, r->wake_owner ? -1 : r->wake_write, r->queue_fd};
    for (uint32_t i = 0; i < 3; ++i) if (fds[i] >= 0) { int error = rn_close_fd(fds[i]); if (error && !first_error) first_error = error; }
    if (r->wake_owner) { int error = rn_waker_release(r->wake_owner); if (error && !first_error) first_error = error; }
    if (r->buffers != NULL) for (uint32_t i = 0; i < r->buffer_count; ++i) if (r->buffers[i].bytes) lean_dec(r->buffers[i].bytes);
    free(r->connections); free(r->free_connections); free(r->paused_connections); free(r->buffers); free(r->free_buffers);
    free(r->writes); free(r->free_writes); free(r->timers); free(r->events); free(r->native_events); free(r);
    return first_error;
}
int rn_new(const rn_config *config, rn_reactor **out) {
    if (config == NULL || out == NULL || config->max_connections == 0 || config->max_events == 0 ||
        config->max_writes == 0 || config->timer_tick_ms == 0 || config->timer_tick_ms > 1000u ||
        config->max_connections > 1000000u || config->max_events > 1000000u || config->max_writes > 1000000u) return -EINVAL;
    uint64_t buffers = (uint64_t)config->buffers_4k + config->buffers_16k + config->buffers_64k;
    if (buffers == 0 || buffers > 1000000u) return -EINVAL;
    rn_reactor *r = calloc(1, sizeof(*r)); if (r == NULL) return -ENOMEM;
    r->config = *config; r->queue_fd = r->wake_read = r->wake_write = -1;
    r->buffer_count = (uint32_t)buffers; r->closed_head = r->closed_tail = RN_NONE;
    r->tick = rn_now_ms() / config->timer_tick_ms;
    r->connections = calloc(config->max_connections, sizeof(*r->connections));
    r->free_connections = calloc(config->max_connections, sizeof(*r->free_connections));
    r->paused_connections = calloc(config->max_connections, sizeof(*r->paused_connections));
    r->buffers = calloc(r->buffer_count, sizeof(*r->buffers));
    r->free_buffers = calloc(r->buffer_count, sizeof(*r->free_buffers));
    r->writes = calloc(config->max_writes, sizeof(*r->writes));
    r->free_writes = calloc(config->max_writes, sizeof(*r->free_writes));
    r->timers = calloc((size_t)config->max_connections * RN_TIMER_KINDS, sizeof(*r->timers));
    r->events = calloc(config->max_events, sizeof(*r->events));
    r->native_events = calloc(config->max_events, sizeof(*r->native_events));
    if (!r->connections || !r->free_connections || !r->paused_connections || !r->buffers || !r->free_buffers || !r->writes || !r->free_writes ||
        !r->timers || !r->events || !r->native_events) { (void)rn_free(r); return -ENOMEM; }
    for (uint32_t i = 0; i < config->max_connections; ++i) {
        r->connections[i].fd = r->connections[i].pending_accept_fd = -1;
        r->free_connections[r->free_connection_count++] = i;
    }
    for (uint32_t i = 0; i < config->max_writes; ++i) r->free_writes[r->free_write_count++] = i;
    for (uint32_t i = 0; i < RN_WHEEL_SIZE; ++i) r->wheel[i] = RN_NONE;
    for (uint32_t i = 0; i < r->buffer_count; ++i) {
        uint32_t capacity = i < config->buffers_4k ? 4096u : i < config->buffers_4k + config->buffers_16k ? 16384u : 65536u;
        r->buffers[i].bytes = lean_alloc_sarray(1, 0, capacity);
        r->buffers[i].capacity = capacity; r->buffers[i].on_free = 1;
        r->free_buffers[r->free_buffer_count++] = i;
    }
    int pipe_fds[2];
    if (pipe(pipe_fds) < 0) { int error = -errno; (void)rn_free(r); return error; }
    r->wake_read = pipe_fds[0]; r->wake_write = pipe_fds[1];
    r->wake_owner = calloc(1, sizeof(*r->wake_owner));
    if (!r->wake_owner) { (void)rn_free(r); return -ENOMEM; }
    r->wake_owner->read_fd = r->wake_read; r->wake_owner->write_fd = r->wake_write;
    atomic_init(&r->wake_owner->references, 1); atomic_init(&r->wake_owner->closed, 0);
    int error = rn_nonblocking(r->wake_read);
    if (!error) error = rn_nonblocking(r->wake_write);
    if (error) { (void)rn_free(r); return error; }
#if defined(__linux__)
    r->queue_fd = epoll_create1(EPOLL_CLOEXEC);
    if (r->queue_fd >= 0) {
        struct epoll_event event; memset(&event, 0, sizeof(event)); event.events = EPOLLIN; event.data.u64 = 0;
        if (epoll_ctl(r->queue_fd, EPOLL_CTL_ADD, r->wake_read, &event) < 0) error = -errno;
    } else error = -errno;
#else
    r->queue_fd = kqueue();
    if (r->queue_fd >= 0) {
        int flags = fcntl(r->queue_fd, F_GETFD);
        if (flags < 0 || fcntl(r->queue_fd, F_SETFD, flags | FD_CLOEXEC) < 0) error = -errno;
        struct kevent event;
        EV_SET(&event, (uintptr_t)r->wake_read, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
        if (!error && kevent(r->queue_fd, &event, 1, NULL, 0, NULL) < 0) error = -errno;
    } else error = -errno;
#endif
    if (error) { (void)rn_free(r); return error; }
    *out = r; return 0;
}
static int rn_transport_access(rn_reactor *r, uint64_t token, uint64_t capability, int plain) {
    if (!r) return -EINVAL;
    rn_conn *c; int error = rn_conn_get(r, token, &c); if (error) return error;
    if (plain) return c->transport_mode ? -EACCES : 0;
    return c->state == 4 && c->transport_mode && capability && c->transport_cap == capability ? 0 : -EACCES;
}
int rn_file_table_init(rn_reactor *r, uint32_t capacity) {
    if (!r) return -EINVAL;
    if (r->has_polled) return -EBUSY;
    return rn_files_init(&r->files, capacity);
}
uint64_t rn_file_owner(const rn_reactor *r) { return r ? r->files.owner : 0; }
int rn_file_import(rn_reactor *r, rn_file_source *source, uint64_t *out) {
    if (!r) return -EINVAL;
    if (r->has_polled) return -EBUSY;
    return rn_files_import(&r->files, source, out);
}
int rn_file_release(rn_reactor *r, uint64_t token) {
    return r ? rn_files_release(&r->files, token) : -EINVAL;
}
int rn_file_pin(rn_reactor *r, uint64_t owner, uint64_t token,
                uint64_t offset, uint32_t length, rn_file_source **out) {
    if (!r) return -EINVAL;
    if (!owner || owner != r->files.owner) return -EACCES;
    return rn_files_pin(&r->files, token, offset, length, out);
}
int rn_queue_file(rn_reactor *r, uint64_t connection, uint64_t owner,
                  uint64_t file, uint64_t offset, uint32_t length,
                  uint64_t operation) {
    int error = rn_transport_access(r, connection, 0, 1);
    return error ? error : rn_queue_file_impl(r, connection, owner, file, offset, length, operation);
}
int rn_transport_state(rn_reactor *r, uint64_t token) {
    if (!r) return -EINVAL;
    rn_conn *c; int error = rn_conn_get(r, token, &c); if (error) return error;
    return c->transport_mode;
}
int rn_transport_claim(rn_reactor *r, uint64_t token, uint64_t *capability) {
    if (!r || !capability) return -EINVAL;
    rn_conn *c; int error = rn_conn_get(r, token, &c); if (error) return error;
    if (c->state != 4) return -EINVAL;
    if (c->transport_mode) return -EALREADY;
    if (c->head_write != RN_NONE || c->drain_close) return -EBUSY;
    c->transport_cap = token; c->transport_mode = 1; *capability = token; return 0;
}
int rn_transport_ready(rn_reactor *r, uint64_t token, uint64_t capability) {
    int error = rn_transport_access(r, token, capability, 0); if (error) return error;
    rn_conn *c = &r->connections[rn_index(token)];
    if (c->transport_mode != 1) return -EALREADY;
    c->transport_mode = 2; return 0;
}
int rn_transport_mode(rn_reactor *r, uint64_t token, uint64_t capability) {
    int error = rn_transport_access(r, token, capability, 0);
    return error ? error : rn_transport_state(r, token);
}
#include "reactor_transport_impl.h"

#endif
