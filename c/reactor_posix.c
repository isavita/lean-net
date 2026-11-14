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
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/epoll.h>
#else
#include <sys/event.h>
#include <sys/time.h>
#endif

#define RN_NONE UINT32_MAX
#define RN_WHEEL_SIZE 1024u
#define RN_READ_BUDGET 16u
#define RN_WRITE_BUDGET 16u
#define RN_ACCEPT_BUDGET 64u

typedef struct rn_conn {
    int fd;
    uint32_t generation;
    uint32_t head_write, tail_write;
    uint32_t next_closed;
    int close_error;
    uint8_t state; /* 0 free, 1 fresh, 2 bound, 3 listener, 4 connected, 5 closing */
    uint8_t interest;
    uint8_t paused;
    uint8_t eof;
    uint8_t drain_close;
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
} rn_write;
typedef struct rn_timer {
    uint64_t connection, deadline_ms, deadline_tick;
    uint32_t next, previous, bucket;
    uint8_t active;
} rn_timer;
struct rn_reactor {
    rn_config config;
    int queue_fd, wake_read, wake_write;
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
    uint32_t closed_head, closed_tail;
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
    uint32_t next = (old + 1u) & 0x7fffffffu;
    return next == 0 ? 1u : next;
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
    event.events = EPOLLRDHUP;
    if (mask & 1u) event.events |= EPOLLIN;
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
    if (!b->owner && b->writes == 0 && !b->on_free) {
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
int rn_arm_timer(rn_reactor *r, uint64_t token, uint32_t kind, uint64_t deadline) {
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
int rn_cancel_timer(rn_reactor *r, uint64_t token, uint32_t kind) {
    rn_conn *c; int error = rn_conn_get(r, token, &c); (void)c;
    if (error) return error;
    if (kind >= RN_TIMER_KINDS) return -EINVAL;
    rn_timer_remove(r, rn_index(token) * RN_TIMER_KINDS + kind); return 0;
}
static void rn_write_release(rn_reactor *r, uint32_t index) {
    rn_write *w = &r->writes[index];
    rn_buffer *b = &r->buffers[rn_index(w->buffer)];
    if (b->writes) --b->writes;
    rn_buffer_free_candidate(r, rn_index(w->buffer));
    w->active = 0; r->free_writes[r->free_write_count++] = index;
}
int rn_close_connection(rn_reactor *r, uint64_t token) {
    rn_conn *c; int error = rn_conn_get(r, token, &c);
    if (error) return error;
    uint32_t index = rn_index(token);
    for (uint32_t kind = 0; kind < RN_TIMER_KINDS; ++kind) rn_timer_remove(r, index * RN_TIMER_KINDS + kind);
    if (c->fd >= 0) {
        /* Last close removes registered filters even if explicit deletion failed. */
        int removed = rn_interest(r, index, 0);
        int closed = rn_close_fd(c->fd);
        error = closed ? closed : removed;
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
    if (r->free_connection_count == 0) return -EAGAIN;
    uint32_t index = r->free_connections[--r->free_connection_count];
    rn_conn *c = &r->connections[index];
    uint32_t generation = rn_generation(c->generation);
    memset(c, 0, sizeof(*c)); c->fd = -1; c->generation = generation; c->state = 1;
    c->head_write = c->tail_write = c->next_closed = RN_NONE;
    *out = rn_token(index, generation); return 0;
}
int rn_bind(rn_reactor *r, uint64_t token, const char *host, uint16_t port, int reuse_port) {
    rn_conn *c; int error = rn_conn_get(r, token, &c);
    if (error) return error;
    if (c->state != 1 || host == NULL || (reuse_port != 0 && reuse_port != 1)) return -EINVAL;
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
    if (error) { int closed = rn_close_connection(r, token); return closed ? closed : error; }
    *out = token; return 0;
}
int rn_queue_write(rn_reactor *r, uint64_t token, uint64_t buffer, uint32_t offset, uint32_t length, uint64_t operation) {
    rn_conn *c; rn_buffer *b;
    int error = rn_conn_get(r, token, &c); if (error) return error;
    error = rn_buffer_get(r, buffer, &b); if (error) return error;
    size_t size = lean_sarray_size(b->bytes);
    if (c->state != 4 || !b->owner || offset > size || length > size - offset) return -EINVAL;
    if (r->free_write_count == 0) return -EAGAIN;
    uint32_t index = r->free_writes[--r->free_write_count];
    r->writes[index] = (rn_write){token, operation, buffer, offset, length, 0, RN_NONE, 1};
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

int rn_close_after_writes(rn_reactor *r, uint64_t token) {
    rn_conn *c; int error = rn_conn_get(r, token, &c);
    if (error) return error;
    if (c->state != 4) return -EINVAL;
    if (c->head_write == RN_NONE) return rn_close_connection(r, token);
    c->drain_close = 1;
    return rn_interest(r, rn_index(token), 2);
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
static int rn_accept_ready(rn_reactor *r, uint32_t index) {
    rn_conn *listener = &r->connections[index];
    uint64_t listener_token = rn_token(index, listener->generation);
    for (uint32_t attempt = 0; attempt < RN_ACCEPT_BUDGET && r->event_count < r->config.max_events; ++attempt) {
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
        uint64_t token;
        int allocated = rn_socket_new(r, &token);
        if (allocated) { int closed = rn_close_fd(fd); return closed ? closed : allocated; }
        rn_conn *c = &r->connections[rn_index(token)]; c->fd = fd; c->state = 4;
        error = rn_interest(r, rn_index(token), 1);
        if (error) { int closed = rn_close_connection(r, token); return closed ? closed : error; }
        int emitted = rn_emit(r, RN_ACCEPTED, token, listener_token, 0, 0, 0, 0, 0);
        if (emitted) return emitted;
    }
    return 0;
}
static int rn_read_ready(rn_reactor *r, uint32_t index) {
    rn_conn *c = &r->connections[index]; uint64_t token = rn_token(index, c->generation);
    if (c->eof || c->drain_close) return 0;
    for (uint32_t attempt = 0; attempt < RN_READ_BUDGET && r->event_count < r->config.max_events; ++attempt) {
        uint64_t lease;
        int error = rn_acquire_buffer(r, 4096, &lease);
        if (error == -EAGAIN) { rn_pause(r, index); return rn_interest(r, index, (uint8_t)(c->interest & 2u)); }
        if (error) return error;
        rn_buffer *b = &r->buffers[rn_index(lease)];
        ssize_t n = recv(c->fd, lean_sarray_cptr(b->bytes), b->capacity, 0);
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
            if (e != EINTR) return rn_close_connection(r, token);
            return 0;
        }
        lean_sarray_set_size(b->bytes, (size_t)n);
        error = rn_emit(r, RN_READ, token, 0, lease, 0, (uint32_t)n, n, 0);
        if (error) { (void)rn_buffer_release(r, lease); return error; }
    }
    return 0;
}
static int rn_write_ready(rn_reactor *r, uint32_t index) {
    rn_conn *c = &r->connections[index]; uint64_t token = rn_token(index, c->generation);
    for (uint32_t attempt = 0; attempt < RN_WRITE_BUDGET && c->head_write != RN_NONE &&
         r->event_count < r->config.max_events; ++attempt) {
        uint32_t write_index = c->head_write; rn_write *w = &r->writes[write_index];
        rn_buffer *b = &r->buffers[rn_index(w->buffer)];
        uint32_t remaining = w->length - w->sent;
        ssize_t n;
        if (remaining == 0) n = 0;
        else {
#ifdef MSG_NOSIGNAL
            int flags = MSG_NOSIGNAL;
#else
            int flags = 0;
#endif
            n = send(c->fd, lean_sarray_cptr(b->bytes) + w->offset + w->sent, remaining, flags);
        }
        if (n < 0) {
            int e = errno;
            if (e == EAGAIN || e == EWOULDBLOCK) return 0;
            int error = rn_emit(r, RN_ERROR, token, w->operation, 0, 0, 0, -e, 0);
            if (error) return error;
            if (e != EINTR) return rn_close_connection(r, token);
            return 0;
        }
        if (remaining && n == 0) {
            int error = rn_emit(r, RN_ERROR, token, w->operation, 0, 0, 0, -EIO, 0);
            if (error) return error;
            return rn_close_connection(r, token);
        }
        w->sent += (uint32_t)n;
        if (w->sent == w->length) {
            int error = rn_emit(r, RN_WRITTEN, token, w->operation, 0, 0, w->length, w->length, 0);
            if (error) return error;
            c->head_write = w->next;
            if (c->head_write == RN_NONE) c->tail_write = RN_NONE;
            rn_write_release(r, write_index);
        }
    }
    if (c->head_write == RN_NONE) {
        if (c->drain_close) return rn_close_connection(r, token);
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
        if (lean_is_exclusive(r->buffers[r->free_buffers[pos]].bytes)) return 1;
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
        int enabled = c->state == 3 ? r->free_connection_count != 0 : available;
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
int rn_step(rn_reactor *r, int timeout_ms) {
    if (r == NULL || timeout_ms < -1) return -EINVAL;
    r->event_count = 0;
    int error = rn_closed_events(r); if (error) return error;
    rn_due_timers(r, rn_now_ms());
    error = rn_resume_paused(r); if (error) return error;
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
    if (ready < 0) return -errno;
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
            if (result < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return -errno;
            (void)rn_emit(r, RN_WAKE, 0, 0, 0, 0, 0, result < 0 && errno == EINTR ? -EINTR : 0, 0);
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
                error = rn_close_connection(r, token); if (error) return error;
                continue;
            }
        }
        if (c->state == 3 && readable) error = rn_accept_ready(r, index);
        else if (c->state == 4) {
            if (readable) error = rn_read_ready(r, index);
            if (!error && c->state == 4 && writable && r->event_count < r->config.max_events) error = rn_write_ready(r, index);
        }
        if (error) return error;
    }
    error = rn_closed_events(r); if (error) return error;
    rn_compact_canceled_events(r);
    return (int)r->event_count;
}
const rn_event *rn_event_at(const rn_reactor *r, uint32_t index) {
    return r != NULL && index < r->event_count ? &r->events[index] : NULL;
}
int rn_wake(rn_reactor *r) {
    if (r == NULL) return -EINVAL;
    int saved_errno = errno;
    unsigned char value = 1;
    ssize_t n = write(r->wake_write, &value, 1);
    int result = n == 1 || (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) ? 0 : n < 0 ? -errno : -EIO;
    errno = saved_errno; return result;
}
int rn_free(rn_reactor *r) {
    if (r == NULL) return -EINVAL;
    int first_error = 0;
    if (r->connections != NULL) {
        for (uint32_t i = 0; i < r->config.max_connections; ++i) {
            rn_conn *c = &r->connections[i];
            if (c->state && c->state != 5 && c->fd >= 0) {
                int error = rn_close_fd(c->fd); if (error && !first_error) first_error = error;
            }
        }
    }
    int fds[3] = {r->wake_read, r->wake_write, r->queue_fd};
    for (uint32_t i = 0; i < 3; ++i) if (fds[i] >= 0) { int error = rn_close_fd(fds[i]); if (error && !first_error) first_error = error; }
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
    for (uint32_t i = 0; i < config->max_connections; ++i) { r->connections[i].fd = -1; r->free_connections[r->free_connection_count++] = i; }
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
#endif
