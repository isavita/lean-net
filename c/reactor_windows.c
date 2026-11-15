/* Windows completion backend for the reactor API. No Lean callbacks run on an
 * IOCP thread; the owning Lean loop drains events through rn_step. All native
 * operation records and buffers are allocated before the listener starts. */
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#include "reactor.h"
#define LN_RL_NO_LEAN
#include "ratelimit.h"
#include "windows_error.h"
#include "reactor_file_internal.h"
#include <errno.h>
#include <limits.h>
#include <mswsock.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define RN_NONE UINT32_MAX
#define RN_WHEEL_SLOTS 1024u
#define RN_WAKE_KEY ((ULONG_PTR)1)
#define RN_MAX_ACCEPT_TARGETS 256u
#define RN_MAX_ACCEPT_QUEUE 1000000u
#define RN_WRITE_VECTORS 16u
#define RN_GENERATION_MAX ((uint32_t)INT32_MAX)

/* A configured channel has one acceptor producer and one worker consumer.
 * Only SOCKET values cross it; each loop retains private protocol/buffer state.
 * Both reactors are stopped and joined before their setup-time refs are freed.
 */
typedef struct rn_port_owner {
  HANDLE handle;
  atomic_uint references;
} rn_port_owner;
struct rn_waker {
  rn_port_owner *port_owner;
  atomic_uint references;
  atomic_int closed;
};
typedef struct rn_accept_channel {
  SOCKET *sockets;
  rn_port_owner *producer_port, *consumer_port;
  uint32_t capacity;
  atomic_uint head, tail, references;
  atomic_int notified, producer_waiting, producer_closed, consumer_closed;
} rn_accept_channel;
_Static_assert(ATOMIC_INT_LOCK_FREE == 2,
               "accept handoff needs lock-free atomics");

enum rn_socket_state {
  RN_UNUSED,
  RN_FRESH,
  RN_BOUND,
  RN_LISTENING,
  RN_ACCEPTING,
  RN_DISPATCH_PENDING,
  RN_CONNECTING,
  RN_CONNECTED,
  RN_CLOSING
};
enum rn_operation_kind { RN_OP_ACCEPT, RN_OP_READ, RN_OP_WRITE, RN_OP_FILE, RN_OP_CONNECT };
typedef struct rn_operation {
  OVERLAPPED overlapped; /* Must be first: completion pointer casts here. */
  uint32_t kind, connection, listener, buffer, write;
  uint32_t pending;
  WSABUF wsabuf;
  DWORD recv_flags;
  unsigned char addresses[2 * (sizeof(struct sockaddr_storage) + 16)];
} rn_operation;
typedef struct rn_connection {
  SOCKET socket;
  uint32_t generation, state, pending, write_head, write_tail;
  uint64_t transport_cap;
  uint8_t transport_mode;
  uint32_t dispatch_pending, dispatch_listener;
  LPFN_ACCEPTEX accept_ex;
  LPFN_CONNECTEX connect_ex;
  LPFN_TRANSMITFILE transmit_file;
  uint32_t paused_position;
  int paused;
  int read_paused, read_disabled, accept_paused, eof, draining;
  rn_operation read, accept, connect;
} rn_connection;
typedef struct rn_buffer {
  lean_object *bytes;
  uint32_t capacity, generation, io_refs;
  uint32_t class_id;
  int in_free;
  int leased;
} rn_buffer;
typedef struct rn_write {
  rn_operation op;
  uint32_t used, next, buffer, offset, length, sent;
  /* The submitted head owns stable descriptors until its one OVERLAPPED
   * completion. Every logical member separately pins its buffer. */
  uint32_t submitted, vector_count, vector_total;
  uint32_t vector_writes[RN_WRITE_VECTORS];
  WSABUF vectors[RN_WRITE_VECTORS];
  uint64_t operation;
  uint32_t file;
  uint64_t file_offset;
  uint8_t is_file;
} rn_write;
typedef struct rn_timer {
  uint64_t deadline;
  uint32_t next, previous, bucket;
  int armed;
} rn_timer;
struct rn_reactor {
  rn_config config;
  HANDLE port;
  rn_port_owner *port_owner;
  rn_waker *wake_owner;
  rn_connection *connections;
  rn_buffer *buffers;
  rn_write *writes;
  rn_file_table files;
  LPFN_TRANSMITFILE transmit_file;
  rn_timer *timers;
  uint32_t *buckets;
  uint32_t *free_connections, *free_writes, *free_buffers, *paused_connections;
  uint32_t free_connection_count, free_write_count, paused_count;
  uint32_t free_buffer_base[3], free_buffer_count[3];
  rn_event *events, *queued;
  uint32_t event_count, queue_capacity, queue_head, queue_count, buffer_count;
  uint32_t outstanding;
  uint64_t timer_tick;
  int destroying, queue_error, cleanup_error, wsa_started;
  int started, polled;
  rn_accept_channel **accept_targets;
  uint32_t accept_target_count, accept_target_next;
  rn_accept_channel *incoming_accepts;
  /* Descriptor/memory exhaustion pauses AcceptEx reposting for a short time. */
  uint64_t accept_backoff_until;
  ln_rl *accept_limiter;
  uint32_t accept_lane;
};
#include "reactor_file_impl.h"

static int rn_error(DWORD error) { return ln_windows_errno(error); }
static int rn_close_connection_impl(rn_reactor *, uint64_t);
static int rn_raw_peer(const struct sockaddr_storage *, uint8_t out[16]);

static uint32_t rn_channel_count(const rn_accept_channel *channel,
                                 uint32_t head, uint32_t tail) {
  return head >= tail ? head - tail : head + (2u * channel->capacity - tail);
}
static uint32_t rn_channel_next(const rn_accept_channel *channel,
                                uint32_t index) {
  return index + 1 == 2u * channel->capacity ? 0 : index + 1;
}
static int rn_channel_discard(rn_accept_channel *channel) {
  int error = 0;
  uint32_t tail = atomic_load(&channel->tail);
  uint32_t head = atomic_load(&channel->head);
  while (tail != head) {
    if (closesocket(channel->sockets[tail % channel->capacity]) ==
            SOCKET_ERROR &&
        !error)
      error = rn_error(WSAGetLastError());
    tail = rn_channel_next(channel, tail);
  }
  atomic_store(&channel->tail, tail);
  return -error;
}
static int rn_port_release(rn_port_owner *owner) {
  if (atomic_fetch_sub(&owner->references, 1) != 1)
    return 0;
  int error = CloseHandle(owner->handle) ? 0 : -rn_error(GetLastError());
  free(owner);
  return error;
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
  return PostQueuedCompletionStatus(w->port_owner->handle, 0, RN_WAKE_KEY, NULL)
      ? 0 : -rn_error(GetLastError());
}
int rn_waker_release(rn_waker *w) {
  if (!w) return -EINVAL;
  if (atomic_fetch_sub(&w->references, 1) != 1) return 0;
  int error = rn_port_release(w->port_owner); free(w); return error;
}
static int rn_channel_destroy(rn_accept_channel *channel) {
  int error = rn_channel_discard(channel);
  if (channel->producer_port) {
    int released = rn_port_release(channel->producer_port);
    if (released && !error)
      error = released;
  }
  if (channel->consumer_port) {
    int released = rn_port_release(channel->consumer_port);
    if (released && !error)
      error = released;
  }
  free(channel->sockets);
  free(channel);
  return error;
}
static int rn_channel_release(rn_accept_channel *channel) {
  return atomic_fetch_sub(&channel->references, 1) == 1
             ? rn_channel_destroy(channel)
             : 0;
}

int rn_set_accept_targets(rn_reactor *acceptor, rn_reactor *const *workers,
                          uint32_t count, uint32_t capacity) {
  if (!acceptor || !workers || !count || count > RN_MAX_ACCEPT_TARGETS ||
      !capacity || capacity > RN_MAX_ACCEPT_QUEUE)
    return -EINVAL;
  if (acceptor->started || acceptor->outstanding ||
      acceptor->incoming_accepts || acceptor->accept_targets ||
      acceptor->destroying)
    return -EBUSY;
  for (uint32_t i = 0; i < count; ++i) {
    rn_reactor *worker = workers[i];
    if (!worker || worker == acceptor)
      return -EINVAL;
    if (worker->started || worker->outstanding || worker->incoming_accepts ||
        worker->accept_targets || worker->destroying)
      return -EBUSY;
    for (uint32_t j = 0; j < i; ++j)
      if (workers[j] == worker)
        return -EINVAL;
  }
  rn_accept_channel **channels = calloc(count, sizeof(*channels));
  if (!channels)
    return -ENOMEM;
  int error = 0;
  for (uint32_t i = 0; i < count; ++i) {
    rn_accept_channel *channel = calloc(1, sizeof(*channel));
    if (!channel) {
      error = -ENOMEM;
      break;
    }
    channels[i] = channel;
    channel->capacity = capacity;
    atomic_init(&channel->head, 0);
    atomic_init(&channel->tail, 0);
    atomic_init(&channel->references, 2);
    atomic_init(&channel->notified, 0);
    atomic_init(&channel->producer_waiting, 0);
    atomic_init(&channel->producer_closed, 0);
    atomic_init(&channel->consumer_closed, 0);
    channel->sockets = malloc((size_t)capacity * sizeof(*channel->sockets));
    if (!channel->sockets) {
      error = -ENOMEM;
      break;
    }
    channel->producer_port = acceptor->port_owner;
    channel->consumer_port = workers[i]->port_owner;
    atomic_fetch_add(&channel->producer_port->references, 1);
    atomic_fetch_add(&channel->consumer_port->references, 1);
  }
  if (error) {
    for (uint32_t i = 0; i < count; ++i)
      if (channels[i]) {
        int cleanup = rn_channel_destroy(channels[i]);
        if (cleanup)
          error = cleanup;
      }
    free(channels);
    return error;
  }
  for (uint32_t i = 0; i < count; ++i)
    workers[i]->incoming_accepts = channels[i];
  acceptor->accept_targets = channels;
  acceptor->accept_target_count = count;
  return 0;
}

int rn_set_accept_limiter(rn_reactor *r, ln_rl *limiter, uint32_t lane) {
  if (!r || !limiter || lane >= limiter->workers || limiter->rule_count != 1 ||
      limiter->rules[0].kind != LN_RL_KEYED)
    return -EINVAL;
  if (r->started || r->polled || r->outstanding || r->accept_limiter ||
      r->free_connection_count != r->config.max_connections)
    return -EBUSY;
  r->accept_limiter = limiter;
  r->accept_lane = lane;
  return 0;
}

uint64_t rn_now_ms(void) { return (uint64_t)GetTickCount64(); }
static uint64_t rn_token(uint32_t index, uint32_t generation) {
  return ((uint64_t)generation << 32) | ((uint64_t)index + 1);
}
static uint32_t rn_index(uint64_t token) { return (uint32_t)token - 1; }
static rn_connection *rn_connection_get(rn_reactor *r, uint64_t token) {
  uint32_t i = rn_index(token);
  if (!token || i >= r->config.max_connections)
    return NULL;
  rn_connection *c = &r->connections[i];
  return c->state != RN_UNUSED && c->generation == (uint32_t)(token >> 32)
             ? c
             : NULL;
}
static rn_buffer *rn_buffer_get(rn_reactor *r, uint64_t token) {
  uint32_t i = rn_index(token);
  if (!token || i >= r->buffer_count)
    return NULL;
  rn_buffer *b = &r->buffers[i];
  return b->leased && b->generation == (uint32_t)(token >> 32) ? b : NULL;
}
static int rn_emit(rn_reactor *r, uint32_t kind, uint64_t connection,
                   uint64_t operation, uint64_t buffer, int64_t result,
                   uint32_t flags, uint32_t offset, uint32_t length) {
  if (r->destroying)
    return 0;
  if (r->queue_count == r->queue_capacity) {
    r->queue_error = ENOBUFS;
    return -ENOBUFS;
  }
  uint32_t position = (r->queue_head + r->queue_count) % r->queue_capacity;
  r->queued[position] = (rn_event){connection, operation, buffer, result,
                                   kind,       flags,     offset, length};
  ++r->queue_count;
  return 0;
}
static uint32_t rn_alloc_connection(rn_reactor *r) {
  while (r->free_connection_count) {
    uint32_t i = r->free_connections[--r->free_connection_count];
    rn_connection *c = &r->connections[i];
    if (c->state == RN_UNUSED && c->generation < RN_GENERATION_MAX) {
      uint32_t generation = c->generation + 1;
      memset(c, 0, sizeof(*c));
      c->generation = generation;
      c->socket = INVALID_SOCKET;
      c->state = RN_FRESH;
      c->write_head = c->write_tail = RN_NONE;
      c->dispatch_pending = RN_NONE;
      return i;
    }
  }
  return RN_NONE;
}
static void rn_pause(rn_reactor *r, uint32_t index) {
  rn_connection *connection = &r->connections[index];
  if (connection->paused)
    return;
  connection->paused = 1;
  connection->paused_position = r->paused_count;
  r->paused_connections[r->paused_count++] = index;
}
static void rn_unpause(rn_reactor *r, uint32_t index) {
  rn_connection *connection = &r->connections[index];
  if (!connection->paused)
    return;
  uint32_t last = r->paused_connections[--r->paused_count];
  r->paused_connections[connection->paused_position] = last;
  r->connections[last].paused_position = connection->paused_position;
  connection->paused = 0;
}
static void rn_recycle_buffer(rn_reactor *r, uint32_t index) {
  rn_buffer *buffer = &r->buffers[index];
  if (buffer->leased || buffer->io_refs || buffer->in_free ||
      buffer->generation >= RN_GENERATION_MAX)
    return;
  uint32_t class_id = buffer->class_id;
  r->free_buffers[r->free_buffer_base[class_id] +
                  r->free_buffer_count[class_id]++] = index;
  buffer->in_free = 1;
}
static void rn_timer_remove(rn_reactor *r, uint32_t index) {
  rn_timer *t = &r->timers[index];
  if (!t->armed)
    return;
  if (t->previous == RN_NONE)
    r->buckets[t->bucket] = t->next;
  else
    r->timers[t->previous].next = t->next;
  if (t->next != RN_NONE)
    r->timers[t->next].previous = t->previous;
  t->armed = 0;
}
static void rn_cancel_all_timers(rn_reactor *r, uint32_t connection) {
  for (uint32_t k = 0; k < RN_TIMER_KINDS; ++k)
    rn_timer_remove(r, connection * RN_TIMER_KINDS + k);
}
static void rn_finalize_connection(rn_reactor *r, uint32_t index) {
  rn_connection *c = &r->connections[index];
  if (c->state != RN_CLOSING || c->pending != 0 || c->write_head != RN_NONE)
    return;
  rn_cancel_all_timers(r, index);
  rn_emit(r, RN_CLOSED, rn_token(index, c->generation), 0, 0, 0, 0, 0, 0);
  c->state = RN_UNUSED;
  if (c->generation < RN_GENERATION_MAX)
    r->free_connections[r->free_connection_count++] = index;
}
static void rn_write_release(rn_reactor *r, uint32_t wi) {
  rn_write *w = &r->writes[wi];
  if (w->is_file) {
    rn_file_entry *entry = &r->files.entries[w->file];
    if (entry->writes) --entry->writes;
  }
  if (w->buffer != RN_NONE && r->buffers[w->buffer].io_refs != 0)
    --r->buffers[w->buffer].io_refs;
  if (w->buffer != RN_NONE)
    rn_recycle_buffer(r, w->buffer);
  w->used = 0; w->submitted = 0;
  r->free_writes[r->free_write_count++] = wi;
}
static void rn_close_native(rn_reactor *r, uint32_t index) {
  rn_connection *c = &r->connections[index];
  if (c->state == RN_UNUSED || c->state == RN_CLOSING)
    return;
  int was_listener = c->state == RN_LISTENING;
  rn_unpause(r, index);
  c->state = RN_CLOSING;
  rn_cancel_all_timers(r, index);
  if (c->socket != INVALID_SOCKET) {
    if (!CancelIoEx((HANDLE)c->socket, NULL)) {
      DWORD e = GetLastError();
      if (e != ERROR_NOT_FOUND) {
        if (r->destroying && !r->cleanup_error)
          r->cleanup_error = rn_error(e);
        rn_emit(r, RN_ERROR, rn_token(index, c->generation), 0, 0, -rn_error(e),
                0, 0, 0);
      }
    }
    SOCKET socket = c->socket;
    c->socket = INVALID_SOCKET;
    if (closesocket(socket) == SOCKET_ERROR) {
      int error = rn_error(WSAGetLastError());
      if (r->destroying && !r->cleanup_error)
        r->cleanup_error = error;
      rn_emit(r, RN_ERROR, rn_token(index, c->generation), 0, 0, -error,
              RN_CLOSE_ERROR, 0, 0);
    }
  }
  /* Retain the whole submitted prefix, not only its OVERLAPPED head: the
   * provider can still read any vector until cancellation has been drained. */
  uint32_t wi = c->write_head;
  uint32_t keep = RN_NONE, keep_tail = RN_NONE;
  while (wi != RN_NONE) {
    rn_write *w = &r->writes[wi];
    uint32_t next = w->next;
    if (w->submitted) {
      if (keep_tail == RN_NONE) keep = wi;
      else r->writes[keep_tail].next = wi;
      keep_tail = wi;
    } else {
      rn_emit(r, RN_ERROR, rn_token(index, c->generation), w->operation, 0,
              -ECANCELED, 0, 0, 0);
      rn_write_release(r, wi);
    }
    wi = next;
  }
  if (keep_tail != RN_NONE) r->writes[keep_tail].next = RN_NONE;
  c->write_head = keep; c->write_tail = keep_tail;
  /* Pending AcceptEx records use the listener handle, but the accepting
   * socket belongs to a separate slot; cancel that handle before freeing. */
  for (uint32_t i = 0; was_listener && i < r->config.max_connections; ++i) {
    rn_connection *a = &r->connections[i];
    if ((a->state == RN_ACCEPTING && a->accept.listener == index) ||
        (a->state == RN_DISPATCH_PENDING && a->dispatch_listener == index))
      rn_close_native(r, i);
  }
  rn_finalize_connection(r, index);
}
static uint32_t rn_take_buffer(rn_reactor *r, uint32_t minimum, int leased) {
  for (uint32_t k = minimum <= 4096    ? 0
                    : minimum <= 16384 ? 1
                                       : 2;
       k < 3; ++k) {
    uint32_t base = r->free_buffer_base[k];
    for (uint32_t n = r->free_buffer_count[k]; n > 0; --n) {
      uint32_t index = r->free_buffers[base + n - 1];
      rn_buffer *b = &r->buffers[index];
      if (b->generation >= RN_GENERATION_MAX) {
        r->free_buffers[base + n - 1] = r->free_buffers[base + --r->free_buffer_count[k]];
        b->in_free = 0;
        continue;
      }
      if (!lean_is_exclusive(b->bytes))
        continue;
      r->free_buffers[base + n - 1] =
          r->free_buffers[base + --r->free_buffer_count[k]];
      b->in_free = 0;
      ++b->generation;
      b->leased = leased;
      lean_sarray_set_size(b->bytes, 0);
      return index;
    }
  }
  return RN_NONE;
}
static void rn_post_read(rn_reactor *r, uint32_t index) {
  rn_connection *c = &r->connections[index];
  if (c->state != RN_CONNECTED || c->read.pending || c->eof || c->draining || c->read_disabled)
    return;
  uint32_t bi = rn_take_buffer(r, 4096, 0);
  if (bi == RN_NONE) {
    c->read_paused = 1;
    rn_pause(r, index);
    return;
  }
  c->read_paused = 0;
  rn_buffer *b = &r->buffers[bi];
  rn_operation *op = &c->read;
  memset(op, 0, sizeof(*op));
  op->kind = RN_OP_READ;
  op->connection = index;
  op->buffer = bi;
  op->wsabuf.buf = (CHAR *)lean_sarray_cptr(b->bytes);
  op->wsabuf.len = b->capacity;
  op->pending = 1;
  ++b->io_refs;
  ++c->pending;
  ++r->outstanding;
  int result = WSARecv(c->socket, &op->wsabuf, 1, NULL, &op->recv_flags,
                       &op->overlapped, NULL);
  if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
    int error = rn_error(WSAGetLastError());
    op->pending = 0;
    --b->io_refs;
    rn_recycle_buffer(r, bi);
    --c->pending;
    --r->outstanding;
    rn_emit(r, RN_ERROR, rn_token(index, c->generation), 0, 0, -error, 0, 0, 0);
    rn_close_native(r, index);
  }
}
static void rn_post_write(rn_reactor *r, uint32_t index) {
  rn_connection *c = &r->connections[index];
  if (c->state != RN_CONNECTED || c->write_head == RN_NONE)
    return;
  rn_write *w = &r->writes[c->write_head];
  rn_operation *op = &w->op;
  if (op->pending)
    return;
  rn_pause(r, index);
  uint32_t limit = r->queue_count >= r->config.max_events ? 0 : r->config.max_events - r->queue_count;
  if (limit > RN_WRITE_VECTORS) limit = RN_WRITE_VECTORS;
  if (!limit) return;
  if (w->is_file) {
    if (w->sent == w->length) {
      rn_emit(r, RN_WRITTEN, rn_token(index, c->generation), w->operation, 0, w->length, 0, 0, w->length);
      uint32_t done = c->write_head; c->write_head = w->next;
      if (c->write_head == RN_NONE) c->write_tail = RN_NONE;
      rn_write_release(r, done);
      if (c->draining && c->write_head == RN_NONE) rn_close_native(r, index);
      return;
    }
    uint32_t length = w->length - w->sent;
    if (length > 65536u) length = 65536u;
    memset(&op->overlapped, 0, sizeof(op->overlapped));
    uint64_t offset = w->file_offset + w->sent;
    op->overlapped.Offset = (DWORD)offset;
    op->overlapped.OffsetHigh = (DWORD)(offset >> 32);
    op->kind = RN_OP_FILE; op->connection = index; op->write = c->write_head;
    op->pending = w->submitted = 1; w->vector_total = length;
    ++c->pending; ++r->outstanding;
    BOOL submitted = c->transmit_file(c->socket, (HANDLE)r->files.entries[w->file].handle,
                                     length, 0, &op->overlapped, NULL, 0);
    if (!submitted) {
      int native_error = WSAGetLastError();
      if (native_error != WSA_IO_PENDING && native_error != ERROR_IO_PENDING) {
        op->pending = w->submitted = 0; --c->pending; --r->outstanding;
        rn_emit(r, RN_ERROR, rn_token(index, c->generation), w->operation, 0,
                -rn_error((DWORD)native_error), 0, 0, 0);
        uint32_t failed = c->write_head; c->write_head = w->next;
        if (c->write_head == RN_NONE) c->write_tail = RN_NONE;
        rn_write_release(r, failed);
        rn_close_native(r, index);
      }
    }
    return;
  }
  w->vector_count = w->vector_total = 0;
  uint32_t wi = c->write_head;
  while (wi != RN_NONE && w->vector_count < limit) {
    rn_write *part = &r->writes[wi];
    if (part->is_file) break;
    uint32_t vector = w->vector_count++;
    w->vector_writes[vector] = wi;
    w->vectors[vector].buf = (CHAR *)lean_sarray_cptr(r->buffers[part->buffer].bytes) + part->offset + part->sent;
    w->vectors[vector].len = part->length - part->sent;
    w->vector_total += w->vectors[vector].len;
    part->submitted = 1;
    wi = part->next;
  }
  if (w->vector_total == 0) {
    uint32_t count = w->vector_count;
    for (uint32_t n = 0; n < count; ++n) {
      uint32_t zero = c->write_head; rn_write *part = &r->writes[zero];
      rn_emit(r, RN_WRITTEN, rn_token(index, c->generation), part->operation, 0, 0, 0, 0, 0);
      c->write_head = part->next;
      rn_write_release(r, zero);
    }
    if (c->write_head == RN_NONE) {
      c->write_tail = RN_NONE;
      if (c->draining) rn_close_native(r, index);
    }
    return;
  }
  memset(&op->overlapped, 0, sizeof(op->overlapped));
  op->kind = RN_OP_WRITE;
  op->connection = index;
  op->write = c->write_head;
  op->pending = 1;
  ++c->pending;
  ++r->outstanding;
  int result =
      WSASend(c->socket, w->vectors, w->vector_count, NULL, 0, &op->overlapped, NULL);
  if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
    int error = rn_error(WSAGetLastError());
    op->pending = 0;
    --c->pending;
    --r->outstanding;
    for (uint32_t n = 0; n < w->vector_count; ++n)
      r->writes[w->vector_writes[n]].submitted = 0;
    rn_emit(r, RN_ERROR, rn_token(index, c->generation), w->operation, 0,
            -error, 0, 0, 0);
    c->write_head = w->next;
    if (c->write_head == RN_NONE)
      c->write_tail = RN_NONE;
    rn_write_release(r, op->write);
    rn_close_native(r, index);
  }
}
static void rn_release_transferred_slot(rn_reactor *r, uint32_t index) {
  rn_connection *connection = &r->connections[index];
  connection->socket = INVALID_SOCKET;
  connection->state = RN_UNUSED;
  if (connection->generation < RN_GENERATION_MAX)
    r->free_connections[r->free_connection_count++] = index;
}
/* Successful publication transfers socket ownership even if the wake fails.
 * The worker's queue/free path then remains responsible for closing it. */
static int rn_dispatch_socket(rn_reactor *r, uint32_t index) {
  rn_connection *connection = &r->connections[index];
  uint32_t alive = 0;
  for (uint32_t n = 0; n < r->accept_target_count; ++n) {
    uint32_t target = (r->accept_target_next + n) % r->accept_target_count;
    rn_accept_channel *channel = r->accept_targets[target];
    if (atomic_load(&channel->consumer_closed))
      continue;
    ++alive;
    uint32_t head = atomic_load(&channel->head);
    uint32_t tail = atomic_load(&channel->tail);
    if (rn_channel_count(channel, head, tail) == channel->capacity) {
      /* Publish the request before rechecking capacity. A concurrent pop will
       * either wake us or be visible to the second sequentially-consistent
       * load. */
      atomic_store(&channel->producer_waiting, 1);
      tail = atomic_load(&channel->tail);
      if (rn_channel_count(channel, head, tail) == channel->capacity)
        continue;
      atomic_store(&channel->producer_waiting, 0);
    }
    channel->sockets[head % channel->capacity] = connection->socket;
    atomic_store(&channel->head, rn_channel_next(channel, head));
    rn_release_transferred_slot(r, index);
    r->accept_target_next = (target + 1) % r->accept_target_count;
    if (!atomic_exchange(&channel->notified, 1) &&
        !PostQueuedCompletionStatus(channel->consumer_port->handle, 0,
                                    RN_WAKE_KEY, NULL))
      rn_emit(r, RN_ERROR, 0, 0, 0, -rn_error(GetLastError()), RN_SETUP_ERROR,
              0, 0);
    return 1;
  }
  return alive ? 0 : -EPIPE;
}
static int rn_adopt_sockets(rn_reactor *r) {
  rn_accept_channel *channel = r->incoming_accepts;
  if (!channel)
    return 0;
  atomic_store(&channel->notified, 0);
  while (r->free_connection_count && r->queue_count < r->config.max_events) {
    uint32_t tail = atomic_load(&channel->tail);
    if (tail == atomic_load(&channel->head))
      break;
    uint32_t index = rn_alloc_connection(r);
    if (index == RN_NONE)
      break;
    rn_connection *connection = &r->connections[index];
    connection->socket = channel->sockets[tail % channel->capacity];
    atomic_store(&channel->tail, rn_channel_next(channel, tail));
    if (atomic_exchange(&channel->producer_waiting, 0) &&
        !atomic_load(&channel->producer_closed) &&
        !PostQueuedCompletionStatus(channel->producer_port->handle, 0,
                                    RN_WAKE_KEY, NULL))
      return -rn_error(GetLastError());
    uint64_t token = rn_token(index, connection->generation);
    if (!CreateIoCompletionPort((HANDLE)connection->socket, r->port, 0, 0)) {
      int error = rn_error(GetLastError());
      rn_emit(r, RN_ERROR, token, 0, 0, -error, RN_SETUP_ERROR, 0, 0);
      rn_close_native(r, index);
      continue;
    }
    connection->state = RN_CONNECTED;
    rn_emit(r, RN_ACCEPTED, token, 0, 0, 0, 0, 0, 0);
    rn_post_read(r, index);
    if (r->queue_count >= r->config.max_events)
      break;
  }
  return 0;
}
static void rn_post_accept(rn_reactor *r, uint32_t listener) {
  rn_connection *l = &r->connections[listener];
  if (l->state != RN_LISTENING || l->pending != 0 || r->destroying)
    return;
  if (l->dispatch_pending != RN_NONE) {
    int dispatched = rn_dispatch_socket(r, l->dispatch_pending);
    if (dispatched < 0) {
      rn_emit(r, RN_ERROR, rn_token(listener, l->generation), 0, 0, dispatched,
              RN_SETUP_ERROR, 0, 0);
      rn_close_native(r, listener);
      return;
    }
    if (!dispatched) {
      rn_pause(r, listener);
      return;
    }
    l->dispatch_pending = RN_NONE;
  }
  uint32_t index = rn_alloc_connection(r);
  if (index == RN_NONE) {
    l->accept_paused = 1;
    rn_pause(r, listener);
    return;
  }
  l->accept_paused = 0;
  rn_unpause(r, listener);
  rn_connection *c = &r->connections[index];
  struct sockaddr_storage address;
  int address_len = sizeof(address);
  if (getsockname(l->socket, (struct sockaddr *)&address, &address_len) ==
      SOCKET_ERROR) {
    rn_emit(r, RN_ERROR, rn_token(listener, l->generation), 0, 0,
            -rn_error(WSAGetLastError()), RN_ACCEPT_ERROR, 0, 0);
    c->state = RN_UNUSED;
    if (c->generation < RN_GENERATION_MAX)
      r->free_connections[r->free_connection_count++] = index;
    rn_pause(r, listener);
    return;
  }
  c->socket = WSASocketW(address.ss_family, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                         WSA_FLAG_OVERLAPPED);
  if (c->socket == INVALID_SOCKET) {
    int socket_error = rn_error(WSAGetLastError());
    if (socket_error == EMFILE || socket_error == ENFILE || socket_error == ENOBUFS ||
        socket_error == ENOMEM)
      r->accept_backoff_until = rn_now_ms() + 100;
    rn_emit(r, RN_ERROR, rn_token(listener, l->generation), 0, 0,
            -socket_error, RN_ACCEPT_ERROR, 0, 0);
    c->state = RN_UNUSED;
    if (c->generation < RN_GENERATION_MAX)
      r->free_connections[r->free_connection_count++] = index;
    rn_pause(r, listener);
    return;
  }
  c->state = RN_ACCEPTING;
  rn_operation *op = &c->accept;
  memset(op, 0, sizeof(*op));
  op->kind = RN_OP_ACCEPT;
  op->connection = index;
  op->listener = listener;
  op->pending = 1;
  ++c->pending;
  ++l->pending;
  ++r->outstanding;
  DWORD received = 0;
  BOOL result = l->accept_ex(l->socket, c->socket, op->addresses, 0,
                             sizeof(struct sockaddr_storage) + 16,
                             sizeof(struct sockaddr_storage) + 16, &received,
                             &op->overlapped);
  if (!result && WSAGetLastError() != ERROR_IO_PENDING) {
    int error = rn_error(WSAGetLastError());
    if (error == EMFILE || error == ENFILE || error == ENOBUFS || error == ENOMEM)
      r->accept_backoff_until = rn_now_ms() + 100;
    op->pending = 0;
    --c->pending;
    --l->pending;
    --r->outstanding;
    rn_emit(r, RN_ERROR, rn_token(listener, l->generation), 0, 0, -error,
            RN_ACCEPT_ERROR, 0, 0);
    rn_close_native(r, index);
    rn_pause(r, listener);
  }
}
static void rn_resume(rn_reactor *r) {
  uint32_t position = 0;
  while (position < r->paused_count) {
    uint32_t i = r->paused_connections[position];
    rn_connection *c = &r->connections[i];
    if (c->state == RN_LISTENING && c->pending == 0) {
      if (rn_now_ms() >= r->accept_backoff_until)
        rn_post_accept(r, i);
    }
    else if (c->state == RN_CONNECTED) {
      if (c->write_head != RN_NONE && !r->writes[c->write_head].op.pending)
        rn_post_write(r, i);
      if (c->state == RN_CONNECTED && c->read_paused && !c->read_disabled && !c->eof && !c->draining)
        rn_post_read(r, i);
      if (c->state == RN_CONNECTED) {
        int needs_read = c->read_paused && !c->read_disabled && !c->eof && !c->draining;
        int needs_write = c->write_head != RN_NONE && !r->writes[c->write_head].op.pending;
        if (needs_read || needs_write) rn_pause(r, i);
        else rn_unpause(r, i);
      }
    } else
      rn_unpause(r, i);
    if (c->paused)
      ++position;
  }
}
static void rn_completed(rn_reactor *r, rn_operation *op, DWORD bytes,
                         int error) {
  if (!op->pending || op->connection >= r->config.max_connections) {
    r->queue_error = EIO;
    return;
  }
  uint32_t index = op->connection;
  rn_connection *c = &r->connections[index];
  op->pending = 0;
  --c->pending;
  --r->outstanding;
  uint64_t token = rn_token(index, c->generation);
  if (op->kind == RN_OP_ACCEPT) {
    rn_connection *l = &r->connections[op->listener];
    --l->pending;
    if (!error && c->state != RN_CLOSING && l->state == RN_LISTENING) {
      SOCKET listener_socket = l->socket;
      int one = 1;
      int option_failure = 0;
      int limited = 0;
      if (setsockopt(c->socket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
                     (const char *)&listener_socket,
                     sizeof(listener_socket)) == SOCKET_ERROR ||
          setsockopt(c->socket, IPPROTO_TCP, TCP_NODELAY, (const char *)&one,
                     sizeof(one)) == SOCKET_ERROR) {
        error = rn_error(WSAGetLastError());
        option_failure = 1;
      }
      if (!error && r->accept_limiter) {
        struct sockaddr_storage peer;
        int peer_length = sizeof(peer);
        uint8_t key[16];
        int length = getpeername(c->socket, (struct sockaddr *)&peer,
                                 &peer_length) == SOCKET_ERROR
                         ? -rn_error(WSAGetLastError()) : rn_raw_peer(&peer, key);
        uint64_t now = rn_now_ms();
        limited = length < 0 || !now || ln_rl_acquire(r->accept_limiter,
                  r->accept_lane, 0, 0, key,
                  (size_t)(length < 0 ? 0 : length), now) != 0;
      }
      if (!error && !limited && !r->accept_target_count &&
                 CreateIoCompletionPort((HANDLE)c->socket, r->port, 0, 0) ==
                     NULL)
        error = rn_error(GetLastError());
      if (limited) {
        rn_close_native(r, index);
      } else if (error) {
        uint32_t flags = RN_SETUP_ERROR;
        int pending = 0, pending_size = sizeof(pending);
        if (option_failure &&
            getsockopt(c->socket, SOL_SOCKET, SO_ERROR, (char *)&pending,
                       &pending_size) == 0 &&
            (pending == WSAECONNRESET || pending == WSAECONNABORTED ||
             pending == WSAENOTCONN || pending == WSAETIMEDOUT ||
             pending == WSAENETDOWN || pending == WSAENETUNREACH ||
             pending == WSAEHOSTUNREACH || pending == WSAECONNREFUSED) &&
            (error == EINVAL || error == rn_error((DWORD)pending))) {
          error = rn_error((DWORD)pending);
          flags = RN_ACCEPT_ERROR;
        }
        rn_emit(r, RN_ERROR, rn_token(op->listener, l->generation), 0, 0,
                -error, flags, 0, 0);
        rn_close_native(r, index);
      } else if (r->accept_target_count) {
        c->state = RN_DISPATCH_PENDING;
        c->dispatch_listener = op->listener;
        int dispatched = rn_dispatch_socket(r, index);
        if (dispatched < 0) {
          rn_emit(r, RN_ERROR, rn_token(op->listener, l->generation), 0, 0,
                  dispatched, RN_SETUP_ERROR, 0, 0);
          rn_close_native(r, op->listener);
        } else if (!dispatched) {
          l->dispatch_pending = index;
          rn_pause(r, op->listener);
        }
      } else {
        c->state = RN_CONNECTED;
        rn_emit(r, RN_ACCEPTED, token, 0, 0, 0, 0, 0, 0);
        rn_post_read(r, index);
      }
    } else {
      if (error && c->state != RN_CLOSING && l->state == RN_LISTENING)
        rn_emit(r, RN_ERROR, rn_token(op->listener, l->generation), 0, 0,
                -error, RN_ACCEPT_ERROR, 0, 0);
      rn_close_native(r, index);
    }
    rn_finalize_connection(r, op->listener);
    rn_post_accept(r, op->listener);
  } else if (op->kind == RN_OP_CONNECT) {
    if (c->state == RN_CLOSING) {
      rn_finalize_connection(r, index);
      return;
    }
    if (!error) {
      int pending = 0, pending_size = sizeof(pending);
      if (getsockopt(c->socket, SOL_SOCKET, SO_ERROR, (char *)&pending,
                     &pending_size) == SOCKET_ERROR)
        error = rn_error(WSAGetLastError());
      else if (pending_size != sizeof(pending)) error = EIO;
      else if (pending) error = rn_error((DWORD)pending);
    }
    if (!error && setsockopt(c->socket, SOL_SOCKET,
                             SO_UPDATE_CONNECT_CONTEXT, NULL, 0) == SOCKET_ERROR) {
      error = rn_error(WSAGetLastError());
      rn_emit(r, RN_ERROR, token, 0, 0, -error, RN_SETUP_ERROR, 0, 0);
      rn_close_native(r, index);
    } else if (error) {
      rn_emit(r, RN_ERROR, token, 0, 0, -error, 0, 0, 0);
      rn_close_native(r, index);
    } else {
      c->state = RN_CONNECTED;
      rn_emit(r, RN_CONNECT_COMPLETE, token, 0, 0, 0, 0, 0, 0);
      rn_post_read(r, index);
    }
  } else if (op->kind == RN_OP_READ) {
    rn_buffer *b = &r->buffers[op->buffer];
    --b->io_refs;
    if (c->state == RN_CLOSING) {
      rn_recycle_buffer(r, op->buffer);
      rn_finalize_connection(r, index);
      return;
    }
    if (c->draining) {
      rn_recycle_buffer(r, op->buffer);
      if (c->write_head == RN_NONE)
        rn_close_native(r, index);
      return;
    }
    if (error) {
      rn_recycle_buffer(r, op->buffer);
      rn_emit(r, RN_ERROR, token, 0, 0, -error, 0, 0, 0);
      rn_close_native(r, index);
    } else if (bytes == 0) {
      rn_recycle_buffer(r, op->buffer);
      c->eof = 1;
      rn_emit(r, RN_EOF, token, 0, 0, 0, 0, 0, 0);
    } else if (bytes > b->capacity) {
      rn_recycle_buffer(r, op->buffer);
      rn_emit(r, RN_ERROR, token, 0, 0, -EIO, 0, 0, 0);
      rn_close_native(r, index);
    } else {
      lean_sarray_set_size(b->bytes, bytes);
      b->leased = 1;
      rn_emit(r, RN_READ, token, 0, rn_token(op->buffer, b->generation), bytes,
              0, 0, bytes);
      /* Let the owning dispatcher apply backpressure before another receive.
       * Reposting here can fill an entire immutable batch from one peer before
       * set_read_enabled(false) gets a chance to run. Resume on the next step. */
      c->read_paused = 1;
      rn_pause(r, index);
    }
  } else if (op->kind == RN_OP_FILE) {
    rn_write *w = &r->writes[op->write]; w->submitted = 0;
    if (error || c->state == RN_CLOSING || !bytes || bytes > w->vector_total) {
      int result = error ? error : c->state == RN_CLOSING ? ECANCELED : EIO;
      rn_emit(r, RN_ERROR, token, w->operation, 0, -result, 0, 0, 0);
      c->write_head = w->next;
      if (c->write_head == RN_NONE) c->write_tail = RN_NONE;
      rn_write_release(r, op->write);
      if (c->state != RN_CLOSING) rn_close_native(r, index);
    } else {
      w->sent += bytes;
      if (w->sent == w->length) {
        rn_emit(r, RN_WRITTEN, token, w->operation, 0, w->length, 0, 0, w->length);
        c->write_head = w->next;
        if (c->write_head == RN_NONE) c->write_tail = RN_NONE;
        rn_write_release(r, op->write);
      }
      if (c->draining && c->write_head == RN_NONE) rn_close_native(r, index);
      else rn_pause(r, index);
    }
  } else if (op->kind == RN_OP_WRITE) {
    rn_write *w = &r->writes[op->write];
    uint32_t batch[RN_WRITE_VECTORS], count = w->vector_count, total = w->vector_total;
    memcpy(batch, w->vector_writes, count * sizeof(*batch));
    for (uint32_t n = 0; n < count; ++n) r->writes[batch[n]].submitted = 0;
    if (error || c->state == RN_CLOSING || bytes == 0 ||
        bytes > total) {
      int result = error ? error : c->state == RN_CLOSING ? ECANCELED : EIO;
      for (uint32_t n = 0; n < count; ++n) {
        rn_write *part = &r->writes[batch[n]];
        rn_emit(r, RN_ERROR, token, part->operation, 0, -result, 0, 0, 0);
        c->write_head = part->next;
        rn_write_release(r, batch[n]);
      }
      if (c->write_head == RN_NONE)
        c->write_tail = RN_NONE;
      if (c->state != RN_CLOSING)
        rn_close_native(r, index);
    } else {
      uint32_t remaining = bytes;
      for (uint32_t n = 0; n < count; ++n) {
        rn_write *part = &r->writes[batch[n]];
        uint32_t length = part->length - part->sent;
        if (remaining < length) { part->sent += remaining; break; }
        remaining -= length;
        rn_emit(r, RN_WRITTEN, token, part->operation, 0, part->length, 0, 0,
                part->length);
        c->write_head = part->next;
        rn_write_release(r, batch[n]);
      }
      if (c->write_head == RN_NONE)
        c->write_tail = RN_NONE;
      if (c->draining && c->write_head == RN_NONE)
        rn_close_native(r, index);
      else
        rn_post_write(r, index);
    }
  }
  rn_finalize_connection(r, index);
}
static void rn_expire(rn_reactor *r, uint64_t now) {
  uint64_t tick = now / r->config.timer_tick_ms;
  uint64_t elapsed = tick - r->timer_tick;
  uint64_t first =
      elapsed >= RN_WHEEL_SLOTS ? tick - RN_WHEEL_SLOTS + 1 : r->timer_tick;
  for (uint64_t t = first; t <= tick; ++t) {
    uint32_t bucket = (uint32_t)(t % RN_WHEEL_SLOTS);
    uint32_t i = r->buckets[bucket];
    while (i != RN_NONE) {
      rn_timer *timer = &r->timers[i];
      uint32_t next = timer->next;
      if (timer->deadline <= now) {
        uint32_t ci = i / RN_TIMER_KINDS, kind = i % RN_TIMER_KINDS;
        rn_connection *c = &r->connections[ci];
        uint64_t deadline = timer->deadline;
        rn_timer_remove(r, i);
        if (c->state != RN_UNUSED && c->state != RN_CLOSING)
          rn_emit(r, RN_TIMER, rn_token(ci, c->generation), kind, 0,
                  (int64_t)deadline,
                  c->state == RN_CONNECTING ? RN_CONNECTING_TIMER : 0, 0, 0);
      }
      i = next;
    }
  }
  r->timer_tick = tick;
}
int rn_new(const rn_config *config, rn_reactor **out) {
  if (out)
    *out = NULL;
  if (!config || !out || !config->max_connections || !config->max_events ||
      !config->max_writes || !config->timer_tick_ms ||
      config->max_events > INT_MAX)
    return -EINVAL;
  uint64_t count =
      (uint64_t)config->buffers_4k + config->buffers_16k + config->buffers_64k;
  uint64_t queue = (uint64_t)config->max_connections * (RN_TIMER_KINDS + 3) +
                   config->max_writes + config->max_events + 16;
  if (!count || count > UINT32_MAX || queue > UINT32_MAX ||
      config->max_connections > UINT32_MAX / RN_TIMER_KINDS)
    return -EINVAL;
  rn_reactor *r = calloc(1, sizeof(*r));
  if (!r)
    return -ENOMEM;
  r->config = *config;
  r->buffer_count = (uint32_t)count;
  r->queue_capacity = (uint32_t)queue;
  WSADATA wsa;
  int startup = WSAStartup(MAKEWORD(2, 2), &wsa);
  if (startup) {
    free(r);
    return -rn_error(startup);
  }
  r->wsa_started = 1;
  r->port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
  if (!r->port) {
    int error = rn_error(GetLastError());
    int cleanup = rn_free(r);
    return cleanup ? cleanup : -error;
  }
  /* IOCP handles must not be duplicated with DuplicateHandle. Channels retain
   * this original handle through a shared owner that outlives either reactor.
   */
  r->port_owner = calloc(1, sizeof(*r->port_owner));
  if (!r->port_owner) {
    int cleanup = rn_free(r);
    return cleanup ? cleanup : -ENOMEM;
  }
  r->port_owner->handle = r->port;
  atomic_init(&r->port_owner->references, 1);
  r->wake_owner = calloc(1, sizeof(*r->wake_owner));
  if (!r->wake_owner) { int cleanup = rn_free(r); return cleanup ? cleanup : -ENOMEM; }
  r->wake_owner->port_owner = r->port_owner;
  atomic_fetch_add(&r->port_owner->references, 1);
  atomic_init(&r->wake_owner->references, 1); atomic_init(&r->wake_owner->closed, 0);
  r->connections = calloc(config->max_connections, sizeof(*r->connections));
  r->buffers = calloc(r->buffer_count, sizeof(*r->buffers));
  r->writes = calloc(config->max_writes, sizeof(*r->writes));
  r->timers = calloc((size_t)config->max_connections * RN_TIMER_KINDS,
                     sizeof(*r->timers));
  r->buckets = malloc(RN_WHEEL_SLOTS * sizeof(*r->buckets));
  r->events = calloc(config->max_events, sizeof(*r->events));
  r->queued = calloc(r->queue_capacity, sizeof(*r->queued));
  r->free_connections =
      malloc((size_t)config->max_connections * sizeof(uint32_t));
  r->free_writes = malloc((size_t)config->max_writes * sizeof(uint32_t));
  r->free_buffers = malloc((size_t)r->buffer_count * sizeof(uint32_t));
  r->paused_connections =
      malloc((size_t)config->max_connections * sizeof(uint32_t));
  if (!r->connections || !r->buffers || !r->writes || !r->timers ||
      !r->buckets || !r->events || !r->queued || !r->free_connections ||
      !r->free_writes || !r->free_buffers || !r->paused_connections) {
    int cleanup = rn_free(r);
    return cleanup ? cleanup : -ENOMEM;
  }
  for (uint32_t i = 0; i < config->max_connections; ++i) {
    r->connections[i].socket = INVALID_SOCKET;
    r->free_connections[i] = config->max_connections - i - 1;
  }
  r->free_connection_count = config->max_connections;
  for (uint32_t i = 0; i < config->max_writes; ++i)
    r->free_writes[i] = config->max_writes - i - 1;
  r->free_write_count = config->max_writes;
  for (uint32_t i = 0; i < RN_WHEEL_SLOTS; ++i)
    r->buckets[i] = RN_NONE;
  uint32_t i = 0;
  uint32_t amounts[3] = {config->buffers_4k, config->buffers_16k,
                         config->buffers_64k};
  uint32_t sizes[3] = {4096, 16384, 65536};
  for (uint32_t k = 0; k < 3; ++k) {
    r->free_buffer_base[k] = i;
    r->free_buffer_count[k] = amounts[k];
    for (uint32_t n = 0; n < amounts[k]; ++n, ++i) {
      r->buffers[i].bytes = lean_alloc_sarray(1, 0, sizes[k]);
      r->buffers[i].capacity = sizes[k];
      r->buffers[i].class_id = k;
      r->buffers[i].in_free = 1;
      r->free_buffers[i] = i;
    }
  }
  r->timer_tick = rn_now_ms() / config->timer_tick_ms;
  *out = r;
  return 0;
}
int rn_socket_new(rn_reactor *r, uint64_t *out) {
  if (!r || !out)
    return -EINVAL;
  uint32_t i = rn_alloc_connection(r);
  if (i == RN_NONE)
    return -ENOBUFS;
  *out = rn_token(i, r->connections[i].generation);
  return 0;
}
int rn_connect(rn_reactor *r, uint64_t token, const uint8_t *address,
               uint32_t address_length, uint16_t port) {
  if (!r || !address || (address_length != 4 && address_length != 16) || !port)
    return -EINVAL;
  rn_connection *c = rn_connection_get(r, token);
  if (!c || c->state != RN_FRESH) return -EINVAL;
  struct sockaddr_storage remote, local;
  memset(&remote, 0, sizeof(remote)); memset(&local, 0, sizeof(local));
  int length, family;
  if (address_length == 4) {
    struct sockaddr_in *to = (struct sockaddr_in *)&remote;
    struct sockaddr_in *from = (struct sockaddr_in *)&local;
    family = AF_INET; length = (int)sizeof(*to);
    to->sin_family = from->sin_family = AF_INET;
    to->sin_port = htons(port);
    memcpy(&to->sin_addr, address, 4);
  } else {
    struct sockaddr_in6 *to = (struct sockaddr_in6 *)&remote;
    struct sockaddr_in6 *from = (struct sockaddr_in6 *)&local;
    family = AF_INET6; length = (int)sizeof(*to);
    to->sin6_family = from->sin6_family = AF_INET6;
    to->sin6_port = htons(port);
    memcpy(&to->sin6_addr, address, 16);
  }
  SOCKET socket = WSASocketW(family, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                             WSA_FLAG_OVERLAPPED);
  if (socket == INVALID_SOCKET) return -rn_error(WSAGetLastError());
  int error = 0, one = 1;
  if (bind(socket, (struct sockaddr *)&local, length) == SOCKET_ERROR ||
      setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, (const char *)&one,
                 sizeof(one)) == SOCKET_ERROR)
    error = rn_error(WSAGetLastError());
  GUID guid = WSAID_CONNECTEX; DWORD written = 0;
  if (!error && WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER,
                         &guid, sizeof(guid), &c->connect_ex,
                         sizeof(c->connect_ex), &written, NULL, NULL) == SOCKET_ERROR)
    error = rn_error(WSAGetLastError());
  if (!error && !CreateIoCompletionPort((HANDLE)socket, r->port, 0, 0))
    error = rn_error(GetLastError());
  if (error) {
    int closed = closesocket(socket) == SOCKET_ERROR ? rn_error(WSAGetLastError()) : 0;
    return -(closed ? closed : error);
  }
  c->socket = socket; c->state = RN_CONNECTING;
  rn_operation *op = &c->connect;
  memset(op, 0, sizeof(*op));
  op->kind = RN_OP_CONNECT; op->connection = rn_index(token); op->pending = 1;
  ++c->pending; ++r->outstanding;
  DWORD sent = 0;
  BOOL connected = c->connect_ex(socket, (struct sockaddr *)&remote, length,
                                 NULL, 0, &sent, &op->overlapped);
  if (!connected && WSAGetLastError() != ERROR_IO_PENDING) {
    error = rn_error(WSAGetLastError());
    op->pending = 0; --c->pending; --r->outstanding;
    c->socket = INVALID_SOCKET; c->state = RN_FRESH;
    int closed = closesocket(socket) == SOCKET_ERROR ? rn_error(WSAGetLastError()) : 0;
    return -(closed ? closed : error);
  }
  r->started = 1;
  return 0;
}
int rn_bind(rn_reactor *r, uint64_t token, const char *host, uint16_t port,
            int reuse_port) {
  if (!r || !host || (reuse_port != 0 && reuse_port != 1))
    return -EINVAL;
  rn_connection *c = rn_connection_get(r, token);
  if (!c || c->state != RN_FRESH)
    return -EINVAL;
  if (reuse_port)
    return -ENOTSUP; /* Windows has no TCP SO_REUSEPORT equivalent. */
  ADDRINFOA hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  char service[6];
  snprintf(service, sizeof(service), "%u", (unsigned)port);
  ADDRINFOA *addresses = NULL;
  int error = getaddrinfo(host[0] ? host : NULL, service, &hints, &addresses);
  if (error)
    return -(100000 + error);
  int last = EADDRNOTAVAIL;
  for (ADDRINFOA *a = addresses; a; a = a->ai_next) {
    SOCKET s = WSASocketW(a->ai_family, a->ai_socktype, a->ai_protocol, NULL, 0,
                          WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) {
      last = rn_error(WSAGetLastError());
      continue;
    }
    int one = 1;
    if (setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&one,
                   sizeof(one)) == SOCKET_ERROR ||
        bind(s, a->ai_addr, (int)a->ai_addrlen) == SOCKET_ERROR) {
      last = rn_error(WSAGetLastError());
      if (closesocket(s) == SOCKET_ERROR) {
        last = rn_error(WSAGetLastError());
        break;
      }
      continue;
    }
    GUID guid = WSAID_ACCEPTEX;
    DWORD written = 0;
    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid),
                 &c->accept_ex, sizeof(c->accept_ex), &written, NULL,
                 NULL) == SOCKET_ERROR) {
      last = rn_error(WSAGetLastError());
      if (closesocket(s) == SOCKET_ERROR)
        last = rn_error(WSAGetLastError());
      break;
    }
    if (!CreateIoCompletionPort((HANDLE)s, r->port, 0, 0)) {
      last = rn_error(GetLastError());
      if (closesocket(s) == SOCKET_ERROR)
        last = rn_error(WSAGetLastError());
      break;
    }
    c->socket = s;
    c->state = RN_BOUND;
    last = 0;
    break;
  }
  freeaddrinfo(addresses);
  return -last;
}
int rn_start_listening(rn_reactor *r, uint64_t token, int backlog) {
  if (!r || backlog <= 0)
    return -EINVAL;
  if (r->incoming_accepts)
    return -EINVAL;
  rn_connection *c = rn_connection_get(r, token);
  if (!c || c->state != RN_BOUND)
    return -EINVAL;
  if (listen(c->socket, backlog) == SOCKET_ERROR)
    return -rn_error(WSAGetLastError());
  c->state = RN_LISTENING;
  r->started = 1;
  rn_post_accept(r, rn_index(token));
  return 0;
}
int rn_listen(rn_reactor *r, const char *host, uint16_t port, int reuse_port,
              uint64_t *out) {
  int e = rn_socket_new(r, out);
  if (e)
    return e;
  e = rn_bind(r, *out, host, port, reuse_port);
  if (!e)
    e = rn_start_listening(r, *out, 4096);
  if (e) {
    int cleanup = rn_close_connection_impl(r, *out);
    if (cleanup)
      return cleanup;
  }
  return e;
}
int rn_step(rn_reactor *r, int timeout_ms) {
  if (!r || timeout_ms < -1)
    return -EINVAL;
  r->event_count = 0; r->polled = 1;
  r->started = 1;
  if (r->queue_error)
    return -r->queue_error;
  int adopt_error = rn_adopt_sockets(r);
  if (adopt_error)
    return adopt_error;
  rn_resume(r);
  rn_expire(r, rn_now_ms());
  DWORD wait = timeout_ms < 0 ? INFINITE : (DWORD)timeout_ms;
  DWORD tick = r->config.timer_tick_ms;
  if (wait == INFINITE || wait > tick)
    wait = tick;
  if (r->accept_backoff_until) {
    uint64_t now = rn_now_ms();
    if (now >= r->accept_backoff_until)
      r->accept_backoff_until = 0;
    else {
      uint64_t remaining = r->accept_backoff_until - now;
      if (wait == INFINITE || remaining < wait)
        wait = (DWORD)remaining;
    }
  }
  if (r->queue_count)
    wait = 0;
  for (uint32_t n = 0; n < r->config.max_events; ++n) {
    DWORD bytes = 0;
    ULONG_PTR key = 0;
    OVERLAPPED *overlapped = NULL;
    BOOL success = GetQueuedCompletionStatus(r->port, &bytes, &key, &overlapped,
                                             n ? 0 : wait);
    DWORD error = success ? 0 : GetLastError();
    if (!overlapped) {
      if (success && key == RN_WAKE_KEY)
        rn_emit(r, RN_WAKE, 0, 0, 0, 0, 0, 0, 0);
      else if (!success && error != WAIT_TIMEOUT)
        return -rn_error(error);
      else
        break;
    } else
      rn_completed(r, (rn_operation *)overlapped, bytes, rn_error(error));
    if (r->queue_count >= r->config.max_events)
      break;
  }
  adopt_error = rn_adopt_sockets(r);
  if (adopt_error)
    return adopt_error;
  rn_expire(r, rn_now_ms());
  while (r->event_count < r->config.max_events && r->queue_count) {
    rn_event event = r->queued[r->queue_head];
    r->queue_head = (r->queue_head + 1) % r->queue_capacity;
    --r->queue_count;
    if (event.kind == RN_ACCEPTED || event.kind == RN_CONNECT_COMPLETE || event.kind == RN_READ ||
        event.kind == RN_EOF || event.kind == RN_TIMER) {
      rn_connection *connection = rn_connection_get(r, event.connection);
      if (!connection || connection->state == RN_CLOSING) {
        if (event.kind == RN_READ) {
          rn_buffer *buffer = rn_buffer_get(r, event.buffer);
          if (buffer) {
            buffer->leased = 0;
            rn_recycle_buffer(r, rn_index(event.buffer));
          }
        }
        continue;
      }
    }
    r->events[r->event_count++] = event;
  }
  if (r->queue_error)
    return -r->queue_error;
  return (int)r->event_count;
}
const rn_event *rn_event_at(const rn_reactor *r, uint32_t index) {
  return r && index < r->event_count ? &r->events[index] : NULL;
}
static int rn_queue_write_impl(rn_reactor *r, uint64_t token, uint64_t buffer,
                   uint32_t offset, uint32_t length, uint64_t operation) {
  if (!r)
    return -EINVAL;
  rn_connection *c = rn_connection_get(r, token);
  rn_buffer *b = rn_buffer_get(r, buffer);
  if (!c || c->state != RN_CONNECTED || !b)
    return -EINVAL;
  if (c->draining)
    return -EPIPE;
  size_t size = lean_sarray_size(b->bytes);
  if (offset > size || length > size - offset)
    return -EINVAL;
  if (!r->free_write_count)
    return -EAGAIN;
  uint32_t wi = r->free_writes[--r->free_write_count];
  rn_write *w = &r->writes[wi];
  memset(w, 0, sizeof(*w));
  w->used = 1;
  w->next = RN_NONE;
  w->buffer = rn_index(buffer);
  w->offset = offset;
  w->length = length;
  w->operation = operation;
  ++b->io_refs;
  if (c->write_tail == RN_NONE)
    c->write_head = wi;
  else
    r->writes[c->write_tail].next = wi;
  c->write_tail = wi;
  /* Submit on the owning step. A synchronous send failure must not close a
   * connection while Lean is still dispatching the previous immutable batch. */
  rn_pause(r, rn_index(token));
  return 0;
}
int rn_file_table_init(rn_reactor *r, uint32_t capacity) {
  if (!r || r->polled) return -EINVAL;
  int result = rn_files_init(&r->files, capacity); if (result) return result;
  SOCKET probe = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
  if (probe == INVALID_SOCKET) return -rn_error(WSAGetLastError());
  GUID extension = WSAID_TRANSMITFILE; DWORD bytes = 0; LPFN_TRANSMITFILE transmit = NULL;
  int called = WSAIoctl(probe, SIO_GET_EXTENSION_FUNCTION_POINTER, &extension, sizeof(extension),
                       &transmit, sizeof(transmit), &bytes, NULL, NULL);
  int error = called == SOCKET_ERROR ? -rn_error(WSAGetLastError()) : 0;
  if (!error && (!transmit || bytes != sizeof(transmit))) error = -EIO;
  if (closesocket(probe) == SOCKET_ERROR) error = -rn_error(WSAGetLastError());
  if (!error) r->transmit_file = transmit;
  return error;
}
int rn_file_import(rn_reactor *r, rn_file_source *source, uint64_t *out) {
  return !r || r->polled ? -EINVAL : rn_files_import(&r->files, source, out);
}
uint64_t rn_file_owner(const rn_reactor *r) { return r ? r->files.owner : 0; }
int rn_file_release(rn_reactor *r, uint64_t token) {
  return !r ? -EINVAL : rn_files_release(&r->files, token);
}
int rn_file_pin(rn_reactor *r, uint64_t owner, uint64_t token, uint64_t offset,
                 uint32_t length, rn_file_source **out) {
  return !r || !owner || owner != r->files.owner ? -EINVAL : rn_files_pin(&r->files, token, offset, length, out);
}
int rn_queue_file(rn_reactor *r, uint64_t token, uint64_t owner, uint64_t file,
                   uint64_t offset, uint32_t length, uint64_t operation) {
  if (!r || !owner || owner != r->files.owner || !r->transmit_file) return -EINVAL;
  rn_connection *c = rn_connection_get(r, token); rn_file_entry *entry;
  if (!c || c->state != RN_CONNECTED) return -EINVAL;
  if (c->transport_mode) return -EACCES;
  if (c->draining) return -EPIPE;
  int error = rn_files_get(&r->files, file, &entry); const uint8_t *bytes;
  if (error) return error;
  error = rn_file_source_view(entry->source, offset, length, &bytes); if (error) return error;
  if (!r->free_write_count) return -EAGAIN;
  if (!c->transmit_file) {
    GUID extension = WSAID_TRANSMITFILE; DWORD count = 0; LPFN_TRANSMITFILE transmit = NULL;
    if (WSAIoctl(c->socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &extension, sizeof(extension),
                 &transmit, sizeof(transmit), &count, NULL, NULL) == SOCKET_ERROR)
      return -rn_error(WSAGetLastError());
    if (!transmit || count != sizeof(transmit)) return -EIO;
    c->transmit_file = transmit;
  }
  uint32_t wi = r->free_writes[--r->free_write_count]; rn_write *w = &r->writes[wi];
  memset(w, 0, sizeof(*w)); w->used = w->is_file = 1; w->buffer = RN_NONE;
  w->next = RN_NONE; w->file = (uint32_t)file - 1; w->file_offset = offset;
  w->length = length; w->operation = operation; ++entry->writes;
  if (c->write_tail == RN_NONE) c->write_head = wi;
  else r->writes[c->write_tail].next = wi;
  c->write_tail = wi; rn_pause(r, rn_index(token)); return 0;
}
int rn_acquire_buffer(rn_reactor *r, uint32_t minimum, uint64_t *out) {
  if (!r || !out || !minimum || minimum > 65536)
    return -EINVAL;
  uint32_t i = rn_take_buffer(r, minimum, 1);
  if (i == RN_NONE)
    return -EAGAIN;
  *out = rn_token(i, r->buffers[i].generation);
  return 0;
}
int rn_buffer_view(rn_reactor *r, uint64_t token, lean_object **out) {
  if (!r || !out)
    return -EINVAL;
  rn_buffer *b = rn_buffer_get(r, token);
  if (!b)
    return -EINVAL;
  *out = b->bytes;
  return 0;
}
int rn_buffer_release(rn_reactor *r, uint64_t token) {
  if (!r)
    return -EINVAL;
  rn_buffer *b = rn_buffer_get(r, token);
  if (!b)
    return -EINVAL;
  b->leased = 0;
  rn_recycle_buffer(r, rn_index(token));
  return 0;
}
int rn_buffer_copy(rn_reactor *r, uint64_t token, const uint8_t *data,
                   uint32_t length) {
  if (!r || (!data && length))
    return -EINVAL;
  rn_buffer *b = rn_buffer_get(r, token);
  if (!b || length > b->capacity)
    return -EINVAL;
  if (b->io_refs || !lean_is_exclusive(b->bytes))
    return -EBUSY;
  if (length)
    memmove(lean_sarray_cptr(b->bytes), data, length);
  lean_sarray_set_size(b->bytes, length);
  return 0;
}
static int rn_arm_timer_impl(rn_reactor *r, uint64_t token, uint32_t kind,
                 uint64_t deadline) {
  if (!r || kind >= RN_TIMER_KINDS || deadline > INT64_MAX)
    return -EINVAL;
  rn_connection *c = rn_connection_get(r, token);
  if (!c || c->state == RN_CLOSING)
    return -EINVAL;
  uint32_t i = rn_index(token) * RN_TIMER_KINDS + kind;
  rn_timer_remove(r, i);
  rn_timer *t = &r->timers[i];
  t->deadline = deadline;
  uint64_t scheduled = deadline / r->config.timer_tick_ms;
  if (scheduled < r->timer_tick)
    scheduled = r->timer_tick;
  t->bucket = (uint32_t)(scheduled % RN_WHEEL_SLOTS);
  t->previous = RN_NONE;
  t->next = r->buckets[t->bucket];
  if (t->next != RN_NONE)
    r->timers[t->next].previous = i;
  r->buckets[t->bucket] = i;
  t->armed = 1;
  return 0;
}
static int rn_cancel_timer_impl(rn_reactor *r, uint64_t token, uint32_t kind) {
  if (!r || kind >= RN_TIMER_KINDS || !rn_connection_get(r, token))
    return -EINVAL;
  rn_timer_remove(r, rn_index(token) * RN_TIMER_KINDS + kind);
  return 0;
}
static int rn_close_connection_impl(rn_reactor *r, uint64_t token) {
  if (!r)
    return -EINVAL;
  rn_connection *c = rn_connection_get(r, token);
  if (!c || c->state == RN_CLOSING)
    return -EINVAL;
  rn_close_native(r, rn_index(token));
  return 0;
}
static int rn_close_after_writes_impl(rn_reactor *r, uint64_t token) {
  if (!r)
    return -EINVAL;
  rn_connection *c = rn_connection_get(r, token);
  if (!c || c->state != RN_CONNECTED || c->draining)
    return -EINVAL;
  c->draining = 1;
  if (c->write_head == RN_NONE || r->writes[c->write_head].op.pending)
    rn_unpause(r, rn_index(token));
  if (c->read.pending && !CancelIoEx((HANDLE)c->socket, &c->read.overlapped)) {
    DWORD error = GetLastError();
    if (error != ERROR_NOT_FOUND)
      return -rn_error(error);
  }
  if (c->write_head == RN_NONE)
    rn_close_native(r, rn_index(token));
  return 0;
}
static int rn_set_read_enabled_impl(rn_reactor *r, uint64_t token, int enabled) {
  if (!r || (enabled != 0 && enabled != 1)) return -EINVAL;
  rn_connection *c = rn_connection_get(r, token);
  if (!c || c->state != RN_CONNECTED) return -EINVAL;
  c->read_disabled = !enabled;
  if (enabled && !c->read.pending && !c->eof && !c->draining) {
    c->read_paused = 1;
    rn_pause(r, rn_index(token));
  }
  return 0;
}

static int rn_format_peer(const struct sockaddr_storage *address, char *out, size_t capacity) {
    if (address->ss_family == AF_INET) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)address;
        if (!inet_ntop(AF_INET, &v4->sin_addr, out, capacity)) return -EINVAL;
    } else if (address->ss_family == AF_INET6) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)address;
        const unsigned char *bytes = (const unsigned char *)&v6->sin6_addr;
        static const unsigned char mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
        if (memcmp(bytes, mapped, sizeof(mapped)) == 0) {
            if (!inet_ntop(AF_INET, bytes + 12, out, capacity)) return -EINVAL;
        } else if (!inet_ntop(AF_INET6, &v6->sin6_addr, out, capacity)) return -EINVAL;
    } else return -EAFNOSUPPORT;
    return (int)strlen(out);
}

/* Binary peer address: 4 bytes for IPv4 (including IPv4-mapped IPv6), 16 for
 * IPv6. Returns the length or a negative errno. */
static int rn_raw_peer(const struct sockaddr_storage *address, uint8_t out[16]) {
    if (address->ss_family == AF_INET) {
        memcpy(out, &((const struct sockaddr_in *)address)->sin_addr, 4);
        return 4;
    }
    if (address->ss_family == AF_INET6) {
        const uint8_t *bytes = (const uint8_t *)&((const struct sockaddr_in6 *)address)->sin6_addr;
        static const uint8_t mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
        if (memcmp(bytes, mapped, sizeof(mapped)) == 0) { memcpy(out, bytes + 12, 4); return 4; }
        memcpy(out, bytes, 16);
        return 16;
    }
    return -EAFNOSUPPORT;
}
int rn_peer_raw(rn_reactor *r, uint64_t token, uint8_t out[16]) {
  if (!r || !out) return -EINVAL;
  rn_connection *c = rn_connection_get(r, token);
  if (!c || c->state != RN_CONNECTED) return -ENOTCONN;
  struct sockaddr_storage address;
  int length = sizeof(address);
  if (getpeername(c->socket, (struct sockaddr *)&address, &length) == SOCKET_ERROR)
    return -rn_error(WSAGetLastError());
  return rn_raw_peer(&address, out);
}
int rn_peer_address(rn_reactor *r, uint64_t token, char *out, size_t capacity) {
  if (!r || !out || capacity < 46) return -EINVAL;
  rn_connection *c = rn_connection_get(r, token);
  if (!c || c->state != RN_CONNECTED) return -ENOTCONN;
  struct sockaddr_storage address;
  int length = sizeof(address);
  if (getpeername(c->socket, (struct sockaddr *)&address, &length) == SOCKET_ERROR)
    return -rn_error(WSAGetLastError());
  return rn_format_peer(&address, out, capacity);
}
int rn_connection_live(rn_reactor *r, uint64_t token) {
  if (!r) return -EINVAL;
  rn_connection *c = rn_connection_get(r, token);
  return c && c->state == RN_CONNECTED;
}
int rn_wake(rn_reactor *r) {
  if (!r)
    return -EINVAL;
  return PostQueuedCompletionStatus(r->port, 0, RN_WAKE_KEY, NULL)
             ? 0
             : -rn_error(GetLastError());
}
int rn_free(rn_reactor *r) {
  if (!r)
    return -EINVAL;
  r->destroying = 1;
  if (r->wake_owner) atomic_store(&r->wake_owner->closed, 1);
  int error = 0;
  if (r->incoming_accepts) {
    atomic_store(&r->incoming_accepts->consumer_closed, 1);
    int discarded = rn_channel_discard(r->incoming_accepts);
    if (discarded)
      error = -discarded;
  }
  for (uint32_t i = 0; i < r->accept_target_count; ++i)
    atomic_store(&r->accept_targets[i]->producer_closed, 1);
  if (r->connections)
    for (uint32_t i = 0; i < r->config.max_connections; ++i)
      rn_close_native(r, i);
  while (r->outstanding) {
    DWORD bytes = 0;
    ULONG_PTR key = 0;
    OVERLAPPED *overlapped = NULL;
    BOOL ok =
        GetQueuedCompletionStatus(r->port, &bytes, &key, &overlapped, INFINITE);
    DWORD e = ok ? 0 : GetLastError();
    if (overlapped)
      rn_completed(r, (rn_operation *)overlapped, bytes, rn_error(e));
    else if (!ok) {
      error = rn_error(e);
      break;
    }
  }
  /* Never free outstanding OVERLAPPED memory after a failed completion drain.
   */
  if (r->outstanding)
    return error ? -error : -EBUSY;
  if (!error)
    error = r->cleanup_error;
  for (uint32_t i = 0; i < r->accept_target_count; ++i) {
    int released = rn_channel_release(r->accept_targets[i]);
    if (released && !error)
      error = -released;
  }
  if (r->incoming_accepts) {
    int released = rn_channel_release(r->incoming_accepts);
    if (released && !error)
      error = -released;
  }
  if (r->buffers)
    for (uint32_t i = 0; i < r->buffer_count; ++i)
      if (r->buffers[i].bytes)
        lean_dec(r->buffers[i].bytes);
  if (r->port_owner) {
    int released = rn_port_release(r->port_owner);
    if (released && !error)
      error = -released;
  } else if (r->port && !CloseHandle(r->port) && !error)
    error = rn_error(GetLastError());
  if (r->wake_owner) {
    int released = rn_waker_release(r->wake_owner);
    if (released && !error) error = -released;
  }
  if (r->wsa_started && WSACleanup() == SOCKET_ERROR && !error)
    error = rn_error(WSAGetLastError());
  { int released = rn_files_destroy(&r->files); if (released && !error) error = -released; }
  free(r->queued);
  free(r->accept_targets);
  free(r->paused_connections);
  free(r->free_buffers);
  free(r->free_writes);
  free(r->free_connections);
  free(r->events);
  free(r->buckets);
  free(r->timers);
  free(r->writes);
  free(r->buffers);
  free(r->connections);
  free(r);
  return -error;
}
static int rn_transport_access(rn_reactor *r, uint64_t token, uint64_t capability, int plain) {
    if (!r) return -EINVAL;
    rn_connection *c = rn_connection_get(r, token); if (!c) return -EINVAL;
    if (plain) return c->transport_mode ? -EACCES : 0;
    return c->state == RN_CONNECTED && c->transport_mode && capability && c->transport_cap == capability ? 0 : -EACCES;
}
int rn_transport_state(rn_reactor *r, uint64_t token) {
    if (!r) return -EINVAL;
    rn_connection *c = rn_connection_get(r, token); if (!c) return -EINVAL;
    return c->transport_mode;
}
int rn_transport_claim(rn_reactor *r, uint64_t token, uint64_t *capability) {
    if (!r || !capability) return -EINVAL;
    rn_connection *c = rn_connection_get(r, token); if (!c) return -EINVAL;
    if (c->state != RN_CONNECTED) return -EINVAL;
    if (c->transport_mode) return -EALREADY;
    if (c->write_head != RN_NONE || c->draining) return -EBUSY;
    c->transport_cap = token; c->transport_mode = 1; *capability = token; return 0;
}
int rn_transport_ready(rn_reactor *r, uint64_t token, uint64_t capability) {
    int error = rn_transport_access(r, token, capability, 0); if (error) return error;
    rn_connection *c = rn_connection_get(r, token); if (!c) return -EINVAL;
    if (c->transport_mode != 1) return -EALREADY;
    c->transport_mode = 2; return 0;
}
int rn_transport_mode(rn_reactor *r, uint64_t token, uint64_t capability) {
    int error = rn_transport_access(r, token, capability, 0);
    return error ? error : rn_transport_state(r, token);
}
#include "reactor_transport_impl.h"

#endif
