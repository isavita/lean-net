#ifndef LEAN_NET_REACTOR_H
#define LEAN_NET_REACTOR_H
#include <lean/lean.h>
#include <stddef.h>
#include <stdint.h>

typedef struct rn_reactor rn_reactor;
typedef struct rn_config {
    uint32_t max_connections;
    uint32_t max_events;
    uint32_t max_writes;
    uint32_t buffers_4k;
    uint32_t buffers_16k;
    uint32_t buffers_64k;
    uint32_t timer_tick_ms;
} rn_config;

enum rn_event_kind { RN_ACCEPTED=1, RN_READ=2, RN_WRITTEN=3, RN_EOF=4,
    RN_TIMER=5, RN_CLOSED=6, RN_ERROR=7, RN_WAKE=8 };
#define RN_TIMER_KINDS 8u

enum rn_event_flags { RN_ACCEPT_ERROR=1, RN_SETUP_ERROR=2, RN_CLOSE_ERROR=4 };
/* WRITTEN is a historical completion: its connection identity can already be
 * closed, and successful writes precede CLOSED even within the same batch. */
typedef struct rn_event {
    uint64_t connection;
    uint64_t operation;
    uint64_t buffer;
    int64_t result;
    uint32_t kind;
    uint32_t flags;
    uint32_t offset;
    uint32_t length;
} rn_event;

/* Native API returns zero on success or negative errno. rn_step returns the
 * event count, or negative errno (including EINTR without retry). Every token
 * has a generation; zero is never a valid connection or buffer token.
 * rn_listen takes ownership only of the socket it creates. Buffers and socket
 * descriptors are exclusively owned by the reactor; they never escape. */
int rn_new(const rn_config *config, rn_reactor **out);
int rn_free(rn_reactor *reactor);
int rn_socket_new(rn_reactor *reactor, uint64_t *out_token);
int rn_bind(rn_reactor *reactor, uint64_t token, const char *host, uint16_t port,
            int reuse_port);
int rn_start_listening(rn_reactor *reactor, uint64_t token, int backlog);
int rn_listen(rn_reactor *reactor, const char *host, uint16_t port,
              int reuse_port, uint64_t *out_token);
int rn_step(rn_reactor *reactor, int timeout_ms);
const rn_event *rn_event_at(const rn_reactor *reactor, uint32_t index);
int rn_queue_write(rn_reactor *reactor, uint64_t connection, uint64_t buffer,
                   uint32_t offset, uint32_t length, uint64_t operation);
int rn_acquire_buffer(rn_reactor *reactor, uint32_t minimum, uint64_t *out_token);
/* View is borrowed. The FFI increments its reference before returning to Lean.
 * Releasing a lease forbids further views. Buffer storage is never reused until
 * queued I/O is complete AND the reactor's Lean ByteArray reference is unique. */
int rn_buffer_view(rn_reactor *reactor, uint64_t token, lean_object **out);
int rn_buffer_release(rn_reactor *reactor, uint64_t token);
int rn_buffer_copy(rn_reactor *reactor, uint64_t token, const uint8_t *data, uint32_t length);
/* Timer kinds are 0..7. RN_TIMER carries operation=kind, result=deadline_ms. */
int rn_arm_timer(rn_reactor *reactor, uint64_t connection, uint32_t timer_kind,
                 uint64_t deadline_ms);
int rn_cancel_timer(rn_reactor *reactor, uint64_t connection, uint32_t timer_kind);
int rn_close_after_writes(rn_reactor *reactor, uint64_t connection);
int rn_close_connection(rn_reactor *reactor, uint64_t connection);
/* Wake is the only API callable by another thread. No protocol/Lean objects
 * are touched; it wakes rn_step. The queue command protocol owns its data. */
int rn_wake(rn_reactor *reactor);
uint64_t rn_now_ms(void);
#endif
