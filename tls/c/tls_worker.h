#ifndef LEAN_NET_TLS_WORKER_H
#define LEAN_NET_TLS_WORKER_H
#include <lean/lean.h>
#include <stdint.h>

/* This adapter is called only by its owning reactor thread. Its separate
 * native thread sees fixed byte lanes and OpenSSL objects, never Lean objects,
 * reactor pointers or socket handles. A worker reserves two native 4K credits
 * per session: ciphertext output and an independently replenished plaintext
 * delivery lease. Its stop/join/free barrier precedes reactor destruction. */
#define TLSW_CELL_SIZE 4096u
#define TLSW_CIPHER_OPERATION (UINT64_C(1) << 63)
enum tlsw_event_kind {
  TLSW_READY = 1, TLSW_READ = 2, TLSW_WRITTEN = 3, TLSW_EOF = 4,
  TLSW_CLOSED = 6, TLSW_ERROR = 7
};

lean_object *lean_tlsw_bundle_new(b_lean_obj_arg cert, b_lean_obj_arg key,
    b_lean_obj_arg names, b_lean_obj_arg certs, b_lean_obj_arg keys,
    uint8_t tickets);
lean_object *lean_tlsw_bundle_free(uint64_t handle);
lean_object *lean_tlsw_worker_new(uint64_t bundle, b_lean_obj_arg reactor,
    uint32_t max_sessions, uint32_t queue_capacity, uint64_t handshake_ms,
    uint64_t shutdown_ms);
lean_object *lean_tlsw_worker_free(uint64_t handle);
lean_object *lean_tlsw_attach(uint64_t handle, b_lean_obj_arg wire);
lean_object *lean_tlsw_feed(uint64_t handle, uint64_t session,
    b_lean_obj_arg buffer, uint32_t offset, uint32_t length);
lean_object *lean_tlsw_write(uint64_t handle, uint64_t session,
    b_lean_obj_arg buffer, uint32_t offset, uint32_t length, uint64_t operation);
lean_object *lean_tlsw_write_file(uint64_t handle, uint64_t session, uint64_t owner,
    uint64_t file, uint64_t offset, uint32_t length, uint64_t operation);
lean_object *lean_tlsw_resume_file(uint64_t handle, uint64_t session);
lean_object *lean_tlsw_peer_eof(uint64_t handle, uint64_t session);
lean_object *lean_tlsw_shutdown(uint64_t handle, uint64_t session);
lean_object *lean_tlsw_abort(uint64_t handle, uint64_t session);
lean_object *lean_tlsw_native_closed(uint64_t handle, uint64_t session);
lean_object *lean_tlsw_release_plain(uint64_t handle, uint64_t session);
lean_object *lean_tlsw_read_enabled(uint64_t handle, uint64_t session,
    uint8_t enabled);
lean_object *lean_tlsw_pump(uint64_t handle);
lean_object *lean_tlsw_event(uint64_t handle, uint32_t index);
lean_object *lean_tlsw_event_buffer(uint64_t handle, uint32_t index);
lean_object *lean_tlsw_on_written(uint64_t handle, uint64_t operation,
    uint64_t count);
lean_object *lean_tlsw_has_work(uint64_t handle);
/* Instrumentation: SSL operation count, owner-thread violations, active native
 * threads. Read atomically; no SSL operation is performed by this entrypoint. */
lean_object *lean_tlsw_stats(uint64_t handle);
#endif
