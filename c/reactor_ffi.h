/* Lean IO adapters for the owned, completion-based native reactor. */
#ifndef LEAN_NET_REACTOR_FFI_H
#define LEAN_NET_REACTOR_FFI_H
#include "reactor.h"
#include "reactor_lean.h"
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

static lean_object *rn_io_number(int64_t value) {
    return lean_io_result_mk_ok(lean_box_uint64((uint64_t)value));
}
static rn_reactor *rn_handle(uint64_t handle) { return (rn_reactor *)(uintptr_t)handle; }
static lean_object *rn_io_buffer(int64_t result, lean_object *bytes) {
    lean_object *pair = lean_alloc_ctor(0, 2, 0);
    lean_ctor_set(pair, 0, lean_box_uint64((uint64_t)result));
    lean_ctor_set(pair, 1, bytes);
    return lean_io_result_mk_ok(pair);
}
lean_object *shim_reactor_new(uint32_t connections, uint32_t events, uint32_t writes,
                             uint32_t buffers4k, uint32_t buffers16k,
                             uint32_t buffers64k, uint32_t tick_ms) {
    rn_config config = { connections, events, writes, buffers4k, buffers16k, buffers64k, tick_ms };
    rn_reactor *reactor = NULL;
    int rc = rn_new(&config, &reactor);
    if (rc < 0) return rn_io_number(rc);
    if ((uintptr_t)reactor > INT64_MAX) {
        int cleanup = rn_free(reactor);
        return rn_io_number(cleanup < 0 ? cleanup : -EOVERFLOW);
    }
    return rn_io_number((int64_t)(uintptr_t)reactor);
}
lean_object *shim_reactor_free(uint64_t handle) {
    return rn_io_number(handle == 0 ? -EINVAL : rn_free(rn_handle(handle)));
}
lean_object *shim_reactor_set_accept_targets(uint64_t handle, b_lean_obj_arg handles,
                                             uint32_t queue_capacity) {
    size_t count = lean_array_size(handles);
    if (handle == 0 || count == 0 || count > 256 || queue_capacity == 0)
        return rn_io_number(-EINVAL);
    rn_reactor **workers = malloc(count * sizeof(*workers));
    if (workers == NULL) return rn_io_number(-ENOMEM);
    for (size_t i = 0; i < count; ++i) {
        uint64_t worker = lean_unbox_uint64(lean_array_uget_borrowed(handles, i));
        if (worker == 0 || worker > INT64_MAX) {
            free(workers);
            return rn_io_number(-EINVAL);
        }
        workers[i] = rn_handle(worker);
    }
    int rc = rn_set_accept_targets(rn_handle(handle), workers, (uint32_t)count, queue_capacity);
    free(workers);
    return rn_io_number(rc);
}
lean_object *shim_reactor_socket_new(uint64_t handle) {
    if (handle == 0) return rn_io_number(-EINVAL);
    uint64_t token = 0;
    int rc = rn_socket_new(rn_handle(handle), &token);
    return rn_io_number(rc < 0 ? rc : (int64_t)token);
}
lean_object *shim_reactor_bind(uint64_t handle, uint64_t token, b_lean_obj_arg host, uint16_t port, uint8_t reuse) {
    if (handle == 0 || reuse > 1) return rn_io_number(-EINVAL);
    return rn_io_number(rn_bind(rn_handle(handle), token, lean_string_cstr(host), port, reuse));
}
lean_object *shim_reactor_start_listening(uint64_t handle, uint64_t token, uint32_t backlog) {
    if (handle == 0 || backlog > INT_MAX) return rn_io_number(-EINVAL);
    return rn_io_number(rn_start_listening(rn_handle(handle), token, (int)backlog));
}
lean_object *shim_reactor_listen(uint64_t handle, b_lean_obj_arg host, uint16_t port, uint8_t reuse) {
    if (handle == 0 || reuse > 1) return rn_io_number(-EINVAL);
    uint64_t token = 0;
    int rc = rn_listen(rn_handle(handle), lean_string_cstr(host), port, reuse, &token);
    return rn_io_number(rc < 0 ? rc : (int64_t)token);
}
lean_object *shim_reactor_step(uint64_t handle, int32_t timeout) {
    return rn_io_number(handle == 0 ? -EINVAL : rn_step(rn_handle(handle), timeout));
}
lean_object *shim_reactor_event(uint64_t handle, uint32_t index) {
    rn_event invalid = {0,0,0,-EINVAL,0,0,0,0};
    const rn_event *event = handle == 0 ? NULL : rn_event_at(rn_handle(handle), index);
    if (event == NULL) event = &invalid;
    lean_object *record = lean_alloc_ctor(0, 0, 48);
    lean_ctor_set_uint64(record, 0, event->connection);
    lean_ctor_set_uint64(record, 8, event->operation);
    lean_ctor_set_uint64(record, 16, event->buffer);
    lean_ctor_set_uint64(record, 24, (uint64_t)event->result);
    lean_ctor_set_uint32(record, 32, event->kind);
    uint32_t flags = event->flags;
    if (handle && (event->kind == RN_READ || event->kind == RN_EOF || event->kind == RN_TIMER) &&
        rn_transport_state(rn_handle(handle), event->connection) > 0) flags |= RN_CIPHERTEXT;
    lean_ctor_set_uint32(record, 36, flags);
    lean_ctor_set_uint32(record, 40, event->offset);
    lean_ctor_set_uint32(record, 44, event->length);
    return lean_io_result_mk_ok(record);
}
lean_object *shim_reactor_write(uint64_t handle, uint64_t connection, uint64_t buffer,
                               uint32_t offset, uint32_t length, uint64_t operation) {
    return rn_io_number(handle == 0 ? -EINVAL : rn_queue_write(rn_handle(handle), connection, buffer, offset, length, operation));
}
lean_object *shim_reactor_file_table(uint64_t handle, uint32_t capacity) {
    return rn_io_number(handle ? rn_file_table_init(rn_handle(handle), capacity) : -EINVAL);
}
lean_object *shim_reactor_file_owner(uint64_t handle) {
    uint64_t owner = handle ? rn_file_owner(rn_handle(handle)) : 0;
    return rn_io_number(owner ? (int64_t)owner : -EINVAL);
}
lean_object *shim_file_source_retain(uint64_t source) {
    return rn_io_number(source ? rn_file_source_retain((rn_file_source *)(uintptr_t)source) : -EINVAL);
}
lean_object *shim_file_source_release(uint64_t source) {
    return rn_io_number(source ? rn_file_source_release((rn_file_source *)(uintptr_t)source) : -EINVAL);
}
lean_object *shim_file_source_size(uint64_t source) {
    return rn_io_number(source ? (int64_t)rn_file_source_size((rn_file_source *)(uintptr_t)source) : -EINVAL);
}
lean_object *shim_file_prepare_residency(uint64_t budget) {
    return rn_io_number(rn_file_prepare_residency_budget(budget));
}
lean_object *shim_reactor_file_import(uint64_t handle, uint64_t source) {
    uint64_t token = 0;
    int error = handle && source ? rn_file_import(rn_handle(handle), (rn_file_source *)(uintptr_t)source, &token) : -EINVAL;
    return rn_io_number(error ? error : (int64_t)token);
}
lean_object *shim_reactor_file_release(uint64_t handle, uint64_t token) {
    return rn_io_number(handle ? rn_file_release(rn_handle(handle), token) : -EINVAL);
}
lean_object *shim_reactor_file_write(uint64_t handle, uint64_t connection, uint64_t owner,
                                    uint64_t token, uint64_t offset, uint32_t length, uint64_t operation) {
    return rn_io_number(handle ? rn_queue_file(rn_handle(handle), connection, owner, token, offset, length, operation) : -EINVAL);
}
lean_object *shim_reactor_read_enabled(uint64_t handle, uint64_t connection, uint8_t enabled) {
    return rn_io_number(handle == 0 || enabled > 1 ? -EINVAL :
        rn_set_read_enabled(rn_handle(handle), connection, enabled));
}
lean_object *shim_reactor_connection_live(uint64_t handle, uint64_t connection) {
    return rn_io_number(handle == 0 ? -EINVAL : rn_connection_live(rn_handle(handle), connection));
}
lean_object *shim_reactor_acquire(uint64_t handle, uint32_t minimum) {
    if (handle == 0) return rn_io_number(-EINVAL);
    uint64_t token = 0;
    int rc = rn_acquire_buffer(rn_handle(handle), minimum, &token);
    return rn_io_number(rc < 0 ? rc : (int64_t)token);
}
lean_object *shim_reactor_buffer(uint64_t handle, uint64_t token) {
    lean_object *bytes = NULL;
    int rc = handle == 0 ? -EINVAL : rn_buffer_view(rn_handle(handle), token, &bytes);
    if (rc < 0) return rn_io_buffer(rc, lean_alloc_sarray(1, 0, 0));
    lean_inc(bytes);
    return rn_io_buffer(0, bytes);
}
lean_object *shim_reactor_release(uint64_t handle, uint64_t token) {
    return rn_io_number(handle == 0 ? -EINVAL : rn_buffer_release(rn_handle(handle), token));
}
lean_object *shim_reactor_copy(uint64_t handle, uint64_t token, b_lean_obj_arg bytes) {
    size_t size = lean_sarray_size((lean_object *)bytes);
    if (handle == 0 || size > UINT32_MAX) return rn_io_number(-EINVAL);
    return rn_io_number(rn_buffer_copy(rn_handle(handle), token, lean_sarray_cptr((lean_object *)bytes), (uint32_t)size));
}
lean_object *shim_reactor_copy_slice(uint64_t handle, uint64_t token, b_lean_obj_arg bytes,
                                    uint32_t offset, uint32_t length) {
    size_t size = lean_sarray_size((lean_object *)bytes);
    if (handle == 0 || offset > size || length > size - offset) return rn_io_number(-EINVAL);
    return rn_io_number(rn_buffer_copy(rn_handle(handle), token,
        lean_sarray_cptr((lean_object *)bytes) + offset, length));
}
lean_object *shim_reactor_arm_timer(uint64_t handle, uint64_t connection, uint32_t kind, uint64_t deadline) {
    return rn_io_number(handle == 0 ? -EINVAL : rn_arm_timer(rn_handle(handle), connection, kind, deadline));
}
lean_object *shim_reactor_cancel_timer(uint64_t handle, uint64_t connection, uint32_t kind) {
    return rn_io_number(handle == 0 ? -EINVAL : rn_cancel_timer(rn_handle(handle), connection, kind));
}
lean_object *shim_reactor_close(uint64_t handle, uint64_t connection) {
    return rn_io_number(handle == 0 ? -EINVAL : rn_close_connection(rn_handle(handle), connection));
}
lean_object *shim_reactor_close_after_writes(uint64_t handle, uint64_t connection) {
    return rn_io_number(handle == 0 ? -EINVAL : rn_close_after_writes(rn_handle(handle), connection));
}
lean_object *shim_reactor_wake(uint64_t handle) {
    return rn_io_number(handle == 0 ? -EINVAL : rn_wake(rn_handle(handle)));
}
lean_object *shim_reactor_now(void) { return rn_io_number((int64_t)rn_now_ms()); }

lean_object *shim_reactor_transport_claim(uint64_t h, uint64_t t) {
    uint64_t cap = 0; int e = h ? rn_transport_claim(rn_handle(h),t,&cap) : -EINVAL;
    return rn_io_number(e ? e : (int64_t)cap);
}
lean_object *shim_reactor_transport_mode(uint64_t h, uint64_t t, uint64_t c) {
    return rn_io_number(h ? rn_transport_mode(rn_handle(h),t,c) : -EINVAL);
}
lean_object *shim_reactor_transport_ready(uint64_t h, uint64_t t, uint64_t c) {
    return rn_io_number(h ? rn_transport_ready(rn_handle(h),t,c) : -EINVAL);
}
lean_object *shim_reactor_transport_write(uint64_t h,uint64_t t,uint64_t c,uint64_t b,uint32_t o,uint32_t n,uint64_t op) {
    return rn_io_number(h ? rn_transport_write(rn_handle(h),t,c,b,o,n,op) : -EINVAL);
}
lean_object *shim_reactor_transport_read_enabled(uint64_t h,uint64_t t,uint64_t c,uint8_t enabled) {
    return rn_io_number(h && enabled <= 1 ? rn_transport_read_enabled(rn_handle(h),t,c,enabled) : -EINVAL);
}
lean_object *shim_reactor_transport_arm_timer(uint64_t h,uint64_t t,uint64_t c,uint32_t k,uint64_t d) {
    return rn_io_number(h ? rn_transport_arm_timer(rn_handle(h),t,c,k,d) : -EINVAL);
}
lean_object *shim_reactor_transport_cancel_timer(uint64_t h,uint64_t t,uint64_t c,uint32_t k) {
    return rn_io_number(h ? rn_transport_cancel_timer(rn_handle(h),t,c,k) : -EINVAL);
}
lean_object *shim_reactor_transport_drain(uint64_t h,uint64_t t,uint64_t c) {
    return rn_io_number(h ? rn_transport_drain(rn_handle(h),t,c) : -EINVAL);
}
lean_object *shim_reactor_transport_abort(uint64_t h,uint64_t t,uint64_t c) {
    return rn_io_number(h ? rn_transport_abort(rn_handle(h),t,c) : -EINVAL);
}
lean_object *shim_reactor_waker_acquire(uint64_t h) {
    rn_waker *w = NULL; int e = h ? rn_waker_acquire(rn_handle(h),&w) : -EINVAL;
    if (!e && (uintptr_t)w > INT64_MAX) { int released = rn_waker_release(w); return rn_io_number(released ? released : -EOVERFLOW); }
    return rn_io_number(e ? e : (int64_t)(uintptr_t)w);
}
lean_object *shim_reactor_waker_wake(uint64_t h) {
    return rn_io_number(h ? rn_waker_wake((rn_waker *)(uintptr_t)h) : -EINVAL);
}
lean_object *shim_reactor_waker_release(uint64_t h) {
    return rn_io_number(h ? rn_waker_release((rn_waker *)(uintptr_t)h) : -EINVAL);
}

#include "reactor_group_ffi.h"
#endif
