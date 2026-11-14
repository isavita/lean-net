#ifndef LEAN_NET_REACTOR_LEAN_H
#define LEAN_NET_REACTOR_LEAN_H
#include "reactor.h"
#include <errno.h>
#include <limits.h>

/* Trusted extern-only bridge for the private records in Reactor.Basic. All
 * calls run on the owning Lean loop, never on a crypto/native worker thread.
 * Reference fields precede scalars in the Lean ABI. No numeric Lean constructor
 * or descriptor escapes through the public library API. */
static inline int rn_bridge_record(b_lean_obj_arg value) {
    return value && !lean_is_scalar(value) && lean_ptr_tag(value) == 0 && lean_ctor_num_objs(value) == 1;
}
static inline int rn_bridge_alive(b_lean_obj_arg value) {
    if (!rn_bridge_record(value)) return 0;
    lean_object *alive = lean_ctor_get(value, 0);
    return lean_is_ref(alive) && lean_unbox(lean_to_ref(alive)->m_value) == 1;
}
static inline int rn_bridge_reactor(b_lean_obj_arg value, rn_reactor **out) {
    if (!out || !rn_bridge_alive(value)) return -EINVAL;
    uint64_t handle = lean_ctor_get_uint64(value, sizeof(void *));
    if (!handle || handle > INT64_MAX) return -EINVAL;
    *out = (rn_reactor *)(uintptr_t)handle; return 0;
}
static inline int rn_bridge_wire(b_lean_obj_arg value, rn_reactor **out, uint64_t *connection, uint64_t *capability) {
    if (!rn_bridge_record(value) || !out || !connection || !capability) return -EINVAL;
    lean_object *socket = lean_ctor_get(value, 0);
    if (!rn_bridge_record(socket)) return -EINVAL;
    int error = rn_bridge_reactor(lean_ctor_get(socket, 0), out); if (error) return error;
    uint64_t token = lean_ctor_get_uint64(socket, sizeof(void *));
    uint64_t cap = lean_ctor_get_uint64(value, sizeof(void *));
    uint8_t expected = lean_ctor_get_uint8(value, sizeof(void *) + 8);
    int mode = rn_transport_mode(*out, token, cap);
    if (mode < 0) return mode;
    if (mode != expected) return -EACCES;
    *connection = token; *capability = cap; return 0;
}
static inline int rn_bridge_buffer(b_lean_obj_arg value, rn_reactor *expected, uint64_t *out) {
    if (!rn_bridge_record(value) || !out) return -EINVAL;
    rn_reactor *owner = NULL; int error = rn_bridge_reactor(lean_ctor_get(value, 0), &owner);
    if (error || owner != expected) return error ? error : -EINVAL;
    uint64_t token = lean_ctor_get_uint64(value, sizeof(void *)); lean_object *bytes = NULL;
    error = rn_buffer_view(owner, token, &bytes); if (error) return error;
    *out = token; return 0;
}
static inline int rn_bridge_make_buffer(b_lean_obj_arg reactor, uint64_t token, lean_object **out) {
    rn_reactor *owner = NULL; if (!out) return -EINVAL;
    int error = rn_bridge_reactor(reactor, &owner); lean_object *bytes = NULL;
    if (!error) error = rn_buffer_view(owner, token, &bytes);
    if (error) return error;
    lean_object *buffer = lean_alloc_ctor(0, 1, 8);
    lean_inc(reactor); lean_ctor_set(buffer, 0, reactor);
    lean_ctor_set_uint64(buffer, sizeof(void *), token); *out = buffer; return 0;
}
/* Borrowed native handle. The engine must retain its own reference before
 * returning from its setup extern and release after its last possible wake. */
static inline int rn_bridge_waker(b_lean_obj_arg value, rn_waker **out) {
    if (!out || !rn_bridge_alive(value)) return -EINVAL;
    uint64_t handle = lean_ctor_get_uint64(value, sizeof(void *));
    if (!handle || handle > INT64_MAX) return -EINVAL;
    *out = (rn_waker *)(uintptr_t)handle; return 0;
}
#endif
