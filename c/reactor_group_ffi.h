/* Included exactly once by reactor_ffi.h; every adapter returns Lean IO. */
#ifndef LEAN_NET_REACTOR_GROUP_FFI_H
#define LEAN_NET_REACTOR_GROUP_FFI_H
#include "reactor_group.h"
#include <stdlib.h>

static rn_group *rn_group_handle(uint64_t handle) { return (rn_group *)(uintptr_t)handle; }

/* Borrowed Array UInt64, with one positive native reactor handle per element. */
lean_object *shim_reactor_group_new(b_lean_obj_arg handles) {
    size_t count = lean_array_size(handles);
    if (count == 0 || count > 65536 || count > SIZE_MAX / sizeof(rn_reactor *)) return rn_io_number(-EINVAL);
    rn_reactor **reactors = malloc(count * sizeof(*reactors));
    if (reactors == NULL) return rn_io_number(-ENOMEM);
    for (size_t i = 0; i < count; ++i) {
        uint64_t handle = lean_unbox_uint64(lean_array_uget_borrowed(handles, i));
        if (handle == 0 || handle > INT64_MAX) {
            free(reactors);
            return rn_io_number(-EINVAL);
        }
        reactors[i] = rn_handle(handle);
    }
    rn_group *group = NULL;
    int rc = rn_group_new(reactors, count, &group);
    free(reactors);
    if (rc < 0) return rn_io_number(rc);
    if ((uintptr_t)group > INT64_MAX) {
        int cleanup = rn_group_free(group);
        return rn_io_number(cleanup < 0 ? cleanup : -EOVERFLOW);
    }
    return rn_io_number((int64_t)(uintptr_t)group);
}
lean_object *shim_reactor_group_install(uint64_t handle) {
    return rn_io_number(handle == 0 ? -EINVAL : rn_group_install(rn_group_handle(handle)));
}
lean_object *shim_reactor_group_stop(uint64_t handle) {
    return rn_io_number(handle == 0 ? -EINVAL : rn_group_request_stop(rn_group_handle(handle)));
}
lean_object *shim_reactor_group_stopping(uint64_t handle) {
    return rn_io_number(handle == 0 ? -EINVAL : rn_group_stopping(rn_group_handle(handle)));
}
lean_object *shim_reactor_group_wake_error(uint64_t handle) {
    return rn_io_number(handle == 0 ? -EINVAL : rn_group_take_wake_error(rn_group_handle(handle)));
}
lean_object *shim_reactor_group_uninstall(uint64_t handle) {
    return rn_io_number(handle == 0 ? -EINVAL : rn_group_uninstall(rn_group_handle(handle)));
}
lean_object *shim_reactor_group_free(uint64_t handle) {
    return rn_io_number(handle == 0 ? -EINVAL : rn_group_free(rn_group_handle(handle)));
}
lean_object *shim_reactor_cpu_count(void) {
    uint32_t count = 0;
    int rc = rn_group_cpu_count(&count);
    return rn_io_number(rc < 0 ? rc : (int64_t)count);
}
lean_object *shim_reactor_endpoint_acquire(uint16_t port) {
    rn_endpoint_claim *claim = NULL;
    int rc = rn_endpoint_acquire(port, &claim);
    if (rc < 0) return rn_io_number(rc);
    if ((uintptr_t)claim > INT64_MAX) {
        int cleanup = rn_endpoint_release(claim);
        return rn_io_number(cleanup < 0 ? cleanup : -EOVERFLOW);
    }
    return rn_io_number((int64_t)(uintptr_t)claim);
}
lean_object *shim_reactor_endpoint_release(uint64_t handle) {
    return rn_io_number(handle == 0 ? -EINVAL : rn_endpoint_release((rn_endpoint_claim *)(uintptr_t)handle));
}
#endif
