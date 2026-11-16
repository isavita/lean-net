#ifndef LEAN_NET_ATOMIC_FLAG_H
#define LEAN_NET_ATOMIC_FLAG_H

#include <lean/lean.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/* Request-path operations are exactly one lock-free load/store. Registration
 * and allocation happen only during creation, never in isSet/set. */
_Static_assert(ATOMIC_BOOL_LOCK_FREE == 2, "lean-net requires lock-free atomic bool");

typedef struct { atomic_bool value; } rn_atomic_flag;
static _Atomic(lean_external_class *) rn_atomic_flag_class = NULL;
static atomic_flag rn_atomic_flag_registration = ATOMIC_FLAG_INIT;
static _Atomic(uint64_t) rn_atomic_flag_live_count = 0;

static void rn_atomic_flag_finalize(void *data) {
    free(data);
    atomic_fetch_sub_explicit(&rn_atomic_flag_live_count, 1, memory_order_relaxed);
}

static void rn_atomic_flag_foreach(void *data, b_lean_obj_arg visit) {
    (void)data; (void)visit;
}

static lean_external_class *rn_atomic_flag_get_class(void) {
    lean_external_class *result = atomic_load_explicit(&rn_atomic_flag_class, memory_order_acquire);
    if (result) return result;
    while (atomic_flag_test_and_set_explicit(&rn_atomic_flag_registration, memory_order_acquire)) {}
    result = atomic_load_explicit(&rn_atomic_flag_class, memory_order_relaxed);
    if (!result) {
        result = lean_register_external_class(rn_atomic_flag_finalize, rn_atomic_flag_foreach);
        atomic_store_explicit(&rn_atomic_flag_class, result, memory_order_release);
    }
    atomic_flag_clear_explicit(&rn_atomic_flag_registration, memory_order_release);
    return result;
}

lean_object *lean_net_atomic_flag_new(void) {
    lean_external_class *cls = rn_atomic_flag_get_class();
    rn_atomic_flag *flag = (rn_atomic_flag *)malloc(sizeof(*flag));
    if (!flag) return lean_io_result_mk_error(lean_mk_io_user_error(lean_mk_string("atomic flag allocation failed")));
    atomic_init(&flag->value, false);
    atomic_fetch_add_explicit(&rn_atomic_flag_live_count, 1, memory_order_relaxed);
    return lean_io_result_mk_ok(lean_alloc_external(cls, flag));
}

lean_object *lean_net_atomic_flag_is_set(b_lean_obj_arg value) {
    rn_atomic_flag *flag = (rn_atomic_flag *)lean_get_external_data(value);
    bool result = atomic_load_explicit(&flag->value, memory_order_acquire);
    return lean_io_result_mk_ok(lean_box(result));
}

lean_object *lean_net_atomic_flag_set(b_lean_obj_arg value) {
    rn_atomic_flag *flag = (rn_atomic_flag *)lean_get_external_data(value);
    atomic_store_explicit(&flag->value, true, memory_order_release);
    return lean_io_result_mk_ok(lean_box(0));
}

/* Native acceptance observes reclamation without exposing a resource handle. */
lean_object *lean_net_atomic_flag_live(void) {
    return lean_io_result_mk_ok(lean_box_uint64(atomic_load_explicit(&rn_atomic_flag_live_count, memory_order_relaxed)));
}

#endif
