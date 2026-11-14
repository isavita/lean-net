/* Real Lean reference-count regression for setup FFI borrowed Array UInt64.
 * Each boxed handle is owned only by its array. Calling a borrowed adapter
 * must leave it exclusive, on successful setup and on every rejection path. */
#include "../c/reactor_ffi.h"
#include <stdio.h>
#include <stdlib.h>

void lean_initialize_runtime_module(void);

static void check(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "reactor setup test: %s\n", message); exit(1); }
}
static int64_t number(lean_object *result) {
    check(lean_io_result_is_ok(result), "adapter returns a numeric IO result");
    int64_t value = (int64_t)lean_unbox_uint64(lean_io_result_get_value(result));
    lean_dec(result);
    return value;
}
static lean_object *handles(const uint64_t *values, size_t count) {
    lean_object *array = lean_alloc_array(count, count);
    for (size_t i = 0; i < count; ++i)
        lean_array_set_core(array, i, lean_box_uint64(values[i]));
    return array;
}
static void exclusive_elements(lean_object *array) {
    for (size_t i = 0; i < lean_array_size(array); ++i)
        check(lean_is_exclusive(lean_array_uget_borrowed(array, i)),
              "borrowed adapter leaked a boxed handle reference");
}
static void group_case(lean_object *array, int success) {
    exclusive_elements(array);
    int64_t result = number(shim_reactor_group_new(array));
    check(success ? result > 0 : result < 0, "group setup result");
    exclusive_elements(array);
    if (success) check(number(shim_reactor_group_free((uint64_t)result)) == 0, "free setup group");
    exclusive_elements(array);
}
static void targets_rejected(uint64_t acceptor, lean_object *array, uint32_t capacity) {
    exclusive_elements(array);
    check(number(shim_reactor_set_accept_targets(acceptor, array, capacity)) < 0,
          "reject invalid accept-target setup");
    exclusive_elements(array);
}
int main(void) {
    lean_initialize_runtime_module();
    uint64_t reactors[3];
    for (size_t i = 0; i < 3; ++i) {
        int64_t created = number(shim_reactor_new(4, 8, 4, 1, 0, 0, 1));
        check(created > 0, "create setup reactor"); reactors[i] = (uint64_t)created;
    }
    lean_object *workers = handles(reactors + 1, 2);
    uint64_t repeated[] = {reactors[1], reactors[1]};
    uint64_t invalid[] = {reactors[1], 0};
    uint64_t self[] = {reactors[0]};
    lean_object *duplicate = handles(repeated, 2);
    lean_object *zero = handles(invalid, 2);
    lean_object *own = handles(self, 1);
    lean_object *empty = handles(NULL, 0);
    group_case(workers, 1);
    group_case(duplicate, 0); /* Native rejection after all elements extracted. */
    group_case(zero, 0);      /* FFI rejection after extracting the first item. */
    group_case(empty, 0);
    targets_rejected(reactors[0], duplicate, 1);
    targets_rejected(reactors[0], own, 1);
    targets_rejected(reactors[0], zero, 1);
    targets_rejected(reactors[0], workers, 0);
    targets_rejected(reactors[0], empty, 1);
    exclusive_elements(workers);
    int64_t configured = number(shim_reactor_set_accept_targets(reactors[0], workers, 1));
    check(configured == 0 || configured == -ENOTSUP, "valid setup succeeds or platform explicitly rejects it");
    exclusive_elements(workers);
    if (configured == 0) targets_rejected(reactors[0], workers, 1);
    lean_dec(empty); lean_dec(own); lean_dec(zero); lean_dec(duplicate); lean_dec(workers);
    /* No loop was started; producer and both consumers have joined trivially. */
    for (size_t i = 0; i < 3; ++i)
        check(number(shim_reactor_free(reactors[i])) == 0, "free setup reactor");
    puts("reactor setup borrowed-reference tests passed");
    return 0;
}
