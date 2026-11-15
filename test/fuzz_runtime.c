/* The generated Lean main initializes libuv before lean_run_main reads
 * LEAN_STACK_SIZE_KB. Configure only this test executable before any module
 * initializer can create the runtime's early event-loop thread. */
#include <lean/lean.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

extern lean_obj_res lean_internal_set_thread_stack_size(size_t bytes);

#if !defined(__GNUC__) && !defined(__clang__)
#error "The protocol-fuzz runtime setup requires a constructor-capable compiler"
#endif

__attribute__((constructor)) static void lean_net_fuzz_prepare_runtime(void) {
  (void)lean_internal_set_thread_stack_size((size_t)64 * 1024 * 1024);
  if (fputs("FUZZ_RUNTIME_INIT thread_stack_bytes=67108864 phase=before_module_initialization\n", stderr) < 0 ||
      fflush(stderr) != 0)
    exit(2);
}
