/* Process-wide atomic counters for control state (policy generations,
 * rejection reasons, reload outcomes) plus one cache-line-padded counter per
 * worker for hot paths. Workers read the generation with a relaxed load and
 * add only to their own line, so steady state never bounces a cache line
 * between cores, unlike a shared Lean object's atomic reference count. */
#ifndef LEAN_NET_COUNTERS_H
#define LEAN_NET_COUNTERS_H
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>

#define LN_COUNTER_WORKERS 256u
typedef struct { _Alignas(64) _Atomic uint64_t value; } ln_counter_line;
typedef struct {
  uint32_t count;
  void *storage;
  ln_counter_line *workers; /* LN_COUNTER_WORKERS cache lines */
  _Atomic uint64_t *values; /* count shared values */
} ln_counters;

lean_object *lean_net_counters_new(uint32_t count) {
  if (!count || count > 4096) return rn_io_number(-EINVAL);
  ln_counters *c = calloc(1, sizeof(*c));
  if (!c) return rn_io_number(-ENOMEM);
  c->storage = calloc(LN_COUNTER_WORKERS + 2 + (count * sizeof(uint64_t) + 63) / 64, 64);
  if (!c->storage) { free(c); return rn_io_number(-ENOMEM); }
  uintptr_t base = ((uintptr_t)c->storage + 63u) & ~(uintptr_t)63u;
  c->workers = (ln_counter_line *)base;
  c->values = (_Atomic uint64_t *)(base + LN_COUNTER_WORKERS * sizeof(ln_counter_line));
  c->count = count;
  for (uint32_t i = 0; i < LN_COUNTER_WORKERS; ++i) atomic_init(&c->workers[i].value, 0);
  for (uint32_t i = 0; i < count; ++i) atomic_init(&c->values[i], 0);
  if ((uintptr_t)c > INT64_MAX) { free(c->storage); free(c); return rn_io_number(-EOVERFLOW); }
  return rn_io_number((int64_t)(uintptr_t)c);
}
lean_object *lean_net_counters_add(uint64_t handle, uint32_t index, uint64_t amount) {
  ln_counters *c = (ln_counters *)(uintptr_t)handle;
  if (c && index < c->count) atomic_fetch_add_explicit(&c->values[index], amount, memory_order_release);
  return lean_io_result_mk_ok(lean_box(0));
}
lean_object *lean_net_counters_get(uint64_t handle, uint32_t index) {
  ln_counters *c = (ln_counters *)(uintptr_t)handle;
  uint64_t value = c && index < c->count ? atomic_load_explicit(&c->values[index], memory_order_acquire) : 0;
  return lean_io_result_mk_ok(lean_box_uint64(value));
}
/* Low 32 bits as an unboxed scalar: allocation-free generation checks. */
lean_object *lean_net_counters_get32(uint64_t handle, uint32_t index) {
  ln_counters *c = (ln_counters *)(uintptr_t)handle;
  uint64_t value = c && index < c->count ? atomic_load_explicit(&c->values[index], memory_order_acquire) : 0;
  return lean_io_result_mk_ok(lean_box_uint32((uint32_t)value));
}
/* Only worker `worker` writes its line (relaxed); readers sum all lines. */
lean_object *lean_net_counters_worker_add(uint64_t handle, uint32_t worker) {
  ln_counters *c = (ln_counters *)(uintptr_t)handle;
  if (c && worker < LN_COUNTER_WORKERS) {
    _Atomic uint64_t *line = &c->workers[worker].value;
    atomic_store_explicit(line, atomic_load_explicit(line, memory_order_relaxed) + 1, memory_order_relaxed);
  }
  return lean_io_result_mk_ok(lean_box(0));
}
lean_object *lean_net_counters_worker_sum(uint64_t handle) {
  ln_counters *c = (ln_counters *)(uintptr_t)handle;
  uint64_t sum = 0;
  for (uint32_t i = 0; c && i < LN_COUNTER_WORKERS; ++i) sum += atomic_load_explicit(&c->workers[i].value, memory_order_relaxed);
  return lean_io_result_mk_ok(lean_box_uint64(sum));
}
lean_object *lean_net_counters_free(uint64_t handle) {
  ln_counters *c = (ln_counters *)(uintptr_t)handle;
  if (c) { free(c->storage); free(c); }
  return lean_io_result_mk_ok(lean_box(0));
}
#endif
