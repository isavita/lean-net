/* Lock-free GCRA rate limiter shared by all reactor workers.
 *
 * GCRA (generic cell rate algorithm) keeps one "theoretical arrival time"
 * (TAT) per bucket. A cell is admitted when max(TAT, now) + T - now <= tau,
 * where T is the emission interval (period / tokens) and tau = burst * T;
 * admission advances TAT by T. This is a token bucket without a refill timer,
 * with no window-boundary bursts and an exact retry delay.
 *
 * Unkeyed buckets (`global`, or per route) reserve leases of up to L cells
 * with one CAS and spend them on the worker without atomics. Reservation
 * happens before spending, so admissions never exceed the limit; unused
 * leased cells expire (at most workers x L cells per lease period are lost).
 *
 * Keyed buckets (client IP, principal, header value) live in one fixed table
 * of 64-bit words: a 24-bit key tag and a 40-bit TAT in 100 microsecond units.
 * Keys are hashed with SipHash-2-4 under a random per-limiter key, probed over
 * 4 slots. A missing key can claim only an empty or fully expired slot; when
 * all candidates are active it is denied. Evicting an active slot would reset
 * that key's quota. Tag collisions share a budget (stricter, never looser). */
#ifndef LEAN_NET_RATELIMIT_H
#define LEAN_NET_RATELIMIT_H
#include <errno.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(ATOMIC_LLONG_LOCK_FREE == 2, "rate limiter needs lock-free 64-bit atomics");

enum { LN_RL_GLOBAL = 0, LN_RL_ROUTE = 1, LN_RL_KEYED = 2 };
#define LN_RL_PROBE 4u
#define LN_RL_MAX_KEY_BYTES 65536u /* bound hash work per admitted request */
#define LN_RL_TICK_NS 100000ull /* keyed TAT unit: 100 microseconds */
#define LN_RL_TAT_MASK ((1ull << 40) - 1ull)

typedef struct ln_rl_rule {
  uint64_t interval_ns, tau_ns;
  uint32_t kind, scopes, offset, lease;
} ln_rl_rule;

typedef struct { _Alignas(64) _Atomic uint64_t tat; } ln_rl_bucket;
typedef struct { uint64_t remaining, expires_ns; } ln_rl_lease;
typedef struct { _Alignas(64) _Atomic uint64_t allowed, limited; } ln_rl_counter;

typedef struct ln_rl {
  uint32_t rule_count, workers, bucket_count;
  ln_rl_rule *rules;
  ln_rl_bucket *buckets;
  void *bucket_storage; /* unaligned allocation owning `buckets` */
  ln_rl_lease *leases; /* workers x bucket_count, written only by its worker */
  _Atomic uint64_t *slots;
  uint64_t slot_mask, base_ns, k0, k1;
  ln_rl_counter *counters;
  void *counter_storage;
} ln_rl;

static uint64_t ln_rl_rotl(uint64_t x, int b) { return (x << b) | (x >> (64 - b)); }

/* SipHash-2-4 (Aumasson and Bernstein), 64-bit output. */
static uint64_t ln_rl_siphash(uint64_t k0, uint64_t k1, const uint8_t *data, size_t length) {
  uint64_t v0 = 0x736f6d6570736575ull ^ k0, v1 = 0x646f72616e646f6dull ^ k1;
  uint64_t v2 = 0x6c7967656e657261ull ^ k0, v3 = 0x7465646279746573ull ^ k1;
#define LN_RL_ROUND \
  do { v0 += v1; v1 = ln_rl_rotl(v1, 13); v1 ^= v0; v0 = ln_rl_rotl(v0, 32); \
       v2 += v3; v3 = ln_rl_rotl(v3, 16); v3 ^= v2; \
       v0 += v3; v3 = ln_rl_rotl(v3, 21); v3 ^= v0; \
       v2 += v1; v1 = ln_rl_rotl(v1, 17); v1 ^= v2; v2 = ln_rl_rotl(v2, 32); } while (0)
  size_t full = length & ~(size_t)7;
  for (size_t i = 0; i < full; i += 8) {
    uint64_t m = 0;
    for (int b = 7; b >= 0; --b) m = (m << 8) | data[i + (size_t)b];
    v3 ^= m; LN_RL_ROUND; LN_RL_ROUND; v0 ^= m;
  }
  uint64_t last = (uint64_t)length << 56;
  for (size_t i = full; i < length; ++i) last |= (uint64_t)data[i] << (8 * (i - full));
  v3 ^= last; LN_RL_ROUND; LN_RL_ROUND; v0 ^= last;
  v2 ^= 0xff; LN_RL_ROUND; LN_RL_ROUND; LN_RL_ROUND; LN_RL_ROUND;
#undef LN_RL_ROUND
  return v0 ^ v1 ^ v2 ^ v3;
}

/* specs: per rule {tokens, period_ms, burst, kind, scopes}. random: 16 bytes. */
static inline int ln_rl_create(const uint32_t (*specs)[5], uint32_t rule_count, uint32_t workers,
                        uint32_t keyed_slots, const uint8_t random[16], uint64_t now_ms, ln_rl **out) {
  *out = NULL;
  if (!specs || !random || !rule_count || rule_count > 1024 || !workers || workers > 256 ||
      now_ms > UINT64_MAX / 1000000ull || keyed_slots > (1u << 24) ||
      (keyed_slots & (keyed_slots - 1)))
    return -EINVAL;
  ln_rl *l = calloc(1, sizeof(*l));
  if (!l) return -ENOMEM;
  l->rule_count = rule_count; l->workers = workers;
  l->rules = calloc(rule_count, sizeof(*l->rules));
  if (!l->rules) { free(l); return -ENOMEM; }
  uint64_t buckets = 0;
  int keyed = 0;
  for (uint32_t i = 0; i < rule_count; ++i) {
    uint32_t tokens = specs[i][0], period = specs[i][1], burst = specs[i][2], kind = specs[i][3], scopes = specs[i][4];
    if (!tokens || !period || !burst || kind > LN_RL_KEYED || (kind == LN_RL_ROUTE ? !scopes || scopes > 65536 : 0)) {
      free(l->rules); free(l); return -EINVAL;
    }
    ln_rl_rule *rule = &l->rules[i];
    /* Round up: truncation would admit slightly faster than configured. */
    rule->interval_ns = ((uint64_t)period * 1000000ull + tokens - 1) / tokens;
    if (rule->interval_ns > (UINT64_MAX / 2) / burst) {
      free(l->rules); free(l); return -ERANGE;
    }
    rule->tau_ns = rule->interval_ns * burst;
    if (kind == LN_RL_KEYED && rule->tau_ns / LN_RL_TICK_NS >= (LN_RL_TAT_MASK / 2)) {
      free(l->rules); free(l); return -ERANGE;
    }
    rule->kind = kind;
    rule->scopes = kind == LN_RL_ROUTE ? scopes : kind == LN_RL_GLOBAL ? 1 : 0;
    rule->offset = (uint32_t)buckets;
    /* Lease about 5 ms of the global rate per worker, between 1 and 64 cells,
     * and never more than one burst. */
    uint64_t per_5ms = ((uint64_t)tokens * 5u) / ((uint64_t)period * workers);
    uint64_t lease = per_5ms < 1 ? 1 : per_5ms > 64 ? 64 : per_5ms;
    rule->lease = (uint32_t)(lease > burst ? burst : lease);
    buckets += rule->scopes;
    if (kind == LN_RL_KEYED) keyed = 1;
  }
  if (buckets > (1u << 20) || buckets * workers > (1u << 22) || (keyed && !keyed_slots)) {
    free(l->rules); free(l); return -EINVAL;
  }
  l->bucket_count = (uint32_t)buckets;
  if (buckets) {
    /* Portable cache-line alignment (no aligned_alloc on every C runtime). */
    l->bucket_storage = calloc(buckets + 1, sizeof(ln_rl_bucket));
    l->leases = calloc((size_t)workers * buckets, sizeof(ln_rl_lease));
    if (!l->bucket_storage || !l->leases) { free(l->bucket_storage); free(l->leases); free(l->rules); free(l); return -ENOMEM; }
    l->buckets = (ln_rl_bucket *)(((uintptr_t)l->bucket_storage + 63u) & ~(uintptr_t)63u);
    for (uint64_t i = 0; i < buckets; ++i) atomic_init(&l->buckets[i].tat, 0);
  }
  if (keyed) {
    l->slots = calloc(keyed_slots, sizeof(*l->slots));
    if (!l->slots) { free(l->bucket_storage); free(l->leases); free(l->rules); free(l); return -ENOMEM; }
    l->slot_mask = keyed_slots - 1;
    for (uint32_t i = 0; i < keyed_slots; ++i) atomic_init(&l->slots[i], 0);
  }
  l->counter_storage = calloc((size_t)workers + 1, sizeof(ln_rl_counter));
  if (!l->counter_storage) {
    free(l->slots); free(l->bucket_storage); free(l->leases); free(l->rules); free(l); return -ENOMEM;
  }
  l->counters = (ln_rl_counter *)(((uintptr_t)l->counter_storage + 63u) & ~(uintptr_t)63u);
  for (uint32_t i = 0; i < workers; ++i) {
    atomic_init(&l->counters[i].allowed, 0);
    atomic_init(&l->counters[i].limited, 0);
  }
  memcpy(&l->k0, random, 8); memcpy(&l->k1, random + 8, 8);
  l->base_ns = now_ms * 1000000ull;
  *out = l;
  return 0;
}

static inline void ln_rl_free(ln_rl *l) {
  if (!l) return;
  free(l->counter_storage); free(l->slots); free(l->leases); free(l->bucket_storage); free(l->rules); free(l);
}

static uint32_t ln_rl_delay_ms(uint64_t ns) {
  uint64_t ms = ns / 1000000ull + (ns % 1000000ull != 0);
  return ms == 0 ? 1 : ms > 0xFFFFFFFEull ? 0xFFFFFFFEu : (uint32_t)ms;
}

static uint32_t ln_rl_result(ln_rl *l, uint32_t worker, uint32_t delay) {
  ln_rl_counter *counter = &l->counters[worker];
  atomic_fetch_add_explicit(delay ? &counter->limited : &counter->allowed, 1, memory_order_relaxed);
  return delay;
}

/* Unkeyed rule with a per-worker lease. */
static uint32_t ln_rl_unkeyed(ln_rl *l, const ln_rl_rule *rule, uint32_t worker, uint32_t scope, uint64_t now_ns) {
  if (scope >= rule->scopes) return 0xFFFFFFFFu;
  uint32_t bucket_index = rule->offset + scope;
  ln_rl_lease *lease = &l->leases[(size_t)worker * l->bucket_count + bucket_index];
  if (lease->remaining && now_ns < lease->expires_ns) { --lease->remaining; return ln_rl_result(l, worker, 0); }
  lease->remaining = 0;
  _Atomic uint64_t *tat = &l->buckets[bucket_index].tat;
  uint64_t current = atomic_load_explicit(tat, memory_order_relaxed);
  for (;;) {
    uint64_t base = current > now_ns ? current : now_ns;
    uint64_t ahead = base - now_ns;
    if (ahead > rule->tau_ns) {
      uint64_t excess = ahead - rule->tau_ns;
      uint64_t retry = excess > UINT64_MAX - rule->interval_ns ? UINT64_MAX : excess + rule->interval_ns;
      return ln_rl_result(l, worker, ln_rl_delay_ms(retry));
    }
    if (rule->interval_ns > rule->tau_ns - ahead)
      return ln_rl_result(l, worker, ln_rl_delay_ms(rule->interval_ns - (rule->tau_ns - ahead)));
    uint64_t fit = (rule->tau_ns - ahead) / rule->interval_ns;
    uint64_t take = fit < rule->lease ? fit : rule->lease;
    if (atomic_compare_exchange_weak_explicit(tat, &current, base + take * rule->interval_ns,
                                              memory_order_relaxed, memory_order_relaxed)) {
      lease->remaining = take - 1;
      lease->expires_ns = now_ns + take * rule->interval_ns;
      return ln_rl_result(l, worker, 0);
    }
  }
}

static uint32_t ln_rl_keyed(ln_rl *l, const ln_rl_rule *rule, uint32_t worker, uint32_t rule_index, uint32_t scope,
                            const uint8_t *key, size_t key_length, uint64_t now_ns) {
  /* Hash the complete bounded identity first, then domain-separate it by
   * rule and scope. Truncating an mTLS principal or header value here would
   * merge distinct identities into one quota without any indication. */
  uint64_t key_hash = ln_rl_siphash(l->k0, l->k1, key, key_length);
  uint8_t material[16];
  memcpy(material, &rule_index, 4); memcpy(material + 4, &scope, 4);
  memcpy(material + 8, &key_hash, 8);
  uint64_t hash = ln_rl_siphash(l->k0 ^ 0x9e3779b97f4a7c15ull,
                                l->k1 ^ 0xd1b54a32d192ed03ull, material, sizeof(material));
  uint64_t tag = ((hash >> 40) & 0xFFFFFFull) | 1ull; /* nonzero: 0 marks an empty slot */
  uint64_t now = now_ns > l->base_ns ? (now_ns - l->base_ns) / LN_RL_TICK_NS : 0;
  uint64_t interval = (rule->interval_ns + LN_RL_TICK_NS - 1) / LN_RL_TICK_NS;
  uint64_t tau = rule->tau_ns / LN_RL_TICK_NS;
  if (tau < interval) tau = interval;
  /* The packed TAT cannot wrap without forgetting active keyed budgets.
   * A long-lived process fails closed until a new limiter is installed. */
  if (now > LN_RL_TAT_MASK - tau) return ln_rl_result(l, worker, 0xFFFFFFFFu);
  uint64_t start = hash & l->slot_mask;
  for (;;) {
    _Atomic uint64_t *chosen = NULL;
    uint64_t chosen_word = 0, oldest = UINT64_MAX, soonest = UINT64_MAX;
    for (uint32_t probe = 0; probe < LN_RL_PROBE; ++probe) {
      _Atomic uint64_t *slot = &l->slots[(start + probe) & l->slot_mask];
      uint64_t word = atomic_load_explicit(slot, memory_order_relaxed);
      if (word >> 40 == tag) { chosen = slot; chosen_word = word; break; }
      uint64_t tat = word & LN_RL_TAT_MASK;
      if (!word || tat <= now) {
        if (tat < oldest) { oldest = tat; chosen = slot; chosen_word = word; }
      } else if (tat < soonest) soonest = tat;
    }
    if (!chosen) return ln_rl_result(l, worker, ln_rl_delay_ms((soonest - now) * LN_RL_TICK_NS));
    uint64_t current = chosen_word >> 40 == tag ? (chosen_word & 0xFFFFFFFFFFull) : 0;
    uint64_t base = current > now ? current : now;
    uint64_t ahead = base - now;
    if (ahead > tau) return ln_rl_result(l, worker, ln_rl_delay_ms((ahead - tau + interval) * LN_RL_TICK_NS));
    if (interval > tau - ahead)
      return ln_rl_result(l, worker, ln_rl_delay_ms((interval - (tau - ahead)) * LN_RL_TICK_NS));
    uint64_t next = (tag << 40) | (base + interval);
    if (atomic_compare_exchange_strong_explicit(chosen, &chosen_word, next, memory_order_relaxed, memory_order_relaxed))
      return ln_rl_result(l, worker, 0);
  }
}

/* 0 when admitted, otherwise the retry delay in milliseconds (>= 1). */
static uint32_t ln_rl_acquire(ln_rl *l, uint32_t worker, uint32_t rule_index, uint32_t scope,
                              const uint8_t *key, size_t key_length, uint64_t now_ms) {
  if (!l || worker >= l->workers || rule_index >= l->rule_count) return 0xFFFFFFFFu;
  const ln_rl_rule *rule = &l->rules[rule_index];
  if (now_ms > UINT64_MAX / 1000000ull ||
      now_ms * 1000000ull > UINT64_MAX - rule->tau_ns || (key_length && !key) ||
      (rule->kind == LN_RL_KEYED && key_length > LN_RL_MAX_KEY_BYTES)) return 0xFFFFFFFFu;
  uint64_t now_ns = now_ms * 1000000ull;
  if (rule->kind == LN_RL_KEYED) return ln_rl_keyed(l, rule, worker, rule_index, scope, key, key_length, now_ns);
  return ln_rl_unkeyed(l, rule, worker, scope, now_ns);
}

#ifndef LN_RL_NO_LEAN
/* Lean FFI. Rules: rule_count x 5 little-endian uint32 values. */
lean_object *lean_net_rl_new(b_lean_obj_arg rules, uint32_t workers, uint32_t slots, b_lean_obj_arg random,
                             uint64_t now_ms) {
  size_t size = lean_sarray_size(rules);
  if (size == 0 || size % 20 || size / 20 > 1024 || lean_sarray_size(random) != 16)
    return rn_io_number(-EINVAL);
  uint32_t count = (uint32_t)(size / 20);
  uint32_t (*specs)[5] = calloc(count, sizeof(*specs));
  if (!specs) return rn_io_number(-ENOMEM);
  memcpy(specs, lean_sarray_cptr(rules), size);
  ln_rl *l = NULL;
  int rc = ln_rl_create((const uint32_t (*)[5])specs, count, workers, slots, lean_sarray_cptr(random), now_ms, &l);
  free(specs);
  if (rc) return rn_io_number(rc);
  if ((uintptr_t)l > INT64_MAX) { ln_rl_free(l); return rn_io_number(-EOVERFLOW); }
  return rn_io_number((int64_t)(uintptr_t)l);
}
lean_object *lean_net_rl_acquire(uint64_t handle, uint32_t worker, uint32_t rule, uint32_t scope,
                                 b_lean_obj_arg key, uint64_t now_ms) {
  uint32_t delay = ln_rl_acquire((ln_rl *)(uintptr_t)handle, worker, rule, scope, lean_sarray_cptr(key),
                                 lean_sarray_size(key), now_ms);
  return lean_io_result_mk_ok(lean_box_uint32(delay));
}
lean_object *lean_net_rl_stats(uint64_t handle) {
  ln_rl *l = (ln_rl *)(uintptr_t)handle;
  lean_object *pair = lean_alloc_ctor(0, 2, 0);
  uint64_t allowed = 0, limited = 0;
  if (l) for (uint32_t i = 0; i < l->workers; ++i) {
    allowed += atomic_load_explicit(&l->counters[i].allowed, memory_order_relaxed);
    limited += atomic_load_explicit(&l->counters[i].limited, memory_order_relaxed);
  }
  lean_ctor_set(pair, 0, lean_box_uint64(allowed));
  lean_ctor_set(pair, 1, lean_box_uint64(limited));
  return lean_io_result_mk_ok(pair);
}
lean_object *lean_net_rl_free(uint64_t handle) {
  ln_rl_free((ln_rl *)(uintptr_t)handle);
  return rn_io_number(0);
}
#endif
#endif
