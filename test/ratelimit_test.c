/* Native GCRA limiter: deterministic timing, contention invariants, scopes. */
#define LN_RL_NO_LEAN
#include "../c/ratelimit.h"
#include <pthread.h>
#include <stdio.h>

#define REQUIRE(c) do { if (!(c)) { fprintf(stderr, "FAILED %s:%d %s\n", __FILE__, __LINE__, #c); exit(1); } } while (0)

static const uint8_t RANDOM[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};

typedef struct { ln_rl *l; uint32_t worker, rule, scope; uint64_t now; const char *key; long admitted; long calls; } job;

static void *hammer(void *arg) {
  job *j = arg;
  for (long i = 0; i < j->calls; ++i) {
    size_t length = j->key ? strlen(j->key) : 0;
    if (ln_rl_acquire(j->l, j->worker, j->rule, j->scope, (const uint8_t *)j->key, length, j->now) == 0) ++j->admitted;
  }
  return NULL;
}

static long contended(ln_rl *l, uint32_t rule, uint32_t scope, const char *key, uint64_t now) {
  pthread_t threads[8]; job jobs[8];
  for (uint32_t i = 0; i < 8; ++i) {
    jobs[i] = (job){l, i, rule, scope, now, key, 0, 20000};
    REQUIRE(pthread_create(&threads[i], NULL, hammer, &jobs[i]) == 0);
  }
  long total = 0;
  for (uint32_t i = 0; i < 8; ++i) { REQUIRE(pthread_join(threads[i], NULL) == 0); total += jobs[i].admitted; }
  return total;
}

int main(void) {
  /* rule 0: global 1000/s burst 200; rule 1: per route 10/s burst 5;
   * rule 2: keyed 10/s burst 5. */
  const uint32_t specs[3][5] = {{1000, 1000, 200, LN_RL_GLOBAL, 1}, {10, 1000, 5, LN_RL_ROUTE, 4},
                                {10, 1000, 5, LN_RL_KEYED, 1}};
  ln_rl *l = NULL;
  REQUIRE(ln_rl_create(specs, 3, 8, 1024, RANDOM, 1000, &l) == 0);

  /* Deterministic keyed GCRA: burst 5, then one cell every 100 ms. */
  for (int i = 0; i < 5; ++i) REQUIRE(ln_rl_acquire(l, 0, 2, 0, (const uint8_t *)"a", 1, 1000) == 0);
  uint32_t delay = ln_rl_acquire(l, 0, 2, 0, (const uint8_t *)"a", 1, 1000);
  REQUIRE(delay >= 99 && delay <= 101);
  REQUIRE(ln_rl_acquire(l, 0, 2, 0, (const uint8_t *)"a", 1, 1050) != 0);
  REQUIRE(ln_rl_acquire(l, 0, 2, 0, (const uint8_t *)"a", 1, 1100) == 0);
  /* Another key has its own budget. */
  for (int i = 0; i < 5; ++i) REQUIRE(ln_rl_acquire(l, 0, 2, 0, (const uint8_t *)"b", 1, 1000) == 0);

  /* Per-route scopes are independent buckets. */
  for (int i = 0; i < 5; ++i) REQUIRE(ln_rl_acquire(l, 0, 1, 1, NULL, 0, 1000) == 0);
  REQUIRE(ln_rl_acquire(l, 0, 1, 1, NULL, 0, 1000) != 0);
  REQUIRE(ln_rl_acquire(l, 0, 1, 2, NULL, 0, 1000) == 0);

  /* Frozen time under 8-thread contention: never more than the burst. */
  long global = contended(l, 0, 0, NULL, 5000);
  REQUIRE(global <= 200);
  REQUIRE(global >= 200 - 8 * 64);
  long keyed = contended(l, 2, 0, "hot-key", 5000);
  REQUIRE(keyed <= 5 && keyed >= 1);
  long route = contended(l, 1, 3, NULL, 5000);
  REQUIRE(route <= 5);

  /* Sustained rate: across 2 simulated seconds, admissions stay within
   * rate x time + burst. */
  ln_rl *rate = NULL;
  const uint32_t steady[1][5] = {{1000, 1000, 100, LN_RL_GLOBAL, 1}};
  REQUIRE(ln_rl_create(steady, 1, 4, 0, RANDOM, 0, &rate) == 0);
  long admitted = 0;
  for (uint64_t now = 10; now <= 2010; ++now)
    for (uint32_t worker = 0; worker < 4; ++worker)
      for (int i = 0; i < 5; ++i)
        if (ln_rl_acquire(rate, worker, 0, 0, NULL, 0, now) == 0) ++admitted;
  REQUIRE(admitted <= 2000 + 100 + 1);
  REQUIRE(admitted >= 1800);
  uint64_t counted = 0;
  for (uint32_t worker = 0; worker < 4; ++worker)
    counted += atomic_load(&rate->counters[worker].allowed) + atomic_load(&rate->counters[worker].limited);
  REQUIRE(counted == 4u * 2001u * 5u);
  ln_rl_free(rate);

  /* Key churn must not evict an active key and reset its quota. A returning
   * victim remains denied, while a full probe set fails closed for new keys. */
  ln_rl *tiny = NULL;
  const uint32_t one[1][5] = {{1, 60000, 1, LN_RL_KEYED, 1}};
  REQUIRE(ln_rl_create(one, 1, 1, 8, RANDOM, 0, &tiny) == 0);
  REQUIRE(ln_rl_acquire(tiny, 0, 0, 0, (const uint8_t *)"victim", 6, 0) == 0);
  REQUIRE(ln_rl_acquire(tiny, 0, 0, 0, (const uint8_t *)"victim", 6, 0) != 0);
  char name[16];
  for (int i = 0; i < 200; ++i) {
    snprintf(name, sizeof(name), "k%d", i);
    (void)ln_rl_acquire(tiny, 0, 0, 0, (const uint8_t *)name, strlen(name), 1);
  }
  REQUIRE(ln_rl_acquire(tiny, 0, 0, 0, (const uint8_t *)"victim", 6, 1) != 0);
  REQUIRE(ln_rl_acquire(tiny, 0, 0, 0, (const uint8_t *)"new-key", 7, 1) != 0);
  REQUIRE(ln_rl_acquire(tiny, 0, 0, 0, (const uint8_t *)"victim", 6, 60000) == 0);
  REQUIRE(ln_rl_acquire(tiny, 0, 0, 0, (const uint8_t *)"victim", 6, 60000) != 0);
  ln_rl_free(tiny);

  /* Long mTLS/header keys remain distinct past the old 256-byte cutoff.
   * Oversized identities fail closed instead of silently sharing a prefix. */
  ln_rl *extended = NULL;
  REQUIRE(ln_rl_create(one, 1, 1, 1024, RANDOM, 0, &extended) == 0);
  uint8_t key_a[300], key_b[300];
  memset(key_a, 'x', sizeof(key_a));
  memset(key_b, 'x', sizeof(key_b));
  key_a[sizeof(key_a) - 1] = 'a';
  key_b[sizeof(key_b) - 1] = 'b';
  REQUIRE(ln_rl_acquire(extended, 0, 0, 0, key_a, sizeof(key_a), 0) == 0);
  REQUIRE(ln_rl_acquire(extended, 0, 0, 0, key_a, sizeof(key_a), 0) != 0);
  REQUIRE(ln_rl_acquire(extended, 0, 0, 0, key_b, sizeof(key_b), 0) == 0);
  uint8_t *oversized_key = calloc(LN_RL_MAX_KEY_BYTES + 1u, 1);
  REQUIRE(oversized_key != NULL);
  REQUIRE(ln_rl_acquire(extended, 0, 0, 0, oversized_key, LN_RL_MAX_KEY_BYTES + 1u, 0) == 0xFFFFFFFFu);
  free(oversized_key);
  ln_rl_free(extended);

  /* The accept filter uses the same keyed table with raw peer IP bytes.
   * Both listener lanes share one budget; a second IP has its own quota. */
  ln_rl *accepts = NULL;
  const uint32_t accept_rule[1][5] = {{1, 60000, 2, LN_RL_KEYED, 1}};
  const uint8_t ip_a[4] = {127, 0, 0, 1}, ip_b[4] = {127, 0, 0, 2};
  REQUIRE(ln_rl_create(accept_rule, 1, 2, 1024, RANDOM, 0, &accepts) == 0);
  REQUIRE(ln_rl_acquire(accepts, 0, 0, 0, ip_a, 4, 0) == 0);
  REQUIRE(ln_rl_acquire(accepts, 1, 0, 0, ip_a, 4, 0) == 0);
  REQUIRE(ln_rl_acquire(accepts, 0, 0, 0, ip_a, 4, 0) != 0);
  REQUIRE(ln_rl_acquire(accepts, 1, 0, 0, ip_b, 4, 0) == 0);
  ln_rl_free(accepts);

  /* Packed keyed timestamps never wrap into a fresh budget. Recreate the
   * limiter before the horizon; this instance fails closed instead. */
  ln_rl *horizon = NULL;
  const uint32_t quick[1][5] = {{1, 1, 1, LN_RL_KEYED, 1}};
  REQUIRE(ln_rl_create(quick, 1, 1, 8, RANDOM, 0, &horizon) == 0);
  REQUIRE(ln_rl_acquire(horizon, 0, 0, 0, (const uint8_t *)"a", 1,
                        (LN_RL_TAT_MASK - 9) / 10 + 1) == 0xFFFFFFFFu);
  ln_rl_free(horizon);

  /* Invalid configurations. */
  ln_rl *bad = NULL;
  const uint32_t zero[1][5] = {{0, 1000, 1, LN_RL_GLOBAL, 1}};
  const uint32_t overflow[1][5] = {{1, UINT32_MAX, UINT32_MAX, LN_RL_GLOBAL, 1}};
  const uint32_t huge_route[1][5] = {{1, 1000, 1, LN_RL_ROUTE, 65536}};
  const uint32_t fractional[1][5] = {{3, 1, 3, LN_RL_GLOBAL, 1}};
  REQUIRE(ln_rl_create(zero, 1, 1, 0, RANDOM, 0, &bad) == -EINVAL);
  REQUIRE(ln_rl_create(overflow, 1, 1, 0, RANDOM, 0, &bad) == -ERANGE);
  REQUIRE(ln_rl_create(huge_route, 1, 256, 0, RANDOM, 0, &bad) == -EINVAL);
  REQUIRE(ln_rl_create(fractional, 1, 1, 0, RANDOM, 0, &bad) == 0);
  REQUIRE(bad->rules[0].interval_ns == 333334); /* never round toward a faster limit */
  ln_rl_free(bad); bad = NULL;
  REQUIRE(ln_rl_create(specs, 3, 8, 1000, RANDOM, 0, &bad) == -EINVAL); /* not a power of two */
  REQUIRE(ln_rl_create(specs, 3, 8, 0, RANDOM, 0, &bad) == -EINVAL);    /* keyed rule, no table */
  REQUIRE(ln_rl_acquire(l, 0, 1, 4, NULL, 0, 1000) == 0xFFFFFFFFu); /* invalid route scope */
  ln_rl_free(l);
  puts("rate limiter native tests passed");
  return 0;
}
