#ifndef LEAN_NET_REACTOR_AFFINITY_H
#define LEAN_NET_REACTOR_AFFINITY_H
/* Startup-only Linux CPU masks, including CPU IDs beyond CPU_SETSIZE. Buffer
 * growth responds only to EINVAL (insufficient kernel mask size), never EINTR.
 * 64KiB bounds allocation and scans to 524288 CPU IDs on supported targets. */
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux__
#include <sched.h>
#endif

#define RN_AFFINITY_INITIAL_BYTES 128u
#define RN_AFFINITY_MAX_BYTES (64u * 1024u)
typedef int (*rn_affinity_getter)(void *, size_t, void *);
typedef int (*rn_affinity_setter)(void *, size_t, const void *);
typedef struct { unsigned long *words; size_t bytes; uint32_t count; } rn_affinity;

static inline void rn_affinity_release(rn_affinity *mask) {
    free(mask->words); memset(mask, 0, sizeof(*mask));
}
static inline int rn_affinity_load(rn_affinity_getter get, void *context, rn_affinity *out) {
    if (!get || !out) return -EINVAL;
    for (size_t bytes = RN_AFFINITY_INITIAL_BYTES; bytes <= RN_AFFINITY_MAX_BYTES; bytes *= 2) {
        unsigned long *words = malloc(bytes);
        if (!words) return -ENOMEM;
        memset(words, 0, bytes);
        int error = get(context, bytes, words);
        if (!error) {
            uint32_t count = 0;
            for (size_t i = 0; i < bytes / sizeof(*words); ++i) {
                unsigned long bits = words[i];
                while (bits) { bits &= bits - 1; ++count; }
            }
            if (!count) { free(words); return -EINVAL; }
            *out = (rn_affinity){words, bytes, count};
            return 0;
        }
        free(words);
        if (error != -EINVAL) return error < 0 ? error : -EIO;
    }
    return -EOVERFLOW;
}
static inline int rn_affinity_pin(rn_affinity_getter get, rn_affinity_setter set,
                                  void *context, uint32_t index) {
    if (!set) return -EINVAL;
    rn_affinity mask = {0};
    int error = rn_affinity_load(get, context, &mask);
    if (error) return error;
    uint32_t wanted = index % mask.count;
    size_t selected = SIZE_MAX;
    for (size_t word = 0; word < mask.bytes / sizeof(*mask.words); ++word) {
        unsigned long bits = mask.words[word];
        for (unsigned bit = 0; bit < sizeof(bits) * CHAR_BIT; ++bit) {
            if (!(bits & (1UL << bit))) continue;
            if (wanted-- == 0) { selected = word * sizeof(bits) * CHAR_BIT + bit; break; }
        }
        if (selected != SIZE_MAX) break;
    }
    if (selected == SIZE_MAX || selected > INT_MAX) {
        rn_affinity_release(&mask); return -EOVERFLOW;
    }
    memset(mask.words, 0, mask.bytes);
    mask.words[selected / (sizeof(unsigned long) * CHAR_BIT)] =
        1UL << (selected % (sizeof(unsigned long) * CHAR_BIT));
    error = set(context, mask.bytes, mask.words);
    rn_affinity_release(&mask);
    return error ? (error < 0 ? error : -EIO) : (int)selected;
}
#ifdef __linux__
static inline int rn_affinity_get_linux(void *context, size_t bytes, void *mask) {
    (void)context;
    return sched_getaffinity(0, bytes, (cpu_set_t *)mask) < 0 ? -errno : 0;
}
static inline int rn_affinity_set_linux(void *context, size_t bytes, const void *mask) {
    (void)context;
    return sched_setaffinity(0, bytes, (const cpu_set_t *)mask) < 0 ? -errno : 0;
}
#endif
#endif
