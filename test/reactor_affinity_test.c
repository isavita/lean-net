/* Pure startup mask fixtures: no host affinity or process state is changed. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
static unsigned allocations, frees, live, fail_allocation;
static void *test_malloc(size_t bytes) {
    ++allocations;
    if (fail_allocation && allocations == fail_allocation) return NULL;
    void *result = malloc(bytes);
    if (result) ++live;
    return result;
}
static void test_free(void *pointer) {
    if (pointer) { ++frees; --live; }
    free(pointer);
}
#define malloc(...) test_malloc(__VA_ARGS__)
#define free(...) test_free(__VA_ARGS__)
#include "../c/reactor_affinity.h"
#undef malloc
#undef free

typedef struct { size_t minimum; int get_error, set_error, empty; unsigned gets, sets; int selected; } fixture;
static int get_mask(void *context, size_t bytes, void *mask) {
    fixture *f = context; ++f->gets;
    if (f->get_error) return f->get_error;
    if (bytes < f->minimum) return -EINVAL;
    if (!f->empty) {
        unsigned long *words = mask;
        unsigned width = sizeof(unsigned long) * CHAR_BIT;
        words[42 / width] |= 1UL << (42 % width);
        words[5000 / width] |= 1UL << (5000 % width);
    }
    return 0;
}
static int set_mask(void *context, size_t bytes, const void *mask) {
    fixture *f = context; ++f->sets;
    const unsigned long *words = mask;
    unsigned count = 0, width = sizeof(unsigned long) * CHAR_BIT;
    for (size_t word = 0; word < bytes / sizeof(*words); ++word)
        for (unsigned bit = 0; bit < width; ++bit)
            if (words[word] & (1UL << bit)) { ++count; f->selected = (int)(word * width + bit); }
    if (count != 1) return -EIO;
    return f->set_error;
}
static void check(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "affinity test: %s\n", message); exit(1); }
}
int main(void) {
    fixture f = {.minimum = 1024};
    rn_affinity mask = {0};
    check(rn_affinity_load(get_mask, &f, &mask) == 0 && mask.count == 2 &&
          mask.bytes == 1024 && f.gets == 4, "resize to noncontiguous high CPU IDs");
    rn_affinity_release(&mask);
    for (unsigned i = 0; i < 4; ++i) {
        f = (fixture){.minimum = 1024};
        int expected = i % 2 ? 5000 : 42;
        check(rn_affinity_pin(get_mask, set_mask, &f, i) == expected &&
              f.selected == expected && f.sets == 1, "select only allowed CPU IDs modulo count");
    }
    const int errors[] = {-EINTR, -EACCES, -EIO, 1};
    for (unsigned i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        int expected = errors[i] < 0 ? errors[i] : -EIO;
        f = (fixture){.minimum = 1024, .get_error = errors[i]};
        check(rn_affinity_load(get_mask, &f, &mask) == expected && f.gets == 1 && !live,
              "real getter errors are not retried/fallen back");
        f = (fixture){.minimum = 1024, .set_error = errors[i]};
        check(rn_affinity_pin(get_mask, set_mask, &f, 1) == expected && f.sets == 1 && !live,
              "setter errno preserved and mask freed once");
    }
    f = (fixture){.minimum = 1024, .empty = 1};
    check(rn_affinity_load(get_mask, &f, &mask) == -EINVAL && f.gets == 4 && !live,
          "empty successful mask is invalid without retries");
    f = (fixture){.minimum = RN_AFFINITY_MAX_BYTES * 2};
    check(rn_affinity_load(get_mask, &f, &mask) == -EOVERFLOW && f.gets == 10 && !live,
          "mask byte cap bounds EINVAL growth");
    for (unsigned attempt = 1; attempt <= 4; ++attempt) {
        allocations = frees = live = 0; fail_allocation = attempt;
        f = (fixture){.minimum = 1024};
        check(rn_affinity_load(get_mask, &f, &mask) == -ENOMEM &&
              f.gets == attempt - 1 && !live && frees == attempt - 1,
              "every allocation failure releases all earlier masks");
    }
    puts("reactor dynamic affinity fixtures passed");
    return 0;
}
