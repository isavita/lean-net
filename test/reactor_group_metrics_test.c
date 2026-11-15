/* Process gauges must count live owned descriptors, rather than capacity. */
#define _POSIX_C_SOURCE 200809L
#if defined(__linux__)
#define _GNU_SOURCE 1
#include <sched.h>
#endif
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../c/reactor_group.h"
#if defined(__linux__)
#include "../c/reactor_affinity.h"
#endif

int rn_wake(rn_reactor *reactor) { (void)reactor; return 0; }

static void check(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "group metrics test: %s\n", message); exit(1); }
}

int main(void) {
    uint32_t cpus = 0;
    check(rn_group_cpu_count(&cpus) == 0 && cpus > 0, "positive CPU count");
    check(rn_process_resident_bytes() > 0, "positive resident bytes");
    check(rn_process_open_fds() >= 0, "initial descriptor query");
    int64_t baseline = rn_process_open_fds();
    check(baseline >= 0, "descriptor baseline");
    int ends[2];
    check(pipe(ends) == 0, "owned pipe");
    check(rn_process_open_fds() == baseline + 2, "pipe adds exactly two descriptors");
    char name[] = "/tmp/lean-net-group-metrics-XXXXXX";
    int file = mkstemp(name);
    check(file >= 0, "owned regular file");
    check(unlink(name) == 0, "unlink owned regular file");
    check(rn_process_open_fds() == baseline + 3, "file adds exactly one descriptor");
    int duplicate = dup(file);
    check(duplicate >= 0, "duplicate file descriptor");
    check(rn_process_open_fds() == baseline + 4, "duplicate is counted separately");
    check(close(ends[0]) == 0 && close(ends[1]) == 0, "close pipe");
    check(rn_process_open_fds() == baseline + 2, "closed pipe disappears");
    check(close(file) == 0 && close(duplicate) == 0, "close files");
    check(rn_process_open_fds() == baseline, "all owned descriptors released");
#if defined(__linux__)
    /* This fixture is a private child process. Restrict only its own thread,
     * then restore its original mask; never change another task or cgroup. */
    rn_affinity original = {0};
    check(rn_affinity_load(rn_affinity_get_linux, NULL, &original) == 0, "original affinity");
    int selected = rn_pin_current_thread(0);
    check(selected >= 0, "restrict own fixture thread to an allowed CPU");
    check(rn_group_cpu_count(&cpus) == 0 && cpus == 1, "automatic hint respects one allowed CPU");
    check(rn_pin_current_thread(0) == selected && rn_pin_current_thread(100) == selected,
          "pinning uses real allowed CPU IDs modulo the allowed set");
    check(rn_affinity_set_linux(NULL, original.bytes, original.words) == 0, "restore own affinity");
    rn_affinity_release(&original);
#endif
    puts("reactor group process metrics test passed");
    return 0;
}
