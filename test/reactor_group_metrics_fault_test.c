/* libproc returns zero with errno on failure; never hide it as an FD count. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include <errno.h>
#include <libproc.h>
#include <stdio.h>
#include <stdlib.h>
#include "../c/reactor_group.h"

static unsigned mode, calls;
static int test_proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int bytes) {
    (void)pid; (void)flavor; (void)arg;
    ++calls;
    if (buffer == NULL) {
        if (mode == 0) { errno = EINTR; return 0; }
        if (mode == 1) return 1;
        if (mode == 2) return 32 * 1024 * 1024;
        return 8 * PROC_PIDLISTFD_SIZE;
    }
    if (mode == 3) { errno = EIO; return 0; }
    if (mode == 4) return bytes;
    if (mode == 5) return 1;
    return 3 * PROC_PIDLISTFD_SIZE;
}
#define proc_pidinfo(...) test_proc_pidinfo(__VA_ARGS__)
#include "../c/reactor_group.c"
#undef proc_pidinfo

int rn_wake(rn_reactor *reactor) { (void)reactor; return 0; }
static void check(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "group metrics fault test: %s\n", message); exit(1); }
}
int main(void) {
    static const int64_t expected[] = {-EINTR, -EIO, -EOVERFLOW, -EIO, -ENOBUFS, -EIO, 3};
    for (mode = 0; mode < sizeof(expected) / sizeof(expected[0]); ++mode) {
        calls = 0;
        check(rn_process_open_fds() == expected[mode], "query/count/failure result");
        check(calls == (mode < 3 ? 1U : 2U), "no hidden syscall retries");
    }
    puts("reactor group process metrics fault test passed");
    return 0;
}
