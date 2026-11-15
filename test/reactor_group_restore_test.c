/* Fault injection for failed OS handler restoration. Include the production
 * implementation with a function-like syscall wrapper; no production hooks. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#endif
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include "../c/reactor_group.h"

struct rn_reactor { atomic_int wakes; };
static int fail_restore;
static int fail_install;
static void prior_handler(int signo) { (void)signo; }
static int test_sigaction(int signo, const struct sigaction *action, struct sigaction *old) {
    if (fail_install && signo == SIGHUP && action != NULL && old != NULL) {
        fail_install = 0;
        errno = EINTR;
        return -1;
    }
    if (fail_restore && action != NULL && action->sa_handler == prior_handler) {
        fail_restore = 0;
        errno = EIO;
        return -1;
    }
    return sigaction(signo, action, old);
}
#define sigaction(...) test_sigaction(__VA_ARGS__)
#include "../c/reactor_group.c"
#undef sigaction

int rn_wake(rn_reactor *reactor) { atomic_fetch_add(&reactor->wakes, 1); return 0; }
static void check(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "group restoration test: %s\n", message); exit(1); }
}
int main(int argc, char **argv) {
    if (argc > 1) {
        int rollback_fails = strcmp(argv[1], "partial-install") == 0;
        struct sigaction prior = {0}, original[3];
        prior.sa_handler = prior_handler;
        check(sigemptyset(&prior.sa_mask) == 0, "partial-install mask");
        for (unsigned i = 0; i < 3; ++i)
            check(sigaction(group_signals[i], &prior, &original[i]) == 0, "partial-install prior");
        rn_reactor reactor = {0}; rn_reactor *pointer = &reactor;
        rn_group *group = NULL;
        check(rn_group_new(&pointer, 1, &group) == 0, "partial-install group");
        fail_install = 1;
        fail_restore = rollback_fails;
        check(rn_group_install(group) == (rollback_fails ? -EIO : -EINTR), "rollback restoration error takes precedence");
        check(rn_group_free(group) == (rollback_fails ? -EIO : 0), "rollback result remains visible on free");
        check(rn_group_new(&pointer, 1, &group) == 0, "group after failed rollback");
        check(rn_group_install(group) == (rollback_fails ? -EBUSY : 0), "rollback registration state");
        check(rn_group_free(group) == 0, "unregistered group after rollback");
        for (unsigned i = 0; i < 3; ++i) {
            check(raise(group_signals[i]) == 0, "safe signal after partial-install free");
            check(sigaction(group_signals[i], &original[i], NULL) == 0, "restore partial-install original");
        }
        puts("reactor group partial-install rollback test passed");
        return 0;
    }
    struct sigaction prior = {0}, original;
    prior.sa_handler = prior_handler;
    check(sigemptyset(&prior.sa_mask) == 0, "mask");
    check(sigaction(SIGINT, &prior, &original) == 0, "install prior handler");
    rn_reactor *reactor = calloc(1, sizeof(*reactor));
    check(reactor != NULL, "allocate reactor stub");
    rn_group *group = NULL;
    check(rn_group_new(&reactor, 1, &group) == 0, "create group");
    check(rn_group_install(group) == 0, "install group");
    fail_restore = 1;
    check(rn_group_free(group) == -EIO, "restoration error is reported");
    check(atomic_load(&reactor->wakes) == 0, "unexpected wake");
    /* Outer reactor brackets can now free descriptors and memory despite the
     * restoration error. The still-installed handler must see only NULL. */
    free(reactor);
    for (unsigned i = 0; i < 100; ++i) check(raise(SIGINT) == 0, "signal after free");
    rn_reactor other = {0}; rn_reactor *pointer = &other;
    check(rn_group_new(&pointer, 1, &group) == 0, "create after failed restoration");
    check(rn_group_install(group) == -EBUSY, "failed OS state poisons subsequent registration");
    check(rn_group_free(group) == 0, "uninstalled group free");
    check(sigaction(SIGINT, &original, NULL) == 0, "restore original handler manually");
    puts("reactor group failed-restoration lifetime test passed");
    return 0;
}
