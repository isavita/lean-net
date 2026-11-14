/* Signal publication/lifetime regression, independent of a reactor backend.
 * Link reactor_group.c with this wake stub. Run under AddressSanitizer to catch
 * late signal readers touching a group after its immutable array was freed. */
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#endif
#include "../c/reactor_group.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>

struct rn_reactor { atomic_int wakes; atomic_int error; };
static atomic_int previous_calls;
static atomic_int running;
static pthread_t receivers[2];

int rn_wake(rn_reactor *reactor) {
    atomic_fetch_add_explicit(&reactor->wakes, 1, memory_order_relaxed);
    return atomic_load_explicit(&reactor->error, memory_order_relaxed);
}
static void check(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "reactor group test: %s\n", message); exit(1); }
}
static void previous_handler(int signo) {
    (void)signo;
    atomic_fetch_add_explicit(&previous_calls, 1, memory_order_relaxed);
}
static void *receiver(void *arg) {
    (void)arg;
    while (atomic_load_explicit(&running, memory_order_relaxed)) (void)sched_yield();
    return NULL;
}
static void *sender(void *arg) {
    (void)arg;
    const struct timespec pause = {0, 100000};
    unsigned i = 0;
    while (atomic_load_explicit(&running, memory_order_relaxed)) {
        check(pthread_kill(receivers[i++ % 2], SIGINT) == 0, "pthread_kill");
        (void)nanosleep(&pause, NULL);
    }
    return NULL;
}
int main(void) {
    struct sigaction previous = {0}, original, actual;
    previous.sa_handler = previous_handler;
    check(sigemptyset(&previous.sa_mask) == 0, "empty signal mask");
    check(sigaction(SIGINT, &previous, &original) == 0, "install test previous handler");
    struct rn_reactor a = {0}, b = {0};
    rn_reactor *reactors[] = {&a, &b};
    rn_group *group = NULL, *second = NULL;
    uint32_t cpus = 0;
    check(rn_group_cpu_count(&cpus) == 0 && cpus > 0, "active CPU count");
    check(rn_group_new(NULL, 0, &group) == -EINVAL && group == NULL, "reject empty group");
    rn_reactor *duplicates[] = {&a, &a};
    check(rn_group_new(duplicates, 2, &group) == -EINVAL, "reject duplicate reactor");
    check(rn_group_new(reactors, 2, &group) == 0, "create group");
    check(rn_group_new(reactors, 2, &second) == 0, "create second group");
    check(rn_group_stopping(group) == 0, "initial state");
    check(rn_group_install(group) == 0, "install group");
    check(rn_group_install(group) == -EALREADY, "reject duplicate install");
    check(rn_group_install(second) == -EBUSY, "reject competing group");
    check(rn_group_free(second) == 0, "free uninstalled second group");
    check(raise(SIGINT) == 0, "raise SIGINT");
    check(rn_group_stopping(group) == 1, "signal sets stop flag");
    check(atomic_load(&a.wakes) == 1 && atomic_load(&b.wakes) == 1, "signal wakes every reactor");
    atomic_store(&b.error, -EINTR);
    check(rn_group_request_stop(group) == -EINTR, "wake errors surfaced");
    check(atomic_load(&a.wakes) == 2 && atomic_load(&b.wakes) == 2, "wake failure does not skip reactors");
    check(rn_group_take_wake_error(group) == -EINTR && rn_group_take_wake_error(group) == 0, "wake error fetch-clear");
    atomic_store(&b.error, 0);
    check(rn_group_uninstall(group) == 0, "uninstall group");
    check(sigaction(SIGINT, NULL, &actual) == 0 && actual.sa_handler == previous_handler, "restore previous disposition");
    check(raise(SIGINT) == 0 && atomic_load(&previous_calls) == 1, "previous handler works");
    check(rn_group_free(group) == 0, "free group");

    /* One process claim encloses all workers sharing SO_REUSEPORT. A second
     * open description (even in the same process) must conflict. */
    uint16_t port = (uint16_t)(30000u + (unsigned)getpid() % 20000u);
    rn_endpoint_claim *claim = NULL, *competing = NULL;
    check(rn_endpoint_acquire(0, &claim) == -EINVAL && claim == NULL, "reject ephemeral port claim");
    check(rn_endpoint_acquire(port, &claim) == 0, "claim endpoint");
    check(rn_endpoint_acquire(port, &competing) == -EADDRINUSE && competing == NULL, "same-process endpoint conflict");
    pid_t child = fork();
    check(child >= 0, "fork competing process");
    if (child == 0) {
        rn_endpoint_claim *other = NULL;
        int rc = rn_endpoint_acquire(port, &other);
        if (rc == 0) (void)rn_endpoint_release(other);
        _exit(rc == -EADDRINUSE ? 0 : 1);
    }
    int status = 0;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "cross-process endpoint conflict");
    check(rn_endpoint_release(claim) == 0, "release endpoint");
    check(rn_endpoint_acquire(port, &claim) == 0, "reacquire released endpoint");
    check(rn_endpoint_release(claim) == 0, "release reacquired endpoint");
    child = fork();
    check(child >= 0, "fork crashed owner");
    if (child == 0) {
        rn_endpoint_claim *orphan = NULL;
        _exit(rn_endpoint_acquire(port, &orphan) == 0 ? 0 : 1);
    }
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "crashed owner obtained claim");
    check(rn_endpoint_acquire(port, &claim) == 0, "process exit releases claim");
    check(rn_endpoint_release(claim) == 0, "release after crashed owner");

    char target[] = "/tmp/lean-net-group-sentinel-XXXXXX";
    int sentinel = mkstemp(target);
    check(sentinel >= 0, "create lock safety sentinel");
    check(write(sentinel, "SAFE", 4) == 4 && close(sentinel) == 0, "write lock safety sentinel");
    char lock_path[128]; int made_link = 0;
    for (unsigned candidate = 50000; candidate < 65000; ++candidate) {
        (void)snprintf(lock_path, sizeof(lock_path), "/tmp/lean-net-%lu-tcp-%u.lock", (unsigned long)geteuid(), candidate);
        if (symlink(target, lock_path) == 0) {
            check(rn_endpoint_acquire((uint16_t)candidate, &claim) < 0 && claim == NULL, "reject symlink lockfile");
            check(unlink(lock_path) == 0, "remove owned test symlink");
            made_link = 1; break;
        }
        check(errno == EEXIST, "create owned test symlink");
    }
    check(made_link, "find unused test lock path");
    sentinel = open(target, O_RDONLY);
    char contents[4];
    check(sentinel >= 0 && read(sentinel, contents, 4) == 4 && memcmp(contents, "SAFE", 4) == 0, "symlink target unchanged");
    check(close(sentinel) == 0 && unlink(target) == 0, "remove owned safety sentinel");

    atomic_store(&running, 1);
    for (size_t i = 0; i < 2; ++i) check(pthread_create(&receivers[i], NULL, receiver, NULL) == 0, "create signal target");
    pthread_t source;
    check(pthread_create(&source, NULL, sender, NULL) == 0, "create signal source");
    for (unsigned i = 0; i < 10000; ++i) {
        check(rn_group_new(reactors, 2, &group) == 0, "stress create");
        check(rn_group_install(group) == 0, "stress install");
        check(rn_group_request_stop(group) == 0, "stress explicit stop");
        check(rn_group_free(group) == 0, "stress restore and free");
    }
    atomic_store(&running, 0);
    check(pthread_join(source, NULL) == 0, "join signal source");
    for (size_t i = 0; i < 2; ++i) check(pthread_join(receivers[i], NULL) == 0, "join signal target");
    check(sigaction(SIGINT, NULL, &actual) == 0 && actual.sa_handler == previous_handler, "stress restores previous handler");
    check(sigaction(SIGINT, &original, NULL) == 0, "restore original handler");
    puts("reactor group signal, wake error and lifetime tests passed");
    return 0;
}
