/* Process-level signal coordination. Data path state remains worker-local. */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#endif
#endif
#include "reactor_group.h"
#include <errno.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sched.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#endif

/* Signal handlers must never call an atomic implementation that takes a lock.
 * These are universally lock-free on the supported x86/ARM targets. Fail the
 * build on any target that cannot provide the required safety contract. */
_Static_assert(ATOMIC_POINTER_LOCK_FREE == 2, "reactor group needs lock-free pointers");
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "reactor group needs lock-free integers");

struct rn_group {
    rn_reactor **reactors;
    size_t count;
    atomic_int stop;
    atomic_int wake_error;
    int installed;
    int restore_error;
#ifndef _WIN32
    struct sigaction previous;
#endif
};

static _Atomic(rn_group *) active_group = NULL;
static atomic_uint handler_readers = 0;
/* Control-thread ownership is serialized by the API, but this additional slot
 * rejects accidental installation of two groups without changing disposition. */
static atomic_int registration = 0;

static void save_wake_error(rn_group *group, int error) {
    int expected = 0;
    if (error < 0) (void)atomic_compare_exchange_strong_explicit(
        &group->wake_error, &expected, error, memory_order_seq_cst, memory_order_seq_cst);
}

int rn_group_request_stop(rn_group *group) {
    if (group == NULL) return -EINVAL;
    atomic_store_explicit(&group->stop, 1, memory_order_seq_cst);
    int first = 0;
    for (size_t i = 0; i < group->count; ++i) {
        int rc = rn_wake(group->reactors[i]);
        if (rc < 0 && first == 0) first = rc;
    }
    save_wake_error(group, first);
    return first;
}

/* Reader count comes BEFORE the pointer load. After unpublication, a handler
 * delayed before increment can only observe NULL; any handler that loaded the
 * old group is visible to the teardown barrier. Sequential consistency makes
 * the lifetime proof independent of the platform's memory ordering. */
static int request_from_handler(void) {
    atomic_fetch_add_explicit(&handler_readers, 1, memory_order_seq_cst);
    rn_group *group = atomic_load_explicit(&active_group, memory_order_seq_cst);
    if (group != NULL) (void)rn_group_request_stop(group);
    atomic_fetch_sub_explicit(&handler_readers, 1, memory_order_seq_cst);
    return group != NULL;
}

#ifdef _WIN32
static BOOL WINAPI group_console_handler(DWORD type) {
    if (type != CTRL_C_EVENT && type != CTRL_BREAK_EVENT) return FALSE;
    return request_from_handler() ? TRUE : FALSE;
}
static int win_error(void) {
    DWORD error = GetLastError();
    if (error == ERROR_NOT_ENOUGH_MEMORY || error == ERROR_OUTOFMEMORY) return -ENOMEM;
    if (error == ERROR_ACCESS_DENIED) return -EACCES;
    if (error == ERROR_INVALID_HANDLE) return -EBADF;
    if (error == ERROR_INVALID_PARAMETER) return -EINVAL;
    return -EIO;
}
#else
static void group_signal_handler(int signo) {
    (void)signo;
    int saved_errno = errno;
    (void)request_from_handler();
    errno = saved_errno;
}
#endif

static void wait_for_handlers(void) {
    while (atomic_load_explicit(&handler_readers, memory_order_seq_cst) != 0) {
#ifdef _WIN32
        (void)SwitchToThread();
#else
        (void)sched_yield();
#endif
    }
}

int rn_group_new(rn_reactor *const *reactors, size_t count, rn_group **out) {
    if (out == NULL) return -EINVAL;
    *out = NULL;
    if (reactors == NULL || count == 0 || count > 65536 || count > SIZE_MAX / sizeof(*reactors)) return -EINVAL;
    for (size_t i = 0; i < count; ++i) {
        if (reactors[i] == NULL) return -EINVAL;
        for (size_t j = 0; j < i; ++j) if (reactors[j] == reactors[i]) return -EINVAL;
    }
    rn_group *group = calloc(1, sizeof(*group));
    if (group == NULL) return -ENOMEM;
    group->reactors = malloc(count * sizeof(*group->reactors));
    if (group->reactors == NULL) { free(group); return -ENOMEM; }
    for (size_t i = 0; i < count; ++i) group->reactors[i] = reactors[i];
    group->count = count;
    atomic_init(&group->stop, 0);
    atomic_init(&group->wake_error, 0);
    *out = group;
    return 0;
}

int rn_group_install(rn_group *group) {
    if (group == NULL) return -EINVAL;
    if (group->installed) return -EALREADY;
    if (group->restore_error < 0) return group->restore_error;
    int expected = 0;
    if (!atomic_compare_exchange_strong_explicit(&registration, &expected, 1,
            memory_order_seq_cst, memory_order_seq_cst)) return -EBUSY;
    atomic_store_explicit(&group->stop, 0, memory_order_seq_cst);
    atomic_store_explicit(&group->wake_error, 0, memory_order_seq_cst);
    atomic_store_explicit(&active_group, group, memory_order_seq_cst);
#ifdef _WIN32
    if (!SetConsoleCtrlHandler(group_console_handler, TRUE)) {
        int error = win_error();
#else
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = group_signal_handler;
    /* Avoid nested handlers on the same thread while preserving delivery to
     * other worker threads. No SA_RESTART: reactor syscall policy stays Lean. */
    if (sigfillset(&action.sa_mask) < 0) {
        int error = -errno;
        atomic_store_explicit(&active_group, NULL, memory_order_seq_cst);
        wait_for_handlers();
        atomic_store_explicit(&registration, 0, memory_order_seq_cst);
        return error;
    }
    action.sa_flags = 0;
    if (sigaction(SIGINT, &action, &group->previous) < 0) {
        int error = -errno;
#endif
        atomic_store_explicit(&active_group, NULL, memory_order_seq_cst);
        wait_for_handlers();
        atomic_store_explicit(&registration, 0, memory_order_seq_cst);
        return error;
    }
    group->installed = 1;
    return 0;
}

int rn_group_stopping(const rn_group *group) {
    if (group == NULL) return -EINVAL;
    return atomic_load_explicit(&group->stop, memory_order_seq_cst) != 0;
}

int rn_group_take_wake_error(rn_group *group) {
    if (group == NULL) return -EINVAL;
    return atomic_exchange_explicit(&group->wake_error, 0, memory_order_seq_cst);
}

int rn_group_uninstall(rn_group *group) {
    if (group == NULL) return -EINVAL;
    if (!group->installed) return group->restore_error;
    int error = 0;
    if (atomic_load_explicit(&active_group, memory_order_seq_cst) != group) error = -EINVAL;
#ifdef _WIN32
    else if (!SetConsoleCtrlHandler(group_console_handler, FALSE)) error = win_error();
#else
    else if (sigaction(SIGINT, &group->previous, NULL) < 0) error = -errno;
#endif
    /* Even failed OS restoration must never leave a handler with access to
     * borrowed reactors that outer brackets are about to release. A failed
     * disposition is process-level corruption: report it and poison further
     * installs rather than saving our own stale callback as a prior handler. */
    atomic_store_explicit(&active_group, NULL, memory_order_seq_cst);
    wait_for_handlers();
    group->installed = 0;
    group->restore_error = error;
    atomic_store_explicit(&registration, error < 0 ? 2 : 0, memory_order_seq_cst);
    return error;
}

int rn_group_free(rn_group *group) {
    if (group == NULL) return -EINVAL;
    int rc = rn_group_uninstall(group);
    free(group->reactors);
    free(group);
    return rc;
}

int rn_group_cpu_count(uint32_t *out) {
    if (out == NULL) return -EINVAL;
#ifdef _WIN32
    DWORD count = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (count == 0) return win_error();
    *out = (uint32_t)count;
#else
    errno = 0;
    long count = sysconf(_SC_NPROCESSORS_ONLN);
    if (count <= 0) return errno != 0 ? -errno : -ENOSYS;
    if ((unsigned long)count > UINT32_MAX) return -EOVERFLOW;
    *out = (uint32_t)count;
#endif
    return 0;
}


struct rn_endpoint_claim {
#ifdef _WIN32
    HANDLE mutex;
#else
    int fd;
#endif
};

int rn_endpoint_acquire(uint16_t port, rn_endpoint_claim **out) {
    if (out == NULL) return -EINVAL;
    *out = NULL;
    if (port == 0) return -EINVAL;
    rn_endpoint_claim *claim = malloc(sizeof(*claim));
    if (claim == NULL) return -ENOMEM;
#ifdef _WIN32
    wchar_t name[64];
    int length = _snwprintf(name, 64, L"Local\\LeanNet-TCP-Port-%u", (unsigned)port);
    if (length < 0 || length >= 64) { free(claim); return -EOVERFLOW; }
    HANDLE mutex = CreateMutexW(NULL, FALSE, name);
    if (mutex == NULL) { int error = win_error(); free(claim); return error; }
    DWORD wait = WaitForSingleObject(mutex, 0);
    if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
        int error = wait == WAIT_TIMEOUT ? -EADDRINUSE : win_error();
        if (!CloseHandle(mutex)) error = win_error();
        free(claim);
        return error;
    }
    claim->mutex = mutex;
#else
    char path[128];
    int length = snprintf(path, sizeof(path), "/tmp/lean-net-%lu-tcp-%u.lock",
                          (unsigned long)geteuid(), (unsigned)port);
    if (length < 0 || (size_t)length >= sizeof(path)) { free(claim); return -EOVERFLOW; }
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) { int error = -errno; free(claim); return error; }
    int error = 0;
    struct stat status;
    if (fstat(fd, &status) < 0) error = -errno;
    else if (!S_ISREG(status.st_mode) || status.st_uid != geteuid() ||
             (status.st_mode & 0077) != 0 || status.st_nlink != 1) error = -EACCES;
    else if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        error = (errno == EWOULDBLOCK || errno == EAGAIN) ? -EADDRINUSE : -errno;
    }
    if (error < 0) {
        if (close(fd) < 0) error = -errno;
        free(claim);
        return error;
    }
    claim->fd = fd;
#endif
    *out = claim;
    return 0;
}

int rn_endpoint_release(rn_endpoint_claim *claim) {
    if (claim == NULL) return -EINVAL;
    int error = 0;
#ifdef _WIN32
    if (!ReleaseMutex(claim->mutex)) error = win_error();
    if (!CloseHandle(claim->mutex) && error == 0) error = win_error();
#else
    /* close releases flock. Never retry, including EINTR. */
    if (close(claim->fd) < 0) error = -errno;
#endif
    free(claim);
    return error;
}
