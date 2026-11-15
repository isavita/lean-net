/* Process-level signal coordination. Data path state remains worker-local. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
/* sched_getaffinity/CPU_SET for cpuset-aware worker counts and pinning. */
#define _GNU_SOURCE 1
#endif
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
#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/thread_policy.h>
#include <libproc.h>
#endif
#if defined(__linux__)
#include <dirent.h>
#endif
#ifdef _WIN32
#ifndef PSAPI_VERSION
#define PSAPI_VERSION 2 /* K32GetProcessMemoryInfo lives in kernel32 */
#endif
#include <psapi.h>
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
    /* SIGINT/SIGTERM drain gracefully; SIGHUP requests a configuration reload. */
    struct sigaction previous[3];
#endif
};
#ifndef _WIN32
static const int group_signals[3] = {SIGINT, SIGTERM, SIGHUP};
#endif
/* Monotonic SIGHUP counter. Lean control code compares it with the value it
 * last served; the handler only performs a lock-free increment. */
static atomic_uint_fast64_t reload_requests = 0;
_Static_assert(ATOMIC_LLONG_LOCK_FREE == 2, "reload requests need lock-free 64-bit counters");

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
    /* CTRL_CLOSE/LOGOFF/SHUTDOWN terminate the process when the handler
     * returns, so only the interactive stop events start a graceful drain. */
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
    int saved_errno = errno;
    if (signo == SIGHUP) atomic_fetch_add_explicit(&reload_requests, 1, memory_order_seq_cst);
    else (void)request_from_handler();
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
    int error = 0;
    int installed = 0;
    for (; installed < 3; ++installed) {
        if (sigaction(group_signals[installed], &action, &group->previous[installed]) < 0) {
            error = -errno;
            break;
        }
    }
    if (error) {
        /* Restore every disposition installed before the failure. */
        while (installed-- > 0) (void)sigaction(group_signals[installed], &group->previous[installed], NULL);
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

int rn_group_process_stopping(void) {
    /* Same lifetime protocol as the signal handler: uninstall waits for us. */
    atomic_fetch_add_explicit(&handler_readers, 1, memory_order_seq_cst);
    rn_group *group = atomic_load_explicit(&active_group, memory_order_seq_cst);
    int stopping = group != NULL && atomic_load_explicit(&group->stop, memory_order_seq_cst) != 0;
    atomic_fetch_sub_explicit(&handler_readers, 1, memory_order_seq_cst);
    return stopping;
}

uint64_t rn_group_reload_requests(void) {
    return (uint64_t)atomic_load_explicit(&reload_requests, memory_order_seq_cst);
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
    else {
        for (int index = 2; index >= 0; --index)
            if (sigaction(group_signals[index], &group->previous[index], NULL) < 0 && error == 0) error = -errno;
    }
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
#if defined(__linux__) && defined(CPU_SETSIZE)
    /* Respect cpusets (containers, taskset): count CPUs this process may use. */
    cpu_set_t allowed;
    if (sched_getaffinity(0, sizeof(allowed), &allowed) == 0) {
        int usable = CPU_COUNT(&allowed);
        if (usable > 0) { *out = (uint32_t)usable; return 0; }
    }
#endif
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

#ifndef EOPNOTSUPP
#define EOPNOTSUPP ENOTSUP
#endif
/* Pin the calling thread to the index-th CPU (modulo) of the process's allowed
 * set. Returns the selected CPU number, or negative errno. macOS exposes only
 * affinity tags (a scheduling hint; unsupported on Apple silicon). */
int rn_pin_current_thread(uint32_t index) {
#if defined(__linux__) && defined(CPU_SETSIZE)
    cpu_set_t allowed;
    if (sched_getaffinity(0, sizeof(allowed), &allowed) < 0) return -errno;
    int count = CPU_COUNT(&allowed);
    if (count <= 0) return -EINVAL;
    int wanted = (int)(index % (uint32_t)count), seen = 0;
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (!CPU_ISSET(cpu, &allowed)) continue;
        if (seen++ != wanted) continue;
        cpu_set_t one;
        CPU_ZERO(&one);
        CPU_SET(cpu, &one);
        /* pid 0 selects the calling thread on Linux. */
        if (sched_setaffinity(0, sizeof(one), &one) < 0) return -errno;
        return cpu;
    }
    return -EINVAL;
#elif defined(__APPLE__)
    thread_affinity_policy_data_t policy = { (integer_t)index + 1 };
    mach_port_t thread = mach_thread_self();
    kern_return_t result = thread_policy_set(thread, THREAD_AFFINITY_POLICY,
        (thread_policy_t)&policy, THREAD_AFFINITY_POLICY_COUNT);
    (void)mach_port_deallocate(mach_task_self(), thread);
    if (result == KERN_NOT_SUPPORTED) return -EOPNOTSUPP;
    return result == KERN_SUCCESS ? (int)index : -EINVAL;
#elif defined(_WIN32)
    DWORD_PTR process = 0, system = 0;
    if (!GetProcessAffinityMask(GetCurrentProcess(), &process, &system)) return win_error();
    unsigned count = 0;
    for (unsigned bit = 0; bit < sizeof(process) * 8; ++bit) if (process & ((DWORD_PTR)1 << bit)) ++count;
    if (count == 0) return -EINVAL;
    unsigned wanted = index % count, seen = 0;
    for (unsigned bit = 0; bit < sizeof(process) * 8; ++bit) {
        if (!(process & ((DWORD_PTR)1 << bit))) continue;
        if (seen++ != wanted) continue;
        if (!SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)1 << bit)) return win_error();
        return (int)bit;
    }
    return -EINVAL;
#else
    (void)index;
    return -EOPNOTSUPP;
#endif
}

/* Current resident set size in bytes, or negative errno. */
int64_t rn_process_resident_bytes(void) {
#if defined(__linux__)
    /* Plain read/parse: avoids stdio symbol versions newer than Lean's sysroot. */
    int fd = open("/proc/self/statm", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    char text[128];
    ssize_t length = read(fd, text, sizeof(text) - 1);
    int read_error = length < 0 ? errno : 0;
    if (close(fd) < 0 && read_error == 0) read_error = errno;
    if (read_error) return -read_error;
    text[length] = 0;
    const char *cursor = text;
    while (*cursor >= '0' && *cursor <= '9') ++cursor; /* total size */
    if (*cursor != ' ') return -EIO;
    ++cursor;
    unsigned long long resident = 0;
    if (*cursor < '0' || *cursor > '9') return -EIO;
    while (*cursor >= '0' && *cursor <= '9') resident = resident * 10 + (unsigned long long)(*cursor++ - '0');
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) return -EINVAL;
    return (int64_t)(resident * (unsigned long long)page);
#elif defined(__APPLE__)
    mach_task_basic_info_data_t info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &count) != KERN_SUCCESS) return -EIO;
    return (int64_t)info.resident_size;
#elif defined(_WIN32)
    PROCESS_MEMORY_COUNTERS counters;
    if (!K32GetProcessMemoryInfo(GetCurrentProcess(), &counters, sizeof(counters))) return win_error();
    return (int64_t)counters.WorkingSetSize;
#else
    return -ENOSYS;
#endif
}

/* Open descriptors (POSIX) or kernel handles (Windows), or negative errno. */
int64_t rn_process_open_fds(void) {
#if defined(__linux__)
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) return -errno;
    int64_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) if (entry->d_name[0] != '.') ++count;
    if (closedir(directory) != 0) return -errno;
    return count > 0 ? count - 1 : 0; /* exclude the directory stream itself */
#elif defined(__APPLE__)
    int bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0);
    if (bytes < 0) return -errno;
    return (int64_t)bytes / (int64_t)PROC_PIDLISTFD_SIZE;
#elif defined(_WIN32)
    DWORD handles = 0;
    if (!GetProcessHandleCount(GetCurrentProcess(), &handles)) return win_error();
    return (int64_t)handles;
#else
    return -ENOSYS;
#endif
}
