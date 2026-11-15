#ifndef _WIN32
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#else
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#endif
#include "access_log.h"
#include <errno.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wchar.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
extern char **environ;
#endif

_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "logging lanes require lock-free indices");
_Static_assert(ATOMIC_LLONG_LOCK_FREE == 2, "logging snapshots require lock-free counters");
_Static_assert(ATOMIC_LONG_LOCK_FREE == 2 && sizeof(uint_fast64_t) == 8,
               "logging snapshots require lock-free 64-bit fast integers");
#define OB_MAGIC UINT64_C(0x4c4e45544c4f4731)
typedef struct {
  uint64_t timestamp_ms, duration_us, bytes_sent;
  uint32_t status, protocol, outcome, flags, method_length, target_length;
  uint8_t method[OB_METHOD_BYTES], target[OB_TARGET_BYTES];
} ob_cell;
typedef struct {
  atomic_uint head, tail;
  atomic_uint_fast64_t snapshot_version;
  atomic_uint_fast64_t metrics[OB_METRICS];
  atomic_uint_fast64_t accepted, dropped, written;
} ob_lane;
typedef struct {
  uint64_t magic, memory_bytes, file_bytes;
  uint32_t workers, capacity, files, poll_ms;
  atomic_int ready, stop, error;
  atomic_uint_fast64_t io_errors;
  char path[4096];
} ob_shared;
struct ob_hub {
  ob_shared *shared;
  size_t bytes;
  int mapped, logging, stopping, killed, terminal, transferred;
  int error;
  int init_error;
  uint64_t deadline, kill_deadline;
#ifdef _WIN32
  HANDLE mapping, process;
#else
  pid_t child;
  int mapping_fd;
  char mapping_name[96];
#endif
};
static atomic_int helper_slot = 0;
#ifdef _WIN32
static HANDLE orphan_process;
static int ob_win_error(DWORD error) {
  switch (error) {
  case ERROR_FILE_NOT_FOUND:
  case ERROR_PATH_NOT_FOUND:
    return -ENOENT;
  case ERROR_ACCESS_DENIED:
    return -EACCES;
  case ERROR_INVALID_HANDLE:
    return -EBADF;
  case ERROR_INVALID_PARAMETER:
    return -EINVAL;
  case ERROR_NOT_ENOUGH_MEMORY:
  case ERROR_OUTOFMEMORY:
    return -ENOMEM;
  case ERROR_SHARING_VIOLATION:
    return -EBUSY;
  case ERROR_DISK_FULL:
    return -ENOSPC;
  case ERROR_OPERATION_ABORTED:
    return -EINTR;
  case ERROR_BROKEN_PIPE:
    return -EPIPE;
  default:
    return -EIO;
  }
}
static wchar_t *ob_wide(const char *text) {
  size_t bytes = strlen(text);
  if (bytes > INT_MAX)
    return NULL;
  int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, (int)bytes, NULL, 0);
  if (!n)
    return NULL;
  wchar_t *wide = malloc(((size_t)n + 1) * sizeof(*wide));
  if (!wide)
    return NULL;
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, (int)bytes, wide, n)) {
    free(wide);
    return NULL;
  }
  wide[n] = 0;
  return wide;
}
#else
static pid_t orphan_process;
#endif
static int ob_clock(uint64_t *value) {
#ifdef _WIN32
  *value = GetTickCount64();
  return 0;
#else
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now))
    return -errno;
  *value = (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
  return 0;
#endif
}
static ob_lane *ob_lanes(ob_shared *shared) { return (ob_lane *)(shared + 1); }
static ob_cell *ob_cells(ob_shared *shared, uint32_t worker) {
  return (ob_cell *)(ob_lanes(shared) + shared->workers) + (size_t)worker * shared->capacity;
}
static uint64_t ob_add(uint64_t a, uint64_t b) { return b > UINT64_MAX - a ? UINT64_MAX : a + b; }
static void ob_increment(atomic_uint_fast64_t *field, uint64_t amount) {
  atomic_store_explicit(field, ob_add(atomic_load_explicit(field, memory_order_relaxed), amount),
                        memory_order_relaxed);
}
static void ob_fail(ob_shared *shared, int error) {
  int expected = 0;
  if (error >= 0)
    error = -EIO;
  if (atomic_compare_exchange_strong(&shared->error, &expected, error))
    atomic_fetch_add(&shared->io_errors, 1);
}
static int ob_claim_helper(void) {
  /* Cold control operations are serialized. A timed-out kernel-stalled child
     retains this single slot until the next startup can reap it. */
  if (orphan_process) {
#ifdef _WIN32
    DWORD state = WaitForSingleObject(orphan_process, 0);
    if (state == WAIT_FAILED)
      return ob_win_error(GetLastError());
    if (state != WAIT_OBJECT_0)
      return -EBUSY;
    HANDLE old = orphan_process;
    orphan_process = NULL;
    if (!CloseHandle(old))
      return ob_win_error(GetLastError());
#else
    int status;
    pid_t result = waitpid(orphan_process, &status, WNOHANG);
    if (result < 0) {
      int error = -errno;
      if (error == -ECHILD) {
        orphan_process = 0;
        atomic_store(&helper_slot, 0);
      }
      return error;
    }
    if (!result)
      return -EBUSY;
    orphan_process = 0;
#endif
    atomic_store(&helper_slot, 0);
  }
  int expected = 0;
  return atomic_compare_exchange_strong(&helper_slot, &expected, 1) ? 0 : -EBUSY;
}
int ob_new(uint32_t workers, uint32_t capacity, const char *path, const char *helper,
           uint64_t file_bytes, uint32_t files, uint32_t poll_ms, ob_hub **out) {
  if (!out)
    return -EINVAL;
  *out = NULL;
  if (!path || !helper || !workers || workers > 256)
    return -EINVAL;
  int logging = path[0] != 0;
  if (logging &&
      (!helper[0] || strlen(path) >= 4096 || strlen(helper) > 32760 || !capacity ||
       capacity > 65536 || (capacity & (capacity - 1)) || file_bytes < 4096 ||
       file_bytes > UINT64_C(1073741824) || !files || files > 16 || !poll_ms || poll_ms > 1000))
    return -EINVAL;
  if (!logging)
    capacity = 0;
  size_t bytes = sizeof(ob_shared) + (size_t)workers * sizeof(ob_lane) +
                 (size_t)workers * capacity * sizeof(ob_cell);
  if (bytes > OB_MAX_MEMORY)
    return -E2BIG;
  int error = logging ? ob_claim_helper() : 0;
#ifndef _WIN32
  int fd = -1;
#endif
  if (error)
    return error;
  ob_hub *hub = calloc(1, sizeof(*hub));
  if (!hub) {
    if (logging)
      atomic_store(&helper_slot, 0);
    return -ENOMEM;
  }
  hub->bytes = bytes;
  hub->logging = logging;
#ifndef _WIN32
  hub->mapping_fd = -1;
#endif
  if (!logging) {
    hub->shared = calloc(1, bytes);
    if (!hub->shared) {
      free(hub);
      return -ENOMEM;
    }
  } else {
#ifdef _WIN32
    SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
    hub->mapping =
        CreateFileMappingW(INVALID_HANDLE_VALUE, &security, PAGE_READWRITE, 0, (DWORD)bytes, NULL);
    if (!hub->mapping) {
      error = ob_win_error(GetLastError());
      goto failure;
    }
    hub->shared = MapViewOfFile(hub->mapping, FILE_MAP_ALL_ACCESS, 0, 0, bytes);
    if (!hub->shared) {
      error = ob_win_error(GetLastError());
      goto failure;
    }
    hub->mapped = 1;
#else
    static unsigned serial;
    char name[96];
    int length = snprintf(name, sizeof(name), "/lean-net-log-%ld-%u", (long)getpid(), ++serial);
    if (length <= 0 || (size_t)length >= sizeof(name)) {
      error = -EOVERFLOW;
      goto failure;
    }
    fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
      error = -errno;
      goto failure;
    }
    memcpy(hub->mapping_name, name, (size_t)length + 1);
    if (ftruncate(fd, (off_t)bytes)) {
      error = -errno;
      goto failure;
    }
    void *memory = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (memory == MAP_FAILED) {
      error = -errno;
      goto failure;
    }
    hub->shared = memory;
    hub->mapped = 1;
#endif
  }
  ob_shared *shared = hub->shared;
  shared->magic = OB_MAGIC;
  shared->memory_bytes = bytes;
  shared->file_bytes = file_bytes;
  shared->workers = workers;
  shared->capacity = capacity;
  shared->files = files;
  shared->poll_ms = poll_ms;
  atomic_init(&shared->ready, logging ? 0 : 1);
  atomic_init(&shared->stop, 0);
  atomic_init(&shared->error, 0);
  atomic_init(&shared->io_errors, 0);
  memcpy(shared->path, path, strlen(path) + 1);
  for (uint32_t i = 0; i < workers; ++i) {
    ob_lane *lane = &ob_lanes(shared)[i];
    atomic_init(&lane->head, 0);
    atomic_init(&lane->tail, 0);
    atomic_init(&lane->snapshot_version, 0);
    atomic_init(&lane->accepted, 0);
    atomic_init(&lane->dropped, 0);
    atomic_init(&lane->written, 0);
    for (uint32_t j = 0; j < OB_METRICS; ++j)
      atomic_init(&lane->metrics[j], 0);
  }
  if (logging) {
#ifdef _WIN32
    wchar_t *program = ob_wide(helper);
    if (!program || wcschr(program, L'"')) {
      free(program);
      error = -EINVAL;
      goto failure;
    }
    size_t command_size = wcslen(program) + 128;
    wchar_t *command = calloc(command_size, sizeof(*command));
    if (!command) {
      free(program);
      error = -ENOMEM;
      goto failure;
    }
    int count =
        swprintf(command, command_size, L"\"%ls\" --lean-net-access-log-helper %llu %llu", program,
                 (unsigned long long)(uintptr_t)hub->mapping, (unsigned long long)bytes);
    if (count < 0) {
      free(program);
      free(command);
      error = -EINVAL;
      goto failure;
    }
    STARTUPINFOEXW startup;
    memset(&startup, 0, sizeof(startup));
    startup.StartupInfo.cb = sizeof(startup);
    SIZE_T attribute_bytes = 0;
    if (InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_bytes) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
      free(program);
      free(command);
      error = -EIO;
      goto failure;
    }
    startup.lpAttributeList = malloc(attribute_bytes);
    if (!startup.lpAttributeList) {
      free(program);
      free(command);
      error = -ENOMEM;
      goto failure;
    }
    if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &attribute_bytes)) {
      error = ob_win_error(GetLastError());
      free(startup.lpAttributeList);
      free(program);
      free(command);
      goto failure;
    }
    BOOL configured =
        UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                  &hub->mapping, sizeof(hub->mapping), NULL, NULL);
    PROCESS_INFORMATION process;
    memset(&process, 0, sizeof(process));
    BOOL started = configured && CreateProcessW(program, command, NULL, NULL, TRUE,
                                                EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                                                NULL, NULL, &startup.StartupInfo, &process);
    DWORD spawn_error = GetLastError();
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    free(startup.lpAttributeList);
    free(program);
    free(command);
    if (!started) {
      error = ob_win_error(spawn_error);
      goto failure;
    }
    hub->process = process.hProcess;
    if (!SetHandleInformation(hub->mapping, HANDLE_FLAG_INHERIT, 0))
      ob_fail(shared, ob_win_error(GetLastError()));
    if (!CloseHandle(process.hThread))
      ob_fail(shared, ob_win_error(GetLastError()));
#else
    if (fd == 3) {
      int duplicate = fcntl(fd, F_DUPFD_CLOEXEC, 4);
      if (duplicate < 0) {
        error = -errno;
        goto failure;
      }
      int old = fd;
      fd = duplicate;
      if (close(old)) {
        error = -errno;
        goto failure;
      }
    }
    posix_spawn_file_actions_t actions;
    int setup = posix_spawn_file_actions_init(&actions);
    if (setup) {
      error = -setup;
      goto failure;
    }
    setup = posix_spawn_file_actions_adddup2(&actions, fd, 3);
    if (!setup && fd != 3)
      setup = posix_spawn_file_actions_addclose(&actions, fd);
    char size_text[32];
    int size_count = snprintf(size_text, sizeof(size_text), "%zu", bytes);
    char *arguments[] = {(char *)helper, "--lean-net-access-log-helper", "3", size_text, NULL};
    if (size_count <= 0 || (size_t)size_count >= sizeof(size_text))
      setup = EOVERFLOW;
    posix_spawnattr_t attributes;
    int attributes_ready = 0;
    if (!setup) {
      setup = posix_spawnattr_init(&attributes);
      if (!setup)
        attributes_ready = 1;
    }
    sigset_t empty, defaults;
    if (!setup && (sigemptyset(&empty) || sigemptyset(&defaults) || sigaddset(&defaults, SIGINT) ||
                   sigaddset(&defaults, SIGTERM) || sigaddset(&defaults, SIGHUP) ||
                   sigaddset(&defaults, SIGQUIT) || sigaddset(&defaults, SIGPIPE)))
      setup = errno;
    if (!setup)
      setup = posix_spawnattr_setpgroup(&attributes, 0);
    if (!setup)
      setup = posix_spawnattr_setsigmask(&attributes, &empty);
    if (!setup)
      setup = posix_spawnattr_setsigdefault(&attributes, &defaults);
    if (!setup)
      setup = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK |
                                                        POSIX_SPAWN_SETSIGDEF);
    if (!setup)
      setup = posix_spawn(&hub->child, helper, &actions, &attributes, arguments, environ);
    int attributes_destroyed = attributes_ready ? posix_spawnattr_destroy(&attributes) : 0;
    int destroyed = posix_spawn_file_actions_destroy(&actions);
    int closing = fd;
    fd = -1;
    int closed = close(closing);
    if (setup) {
      error = -setup;
      if (closed)
        error = -errno;
      goto failure;
    }
    if (destroyed)
      ob_fail(shared, -destroyed);
    if (attributes_destroyed)
      ob_fail(shared, -attributes_destroyed);
    if (closed)
      ob_fail(shared, -errno);
#endif
  }
  *out = hub;
  return 0;
failure:
#ifndef _WIN32
  hub->mapping_fd = fd;
#endif
  /* Return acquired ownership to Lean even when construction fails. ready
     reports the original error; the same bracket frees partial resources. */
  hub->init_error = error;
  hub->terminal = 1;
  *out = hub;
  return 0;
}
int ob_emit(ob_hub *hub, uint32_t worker, const ob_record *record) {
  if (!hub || hub->init_error || !hub->shared || !record || worker >= hub->shared->workers ||
      (record->method_length && !record->method) || (record->target_length && !record->target) ||
      record->status > 599 || record->protocol > 2 || record->outcome > 4)
    return -EINVAL;
  if (!hub->logging)
    return 2;
  ob_shared *shared = hub->shared;
  ob_lane *lane = &ob_lanes(shared)[worker];
  unsigned head = atomic_load_explicit(&lane->head, memory_order_relaxed);
  unsigned tail = atomic_load_explicit(&lane->tail, memory_order_acquire);
  if (atomic_load_explicit(&shared->stop, memory_order_relaxed) ||
      atomic_load_explicit(&shared->error, memory_order_relaxed) ||
      head - tail >= shared->capacity) {
    ob_increment(&lane->dropped, 1);
    return 1;
  }
  ob_cell *cell = &ob_cells(shared, worker)[head & (shared->capacity - 1)];
  cell->timestamp_ms = record->timestamp_ms;
  cell->duration_us = record->duration_us;
  cell->bytes_sent = record->bytes_sent;
  cell->status = record->status;
  cell->protocol = record->protocol;
  cell->outcome = record->outcome;
  cell->flags = 0;
  size_t method = record->method_length < OB_METHOD_BYTES ? record->method_length : OB_METHOD_BYTES;
  if (method < record->method_length)
    cell->flags |= 1;
  cell->method_length = (uint32_t)method;
  if (method)
    memcpy(cell->method, record->method, method);
  static const uint8_t hidden[] = "[non-origin-target]";
  const uint8_t *target = record->target;
  size_t length = record->target_length;
  if (!length || (target[0] != '/' && !(length == 1 && target[0] == '*'))) {
    target = hidden;
    length = sizeof(hidden) - 1;
    cell->flags |= 4;
  }
  size_t n = 0;
  while (n < length && n < OB_TARGET_BYTES && target[n] != '?' && target[n] != '#')
    ++n;
  if (n < length && (target[n] == '?' || target[n] == '#'))
    cell->flags |= 4;
  if (n == OB_TARGET_BYTES && n < length && target[n] != '?' && target[n] != '#')
    cell->flags |= 2;
  cell->target_length = (uint32_t)n;
  if (n)
    memcpy(cell->target, target, n);
  ob_increment(&lane->accepted, 1);
  atomic_store_explicit(&lane->head, head + 1, memory_order_release);
  return 0;
}
int ob_publish(ob_hub *hub, uint32_t worker, const uint64_t fields[OB_METRICS]) {
  if (!hub || hub->init_error || !hub->shared || !fields || worker >= hub->shared->workers)
    return -EINVAL;
  ob_lane *lane = &ob_lanes(hub->shared)[worker];
  uint_fast64_t version = atomic_load(&lane->snapshot_version);
  if (version > UINT64_MAX - 2 || (version & 1))
    return -EOVERFLOW;
  atomic_store(&lane->snapshot_version, version + 1);
  for (uint32_t i = 0; i < OB_METRICS; ++i)
    atomic_store(&lane->metrics[i], fields[i]);
  atomic_store(&lane->snapshot_version, version + 2);
  return 0;
}
int ob_snapshot(ob_hub *hub, uint64_t fields[OB_SNAPSHOT_FIELDS]) {
  if (!hub || hub->init_error || !hub->shared || !fields)
    return -EINVAL;
  memset(fields, 0, OB_SNAPSHOT_FIELDS * sizeof(*fields));
  for (uint32_t w = 0; w < hub->shared->workers; ++w) {
    ob_lane *lane = &ob_lanes(hub->shared)[w];
    uint64_t local[OB_METRICS];
    int copied = 0;
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
      uint_fast64_t version = atomic_load(&lane->snapshot_version);
      if (version & 1)
        continue;
      for (uint32_t i = 0; i < OB_METRICS; ++i)
        local[i] = atomic_load(&lane->metrics[i]);
      if (version == atomic_load(&lane->snapshot_version)) {
        copied = 1;
        break;
      }
    }
    if (!copied)
      return -EAGAIN;
    for (uint32_t i = 0; i < OB_METRICS; ++i)
      fields[i] = ob_add(fields[i], local[i]);
    fields[42] = ob_add(fields[42], atomic_load_explicit(&lane->accepted, memory_order_relaxed));
    fields[43] = ob_add(fields[43], atomic_load_explicit(&lane->dropped, memory_order_relaxed));
    fields[44] = ob_add(fields[44], atomic_load_explicit(&lane->written, memory_order_relaxed));
  }
  fields[45] = atomic_load_explicit(&hub->shared->io_errors, memory_order_relaxed);
  fields[46] = fields[42] > fields[44] ? fields[42] - fields[44] : 0;
  return 0;
}
static int ob_poll_child(ob_hub *hub) {
  if (!hub->logging || hub->terminal)
    return 1;
#ifdef _WIN32
  DWORD result = WaitForSingleObject(hub->process, 0);
  if (result == WAIT_FAILED)
    return ob_win_error(GetLastError());
  if (result != WAIT_OBJECT_0)
    return 0;
  DWORD status;
  if (!GetExitCodeProcess(hub->process, &status))
    return ob_win_error(GetLastError());
  if (status && !atomic_load(&hub->shared->error))
    ob_fail(hub->shared, -EIO);
#else
  int status;
  pid_t result = waitpid(hub->child, &status, WNOHANG);
  if (result < 0) {
    int error = -errno;
    if (error == -ECHILD) {
      hub->child = 0;
      hub->terminal = 1;
      hub->error = error;
    }
    return error;
  }
  if (!result)
    return 0;
  hub->child = 0;
  if ((!WIFEXITED(status) || WEXITSTATUS(status)) && !atomic_load(&hub->shared->error))
    ob_fail(hub->shared, -EIO);
#endif
  hub->terminal = 1;
  return 1;
}
int ob_ready(ob_hub *hub) {
  if (!hub)
    return -EINVAL;
  if (hub->init_error)
    return hub->init_error;
#ifndef _WIN32
  if (hub->mapping_name[0]) {
    if (shm_unlink(hub->mapping_name) && errno != ENOENT)
      return -errno;
    hub->mapping_name[0] = 0;
  }
#endif
  int error = atomic_load(&hub->shared->error);
  if (error)
    return error;
  int child = ob_poll_child(hub);
  if (child < 0)
    return child;
  error = atomic_load(&hub->shared->error);
  if (error)
    return error;
  if (hub->logging && hub->terminal)
    return -EPIPE;
  return atomic_load_explicit(&hub->shared->ready, memory_order_acquire) ? 1 : 0;
}
int ob_check(ob_hub *hub) {
  if (!hub)
    return -EINVAL;
  if (hub->init_error)
    return hub->init_error;
  int error = atomic_load(&hub->shared->error);
  if (error)
    return error;
  if (!hub->logging)
    return 0;
  /* Worker-safe observation only. Reaping, process ownership changes and
     pending queue reconciliation belong to the controller after producer join. */
#ifdef _WIN32
  DWORD child = WaitForSingleObject(hub->process, 0);
  if (child == WAIT_FAILED)
    return ob_win_error(GetLastError());
  if (child == WAIT_OBJECT_0 && !hub->stopping)
    ob_fail(hub->shared, -EPIPE);
#else
  siginfo_t state;
  memset(&state, 0, sizeof(state));
  if (waitid(P_PID, (id_t)hub->child, &state, WEXITED | WNOHANG | WNOWAIT)) {
    int error = -errno;
    if (error == -ECHILD)
      ob_fail(hub->shared, error);
    return error;
  }
  if (state.si_pid && !hub->stopping)
    ob_fail(hub->shared, -EPIPE);
#endif
  return atomic_load(&hub->shared->error);
}
int ob_last_error(ob_hub *hub) {
  if (!hub)
    return -EINVAL;
  if (hub->init_error)
    return hub->init_error;
  if (hub->error)
    return hub->error;
  return hub->shared ? atomic_load(&hub->shared->error) : 0;
}
int ob_stop(ob_hub *hub, uint64_t timeout_ms) {
  if (!hub || !timeout_ms || timeout_ms > 60000)
    return -EINVAL;
  if (!hub->stopping) {
    uint64_t now;
    int error = ob_clock(&now);
    if (error)
      return error;
    hub->stopping = 1;
    hub->deadline = now + timeout_ms;
    if (hub->shared && !hub->init_error)
      atomic_store_explicit(&hub->shared->stop, 1, memory_order_release);
  }
  return 0;
}
int ob_join_step(ob_hub *hub) {
  if (!hub || !hub->stopping)
    return -EINVAL;
  int child = ob_poll_child(hub);
  if (child < 0)
    return child;
  if (child)
    return hub->init_error                    ? hub->init_error
           : hub->error                       ? hub->error
           : atomic_load(&hub->shared->error) ? atomic_load(&hub->shared->error)
                                              : 1;
  uint64_t now;
  int clock_error = ob_clock(&now);
  if (clock_error)
    return clock_error;
  if (!hub->killed && now >= hub->deadline) {
    hub->error = -ETIMEDOUT;
    hub->killed = 1;
    hub->kill_deadline = now + 100;
#ifdef _WIN32
    if (!TerminateProcess(hub->process, 1))
      return ob_win_error(GetLastError());
#else
    if (kill(hub->child, SIGKILL) && errno != ESRCH) {
      int error = -errno;
      if (error == -EINTR)
        hub->killed = 0;
      return error;
    }
#endif
  }
  if (hub->killed && now >= hub->kill_deadline) {
    /* Even an uninterruptible kernel write cannot retain parent memory. The
       bounded orphan slot prevents successive failed loggers accumulating. */
#ifdef _WIN32
    orphan_process = hub->process;
    hub->process = NULL;
#else
    orphan_process = hub->child;
    hub->child = 0;
#endif
    hub->transferred = hub->terminal = 1;
    return -ETIMEDOUT;
  }
  return 0;
}
int ob_free(ob_hub *hub) {
  if (!hub)
    return -EINVAL;
  int error = 0;
#ifndef _WIN32
  if (hub->mapping_name[0]) {
    if (shm_unlink(hub->mapping_name) && errno != ENOENT) {
      if (errno == EINTR)
        return -EINTR;
      error = -errno;
    }
    hub->mapping_name[0] = 0;
  }
#endif
  if (hub->logging && !hub->terminal) {
    int owned = ob_poll_child(hub);
    if (owned == -EINTR)
      return owned;
    if (owned < 0)
      error = owned;
    if (owned < 0 && !hub->terminal) {
      /* Ownership could not be established. Never signal a potentially
         reused PID; transfer only its reap obligation to the bounded slot. */
#ifdef _WIN32
      orphan_process = hub->process;
      hub->process = NULL;
#else
      orphan_process = hub->child;
      hub->child = 0;
#endif
      hub->transferred = hub->terminal = 1;
    }
  }
  if (hub->logging && !hub->terminal) {
    /* Covers a failed stop/join call without exposing parent memory to an
       unjoined child. The bounded orphan slot owns the OS process reference. */
#ifdef _WIN32
    if (!TerminateProcess(hub->process, 1)) {
      error = ob_win_error(GetLastError());
      if (error == -EINTR)
        return error;
    }
    orphan_process = hub->process;
    hub->process = NULL;
#else
    if (kill(hub->child, SIGKILL) && errno != ESRCH) {
      error = -errno;
      if (error == -EINTR)
        return error;
    }
    orphan_process = hub->child;
    hub->child = 0;
#endif
    hub->transferred = hub->terminal = 1;
    if (!error)
      error = -ETIMEDOUT;
  }
#ifdef _WIN32
  if (hub->process) {
    HANDLE old = hub->process;
    hub->process = NULL;
    if (!CloseHandle(old) && !error)
      error = ob_win_error(GetLastError());
  }
  if (hub->mapped) {
    if (!UnmapViewOfFile(hub->shared)) {
      if (!error)
        error = ob_win_error(GetLastError());
    } else {
      hub->shared = NULL;
      hub->mapped = 0;
    }
  }
  if (hub->mapping) {
    HANDLE old = hub->mapping;
    hub->mapping = NULL;
    if (!CloseHandle(old) && !error)
      error = ob_win_error(GetLastError());
  }
#else
  if (hub->mapping_fd >= 0) {
    int old = hub->mapping_fd;
    hub->mapping_fd = -1;
    if (close(old) && !error)
      error = -errno;
  }
  if (hub->mapped) {
    if (munmap(hub->shared, hub->bytes)) {
      if (!error)
        error = -errno;
    } else {
      hub->shared = NULL;
      hub->mapped = 0;
    }
  }
#endif
  if (error == -EINTR)
    return error;
  if (!hub->mapped)
    free(hub->shared);
  if (hub->logging && !hub->transferred)
    atomic_store(&helper_slot, 0);
  free(hub);
  return error;
}

typedef struct {
#ifdef _WIN32
  HANDLE file;
#else
  int file;
#endif
  uint64_t size;
  int regular;
  ob_shared *shared;
} ob_sink;
static int ob_sink_close(ob_sink *sink) {
#ifdef _WIN32
  HANDLE old = sink->file;
  sink->file = INVALID_HANDLE_VALUE;
  return old == INVALID_HANDLE_VALUE ? 0 : CloseHandle(old) ? 0 : ob_win_error(GetLastError());
#else
  int old = sink->file;
  sink->file = -1;
  return old < 0 ? 0 : close(old) ? -errno : 0;
#endif
}
static int ob_sink_open(ob_sink *sink) {
#ifdef _WIN32
  wchar_t *path = ob_wide(sink->shared->path);
  if (!path)
    return -EINVAL;
  sink->file = CreateFileW(path, FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                           FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_ALWAYS,
                           FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  DWORD open_error = GetLastError();
  free(path);
  if (sink->file == INVALID_HANDLE_VALUE)
    return ob_win_error(open_error);
  DWORD kind = GetFileType(sink->file);
  if (kind == FILE_TYPE_CHAR || kind == FILE_TYPE_PIPE) {
    sink->regular = 0;
    sink->size = 0;
    return 0;
  }
  BY_HANDLE_FILE_INFORMATION info;
  if (!GetFileInformationByHandle(sink->file, &info))
    return ob_win_error(GetLastError());
  if (kind != FILE_TYPE_DISK ||
      (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
    return -ENOTSUP;
  sink->size = ((uint64_t)info.nFileSizeHigh << 32) | info.nFileSizeLow;
  sink->regular = 1;
#else
  sink->file = open(sink->shared->path,
                    O_WRONLY | O_CREAT | O_APPEND | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (sink->file < 0)
    return -errno;
  struct stat info;
  if (fstat(sink->file, &info))
    return -errno;
  sink->regular = S_ISREG(info.st_mode);
  if ((!sink->regular && !S_ISFIFO(info.st_mode) && !S_ISCHR(info.st_mode)) || info.st_size < 0)
    return -ENOTSUP;
  sink->size = sink->regular ? (uint64_t)info.st_size : 0;
#endif
  return 0;
}
static int ob_path(char out[4140], const char *base, uint32_t suffix) {
  int n = suffix ? snprintf(out, 4140, "%s.%u", base, suffix) : snprintf(out, 4140, "%s", base);
  return n < 0 || n >= 4140 ? -ENAMETOOLONG : 0;
}
static int ob_validate_storage(ob_sink *sink) {
  if (!sink->regular)
    return 0; /* Never inspect/rotate NUL, devices or FIFOs. */
  if (sink->size > sink->shared->file_bytes)
    return -EFBIG;
  for (uint32_t index = 1; index < sink->shared->files; ++index) {
    char path[4140];
    int error = ob_path(path, sink->shared->path, index);
    if (error)
      return error;
    uint64_t size = 0;
#ifdef _WIN32
    wchar_t *wide = ob_wide(path);
    if (!wide)
      return -EINVAL;
    HANDLE file = CreateFileW(wide, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                              OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    DWORD native = GetLastError();
    free(wide);
    if (file == INVALID_HANDLE_VALUE) {
      if (native == ERROR_FILE_NOT_FOUND || native == ERROR_PATH_NOT_FOUND)
        continue;
      return ob_win_error(native);
    }
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(file, &info))
      error = ob_win_error(GetLastError());
    else if (GetFileType(file) != FILE_TYPE_DISK ||
             (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
      error = -ENOTSUP;
    else
      size = ((uint64_t)info.nFileSizeHigh << 32) | info.nFileSizeLow;
    int closed = CloseHandle(file) ? 0 : ob_win_error(GetLastError());
    if (error || closed)
      return error ? error : closed;
#else
    struct stat info;
    if (lstat(path, &info)) {
      if (errno == ENOENT)
        continue;
      return -errno;
    }
    if (!S_ISREG(info.st_mode) || info.st_size < 0)
      return -ENOTSUP;
    size = (uint64_t)info.st_size;
#endif
    if (size > sink->shared->file_bytes)
      return -EFBIG;
  }
  return 0;
}
static int ob_rename(const char *source, const char *target) {
#ifdef _WIN32
  wchar_t *a = ob_wide(source), *b = ob_wide(target);
  if (!a || !b) {
    free(a);
    free(b);
    return -EINVAL;
  }
  BOOL moved = MoveFileExW(a, b, MOVEFILE_REPLACE_EXISTING);
  DWORD error = GetLastError();
  free(a);
  free(b);
  return moved || error == ERROR_FILE_NOT_FOUND ? 0 : ob_win_error(error);
#else
  return rename(source, target) == 0 || errno == ENOENT ? 0 : -errno;
#endif
}
static int ob_remove(const char *path) {
#ifdef _WIN32
  wchar_t *wide = ob_wide(path);
  if (!wide)
    return -EINVAL;
  BOOL removed = DeleteFileW(wide);
  DWORD error = GetLastError();
  free(wide);
  return removed || error == ERROR_FILE_NOT_FOUND ? 0 : ob_win_error(error);
#else
  return unlink(path) == 0 || errno == ENOENT ? 0 : -errno;
#endif
}
static int ob_rotate(ob_sink *sink) {
  int error = ob_sink_close(sink);
  if (error)
    return error;
  char source[4140], target[4140];
  if (sink->shared->files == 1) {
    error = ob_remove(sink->shared->path);
    if (error)
      return error;
  } else {
    for (uint32_t index = sink->shared->files - 1; index > 0; --index) {
      error = ob_path(source, sink->shared->path, index - 1);
      if (!error)
        error = ob_path(target, sink->shared->path, index);
      if (!error)
        error = ob_rename(source, target);
      if (error)
        return error;
    }
  }
  return ob_sink_open(sink);
}
static size_t ob_escape(char *out, const uint8_t *bytes, uint32_t n) {
  static const char hex[] = "0123456789abcdef";
  size_t offset = 0;
  for (uint32_t i = 0; i < n; ++i) {
    unsigned c = bytes[i];
    if (c == '"' || c == '\\') {
      out[offset++] = '\\';
      out[offset++] = (char)c;
    } else if (c < 32 || c >= 127) {
      out[offset++] = '\\';
      out[offset++] = 'u';
      out[offset++] = '0';
      out[offset++] = '0';
      out[offset++] = hex[c >> 4];
      out[offset++] = hex[c & 15];
    } else
      out[offset++] = (char)c;
  }
  return offset;
}
static int ob_line(const ob_cell *cell, uint32_t worker, char out[4096], size_t *length) {
  static const char *protocols[] = {"HTTP/1.0", "HTTP/1.1", "HTTP/2"};
  static const char *outcomes[] = {"completed", "cancelled", "error", "timeout", "shutdown"};
  if (cell->protocol > 2 || cell->outcome > 4 || cell->method_length > OB_METHOD_BYTES ||
      cell->target_length > OB_TARGET_BYTES)
    return -EINVAL;
  int n = snprintf(
      out, 4096,
      "{\"timestamp_ms\":%llu,\"worker\":%u,\"protocol\":\"%s\","
      "\"status\":%u,\"outcome\":\"%s\",\"bytes_sent\":%llu,\"duration_us\":%llu,\"method\":\"",
      (unsigned long long)cell->timestamp_ms, worker, protocols[cell->protocol], cell->status,
      outcomes[cell->outcome], (unsigned long long)cell->bytes_sent,
      (unsigned long long)cell->duration_us);
  if (n < 0 || n > 1024)
    return -EOVERFLOW;
  size_t at = (size_t)n;
  at += ob_escape(out + at, cell->method, cell->method_length);
  memcpy(out + at, "\",\"target\":\"", 12);
  at += 12;
  at += ob_escape(out + at, cell->target, cell->target_length);
  n = snprintf(out + at, 4096 - at,
               "\",\"method_truncated\":%s,\"target_truncated\":%s,\"target_redacted\":%s}\n",
               cell->flags & 1 ? "true" : "false", cell->flags & 2 ? "true" : "false",
               cell->flags & 4 ? "true" : "false");
  if (n < 0 || (size_t)n >= 4096 - at)
    return -EOVERFLOW;
  *length = at + (size_t)n;
  return 0;
}
static int ob_sink_write(ob_sink *sink, const char *bytes, size_t length) {
  if (length > sink->shared->file_bytes)
    return -E2BIG;
  if (sink->regular && sink->size > sink->shared->file_bytes - length) {
    int error = ob_rotate(sink);
    if (error)
      return error;
  }
  size_t offset = 0;
  while (offset < length) {
#ifdef _WIN32
    DWORD wrote = 0;
    if (!WriteFile(sink->file, bytes + offset, (DWORD)(length - offset), &wrote, NULL))
      return ob_win_error(GetLastError());
#else
    ssize_t wrote = write(sink->file, bytes + offset, length - offset);
    if (wrote < 0)
      return -errno; /* Including EINTR: no native retry. */
#endif
    if (!wrote || (size_t)wrote > length - offset)
      return -EIO;
    offset += (size_t)wrote;
    if (sink->regular)
      sink->size += (uint64_t)wrote;
  }
  return 0;
}
static int ob_pause(uint32_t ms) {
#ifdef _WIN32
  Sleep(ms);
  return 0;
#else
  struct timespec delay = {(time_t)(ms / 1000), (long)(ms % 1000) * 1000000};
  return nanosleep(&delay, NULL) ? -errno : 0;
#endif
}
static int ob_decimal(const char *text, uint64_t *out) {
  if (!text || !*text)
    return -EINVAL;
  uint64_t value = 0;
  for (; *text; ++text) {
    if (*text < '0' || *text > '9')
      return -EINVAL;
    unsigned digit = (unsigned)(*text - '0');
    if (value > (UINT64_MAX - digit) / 10)
      return -EOVERFLOW;
    value = value * 10 + digit;
  }
  *out = value;
  return 0;
}
#ifndef _WIN32
static int ob_close_unrelated(void) {
  /* Enumerate actual descriptors: a host can lower RLIMIT_NOFILE while an
     already-open descriptor remains above either limit. No closefrom symbol
     or scan limit assumption is required. Fail closed if neither fd view exists. */
  DIR *directory = opendir("/dev/fd");
  if (!directory && errno != ENOENT && errno != ENOTDIR)
    return -errno;
  if (!directory)
    directory = opendir("/proc/self/fd");
  if (!directory)
    return -errno;
  int own = dirfd(directory), error = 0;
  for (;;) {
    errno = 0;
    struct dirent *entry = readdir(directory);
    if (!entry) {
      if (errno && !error)
        error = -errno;
      break;
    }
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;
    uint64_t descriptor;
    if (ob_decimal(entry->d_name, &descriptor) || descriptor > INT_MAX) {
      error = -EINVAL;
      break;
    }
    int fd = (int)descriptor;
    if (fd >= 4 && fd != own && close(fd) && errno != EBADF && !error)
      error = -errno;
  }
  if (closedir(directory) && !error)
    error = -errno;
  return error;
}
#endif
int ob_helper_main(int argc, char **argv) {
  if (argc != 4 || strcmp(argv[1], "--lean-net-access-log-helper"))
    return 2;
  uint64_t handle, bytes;
  if (ob_decimal(argv[2], &handle) || ob_decimal(argv[3], &bytes) || bytes < sizeof(ob_shared) ||
      bytes > OB_MAX_MEMORY)
    return 2;
  ob_shared *shared;
#ifdef _WIN32
  HANDLE mapping = (HANDLE)(uintptr_t)handle;
  shared = MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, (SIZE_T)bytes);
  if (!shared) {
    BOOL closed = CloseHandle(mapping);
    (void)closed;
    return 2;
  }
  int cleanup = CloseHandle(mapping) ? 0 : ob_win_error(GetLastError());
#else
  if (handle > INT_MAX)
    return 2;
  void *memory = mmap(NULL, (size_t)bytes, PROT_READ | PROT_WRITE, MAP_SHARED, (int)handle, 0);
  int cleanup = close((int)handle) ? -errno : 0;
  if (memory == MAP_FAILED)
    return 2;
  shared = memory;
#endif
  int error = cleanup;
#ifndef _WIN32
  int unrelated = ob_close_unrelated();
  if (!error)
    error = unrelated;
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = SIG_IGN;
  if (sigemptyset(&action.sa_mask) || sigaction(SIGPIPE, &action, NULL))
    error = -errno;
#endif
  if (shared->magic != OB_MAGIC || shared->memory_bytes != bytes || !shared->workers ||
      shared->workers > 256 || !shared->capacity || shared->capacity > 65536 ||
      (shared->capacity & (shared->capacity - 1)) ||
      sizeof(ob_shared) + (size_t)shared->workers * sizeof(ob_lane) +
              (size_t)shared->workers * shared->capacity * sizeof(ob_cell) !=
          bytes ||
      !memchr(shared->path, 0, sizeof(shared->path)))
    error = -EINVAL;
  ob_sink sink;
  memset(&sink, 0, sizeof(sink));
  sink.shared = shared;
#ifdef _WIN32
  sink.file = INVALID_HANDLE_VALUE;
#else
  sink.file = -1;
#endif
  if (!error)
    error = ob_sink_open(&sink);
  if (!error)
    error = ob_validate_storage(&sink);
  if (!error)
    atomic_store_explicit(&shared->ready, 1, memory_order_release);
#ifdef OB_TESTING
  const char *stall = getenv("LEAN_NET_LOG_TEST_STALL_MS");
  uint64_t stall_ms = 0;
  if (!error && stall && !ob_decimal(stall, &stall_ms) && stall_ms <= 60000)
    error = ob_pause((uint32_t)stall_ms);
  const char *failed_write = getenv("LEAN_NET_LOG_TEST_WRITE_ERROR");
  uint64_t write_error = 0;
  if (failed_write && (ob_decimal(failed_write, &write_error) || write_error > 4096))
    write_error = 0;
#endif
  while (!error) {
    int progress = 0;
    for (uint32_t worker = 0; worker < shared->workers; ++worker) {
      ob_lane *lane = &ob_lanes(shared)[worker];
      unsigned tail = atomic_load_explicit(&lane->tail, memory_order_relaxed);
      unsigned head = atomic_load_explicit(&lane->head, memory_order_acquire);
      if (head == tail)
        continue;
      ob_cell *cell = &ob_cells(shared, worker)[tail & (shared->capacity - 1)];
      char line[4096];
      size_t length = 0;
      error = ob_line(cell, worker, line, &length);
#ifdef OB_TESTING
      if (!error && write_error)
        error = -(int)write_error;
#endif
      if (!error)
        error = ob_sink_write(&sink, line, length);
      if (error)
        break;
      ob_increment(&lane->written, 1);
      atomic_store_explicit(&lane->tail, tail + 1, memory_order_release);
      progress = 1;
    }
    if (error)
      break;
    if (!progress) {
      if (atomic_load_explicit(&shared->stop, memory_order_acquire))
        break;
      error = ob_pause(shared->poll_ms);
    }
  }
  int closed = ob_sink_close(&sink);
  if (!error)
    error = closed;
  if (error)
    ob_fail(shared, error);
  atomic_store_explicit(&shared->ready, error ? 2 : 1, memory_order_release);
#ifdef _WIN32
  if (!UnmapViewOfFile(shared))
    error = ob_win_error(GetLastError());
#else
  if (munmap(shared, (size_t)bytes))
    error = -errno;
#endif
  return error ? 1 : 0;
}

#ifndef OB_NO_LEAN_FFI
#include <lean/lean.h>
static lean_object *ob_result(int64_t result) {
  return lean_io_result_mk_ok(lean_box_uint64((uint64_t)result));
}
lean_object *lean_ob_new(uint32_t workers, uint32_t capacity, b_lean_obj_arg path,
                         b_lean_obj_arg helper, uint64_t file_bytes, uint32_t files,
                         uint32_t poll_ms) {
  if (strlen(lean_string_cstr(path)) + 1 != lean_string_size(path) ||
      strlen(lean_string_cstr(helper)) + 1 != lean_string_size(helper))
    return ob_result(-EINVAL);
  ob_hub *hub = NULL;
  int error = ob_new(workers, capacity, lean_string_cstr(path), lean_string_cstr(helper),
                     file_bytes, files, poll_ms, &hub);
  return ob_result(error ? error : (int64_t)(uintptr_t)hub);
}
lean_object *lean_ob_emit(uint64_t handle, uint32_t worker, uint64_t timestamp_ms,
                          uint64_t duration_us, uint64_t bytes_sent, uint32_t status,
                          uint32_t protocol, uint32_t outcome, b_lean_obj_arg method,
                          b_lean_obj_arg target) {
  ob_record record = {timestamp_ms,
                      duration_us,
                      bytes_sent,
                      status,
                      protocol,
                      outcome,
                      lean_sarray_cptr(method),
                      lean_sarray_cptr(target),
                      lean_sarray_size(method),
                      lean_sarray_size(target)};
  return ob_result(ob_emit((ob_hub *)(uintptr_t)handle, worker, &record));
}
lean_object *lean_ob_publish(uint64_t handle, uint32_t worker, b_lean_obj_arg array) {
  if (lean_array_size(array) != OB_METRICS)
    return ob_result(-EINVAL);
  uint64_t fields[OB_METRICS];
  for (uint32_t i = 0; i < OB_METRICS; ++i)
    fields[i] = lean_unbox_uint64(lean_array_get_core(array, i));
  return ob_result(ob_publish((ob_hub *)(uintptr_t)handle, worker, fields));
}
lean_object *lean_ob_snapshot(uint64_t handle) {
  uint64_t fields[OB_SNAPSHOT_FIELDS];
  int error = ob_snapshot((ob_hub *)(uintptr_t)handle, fields);
  lean_object *array = lean_mk_empty_array_with_capacity(lean_box(error ? 0 : OB_SNAPSHOT_FIELDS));
  if (!error)
    for (uint32_t i = 0; i < OB_SNAPSHOT_FIELDS; ++i)
      array = lean_array_push(array, lean_box_uint64(fields[i]));
  lean_object *pair = lean_alloc_ctor(0, 2, 0);
  lean_ctor_set(pair, 0, lean_box_uint64((uint64_t)(int64_t)error));
  lean_ctor_set(pair, 1, array);
  return lean_io_result_mk_ok(pair);
}
lean_object *lean_ob_ready(uint64_t h) { return ob_result(ob_ready((ob_hub *)(uintptr_t)h)); }
lean_object *lean_ob_check(uint64_t h) { return ob_result(ob_check((ob_hub *)(uintptr_t)h)); }
lean_object *lean_ob_last_error(uint64_t h) {
  return ob_result(ob_last_error((ob_hub *)(uintptr_t)h));
}
lean_object *lean_ob_stop(uint64_t h, uint64_t timeout) {
  return ob_result(ob_stop((ob_hub *)(uintptr_t)h, timeout));
}
lean_object *lean_ob_join(uint64_t h) { return ob_result(ob_join_step((ob_hub *)(uintptr_t)h)); }
lean_object *lean_ob_free(uint64_t h) { return ob_result(ob_free((ob_hub *)(uintptr_t)h)); }
#endif
