#ifndef _WIN32
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
static int observing_hot;
static unsigned hot_allocations;
#ifndef _WIN32
#include <signal.h>
#include <pthread.h>
#include <time.h>
static unsigned injected_clock;
static int observed_clock(clockid_t clock, struct timespec *out) {
  if (injected_clock) {
    --injected_clock;
    errno = EIO;
    return -1;
  }
  return clock_gettime(clock, out);
}
#define clock_gettime observed_clock
static volatile sig_atomic_t saw_interrupt;
static void observed_interrupt(int signal_number) {
  (void)signal_number;
  saw_interrupt = 1;
}
#endif
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
static HANDLE WINAPI traced_mapping(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
static LPVOID WINAPI traced_map(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
static BOOL WINAPI traced_attributes(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
static BOOL WINAPI traced_update(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
static VOID WINAPI traced_delete_attributes(LPPROC_THREAD_ATTRIBUTE_LIST);
static BOOL WINAPI traced_process(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
static BOOL WINAPI traced_unmap(LPCVOID);
static BOOL WINAPI traced_close(HANDLE);
#define CreateFileMappingW traced_mapping
#define MapViewOfFile traced_map
#define InitializeProcThreadAttributeList traced_attributes
#define UpdateProcThreadAttribute traced_update
#define DeleteProcThreadAttributeList traced_delete_attributes
#define CreateProcessW traced_process
#define UnmapViewOfFile traced_unmap
#define CloseHandle traced_close
static void *observed_malloc(size_t n) {
  if (observing_hot)
    ++hot_allocations;
  return malloc(n);
}
#define malloc observed_malloc
#endif
static void *observed_calloc(size_t n, size_t size) {
  if (observing_hot)
    ++hot_allocations;
  return calloc(n, size);
}
#define calloc observed_calloc
#define OB_NO_LEAN_FFI
#include "../c/access_log.c"
#ifndef _WIN32
#undef clock_gettime
#endif
#undef malloc
#undef calloc
#ifdef _WIN32
#undef CreateFileMappingW
#undef MapViewOfFile
#undef InitializeProcThreadAttributeList
#undef UpdateProcThreadAttribute
#undef DeleteProcThreadAttributeList
#undef CreateProcessW
#undef UnmapViewOfFile
#undef CloseHandle
#endif
#define REQUIRE(value)                                                                             \
  do {                                                                                             \
    if (!(value)) {                                                                                \
      fprintf(stderr, "line%d: %s\n", __LINE__, #value);                                           \
      abort();                                                                                     \
    }                                                                                              \
  } while (0)
#ifdef _WIN32
/* Diagnostics only: preserve both the incoming and actual API LastError.
 * Count every failed lifetime before retaining the original pre-first gate. */
static int trace_capture, trace_stages;
static HANDLE trace_owned[16];
static unsigned trace_open, trace_created, trace_closed, trace_views, trace_view_created, trace_view_closed;
static unsigned trace_iteration;
static DWORD trace_count(void) {
  DWORD count = 0;
  REQUIRE(GetProcessHandleCount(GetCurrentProcess(), &count));
  return count;
}
static DWORD trace_before(void) {
  DWORD error = GetLastError();
  DWORD count = trace_capture ? trace_count() : 0;
  SetLastError(error);
  return count;
}
static void trace_after(const char *name, DWORD before, DWORD error) {
  if (trace_capture && trace_stages)
    fprintf(stderr, "logger SDK iteration=%u stage=%s handles=%lu->%lu error=%lu owned=%u views=%u\n",
            trace_iteration, name, (unsigned long)before, (unsigned long)trace_count(),
            (unsigned long)error, trace_open, trace_views);
  SetLastError(error);
}
static void trace_add(HANDLE handle) {
  if (!trace_capture || !handle || handle == INVALID_HANDLE_VALUE) return;
  REQUIRE(trace_open < sizeof(trace_owned) / sizeof(*trace_owned));
  trace_owned[trace_open++] = handle;
  ++trace_created;
}
static HANDLE WINAPI traced_mapping(HANDLE file, LPSECURITY_ATTRIBUTES security, DWORD protection,
                                     DWORD high, DWORD low, LPCWSTR name) {
  DWORD before = trace_before();
  HANDLE result = CreateFileMappingW(file, security, protection, high, low, name);
  DWORD error = GetLastError(); trace_add(result);
  trace_after("CreateFileMappingW", before, error); return result;
}
static LPVOID WINAPI traced_map(HANDLE mapping, DWORD access, DWORD high, DWORD low, SIZE_T size) {
  DWORD before = trace_before();
  LPVOID result = MapViewOfFile(mapping, access, high, low, size); DWORD error = GetLastError();
  if (trace_capture && result) { ++trace_views; ++trace_view_created; }
  trace_after("MapViewOfFile", before, error); return result;
}
static BOOL WINAPI traced_attributes(LPPROC_THREAD_ATTRIBUTE_LIST list, DWORD count, DWORD flags, PSIZE_T bytes) {
  DWORD before = trace_before();
  BOOL result = InitializeProcThreadAttributeList(list, count, flags, bytes); DWORD error = GetLastError();
  trace_after("InitializeProcThreadAttributeList", before, error); return result;
}
static BOOL WINAPI traced_update(LPPROC_THREAD_ATTRIBUTE_LIST list, DWORD flags, DWORD_PTR attribute,
                                 PVOID value, SIZE_T bytes, PVOID previous, PSIZE_T returned) {
  DWORD before = trace_before();
  BOOL result = UpdateProcThreadAttribute(list, flags, attribute, value, bytes, previous, returned);
  DWORD error = GetLastError(); trace_after("UpdateProcThreadAttribute", before, error); return result;
}
static VOID WINAPI traced_delete_attributes(LPPROC_THREAD_ATTRIBUTE_LIST list) {
  DWORD before = trace_before(); DeleteProcThreadAttributeList(list); DWORD error = GetLastError();
  trace_after("DeleteProcThreadAttributeList", before, error);
}
static BOOL WINAPI traced_process(LPCWSTR application, LPWSTR command, LPSECURITY_ATTRIBUTES process,
                                  LPSECURITY_ATTRIBUTES thread, BOOL inherit, DWORD flags,
                                  LPVOID environment, LPCWSTR directory, LPSTARTUPINFOW startup,
                                  LPPROCESS_INFORMATION information) {
  DWORD before = trace_before();
  BOOL result = CreateProcessW(application, command, process, thread, inherit, flags,
                               environment, directory, startup, information);
  DWORD error = GetLastError();
  if (result) { trace_add(information->hProcess); trace_add(information->hThread); }
  trace_after("CreateProcessW", before, error); return result;
}
static BOOL WINAPI traced_unmap(LPCVOID view) {
  DWORD before = trace_before(); BOOL result = UnmapViewOfFile(view); DWORD error = GetLastError();
  if (trace_capture && result) { REQUIRE(trace_views); --trace_views; ++trace_view_closed; }
  trace_after("UnmapViewOfFile", before, error); return result;
}
static BOOL WINAPI traced_close(HANDLE handle) {
  DWORD before = trace_before(); BOOL result = CloseHandle(handle); DWORD error = GetLastError();
  if (trace_capture && result)
    for (unsigned i = 0; i < trace_open; ++i)
      if (trace_owned[i] == handle) { trace_owned[i] = trace_owned[--trace_open]; ++trace_closed; break; }
  trace_after("CloseHandle", before, error); return result;
}
typedef struct { unsigned char used[16384]; unsigned count; } trace_snapshot;
static void trace_snapshot_take(trace_snapshot *snapshot) {
  DWORD error = GetLastError();
  memset(snapshot, 0, sizeof(*snapshot));
  for (unsigned i = 1; i < sizeof(snapshot->used); ++i) {
    DWORD flags;
    if (GetHandleInformation((HANDLE)(uintptr_t)(i * 4), &flags)) { snapshot->used[i] = 1; ++snapshot->count; }
  }
  SetLastError(error);
}
static void trace_snapshot_diff(const trace_snapshot *before, const trace_snapshot *after) {
  DWORD error = GetLastError();
  typedef LONG (NTAPI *query_fn)(HANDLE, unsigned, PVOID, ULONG, PULONG);
  FARPROC raw = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"); query_fn query = NULL;
  memcpy(&query, &raw, sizeof(query));
  for (unsigned i = 1; i < sizeof(after->used); ++i) {
    if (!after->used[i] || before->used[i]) continue;
    char type[256] = "unavailable";
    union { uint64_t align; unsigned char bytes[4096]; } buffer;
    ULONG size = 0;
    if (query && query((HANDLE)(uintptr_t)(i * 4), 2, buffer.bytes, sizeof(buffer.bytes), &size) >= 0) {
      struct { USHORT length, maximum; PWSTR text; } *name = (void *)buffer.bytes;
      int n = WideCharToMultiByte(CP_UTF8, 0, name->text, name->length / 2, type, sizeof(type) - 1, NULL, NULL);
      if (n > 0) type[n] = 0;
    }
    /* Type only; never query File/pipe object names, which can block. */
    fprintf(stderr, "logger new handle=%p type=%s\n", (void *)(uintptr_t)(i * 4), type);
  }
  SetLastError(error);
}
static void trace_missing_sdk(void) {
  SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
  HANDLE mapping = traced_mapping(INVALID_HANDLE_VALUE, &security, PAGE_READWRITE, 0, 4096, NULL);
  REQUIRE(mapping);
  SIZE_T bytes = 0;
  REQUIRE(!traced_attributes(NULL, 1, 0, &bytes) && GetLastError() == ERROR_INSUFFICIENT_BUFFER);
  STARTUPINFOEXW startup; memset(&startup, 0, sizeof(startup)); startup.StartupInfo.cb = sizeof(startup);
  startup.lpAttributeList = malloc(bytes); REQUIRE(startup.lpAttributeList);
  REQUIRE(traced_attributes(startup.lpAttributeList, 1, 0, &bytes));
  REQUIRE(traced_update(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                        &mapping, sizeof(mapping), NULL, NULL));
  PROCESS_INFORMATION process; memset(&process, 0, sizeof(process));
  wchar_t command[] = L"\"/missing/lean-net-access-log-helper\" --lean-net-access-log-helper 0 4096";
  REQUIRE(!traced_process(L"/missing/lean-net-access-log-helper", command, NULL, NULL, TRUE,
                          EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, NULL, NULL,
                          &startup.StartupInfo, &process));
  REQUIRE(GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND);
  traced_delete_attributes(startup.lpAttributeList); free(startup.lpAttributeList);
  REQUIRE(traced_close(mapping));
  REQUIRE(trace_open == 0 && trace_created == trace_closed && trace_views == 0);
}
#endif
static uint64_t ob_now(void) {
  uint64_t now = 0;
  REQUIRE(ob_clock(&now) == 0);
  return now;
}
static unsigned handles(void) {
#ifdef _WIN32
  DWORD count;
  REQUIRE(GetProcessHandleCount(GetCurrentProcess(), &count));
  return count;
#else
  unsigned count = 0;
  for (int fd = 0; fd < 4096; ++fd)
    if (fcntl(fd, F_GETFD) >= 0)
      ++count;
  return count;
#endif
}
static int ready(ob_hub *hub) {
  uint64_t cutoff = ob_now() + 3000;
  while (ob_now() < cutoff) {
    int result = ob_ready(hub);
    if (result)
      return result;
    REQUIRE(ob_pause(1) == 0);
  }
  return -ETIMEDOUT;
}
static int finish(ob_hub *hub, uint64_t ms) {
  REQUIRE(ob_stop(hub, ms) == 0);
  uint64_t cutoff = ob_now() + ms + 500;
  while (ob_now() < cutoff) {
    int result = ob_join_step(hub);
    if (result)
      return result;
    REQUIRE(ob_pause(1) == 0);
  }
  return -ETIMEDOUT;
}
static void environment(const char *name, const char *value) {
#ifdef _WIN32
  REQUIRE(SetEnvironmentVariableA(name, value));
#else
  REQUIRE(value ? setenv(name, value, 1) == 0 : unsetenv(name) == 0);
#endif
}
typedef struct {
  ob_hub *hub;
  uint32_t worker;
  int error;
} health_context;
static void health_checks(health_context *context) {
  uint64_t fields[OB_METRICS] = {0}, snapshot[OB_SNAPSHOT_FIELDS];
  for (unsigned i = 0; i < 1000; ++i) {
    fields[12] = fields[23] = i;
    int error = ob_publish(context->hub, context->worker, fields);
    if (!error)
      error = ob_check(context->hub);
    if (error) {
      context->error = error;
      return;
    }
    error = ob_snapshot(context->hub, snapshot);
    if (error && error != -EAGAIN) {
      context->error = error;
      return;
    }
    if (!error && snapshot[12] != snapshot[23]) {
      context->error = -EINVAL;
      return;
    }
  }
}
#ifdef _WIN32
static DWORD WINAPI health_entry(LPVOID argument) {
  health_checks(argument);
  return 0;
}
#else
static void *health_entry(void *argument) {
  health_checks(argument);
  return NULL;
}
#endif
static void concurrent_health(ob_hub *hub) {
  health_context contexts[2] = {{hub, 0, 0}, {hub, 1, 0}};
#ifdef _WIN32
  HANDLE threads[2];
  for (unsigned i = 0; i < 2; ++i) {
    threads[i] = CreateThread(NULL, 0, health_entry, &contexts[i], 0, NULL);
    REQUIRE(threads[i]);
  }
  for (unsigned i = 0; i < 2; ++i) {
    REQUIRE(WaitForSingleObject(threads[i], 5000) == WAIT_OBJECT_0);
    REQUIRE(CloseHandle(threads[i]));
  }
#else
  pthread_t threads[2];
  for (unsigned i = 0; i < 2; ++i)
    REQUIRE(pthread_create(&threads[i], NULL, health_entry, &contexts[i]) == 0);
  for (unsigned i = 0; i < 2; ++i)
    REQUIRE(pthread_join(threads[i], NULL) == 0);
#endif
  REQUIRE(!contexts[0].error && !contexts[1].error);
}
int main(int argc, char **argv) {
  REQUIRE(argc == 3);
  const char *helper = argv[1], *directory = argv[2];
  char path[4096];
  int count = snprintf(path, sizeof(path), "%s/access.jsonl", directory);
  REQUIRE(count > 0 && (size_t)count < sizeof(path));
  ob_hub *hub = NULL;
  uint64_t snapshot[OB_SNAPSHOT_FIELDS], fields[OB_METRICS] = {0};
  REQUIRE(ob_new(2, 0, "", "", 0, 0, 0, &hub) == 0 && ready(hub) == 1);
  fields[4] = 3;
  fields[12] = fields[23] = 4;
  REQUIRE(ob_publish(hub, 0, fields) == 0 && ob_publish(hub, 1, fields) == 0);
  REQUIRE(ob_snapshot(hub, snapshot) == 0 && snapshot[4] == 6 && snapshot[12] == snapshot[23]);
  fields[4] = UINT64_MAX;
  REQUIRE(ob_publish(hub, 0, fields) == 0 && ob_snapshot(hub, snapshot) == 0 &&
          snapshot[4] == UINT64_MAX);
  ob_record record = {1234,
                      25000,
                      99,
                      200,
                      2,
                      0,
                      (const uint8_t *)"GET",
                      (const uint8_t *)"/safe?private_query=never-log",
                      3,
                      27};
  REQUIRE(ob_emit(hub, 0, &record) == 2);
#ifndef _WIN32
  injected_clock = 1;
  REQUIRE(ob_stop(hub, 100) == -EIO && !injected_clock);
#endif
  REQUIRE(finish(hub, 100) == 1 && ob_free(hub) == 0);
  unsigned failed_before = handles();
#ifdef _WIN32
  trace_snapshot failed_snapshot_before, failed_snapshot_after;
  trace_snapshot_take(&failed_snapshot_before);
  trace_capture = trace_stages = 1;
  trace_missing_sdk();
  unsigned control_after = handles();
  fprintf(stderr, "logger direct SDK baseline=%u after=%u owned_created=%u owned_closed=%u owned_open=%u\n",
          failed_before, control_after, trace_created, trace_closed, trace_open);
  unsigned failed_min = UINT_MAX, failed_max = 0;
  for (unsigned i = 0; i < 1000; ++i) {
    trace_iteration = i + 1; trace_stages = i < 2 || i == 999;
    REQUIRE(ob_new(1, 1, path, "/missing/lean-net-access-log-helper", 4096, 3, 1, &hub) == 0);
    REQUIRE(ready(hub) == -ENOENT && finish(hub, 100) == -ENOENT && ob_free(hub) == 0);
    unsigned current = handles();
    if (current < failed_min) failed_min = current;
    if (current > failed_max) failed_max = current;
    REQUIRE(trace_open == 0 && trace_created == trace_closed && trace_views == 0 && trace_view_created == trace_view_closed);
    if (i < 4 || i == 999)
      fprintf(stderr, "logger failed startup iteration=%u handles=%u owned=%u/%u/%u views=%u/%u/%u\n",
              i + 1, current, trace_created, trace_closed, trace_open, trace_view_created, trace_view_closed, trace_views);
  }
  trace_capture = 0;
  trace_snapshot_take(&failed_snapshot_after);
  fprintf(stderr, "logger failed1000 before=%u direct_control=%u min=%u max=%u after=%u census=%u/%u\n",
          failed_before, control_after, failed_min, failed_max, handles(), failed_snapshot_before.count, failed_snapshot_after.count);
  trace_snapshot_diff(&failed_snapshot_before, &failed_snapshot_after);
#else
  REQUIRE(ob_new(1, 1, path, "/missing/lean-net-access-log-helper", 4096, 3, 1, &hub) == 0);
  REQUIRE(ready(hub) == -ENOENT && finish(hub, 100) == -ENOENT && ob_free(hub) == 0);
#endif
  REQUIRE(handles() <= failed_before);
  int opened = ob_new(2, 8, path, helper, 4096, 3, 1, &hub);
  int handshaken = opened ? 0 : ready(hub);
  if (opened || handshaken != 1)
    fprintf(stderr, "helper open=%d ready=%d\n", opened, handshaken);
  REQUIRE(opened == 0 && handshaken == 1);
  concurrent_health(hub);
  observing_hot = 1;
  for (unsigned i = 0; i < 10000; ++i) {
    record.timestamp_ms = i;
    int result = ob_emit(hub, i % 2, &record);
    REQUIRE(result == 0 || result == 1);
  }
  observing_hot = 0;
  REQUIRE(hot_allocations == 0);
  REQUIRE(ob_snapshot(hub, snapshot) == 0 && snapshot[42] + snapshot[43] == 10000 &&
          snapshot[43] > 0);
  REQUIRE(finish(hub, 2000) == 1);
  REQUIRE(ob_snapshot(hub, snapshot) == 0 && snapshot[42] == snapshot[44]);
  uint64_t accepted = snapshot[42], dropped = snapshot[43];
  REQUIRE(ob_free(hub) == 0);
  /* No query/header secrets, arbitrary bytes remain valid JSON, bounded
     truncation, and non-origin userinfo is never retained. */
  REQUIRE(ob_new(1, 8, path, helper, 4096, 3, 1, &hub) == 0 && ready(hub) == 1);
  uint8_t target[600];
  memset(target, 'x', sizeof(target));
  target[0] = '/';
  uint8_t method[] = {'G', 'E', 'T', '"', 10, 255};
  record.method = method;
  record.method_length = sizeof(method);
  record.target = target;
  record.target_length = sizeof(target);
  REQUIRE(ob_emit(hub, 0, &record) == 0);
  record.method = (const uint8_t *)"GET";
  record.method_length = 3;
  record.target = (const uint8_t *)"http://user:private_password@host/path";
  record.target_length = strlen((const char *)record.target);
  REQUIRE(ob_emit(hub, 0, &record) == 0);
  REQUIRE(finish(hub, 2000) == 1 && ob_free(hub) == 0);
  char append_path[4096];
  count = snprintf(append_path, sizeof(append_path), "%s/append.jsonl", directory);
  REQUIRE(count > 0 && (size_t)count < sizeof(append_path));
  FILE *prior = fopen(append_path, "wb");
  REQUIRE(prior);
  REQUIRE(fputs("{\"prior\":true}\n", prior) >= 0 && fclose(prior) == 0);
  REQUIRE(ob_new(1, 8, append_path, helper, 1048576, 3, 1, &hub) == 0 && ready(hub) == 1);
  REQUIRE(ob_emit(hub, 0, &record) == 0);
  REQUIRE(finish(hub, 1000) == 1 && ob_free(hub) == 0);
#ifdef _WIN32
  const char *null_path = "NUL";
#else
  const char *null_path = "/dev/null";
#endif
  REQUIRE(ob_new(1, 8, null_path, helper, 4096, 3, 1, &hub) == 0 && ready(hub) == 1);
#ifndef _WIN32
  struct sigaction action, old_action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = observed_interrupt;
  REQUIRE(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGINT, &action, &old_action) == 0);
  REQUIRE(kill(0, SIGINT) == 0);
  REQUIRE(ob_pause(10) == 0 && saw_interrupt && ob_check(hub) == 0);
  REQUIRE(sigaction(SIGINT, &old_action, NULL) == 0);
#endif
  REQUIRE(ob_emit(hub, 0, &record) == 0);
  REQUIRE(finish(hub, 1000) == 1 && ob_free(hub) == 0);
#ifndef _WIN32
  /* A host can lower its descriptor limit after opening an inheritable fd.
     The helper must enumerate actual fds instead of trusting that new limit. */
  int inherited_pipe[2];
  REQUIRE(pipe(inherited_pipe) == 0);
  int high = fcntl(inherited_pipe[1], F_DUPFD, 200);
  REQUIRE(high >= 200);
  REQUIRE(close(inherited_pipe[1]) == 0 && fcntl(high, F_SETFD, 0) == 0);
  struct rlimit original_limit, lowered_limit;
  REQUIRE(getrlimit(RLIMIT_NOFILE, &original_limit) == 0);
  lowered_limit = original_limit;
  lowered_limit.rlim_cur = 64;
  REQUIRE(setrlimit(RLIMIT_NOFILE, &lowered_limit) == 0);
  REQUIRE(ob_new(1, 8, null_path, helper, 4096, 3, 1, &hub) == 0);
  REQUIRE(setrlimit(RLIMIT_NOFILE, &original_limit) == 0);
  REQUIRE(ready(hub) == 1 && close(high) == 0);
  int read_flags = fcntl(inherited_pipe[0], F_GETFL);
  REQUIRE(read_flags >= 0);
  REQUIRE(fcntl(inherited_pipe[0], F_SETFL, read_flags | O_NONBLOCK) == 0);
  char byte;
  REQUIRE(read(inherited_pipe[0], &byte, 1) == 0);
  REQUIRE(close(inherited_pipe[0]) == 0);
  REQUIRE(finish(hub, 1000) == 1 && ob_free(hub) == 0);
  char pipe_path[4096];
  count = snprintf(pipe_path, sizeof(pipe_path), "%s/blocked.fifo", directory);
  REQUIRE(count > 0 && (size_t)count < sizeof(pipe_path));
  REQUIRE(mkfifo(pipe_path, 0600) == 0);
  int reader = open(pipe_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  REQUIRE(reader >= 0);
  REQUIRE(ob_new(1, 8, pipe_path, helper, 4096, 3, 1, &hub) == 0 && ready(hub) == 1);
  int failed = 0;
  for (unsigned i = 0; i < 5000; ++i) {
    int submitted = ob_emit(hub, 0, &record);
    REQUIRE(submitted == 0 || submitted == 1);
    int result = ob_check(hub);
    if (result) {
      failed = result;
      break;
    }
    if (i % 8 == 0)
      REQUIRE(ob_pause(1) == 0);
  }
  REQUIRE(failed == -EAGAIN || failed == -EWOULDBLOCK);
  int completed = finish(hub, 1000);
  REQUIRE(completed == -EAGAIN || completed == -EWOULDBLOCK);
  REQUIRE(ob_snapshot(hub, snapshot) == 0 && snapshot[45] == 1 && snapshot[43] > 0);
  REQUIRE(ob_free(hub) == 0 && close(reader) == 0);
  char rotated_pipe[4140];
  REQUIRE(ob_path(rotated_pipe, pipe_path, 1) == 0);
  REQUIRE(access(rotated_pipe, F_OK) != 0 && errno == ENOENT);
#endif
  environment("LEAN_NET_LOG_TEST_STALL_MS", "10000");
  REQUIRE(ob_new(1, 1, path, helper, 4096, 3, 1, &hub) == 0 && ready(hub) == 1);
  REQUIRE(ob_emit(hub, 0, &record) == 0);
  REQUIRE(ob_emit(hub, 0, &record) == 1);
  uint64_t started = ob_now();
  REQUIRE(finish(hub, 20) == -ETIMEDOUT);
  uint64_t stopped_ms = ob_now() - started;
  REQUIRE(stopped_ms <= 250);
  REQUIRE(ob_snapshot(hub, snapshot) == 0 && snapshot[43] == 1 && snapshot[46] == 1);
  REQUIRE(ob_free(hub) == 0);
  environment("LEAN_NET_LOG_TEST_STALL_MS", NULL);
  char error_text[32];
  count = snprintf(error_text, sizeof(error_text), "%d", EINTR);
  REQUIRE(count > 0 && (size_t)count < sizeof(error_text));
  environment("LEAN_NET_LOG_TEST_WRITE_ERROR", error_text);
  REQUIRE(ob_new(1, 8, path, helper, 4096, 3, 1, &hub) == 0 && ready(hub) == 1);
  REQUIRE(ob_emit(hub, 0, &record) == 0);
  uint64_t error_cutoff = ob_now() + 1000;
  while (!ob_last_error(hub) && ob_now() < error_cutoff)
    REQUIRE(ob_pause(1) == 0);
  REQUIRE(ob_last_error(hub) == -EINTR && finish(hub, 1000) == -EINTR);
  REQUIRE(ob_snapshot(hub, snapshot) == 0 && snapshot[45] == 1 && snapshot[43] == 0 &&
          snapshot[46] == 1);
  REQUIRE(ob_free(hub) == 0);
  environment("LEAN_NET_LOG_TEST_WRITE_ERROR", NULL);
  char oversized[4096], oversized_archive[4140];
  count = snprintf(oversized, sizeof(oversized), "%s/oversized.jsonl", directory);
  REQUIRE(count > 0 && (size_t)count < sizeof(oversized));
  FILE *large = fopen(oversized, "wb");
  REQUIRE(large);
  for (unsigned i = 0; i < 4097; ++i)
    REQUIRE(fputc('z', large) == 'z');
  REQUIRE(fclose(large) == 0);
  REQUIRE(ob_new(1, 8, oversized, helper, 4096, 3, 1, &hub) == 0);
  REQUIRE(ready(hub) == -EFBIG && finish(hub, 1000) == -EFBIG && ob_free(hub) == 0);
  REQUIRE(ob_path(oversized_archive, oversized, 1) == 0);
  REQUIRE(rename(oversized, oversized_archive) == 0);
  REQUIRE(ob_new(1, 8, oversized, helper, 4096, 3, 1, &hub) == 0);
  REQUIRE(ready(hub) == -EFBIG && finish(hub, 1000) == -EFBIG && ob_free(hub) == 0);
  /* Even a caller's failed stop must not bypass native resource cleanup. */
  REQUIRE(ob_new(1, 8, path, helper, 4096, 3, 1, &hub) == 0 && ready(hub) == 1);
  REQUIRE(ob_stop(hub, 0) == -EINVAL && ob_free(hub) == -ETIMEDOUT);
  int reopened = -EBUSY;
  uint64_t reopen_cutoff = ob_now() + 1000;
  while (reopened == -EBUSY && ob_now() < reopen_cutoff) {
    reopened = ob_new(1, 8, path, helper, 4096, 3, 1, &hub);
    if (reopened == -EBUSY)
      REQUIRE(ob_pause(1) == 0);
  }
  REQUIRE(reopened == 0 && ready(hub) == 1 && finish(hub, 1000) == 1 && ob_free(hub) == 0);
  unsigned before = handles();
  for (unsigned i = 0; i < 1000; ++i) {
    REQUIRE(ob_new(2, 0, "", "", 0, 0, 0, &hub) == 0);
    REQUIRE(finish(hub, 100) == 1 && ob_free(hub) == 0);
  }
  for (unsigned i = 0; i < 30; ++i) {
    REQUIRE(ob_new(1, 1, path, helper, 4096, 3, 1, &hub) == 0 && ready(hub) == 1);
    REQUIRE(finish(hub, 1000) == 1 && ob_free(hub) == 0);
  }
  unsigned after = handles();
  REQUIRE(after <= before);
#ifndef _WIN32
  int status;
  REQUIRE(waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD);
#endif
  printf(
      "{\"accepted\":%llu,\"dropped\":%llu,\"hot_allocations\":%u,\"stop_ms\":%llu,"
      "\"metrics_cycles\":1000,\"helper_cycles\":30,\"handles_before\":%u,\"handles_after\":%u}\n",
      (unsigned long long)accepted, (unsigned long long)dropped, hot_allocations,
      (unsigned long long)stopped_ms, before, after);
  return 0;
}
