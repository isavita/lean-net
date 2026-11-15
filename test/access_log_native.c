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
#define REQUIRE(value)                                                                             \
  do {                                                                                             \
    if (!(value)) {                                                                                \
      fprintf(stderr, "line%d: %s\n", __LINE__, #value);                                           \
      abort();                                                                                     \
    }                                                                                              \
  } while (0)
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
  REQUIRE(ob_new(1, 1, path, "/missing/lean-net-access-log-helper", 4096, 3, 1, &hub) == 0);
  REQUIRE(ready(hub) == -ENOENT && finish(hub, 100) == -ENOENT && ob_free(hub) == 0);
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
