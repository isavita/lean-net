/* Real worker threads with deterministic failures at their control boundary. */
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef OPENSSL_API_COMPAT
#define OPENSSL_API_COMPAT 0x10101000L
#endif
#include "../../c/reactor.h"
#include <openssl/ssl.h>
#include <stdatomic.h>
#include <stdio.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#endif

struct tw_engine;
static _Atomic(struct tw_engine *) control_target;
static atomic_uint write_fault, join_fault, close_fault, reactor_fault;
#ifdef _WIN32
static atomic_uint reset_fault, wait_fault, wait_result;
#else
static atomic_uint read_fault, poll_fault, poll_events, read_zero, write_zero, mask_fault, mask_calls;
#endif
static atomic_uint read_calls, write_calls, poll_calls,
    reset_calls, wait_calls, reactor_calls;
static int tested_reactor_wake(rn_waker *);
#ifdef _WIN32
static BOOL WINAPI tested_set(HANDLE);
static BOOL WINAPI tested_reset(HANDLE);
static DWORD WINAPI tested_wait(HANDLE, DWORD);
static BOOL WINAPI tested_close(HANDLE);
#define SetEvent tested_set
#define ResetEvent tested_reset
#define WaitForSingleObject tested_wait
#define CloseHandle tested_close
#else
static ssize_t tested_read(int, void *, size_t);
static ssize_t tested_write(int, const void *, size_t);
static int tested_poll(struct pollfd *, nfds_t, int);
static int tested_join(pthread_t, void **);
static int tested_sigmask(int, const sigset_t *, sigset_t *);
static int tested_close(int);
#define read tested_read
#define write tested_write
#define poll tested_poll
#define pthread_join tested_join
#define pthread_sigmask tested_sigmask
#define close tested_close
#endif
#define rn_waker_wake tested_reactor_wake
#include "../c/tls_worker.c"
#undef rn_waker_wake
#ifdef _WIN32
#undef SetEvent
#undef ResetEvent
#undef WaitForSingleObject
#undef CloseHandle
#else
#undef read
#undef write
#undef poll
#undef pthread_join
#undef pthread_sigmask
#undef close
#endif

void lean_initialize_runtime_module(void);
static void check(int value, const char *message) {
  if (!value) { fprintf(stderr, "TLS worker control: %s\n", message); exit(1); }
}
static void pause_ms(unsigned count) {
#ifdef _WIN32
  Sleep(count);
#else
  struct timespec delay = {0, (long)count * 1000000};
  check(nanosleep(&delay, NULL) == 0, "fixture pause");
#endif
}
static int tested_reactor_wake(rn_waker *waker) {
  tw_engine *target = atomic_load(&control_target);
  if (target && waker == target->reactor_waker) {
    atomic_fetch_add(&reactor_calls, 1);
    unsigned error = atomic_exchange(&reactor_fault, 0);
    if (error) return -(int)error;
  }
  int result = rn_waker_wake(waker);
#ifdef _WIN32
  /* Force unrelated successful bookkeeping to clobber LastError. */
  SetLastError(ERROR_INVALID_PARAMETER);
#endif
  return result;
}
#ifdef _WIN32
static BOOL WINAPI tested_set(HANDLE handle) {
  tw_engine *target = atomic_load(&control_target);
  if (target && handle == target->wake) {
    atomic_fetch_add(&write_calls, 1);
    unsigned error = atomic_exchange(&write_fault, 0);
    if (error) { SetLastError(error); return FALSE; }
  }
  return SetEvent(handle);
}
static BOOL WINAPI tested_reset(HANDLE handle) {
  tw_engine *target = atomic_load(&control_target);
  if (target && handle == target->wake) {
    atomic_fetch_add(&reset_calls, 1);
    unsigned error = atomic_exchange(&reset_fault, 0);
    if (error) { SetLastError(error); return FALSE; }
  }
  return ResetEvent(handle);
}
static DWORD WINAPI tested_wait(HANDLE handle, DWORD timeout) {
  tw_engine *target = atomic_load(&control_target);
  if (target && handle == target->thread && timeout == INFINITE) {
    unsigned error = atomic_exchange(&join_fault, 0);
    if (error) { SetLastError(error); return WAIT_FAILED; }
  }
  if (target && handle == target->wake) {
    atomic_fetch_add(&wait_calls, 1);
    unsigned error = atomic_exchange(&wait_fault, 0);
    if (error) { SetLastError(error); return WAIT_FAILED; }
    unsigned result = atomic_exchange(&wait_result, 0);
    if (result) return result;
  }
  return WaitForSingleObject(handle, timeout);
}
static BOOL WINAPI tested_close(HANDLE handle) {
  tw_engine *target = atomic_load(&control_target);
  BOOL result = CloseHandle(handle);
  if (result && target && (handle == target->wake || handle == target->thread)) {
    unsigned error = atomic_exchange(&close_fault, 0);
    if (error) { SetLastError(error); return FALSE; }
  }
  return result;
}
#else
static ssize_t tested_read(int fd, void *bytes, size_t count) {
  tw_engine *target = atomic_load(&control_target);
  if (target && fd == target->wake_read) {
    atomic_fetch_add(&read_calls, 1);
    unsigned error = atomic_exchange(&read_fault, 0);
    if (error) { errno = (int)error; return -1; }
    if (atomic_exchange(&read_zero, 0)) return 0;
  }
  return read(fd, bytes, count);
}
static ssize_t tested_write(int fd, const void *bytes, size_t count) {
  tw_engine *target = atomic_load(&control_target);
  if (target && fd == target->wake_write) {
    atomic_fetch_add(&write_calls, 1);
    unsigned error = atomic_exchange(&write_fault, 0);
    if (error) { errno = (int)error; return -1; }
    if (atomic_exchange(&write_zero, 0)) return 0;
  }
  return write(fd, bytes, count);
}
static int tested_poll(struct pollfd *fds, nfds_t count, int timeout) {
  tw_engine *target = atomic_load(&control_target);
  if (target && count == 1 && fds[0].fd == target->wake_read) {
    atomic_fetch_add(&poll_calls, 1);
    unsigned error = atomic_exchange(&poll_fault, 0);
    if (error) { errno = (int)error; return -1; }
    unsigned events = atomic_exchange(&poll_events, 0);
    if (events) { fds[0].revents = (short)events; return 1; }
  }
  return poll(fds, count, timeout);
}
static int tested_join(pthread_t thread, void **result) {
  tw_engine *target = atomic_load(&control_target);
  if (target && pthread_equal(thread, target->thread)) {
    unsigned error = atomic_exchange(&join_fault, 0); if (error) return (int)error;
  }
  return pthread_join(thread, result);
}
static int tested_sigmask(int how, const sigset_t *set, sigset_t *old) {
  if (how == SIG_BLOCK && set && sigismember(set, SIGINT) == 1 && sigismember(set, SIGTERM) == 1) {
    atomic_fetch_add(&mask_calls, 1);
    unsigned error = atomic_exchange(&mask_fault, 0); if (error) return (int)error;
  }
  return pthread_sigmask(how, set, old);
}
static int tested_close(int fd) {
  tw_engine *target = atomic_load(&control_target);
  int result = close(fd);
  if (!result && target && (fd == target->wake_read || fd == target->wake_write)) {
    unsigned error = atomic_exchange(&close_fault, 0);
    if (error) { errno = (int)error; return -1; }
  }
  return result;
}
#endif
static int64_t scalar(lean_object *value) {
  check(lean_io_result_is_ok(value), "scalar IO result");
  int64_t result = (int64_t)lean_unbox_uint64(lean_io_result_get_value(value)); lean_dec(value); return result;
}
static uint64_t native_handle(lean_object *value) {
  check(lean_io_result_is_ok(value), "handle IO result");
  int64_t result = (int64_t)lean_unbox_uint64(lean_ctor_get(lean_io_result_get_value(value), 0));
  check(result > 0, "create native handle"); lean_dec(value); return (uint64_t)result;
}
static unsigned resources(void) {
#ifdef _WIN32
  DWORD count; check(GetProcessHandleCount(GetCurrentProcess(), &count), "process handle count"); return count;
#else
  unsigned count = 0;
  for (int fd = 0; fd < 4096; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++count;
  return count;
#endif
}
typedef struct { rn_reactor *reactor; lean_object *record; uint64_t handle; tw_bridge *bridge; } fixture;
static fixture create_worker(uint64_t bundle, int active) {
  fixture value = {0}; rn_config config = {2, 16, 4, 4, 0, 0, 1};
  check(rn_new(&config, &value.reactor) == 0, "create reactor");
  value.record = lean_alloc_ctor(0, 1, 8);
  lean_ctor_set(value.record, 0, lean_st_mk_ref(lean_box(1)));
  lean_ctor_set_uint64(value.record, sizeof(void *), (uint64_t)(uintptr_t)value.reactor);
  value.handle = native_handle(lean_tlsw_worker_new(bundle, value.record, 1, 1, 5000, 1000));
  value.bridge = (tw_bridge *)(uintptr_t)value.handle;
  atomic_store(&control_target, value.bridge->engine);
  uint64_t end = rn_now_ms() + 2000;
  while (!atomic_load(&value.bridge->engine->running) && !atomic_load(&value.bridge->engine->control_error) && rn_now_ms() < end) pause_ms(1);
  check(atomic_load(&value.bridge->engine->running) || atomic_load(&value.bridge->engine->control_error), "worker enters real thread");
  if (active) {
    tw_session *session = &value.bridge->engine->sessions[0];
    atomic_store_explicit(&session->state, TW_OPEN, memory_order_release);
    tw_notify_session(value.bridge->engine, session);
    while (atomic_load(&session->state) != TW_ACTIVE && rn_now_ms() < end) pause_ms(1);
    check(atomic_load(&session->state) == TW_ACTIVE && atomic_load(&value.bridge->engine->live_ssl) == 1,
        "real memory-BIO handshake waits on worker owner");
  }
  return value;
}
static void wait_stopped(fixture *value, int error) {
  tw_engine *engine = value->bridge->engine; uint64_t end = rn_now_ms() + 2000;
  while (atomic_load_explicit(&engine->running, memory_order_acquire) && rn_now_ms() < end) pause_ms(1);
  check(!atomic_load(&engine->running) && atomic_load(&engine->control_error) == error,
      "control failure stops worker and retains exact first errno");
  check(!atomic_load(&engine->live_ssl) && !atomic_load(&engine->live_bios), "stopped worker releases all SSL/BIO objects");
  unsigned calls = atomic_load(&read_calls) + atomic_load(&poll_calls) + atomic_load(&reset_calls) + atomic_load(&wait_calls);
  pause_ms(10);
  check(calls == atomic_load(&read_calls) + atomic_load(&poll_calls) + atomic_load(&reset_calls) + atomic_load(&wait_calls),
      "failed worker never retries or busy-loops");
  check(scalar(lean_tlsw_pump(value->handle)) == error && scalar(lean_tlsw_pump(value->handle)) == error &&
      scalar(lean_tlsw_has_work(value->handle)) == 1, "empty-session pump exposes sticky control failure without file event");
}
static void destroy_worker(fixture *value, int expected) {
  check(scalar(lean_tlsw_worker_free(value->handle)) == expected, "join consumes graph and preserves cleanup/control errno");
  atomic_store(&control_target, NULL); lean_dec(value->record);
  check(rn_free(value->reactor) == 0, "reactor outlives joined TLS worker");
}
static void controls(uint64_t bundle) {
  fixture warm = create_worker(bundle, 1); destroy_worker(&warm, 0);
  unsigned before = resources();
#ifdef _WIN32
  const unsigned faults[] = {ERROR_INVALID_HANDLE, ERROR_OPERATION_ABORTED, ERROR_ACCESS_DENIED, WAIT_ABANDONED};
  const int expected[] = {-EBADF, -ECANCELED, -EACCES, -EIO};
  for (unsigned kind = 0; kind < 4; ++kind) {
    fixture value = create_worker(bundle, kind == 0);
    if (!kind) atomic_store(&reset_fault, faults[kind]);
    else if (kind < 3) atomic_store(&wait_fault, faults[kind]);
    else atomic_store(&wait_result, faults[kind]);
    tw_notify_thread(value.bridge->engine); wait_stopped(&value, expected[kind]); destroy_worker(&value, expected[kind]);
    check(resources() <= before, "Windows wait/reset failure leaves no resource growth");
  }
  for (unsigned kind = 0; kind < 2; ++kind) {
    fixture value = create_worker(bundle, 0);
    unsigned error = kind ? ERROR_OPERATION_ABORTED : ERROR_ACCESS_DENIED;
    int expected_error = kind ? -ECANCELED : -EACCES;
    atomic_store(&write_fault, error); tw_notify_thread(value.bridge->engine);
    wait_stopped(&value, expected_error); destroy_worker(&value, expected_error);
    check(resources() <= before, "SetEvent failure preserves LastError across reactor wake and releases resources");
  }
#else
  for (unsigned kind = 0; kind < 2; ++kind) {
    unsigned error = kind ? EINVAL : EINTR, before_masks = atomic_load(&mask_calls);
    unsigned before_io = atomic_load(&read_calls) + atomic_load(&poll_calls);
    atomic_store(&mask_fault, error); fixture value = create_worker(bundle, 0);
    wait_stopped(&value, -(int)error);
    check(atomic_load(&mask_calls) == before_masks + 1 &&
        atomic_load(&read_calls) + atomic_load(&poll_calls) == before_io,
        "mask setup failure is terminal before drive/wait and is never retried");
    destroy_worker(&value, -(int)error); check(resources() <= before, "mask failure releases complete worker graph");
  }
  for (unsigned kind = 0; kind < 10; ++kind) {
    fixture value = create_worker(bundle, kind == 0); int expected = -EIO;
    if (kind < 2) { unsigned error = kind ? EBADF : EINTR; atomic_store(&read_fault, error); expected = -(int)error; }
    else if (kind == 2) { atomic_store(&read_zero, 1); expected = -EPIPE; }
    else if (kind < 5) { unsigned error = kind == 3 ? EINTR : EINVAL; atomic_store(&poll_fault, error); expected = -(int)error; }
    else { unsigned events[] = {POLLERR, POLLNVAL, POLLHUP, POLLPRI, POLLIN | POLLHUP};
      atomic_store(&poll_events, events[kind - 5]); expected = kind == 6 ? -EBADF : kind >= 7 && kind != 8 ? -EPIPE : -EIO; }
    tw_notify_thread(value.bridge->engine); wait_stopped(&value, expected); destroy_worker(&value, expected);
    check(resources() <= before, "read/poll fault leaves no resource growth");
  }
  for (unsigned kind = 0; kind < 5; ++kind) {
    fixture value = create_worker(bundle, 0); int expected = 0;
    if (kind < 2) atomic_store(&write_fault, kind ? EWOULDBLOCK : EAGAIN);
    else if (kind < 4) { unsigned error = kind == 2 ? EINTR : EIO; atomic_store(&write_fault, error); expected = -(int)error; }
    else { atomic_store(&write_zero, 1); expected = -EIO; }
    tw_notify_thread(value.bridge->engine);
    if (expected) wait_stopped(&value, expected);
    else check(!atomic_load(&value.bridge->engine->control_error), "full wake pipe coalesces EAGAIN without failure");
    destroy_worker(&value, expected); check(resources() <= before, "producer wake fault/coalescing leaves no resource growth");
  }
#endif
  for (unsigned kind = 0; kind < 3; ++kind) {
    fixture value = create_worker(bundle, 0); unsigned error = kind == 0 ? EINTR : kind == 1 ? EIO : ECANCELED;
    atomic_store(&reactor_fault, error); tw_notify_reactor(value.bridge->engine);
    wait_stopped(&value, -(int)error); destroy_worker(&value, -(int)error);
    check(resources() <= before, "retained reactor wake failure stops safely");
  }
  fixture joined = create_worker(bundle, 0);
#ifdef _WIN32
  atomic_store(&join_fault, ERROR_ACCESS_DENIED); int join_error = -EACCES;
#else
  atomic_store(&join_fault, EDEADLK); int join_error = -EDEADLK;
#endif
  check(scalar(lean_tlsw_worker_free(joined.handle)) == join_error && joined.bridge->engine != NULL,
      "failed join retains complete live ownership graph"); destroy_worker(&joined, 0);
  fixture closed = create_worker(bundle, 0);
#ifdef _WIN32
  atomic_store(&close_fault, ERROR_ACCESS_DENIED); int close_error = -EACCES;
#else
  atomic_store(&close_fault, EINTR); int close_error = -EINTR;
#endif
  destroy_worker(&closed, close_error); check(resources() <= before, "consumed close error is never retried");
}
#ifndef _WIN32
static volatile sig_atomic_t signals_seen;
static void signal_seen(int number) { (void)number; ++signals_seen; }
static void shutdown_signal_routing(uint64_t bundle) {
  struct sigaction action = {0}, old_int, old_term; action.sa_handler = signal_seen;
  check(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGINT, &action, &old_int) == 0 &&
      sigaction(SIGTERM, &action, &old_term) == 0, "install fixture stop-signal handlers");
  sigset_t before, after;
  check(pthread_sigmask(SIG_BLOCK, NULL, &before) == 0, "capture caller signal mask");
  fixture value = create_worker(bundle, 1); pause_ms(10); signals_seen = 0;
  check(pthread_kill(value.bridge->engine->thread, SIGINT) == 0 &&
      pthread_kill(value.bridge->engine->thread, SIGTERM) == 0, "target real TLS worker with stop signals");
  pause_ms(30);
  check(!signals_seen && !atomic_load(&value.bridge->engine->control_error) && atomic_load(&value.bridge->engine->running),
      "TLS thread blocks stop signals instead of interrupting its native wait");
  check(raise(SIGINT) == 0, "deliver shutdown on the application owner thread");
  check(signals_seen == 1 && !atomic_load(&value.bridge->engine->control_error), "application stop remains handled outside TLS thread");
  destroy_worker(&value, 0);
  check(pthread_sigmask(SIG_BLOCK, NULL, &after) == 0 &&
      sigismember(&before, SIGINT) == sigismember(&after, SIGINT) &&
      sigismember(&before, SIGTERM) == sigismember(&after, SIGTERM), "caller signal mask is unchanged");
  check(sigaction(SIGINT, &old_int, NULL) == 0 && sigaction(SIGTERM, &old_term, NULL) == 0,
      "restore fixture signal dispositions");
}
#endif
static void historical_control_failure(uint64_t bundle) {
  fixture value = create_worker(bundle, 0); tw_engine *engine = value.bridge->engine;
  tw_engine_control_fail(engine, -EINTR);
  uint64_t end = rn_now_ms() + 2000;
  while (atomic_load(&engine->running) && rn_now_ms() < end) pause_ms(1);
  check(!atomic_load(&engine->running), "terminal control failure stops before historical test");
  tw_session *session = &engine->sessions[0]; tw_bridge_session *owner = &value.bridge->sessions[0];
  atomic_store(&session->state, TW_DONE); owner->used = owner->plain_borrowed = 1; owner->generation = 1;
  owner->cipher_operation = TLSW_CIPHER_OPERATION | (UINT64_C(1) << 20) | 1; owner->cipher_length = 3;
  value.bridge->event_capacity = 1;
  free(session->fences.cells); memset(&session->fences, 0, sizeof(session->fences));
  check(tw_lane_new(&session->fences, 3) == 0, "preallocate three historical fence cells after producer exit");
  for (unsigned i = 0; i < 3; ++i) {
    tw_cell *cell = tw_producer(&session->fences); check(cell != NULL, "historical fence queue credit");
    cell->operation = 101 + i; cell->length = 1; cell->fence = i == 2 ? 4 : i + 1; tw_publish(&session->fences);
  }
  uint64_t token = tw_token(0, 1);
  check(scalar(lean_tlsw_pump(value.handle)) == 0 && tw_consumer(&session->fences),
      "terminal control preserves unacknowledged fence until native closure");
  check(scalar(lean_tlsw_on_written(value.handle, owner->cipher_operation, 3)) == 0,
      "physical completion remains accepted after engine control failure");
  check(scalar(lean_tlsw_native_closed(value.handle, token)) == 0, "native close remains authoritative");
  check(scalar(lean_tlsw_pump(value.handle)) == 1 && value.bridge->events[0].kind == TLSW_WRITTEN &&
      value.bridge->events[0].operation == 101, "historical fulfilled write precedes terminal control report");
  check(scalar(lean_tlsw_pump(value.handle)) == 1 && value.bridge->events[0].kind == TLSW_WRITTEN &&
      value.bridge->events[0].operation == 102, "second fulfilled operation survives one-event batch exhaustion");
  check(scalar(lean_tlsw_pump(value.handle)) == 1 && value.bridge->events[0].kind == TLSW_CLOSED && owner->used &&
      !tw_consumer(&session->fences),
      "CLOSED is delivered while loan still preserves old generation");
  check(scalar(lean_tlsw_release_plain(value.handle, token)) == 0 && scalar(lean_tlsw_pump(value.handle)) == -EINTR && !owner->used,
      "only later pump returns sticky EINTR after historical completion and close");
  destroy_worker(&value, -EINTR);
}
int main(int argc, char **argv) {
  check(argc == 6, "certificate fixture arguments"); lean_initialize_runtime_module();
  lean_object *cert = lean_mk_string(argv[1]), *key = lean_mk_string(argv[2]), *empty = lean_mk_empty_array();
  uint64_t bundle = native_handle(lean_tlsw_bundle_new(cert, key, empty, empty, empty, 1));
  lean_dec(cert); lean_dec(key); lean_dec(empty);
  tw_provider *provider = (tw_provider *)(uintptr_t)bundle; tw_bundle *original = provider->current;
  controls(bundle); historical_control_failure(bundle);
#ifndef _WIN32
  shutdown_signal_routing(bundle);
#endif
  check(provider->current == original && atomic_load(&provider->generation) == 1 &&
      atomic_load(&original->references) == 1 && atomic_load(&provider->references) == 1,
      "worker control faults preserve last-good bundle and all references");
  check(scalar(lean_tlsw_bundle_free(bundle)) == 0, "free bundle after every worker joins");
  puts("TLS worker control faults, no retry, historical fences and cleanup passed"); return 0;
}
