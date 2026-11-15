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
#include <openssl/crypto.h>
static int tested_reload_unlock(CRYPTO_RWLOCK *);
static int tested_reload_read_lock(CRYPTO_RWLOCK *);
static int tested_reload_write_lock(CRYPTO_RWLOCK *);
#define CRYPTO_THREAD_unlock tested_reload_unlock
#define CRYPTO_THREAD_read_lock tested_reload_read_lock
#define CRYPTO_THREAD_write_lock tested_reload_write_lock
#ifndef _WIN32
#include <pthread.h>
#include <time.h>
static int tested_reload_join(pthread_t, void **);
static int tested_reload_clock(clockid_t, struct timespec *);
static int tested_reload_signal(pthread_cond_t *);
static int tested_reload_wait(pthread_cond_t *, pthread_mutex_t *, const struct timespec *);
#define pthread_join tested_reload_join
#define clock_gettime tested_reload_clock
#define pthread_cond_signal tested_reload_signal
#ifdef __APPLE__
#define pthread_cond_timedwait_relative_np tested_reload_wait
#else
#define pthread_cond_timedwait tested_reload_wait
#endif
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
static BOOL WINAPI tested_reload_signal(HANDLE);
static BOOL WINAPI tested_reload_reset(HANDLE);
static DWORD WINAPI tested_reload_wait(HANDLE, DWORD);
#define SetEvent tested_reload_signal
#define ResetEvent tested_reload_reset
#define WaitForSingleObject tested_reload_wait
#endif
#include "../c/tls_worker.c"
#undef CRYPTO_THREAD_unlock
#undef CRYPTO_THREAD_read_lock
#undef CRYPTO_THREAD_write_lock
#ifndef _WIN32
#undef pthread_join
#undef clock_gettime
#undef pthread_cond_signal
#undef pthread_cond_timedwait
#undef pthread_cond_timedwait_relative_np
#else
#undef SetEvent
#undef ResetEvent
#undef WaitForSingleObject
#endif
#include <stdio.h>

/* Bundles without OCSP responses or client-certificate verification. */
static lean_object *test_bundle_new(lean_object *cert, lean_object *key, lean_object *names,
    lean_object *certs, lean_object *keys, uint8_t tickets) {
  size_t count = lean_array_size(names) + 1;
  lean_object *ocsp = lean_alloc_array(count, count);
  for (size_t i = 0; i < count; ++i) lean_array_set_core(ocsp, i, lean_mk_string(""));
  lean_object *ca = lean_mk_string("");
  lean_object *result = lean_tlsw_bundle_new(cert, key, names, certs, keys, tickets, ocsp, ca, 0);
  lean_dec(ocsp); lean_dec(ca); return result;
}

void lean_initialize_runtime_module(void);
static void check(int condition, const char *message) {
  if (!condition) { fprintf(stderr, "TLS reload native: %s\n", message); exit(1); }
}
static unsigned fail_join;
static atomic_uint signal_error, wait_error, wait_entered, wait_release, unlock_error;
static atomic_uint read_lock_error, write_lock_error;
#ifdef _WIN32
static atomic_uint reset_error;
#endif
static tw_provider *wait_target;
static void pause_ms(unsigned);
static int tested_reload_unlock(CRYPTO_RWLOCK *lock) {
  int result = CRYPTO_THREAD_unlock(lock);
  return atomic_exchange(&unlock_error, 0) ? 0 : result;
}
static int tested_reload_read_lock(CRYPTO_RWLOCK *lock) {
  return atomic_exchange(&read_lock_error, 0) ? 0 : CRYPTO_THREAD_read_lock(lock);
}
static int tested_reload_write_lock(CRYPTO_RWLOCK *lock) {
  return atomic_exchange(&write_lock_error, 0) ? 0 : CRYPTO_THREAD_write_lock(lock);
}
static unsigned wait_fault(void) {
  if (!atomic_load(&wait_error) || !wait_target ||
      atomic_load(&wait_target->requested) <= atomic_load(&wait_target->completed)) return 0;
  uint64_t cutoff = rn_now_ms() + 2000;
  while (!atomic_load(&wait_release) && rn_now_ms() < cutoff) pause_ms(1);
  check(atomic_load(&wait_release), "release deterministic wait-error barrier");
  return atomic_exchange(&wait_error, 0);
}
#ifndef _WIN32
static atomic_uint clock_error;
static int tested_reload_clock(clockid_t id, struct timespec *value) {
  unsigned error = atomic_exchange(&clock_error, 0);
  if (error) { errno = (int)error; return -1; }
  return clock_gettime(id, value);
}
static int tested_reload_join(pthread_t thread, void **result) {
  if (fail_join) { --fail_join; return EBUSY; }
  return pthread_join(thread, result);
}
static int tested_reload_signal(pthread_cond_t *condition) {
  unsigned error = atomic_exchange(&signal_error, 0);
  return error ? (int)error : pthread_cond_signal(condition);
}
static int tested_reload_wait(pthread_cond_t *condition, pthread_mutex_t *mutex, const struct timespec *timeout) {
  atomic_store(&wait_entered, 1);
#ifdef __APPLE__
  int result = pthread_cond_timedwait_relative_np(condition, mutex, timeout);
#else
  int result = pthread_cond_timedwait(condition, mutex, timeout);
#endif
  unsigned error = wait_fault(); return error ? (int)error : result;
}
#else
static BOOL WINAPI tested_reload_signal(HANDLE event) {
  unsigned error = atomic_exchange(&signal_error, 0);
  if (error) { SetLastError(error); return FALSE; }
  return SetEvent(event);
}
static BOOL WINAPI tested_reload_reset(HANDLE event) {
  unsigned error = atomic_exchange(&reset_error, 0);
  if (error) { SetLastError(error); return FALSE; }
  return ResetEvent(event);
}
static DWORD WINAPI tested_reload_wait(HANDLE object, DWORD timeout) {
  if (timeout == INFINITE && fail_join) { --fail_join; SetLastError(ERROR_BUSY); return WAIT_FAILED; }
  if (timeout != INFINITE) atomic_store(&wait_entered, 1);
  DWORD result = WaitForSingleObject(object, timeout);
  unsigned error = timeout != INFINITE ? wait_fault() : 0;
  if (error) { SetLastError(error); return WAIT_FAILED; }
  return result;
}
#endif
static int64_t result(lean_object *value) {
  check(lean_io_result_is_ok(value), "native IO result");
  int64_t number = (int64_t)lean_unbox_uint64(lean_io_result_get_value(value)); lean_dec(value); return number;
}
static uint64_t handle(lean_object *value) {
  check(lean_io_result_is_ok(value), "native handle IO result");
  lean_object *pair = lean_io_result_get_value(value);
  int64_t number = (int64_t)lean_unbox_uint64(lean_ctor_get(pair, 0));
  if (number <= 0) fprintf(stderr, "%s\n", lean_string_cstr(lean_ctor_get(pair, 1)));
  check(number > 0, "create valid TLS provider"); lean_dec(value); return (uint64_t)number;
}
static void pause_ms(unsigned count) {
#ifdef _WIN32
  Sleep(count);
#else
  struct pollfd empty = {-1, 0, 0}; (void)poll(&empty, 0, (int)count);
#endif
}
static void copy_file(const char *from, const char *to) {
  FILE *source = fopen(from, "rb"), *target = fopen(to, "wb");
  check(source && target, "open fixture certificate paths");
  unsigned char bytes[4096]; size_t length;
  while ((length = fread(bytes, 1, sizeof(bytes), source)))
    check(fwrite(bytes, 1, length, target) == length, "copy fixture PEM");
  check(!ferror(source) && fclose(source) == 0 && fclose(target) == 0, "close fixture PEM");
}
static void invalid_certificate(const char *source, const char *secret, const char *target, unsigned kind) {
  BIO *input = BIO_new_file(source, "rb"), *key_input = BIO_new_file(secret, "rb");
  check(input && key_input, "open invalid-certificate fixture inputs");
  X509 *leaf = PEM_read_bio_X509(input, NULL, NULL, NULL);
  EVP_PKEY *key = PEM_read_bio_PrivateKey(key_input, NULL, tw_password, NULL);
  check(leaf && key, "parse invalid-certificate fixture inputs"); BIO_free(input); BIO_free(key_input);
  if (kind < 2) {
    check(X509_gmtime_adj(X509_getm_notBefore(leaf), kind ? 3600 : -7200) &&
          X509_gmtime_adj(X509_getm_notAfter(leaf), kind ? 7200 : -3600), "set certificate validity fixture");
  } else {
    int index;
    while ((index = X509_get_ext_by_NID(leaf, NID_subject_alt_name, -1)) >= 0) X509_EXTENSION_free(X509_delete_ext(leaf, index));
    X509_EXTENSION *extension = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, "DNS:gamma.test");
    check(extension && X509_add_ext(leaf, extension, -1), "set wrong-SNI certificate fixture"); X509_EXTENSION_free(extension);
  }
  check(X509_sign(leaf, key, EVP_sha256()) > 0, "sign invalid-certificate fixture"); EVP_PKEY_free(key);
  BIO *output = BIO_new_file(target, "wb"); check(output && PEM_write_bio_X509(output, leaf), "write invalid-certificate fixture");
  BIO_free(output); X509_free(leaf);
}
static void wait_ticket(tw_provider *provider, uint64_t ticket) {
  uint64_t cutoff = rn_now_ms() + 5000;
  while (atomic_load_explicit(&provider->completed, memory_order_acquire) < ticket && rn_now_ms() < cutoff) pause_ms(1);
  check(atomic_load(&provider->completed) >= ticket, "loader acknowledges bounded explicit request");
}
static void request(tw_provider *provider) {
  int64_t ticket = result(lean_tlsw_bundle_reload_request((uint64_t)(uintptr_t)provider));
  check(ticket > 0, "request asynchronous reload"); wait_ticket(provider, (uint64_t)ticket);
}
static unsigned handles(void) {
#ifdef _WIN32
  DWORD count = 0; check(GetProcessHandleCount(GetCurrentProcess(), &count), "count process handles"); return count;
#else
  unsigned count = 0;
  for (int fd = 0; fd < 4096; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++count;
  return count;
#endif
}
static uint64_t provider(const char *certificate, const char *key) {
  lean_object *cert = lean_mk_string(certificate), *secret = lean_mk_string(key);
  lean_object *names = lean_alloc_array(2, 2), *certs = lean_alloc_array(2, 2), *keys = lean_alloc_array(2, 2);
  lean_array_set_core(names, 0, lean_mk_string("alpha.test")); lean_array_set_core(names, 1, lean_mk_string("beta.test"));
  for (unsigned i = 0; i < 2; ++i) {
    lean_array_set_core(certs, i, lean_mk_string(certificate)); lean_array_set_core(keys, i, lean_mk_string(key));
  }
  uint64_t value = handle(test_bundle_new(cert, secret, names, certs, keys, 1));
  lean_dec(cert); lean_dec(secret); lean_dec(names); lean_dec(certs); lean_dec(keys); return value;
}
static void stats_abi(tw_provider *provider) {
  lean_object *value = lean_tlsw_bundle_reload_stats((uint64_t)(uintptr_t)provider);
  check(lean_io_result_is_ok(value), "reload status IO result"); lean_object *stats = lean_io_result_get_value(value);
  check(lean_ctor_get_uint64(stats, 0) == atomic_load(&provider->generation), "status generation scalar ABI");
  check(lean_ctor_get_uint64(stats, 5 * sizeof(uint64_t)) == atomic_load(&provider->live_versions), "status live version scalar ABI");
  check(lean_ctor_get_uint64(stats, 8 * sizeof(uint64_t)) == atomic_load(&provider->completed), "status acknowledgement scalar ABI"); lean_dec(value);
}
static void wait_atomic(atomic_uint *value, unsigned expected) {
  uint64_t cutoff = rn_now_ms() + 5000;
  while (atomic_load(value) != expected && rn_now_ms() < cutoff) pause_ms(1);
  check(atomic_load(value) == expected, "bounded native control state transition");
}
static void control_faults(const char *certificate, const char *key) {
#ifdef _WIN32
  unsigned native_error = ERROR_INVALID_HANDLE;
  int expected_error = -EBADF;
  int interrupted_error = -ECANCELED; /* ERROR_OPERATION_ABORTED is cancellation. */
#else
  unsigned native_error = EINVAL;
  int expected_error = -EINVAL;
  int interrupted_error = -EINTR;
#endif
  for (unsigned kind = 0; kind < 3; ++kind) {
#ifdef _WIN32
    unsigned injected = kind == 2 ? ERROR_OPERATION_ABORTED : native_error;
#else
    unsigned injected = kind == 2 ? EINTR : native_error;
#endif
    int expected = kind == 2 ? interrupted_error : expected_error;
    uint64_t value = provider(certificate, key); tw_provider *owner = (tw_provider *)(uintptr_t)value;
    atomic_store(&wait_entered, 0); atomic_store(&wait_release, 0); wait_target = owner;
    if (kind) atomic_store(&wait_error, injected);
    check(result(lean_tlsw_bundle_reload_start(value, 0)) == 0, "start fault-injected loader");
    wait_atomic(&wait_entered, 1);
    if (!kind) atomic_store(&signal_error, injected);
    int64_t ticket = result(lean_tlsw_bundle_reload_request(value));
    if (kind) {
      check(ticket > 0, "request accepted before deterministic wait fault"); atomic_store(&wait_release, 1);
      wait_ticket(owner, (uint64_t)ticket);
    } else check(ticket == expected, "signal failure surfaces directly from request");
    wait_atomic(&owner->loader_threads, 0);
    check(atomic_load(&owner->completed) == atomic_load(&owner->requested), "control fault acknowledges every pending ticket");
    check(atomic_load(&owner->control_error) == expected && atomic_load(&owner->last_error) == expected,
          "sticky control fault remains visible");
    check(atomic_load(&owner->generation) == 1 && atomic_load(&owner->live_versions) == 1, "control fault keeps last good context");
    check(result(lean_tlsw_bundle_reload_request(value)) == expected, "failed loader rejects future tickets");
    check(result(lean_tlsw_bundle_free(value)) == 0, "failed loader still joins and releases resources"); wait_target = NULL;
  }
  uint64_t value = provider(certificate, key); tw_provider *owner = (tw_provider *)(uintptr_t)value;
  check(result(lean_tlsw_bundle_reload_start(value, 0)) == 0, "start loader for consumed cleanup error");
  atomic_fetch_add(&owner->references, 1);
#ifdef _WIN32
  atomic_store(&signal_error, ERROR_OPERATION_ABORTED);
#else
  atomic_store(&signal_error, EINTR);
#endif
  check(result(lean_tlsw_bundle_free(value)) == interrupted_error, "joined cleanup reports wake failure without retrying");
  check(atomic_load(&owner->references) == 1 && !atomic_load(&owner->loader_threads), "cleanup error consumes outer ownership after join");
  tw_provider_release(owner);
#ifndef _WIN32
  value = provider(certificate, key); owner = (tw_provider *)(uintptr_t)value;
  atomic_store(&clock_error, EIO);
  check(result(lean_tlsw_bundle_reload_start(value, 0)) == 0, "start clock-error loader");
  int64_t ticket = result(lean_tlsw_bundle_reload_request(value));
  if (ticket > 0) wait_ticket(owner, (uint64_t)ticket);
  else check(ticket == -EIO, "clock error rejects new request explicitly");
  wait_atomic(&owner->loader_threads, 0);
  check(atomic_load(&owner->control_error) == -EIO &&
        atomic_load(&owner->completed) == atomic_load(&owner->requested) && atomic_load(&owner->generation) == 1,
        "clock failure is visible and cannot strand a ticket or publish a candidate");
  check(result(lean_tlsw_bundle_reload_request(value)) == -EIO, "clock failure rejects future tickets");
  check(result(lean_tlsw_bundle_free(value)) == 0, "clock-error loader joins safely");
#endif
#ifdef _WIN32
  value = provider(certificate, key); owner = (tw_provider *)(uintptr_t)value;
  atomic_store(&reset_error, ERROR_INVALID_HANDLE);
  check(result(lean_tlsw_bundle_reload_start(value, 0)) == 0, "start reset-error loader");
  uint64_t cutoff = rn_now_ms() + 5000;
  while (!atomic_load(&owner->control_error) && rn_now_ms() < cutoff) pause_ms(1);
  check(atomic_load(&owner->control_error) == -EBADF, "ResetEvent failure remains visible");
  check(result(lean_tlsw_bundle_reload_request(value)) == -EBADF, "reset fault rejects future ticket");
  check(result(lean_tlsw_bundle_free(value)) == 0, "reset fault joins safely");
#endif
}
static void snapshot_faults(const char *certificate, const char *key,
                            const char *initial_certificate, const char *initial_key,
                            const char *next_certificate, const char *next_key) {
  for (unsigned kind = 0; kind < 2; ++kind) {
  uint64_t value = provider(certificate, key); tw_provider *owner = (tw_provider *)(uintptr_t)value;
  atomic_store(kind ? &read_lock_error : &unlock_error, 1);
  check(!tw_provider_snapshot(owner), "read-unlock fault rejects retained snapshot");
  check(atomic_load(&owner->snapshot_error) == -EIO && atomic_load(&owner->control_error) == -EIO &&
        atomic_load(&owner->current->references) == 1 && atomic_load(&owner->live_versions) == 1,
        "read-unlock failure surfaces EIO and drops exactly the unreturned pin");
  check(!tw_provider_snapshot(owner), "faulted lock is never entered for later TLS opens");
  check(result(lean_tlsw_bundle_free(value)) == 0, "release read-lock-fault provider");
  }
  for (unsigned kind = 0; kind < 2; ++kind) {
  copy_file(initial_certificate, certificate); copy_file(initial_key, key);
  uint64_t value = provider(certificate, key); tw_provider *owner = (tw_provider *)(uintptr_t)value;
  tw_bundle *previous = tw_provider_snapshot(owner); check(previous != NULL, "pin old generation before write-unlock fault");
  check(result(lean_tlsw_bundle_reload_start(value, 0)) == 0, "start write-unlock-fault loader");
  copy_file(next_certificate, certificate); copy_file(next_key, key);
  atomic_store(kind ? &write_lock_error : &unlock_error, 1);
  int64_t ticket = result(lean_tlsw_bundle_reload_request(value));
  if (ticket > 0) wait_ticket(owner, (uint64_t)ticket);
  else check(ticket == -EIO, "concurrent write-unlock fault is explicit request error");
  wait_atomic(&owner->loader_threads, 0);
  check(atomic_load(&owner->snapshot_error) == -EIO && atomic_load(&owner->control_error) == -EIO,
        "write-unlock fault surfaces EIO");
  if (kind) check(owner->current == previous && atomic_load(&owner->generation) == 1 &&
                  atomic_load(&previous->references) == 2 && atomic_load(&owner->live_versions) == 1,
                  "write-lock rejection preserves current and releases candidate");
  else check(owner->current != previous && atomic_load(&owner->generation) == 2 &&
             atomic_load(&previous->references) == 1 && atomic_load(&owner->live_versions) == 2,
             "published current and retired held snapshot retain exact ownership on unlock error");
  tw_bundle_release(previous); check(atomic_load(&owner->live_versions) == 1, "retired fault-path snapshot frees after last pin");
  check(result(lean_tlsw_bundle_free(value)) == 0, "join write-lock-fault loader");
  }
}
int main(int argc, char **argv) {
  check(argc == 6, "old cert/key, new cert/key, temporary directory arguments"); lean_initialize_runtime_module();
  char certificate[4096], key[4096];
  check(snprintf(certificate, sizeof(certificate), "%s/live-cert.pem", argv[5]) > 0 &&
        snprintf(key, sizeof(key), "%s/live-key.pem", argv[5]) > 0, "fixture paths");
  copy_file(argv[1], certificate); copy_file(argv[2], key);
  uint64_t value = provider(certificate, key); tw_provider *owner = (tw_provider *)(uintptr_t)value;
  check(result(lean_tlsw_bundle_reload_request(value)) == -ENOTSUP, "disabled reload rejects request");
  check(result(lean_tlsw_bundle_reload_start(value, 0)) == 0, "start explicit loader");
  check(result(lean_tlsw_bundle_reload_start(value, 0)) == -EALREADY, "duplicate loader rejected");
  tw_bundle *old = tw_provider_snapshot(owner); check(old != NULL, "retain old handshake snapshot");
  SSL *old_ssl = SSL_new(old->contexts[0].ssl); check(old_ssl != NULL, "old SSL owns immutable context");
  unsigned before = handles(); request(owner);
  check(atomic_load(&owner->generation) == 1 && !atomic_load(&owner->publications), "unchanged bytes preserve ticket/cache namespace");
  FILE *bad = fopen(key, "wb"); check(bad && fwrite("partial", 1, 7, bad) == 7 && !fclose(bad), "write partial replacement");
  request(owner); check(atomic_load(&owner->last_error) < 0 && atomic_load(&owner->generation) == 1, "partial replacement keeps last good snapshot");
  copy_file(argv[2], key);
  for (unsigned kind = 0; kind < 3; ++kind) {
    invalid_certificate(argv[1], argv[2], certificate, kind); request(owner);
    check(atomic_load(&owner->last_error) < 0 && atomic_load(&owner->generation) == 1,
          "expired, future and wrong-SNI candidates retain last good snapshot");
  }
  bad = fopen(certificate, "wb"); check(bad != NULL, "open oversized PEM fixture");
  for (unsigned i = 0; i <= TW_MAX_PEM_FILE; ++i) check(fputc('x', bad) == 'x', "write oversized PEM fixture");
  check(!fclose(bad), "close oversized PEM fixture"); request(owner);
  check(atomic_load(&owner->last_error) == -EFBIG && atomic_load(&owner->generation) == 1, "oversized PEM rejected before parsing");
#ifndef _WIN32
  check(unlink(certificate) == 0 && mkfifo(certificate, 0600) == 0, "create nonregular PEM fixture"); request(owner);
  check(atomic_load(&owner->last_error) == -EINVAL && atomic_load(&owner->generation) == 1, "FIFO cannot block native loader");
  check(unlink(certificate) == 0, "remove nonregular PEM fixture");
#endif
  copy_file(argv[2], key); copy_file(argv[3], certificate); request(owner);
  check(atomic_load(&owner->last_error) < 0 && atomic_load(&owner->generation) == 1, "mismatched key never publishes");
  copy_file(argv[4], key); request(owner);
  check(atomic_load(&owner->last_error) == 0 && atomic_load(&owner->generation) == 2, "valid full replacement publishes");
  tw_bundle *fresh = tw_provider_snapshot(owner); check(fresh && fresh != old, "new SSL acquires new snapshot");
  check(memcmp(fresh->contexts[0].identity, old->contexts[0].identity, SHA256_DIGEST_LENGTH), "leaf fingerprint changed");
  unsigned char old_identity[SHA256_DIGEST_LENGTH]; unsigned int identity_size = 0;
  check(X509_digest(SSL_get_certificate(old_ssl), EVP_sha256(), old_identity, &identity_size) == 1 &&
        identity_size == sizeof(old_identity) && !memcmp(old_identity, old->contexts[0].identity, sizeof(old_identity)),
        "old SSL retains its original certificate while new context is published");
  tw_bundle_release(fresh); check(atomic_load(&owner->live_versions) == 2, "retired snapshot bounded by held session");
  for (unsigned cycle = 0; cycle < 1000; ++cycle) {
    unsigned source = cycle % 2 ? 3 : 1;
    copy_file(argv[source], certificate); copy_file(argv[source + 1], key); request(owner);
    check(!atomic_load(&owner->last_error), "repeated valid reload succeeds");
    check(atomic_load(&owner->live_versions) <= 2, "no unbounded retired bundle history");
    check(handles() <= before, "reload file handles remain flat");
  }
  SSL_free(old_ssl); tw_bundle_release(old);
  check(atomic_load(&owner->live_versions) == 1, "last old session releases its context snapshot"); stats_abi(owner);
  fail_join = 1;
  check(result(lean_tlsw_bundle_free(value)) < 0, "failed loader join preserves native graph");
  check(owner->current && atomic_load(&owner->live_versions) == 1, "join failure retains contexts");
  check(result(lean_tlsw_bundle_free(value)) == 0, "stop/join loader then release provider");
  copy_file(argv[1], certificate); copy_file(argv[2], key); value = provider(certificate, key); owner = (tw_provider *)(uintptr_t)value;
  check(result(lean_tlsw_bundle_reload_start(value, 20)) == 0, "start periodic detection");
  copy_file(argv[3], certificate); copy_file(argv[4], key);
  uint64_t deadline = rn_now_ms() + 5000;
  while (atomic_load(&owner->generation) == 1 && rn_now_ms() < deadline) pause_ms(1);
  check(atomic_load(&owner->generation) == 2 && !atomic_load(&owner->requested), "periodic change detection needs no loop request");
  pause_ms(75); check(atomic_load(&owner->generation) == 2, "unchanged periodic scans retain current cache");
  /* A retained engine-style provider reference survives the outer bracket,
   * proving loader join precedes eventual context/provider destruction. */
  atomic_fetch_add(&owner->references, 1); deadline = rn_now_ms();
  check(result(lean_tlsw_bundle_free(value)) == 0, "stop periodic loader");
  check(rn_now_ms() - deadline < 500 && !atomic_load(&owner->loader_threads), "stop interrupts loader interval wait");
  check(!tw_provider_snapshot(owner), "closed provider rejects new handshakes"); tw_provider_release(owner);
  control_faults(certificate, key);
  copy_file(argv[1], certificate); copy_file(argv[2], key);
  snapshot_faults(certificate, key, argv[1], argv[2], argv[3], argv[4]);
  puts("TLS reload ownership, 1000 retirements, failure retention and loader lifetime passed"); return 0;
}
