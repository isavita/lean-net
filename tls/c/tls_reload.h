/* Private implementation included once by tls_worker.c. Only the loader and
 * TLS owner threads take the snapshot lock; reactor requests/stats are atomic. */
#ifndef LEAN_NET_TLS_RELOAD_H
#define LEAN_NET_TLS_RELOAD_H
#define TW_MAX_PEM_FILE (1024u * 1024u)
#define TW_MAX_PEM_TOTAL (16u * 1024u * 1024u)
#define TW_MAX_CHAIN 32
#ifndef ESTALE
#define ESTALE EIO
#endif
typedef struct tw_stamp { uint64_t fields[7]; } tw_stamp;
typedef struct tw_pem { unsigned char *bytes; size_t length; tw_stamp stamp; } tw_pem;
static char *tw_copy_text(b_lean_obj_arg value) {
  size_t length = lean_string_size(value) - 1;
  if (length > 32768 || strlen(lean_string_cstr(value)) != length) return NULL;
  char *copy = malloc(length + 1);
  if (copy) memcpy(copy, lean_string_cstr(value), length + 1);
  return copy;
}
#ifdef _WIN32
static HANDLE tw_pem_open(const char *path, int *error) {
  int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
  if (!length) { *error = -EINVAL; return INVALID_HANDLE_VALUE; }
  wchar_t *wide = malloc((size_t)length * sizeof(*wide));
  if (!wide) { *error = -ENOMEM; return INVALID_HANDLE_VALUE; }
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, length)) {
    free(wide); *error = -EINVAL; return INVALID_HANDLE_VALUE;
  }
  HANDLE file = CreateFileW(wide, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
  DWORD native = GetLastError(); free(wide);
  if (file == INVALID_HANDLE_VALUE) *error = -ln_windows_errno(native);
  return file;
}
static int tw_pem_stamp(HANDLE file, tw_stamp *stamp) {
  BY_HANDLE_FILE_INFORMATION info;
  if (GetFileType(file) != FILE_TYPE_DISK) return -EINVAL;
  if (!GetFileInformationByHandle(file, &info)) return -ln_windows_errno(GetLastError());
  if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return -EINVAL;
  *stamp = (tw_stamp){{info.dwVolumeSerialNumber,
    ((uint64_t)info.nFileIndexHigh << 32) | info.nFileIndexLow,
    ((uint64_t)info.nFileSizeHigh << 32) | info.nFileSizeLow,
    ((uint64_t)info.ftLastWriteTime.dwHighDateTime << 32) | info.ftLastWriteTime.dwLowDateTime,
    ((uint64_t)info.ftCreationTime.dwHighDateTime << 32) | info.ftCreationTime.dwLowDateTime, 0, 0}};
  return 0;
}
static int tw_pem_close(HANDLE file) { return CloseHandle(file) ? 0 : -ln_windows_errno(GetLastError()); }
#else
static int tw_pem_stamp(int file, tw_stamp *stamp) {
  struct stat info;
  if (fstat(file, &info) < 0) return -errno;
  if (!S_ISREG(info.st_mode) || info.st_size < 0) return -EINVAL;
#ifdef __APPLE__
  *stamp = (tw_stamp){{(uint64_t)info.st_dev, (uint64_t)info.st_ino, (uint64_t)info.st_size,
    (uint64_t)info.st_mtimespec.tv_sec, (uint64_t)info.st_mtimespec.tv_nsec,
    (uint64_t)info.st_ctimespec.tv_sec, (uint64_t)info.st_ctimespec.tv_nsec}};
#else
  *stamp = (tw_stamp){{(uint64_t)info.st_dev, (uint64_t)info.st_ino, (uint64_t)info.st_size,
    (uint64_t)info.st_mtim.tv_sec, (uint64_t)info.st_mtim.tv_nsec,
    (uint64_t)info.st_ctim.tv_sec, (uint64_t)info.st_ctim.tv_nsec}};
#endif
  return 0;
}
static int tw_pem_close(int file) { return close(file) < 0 ? -errno : 0; }
#endif
static void tw_pem_free(tw_pem *pem) {
  if (pem->bytes) { OPENSSL_cleanse(pem->bytes, pem->length); free(pem->bytes); }
  pem->bytes = NULL; pem->length = 0;
}
static int tw_pem_read(const char *path, tw_pem *pem, size_t *total) {
  int error = 0;
#ifdef _WIN32
  HANDLE file = tw_pem_open(path, &error);
  if (file == INVALID_HANDLE_VALUE) return error;
#else
  int file = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  if (file < 0) return -errno;
#endif
  error = tw_pem_stamp(file, &pem->stamp);
  uint64_t size = error ? 0 : pem->stamp.fields[2];
  if (!error && (!size || size > TW_MAX_PEM_FILE || size > TW_MAX_PEM_TOTAL - *total)) error = -EFBIG;
  if (!error) {
    pem->length = (size_t)size; pem->bytes = malloc(pem->length);
    if (!pem->bytes) error = -ENOMEM;
  }
  size_t used = 0;
  while (!error && used < pem->length) {
#ifdef _WIN32
    DWORD count = 0;
    if (!ReadFile(file, pem->bytes + used, (DWORD)(pem->length - used), &count, NULL)) error = -ln_windows_errno(GetLastError());
#else
    ssize_t count = read(file, pem->bytes + used, pem->length - used);
    if (count < 0) error = -errno;
#endif
    if (!error && !count) error = -ESTALE;
    if (!error) used += (size_t)count;
  }
  tw_stamp after;
  if (!error) error = tw_pem_stamp(file, &after);
  if (!error && memcmp(&pem->stamp, &after, sizeof(after))) error = -ESTALE;
  int closed = tw_pem_close(file); if (!error) error = closed;
  if (error) { tw_pem_free(pem); return error; }
  *total += pem->length; return 0;
}
static int tw_pem_unchanged(const char *path, const tw_pem *pem) {
  int error = 0;
#ifdef _WIN32
  HANDLE file = tw_pem_open(path, &error); if (file == INVALID_HANDLE_VALUE) return error;
#else
  int file = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC); if (file < 0) return -errno;
#endif
  tw_stamp now; error = tw_pem_stamp(file, &now);
  if (!error && memcmp(&now, &pem->stamp, sizeof(now))) error = -ESTALE;
  int closed = tw_pem_close(file); return error ? error : closed;
}
static int tw_context_load(tw_context *context, const tw_pem *certificate, const tw_pem *key) {
  BIO *cert_bio = BIO_new_mem_buf(certificate->bytes, (int)certificate->length);
  BIO *key_bio = BIO_new_mem_buf(key->bytes, (int)key->length);
  STACK_OF(X509_INFO) *chain = NULL; EVP_PKEY *private_key = NULL; int error = -EINVAL;
  if (!cert_bio || !key_bio) { error = -ENOMEM; goto done; }
  chain = PEM_X509_INFO_read_bio(cert_bio, NULL, tw_password, NULL);
  if (!chain || sk_X509_INFO_num(chain) < 1 || sk_X509_INFO_num(chain) > TW_MAX_CHAIN) goto done;
  for (int i = 0; i < sk_X509_INFO_num(chain); ++i) {
    X509_INFO *item = sk_X509_INFO_value(chain, i);
    if (!item->x509 || item->crl || item->x_pkey) goto done;
    if (!i) {
      if (X509_cmp_current_time(X509_get0_notBefore(item->x509)) >= 0 ||
          X509_cmp_current_time(X509_get0_notAfter(item->x509)) <= 0 ||
          (context->name && X509_check_host(item->x509, context->name, 0,
            X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS, NULL) != 1) ||
          SSL_CTX_use_certificate(context->ssl, item->x509) != 1) goto done;
    } else if (SSL_CTX_add1_chain_cert(context->ssl, item->x509) != 1) goto done;
  }
  private_key = PEM_read_bio_PrivateKey(key_bio, NULL, tw_password, NULL);
  if (!private_key || SSL_CTX_use_PrivateKey(context->ssl, private_key) != 1 ||
      SSL_CTX_check_private_key(context->ssl) != 1) goto done;
  error = 0;
done:
  EVP_PKEY_free(private_key); sk_X509_INFO_pop_free(chain, X509_INFO_free);
  BIO_free(cert_bio); BIO_free(key_bio); return error;
}
static int tw_snapshot_load(tw_provider *provider, tw_bundle **out) {
  *out = NULL; size_t total = 0; int error = -ENOMEM;
  tw_pem *inputs = calloc((size_t)provider->count * 2, sizeof(*inputs));
  EVP_MD_CTX *digest = EVP_MD_CTX_new(); tw_bundle *bundle = NULL;
  unsigned char fingerprint[SHA256_DIGEST_LENGTH]; unsigned int digest_length = 0;
  if (!inputs || !digest) goto done;
  if (EVP_DigestInit_ex(digest, EVP_sha256(), NULL) != 1) { error = -EIO; goto done; }
  for (uint32_t i = 0; i < provider->count * 2; ++i) {
    const char *path = i % 2 ? provider->paths[i / 2].private_key : provider->paths[i / 2].certificate;
    error = tw_pem_read(path, &inputs[i], &total); if (error) goto done;
    uint64_t length = inputs[i].length;
    if (EVP_DigestUpdate(digest, &length, sizeof(length)) != 1 ||
        EVP_DigestUpdate(digest, inputs[i].bytes, inputs[i].length) != 1) { error = -EIO; goto done; }
  }
  if (EVP_DigestFinal_ex(digest, fingerprint, &digest_length) != 1 || digest_length != sizeof(fingerprint)) { error = -EIO; goto done; }
  /* Only this loader changes current. Readers retain it under the lock. */
  if (provider->current && !memcmp(provider->current->fingerprint, fingerprint, sizeof(fingerprint))) { error = 0; goto verify; }
  bundle = calloc(1, sizeof(*bundle)); if (!bundle) { error = -ENOMEM; goto done; }
  atomic_init(&bundle->references, 1); bundle->count = provider->count; bundle->owner = provider;
  atomic_fetch_add(&provider->live_versions, 1);
  bundle->contexts = calloc(bundle->count, sizeof(*bundle->contexts));
  if (!bundle->contexts) { error = -ENOMEM; goto done; }
  memcpy(bundle->fingerprint, fingerprint, sizeof(fingerprint));
  for (uint32_t i = 0; i < bundle->count; ++i) {
    tw_context *context = &bundle->contexts[i];
    if (i) { context->name = strdup(provider->paths[i].name); if (!context->name) { error = -ENOMEM; goto done; } }
    context->ssl = SSL_CTX_new(TLS_server_method()); if (!context->ssl) { error = -ENOMEM; goto done; }
    SSL_CTX_set_default_passwd_cb(context->ssl, tw_password);
    if (SSL_CTX_set_min_proto_version(context->ssl, TLS1_2_VERSION) != 1) { error = -EINVAL; goto done; }
    error = tw_context_load(context, &inputs[i * 2], &inputs[i * 2 + 1]); if (error) goto done;
    unsigned int size = 0;
    if (X509_digest(SSL_CTX_get0_certificate(context->ssl), EVP_sha256(), context->identity, &size) != 1 || size != sizeof(context->identity)) { error = -EIO; goto done; }
    uint64_t options = SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE;
    if (!provider->tickets) options |= SSL_OP_NO_TICKET;
    SSL_CTX_set_options(context->ssl, options); SSL_CTX_set_mode(context->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_CTX_set_session_cache_mode(context->ssl, SSL_SESS_CACHE_SERVER);
    SSL_CTX_sess_set_cache_size(context->ssl, 4096); SSL_CTX_set_timeout(context->ssl, 300);
    if (SSL_CTX_set_session_id_context(context->ssl, context->identity, sizeof(context->identity)) != 1 ||
        SSL_CTX_set_num_tickets(context->ssl, provider->tickets ? 2 : 0) != 1) { error = -EINVAL; goto done; }
    SSL_CTX_set_alpn_select_cb(context->ssl, tw_alpn, bundle);
    SSL_CTX_set_client_hello_cb(context->ssl, tw_client_hello, bundle);
    SSL_CTX_set_tlsext_servername_callback(context->ssl, tw_servername);
    SSL_CTX_set_tlsext_servername_arg(context->ssl, bundle);
  }
  error = 0;
verify:
  for (uint32_t i = 0; i < provider->count * 2; ++i) {
    const char *path = i % 2 ? provider->paths[i / 2].private_key : provider->paths[i / 2].certificate;
    error = tw_pem_unchanged(path, &inputs[i]); if (error) goto done;
  }
  *out = bundle; bundle = NULL;
done:
  if (inputs) for (uint32_t i = 0; i < provider->count * 2; ++i) tw_pem_free(&inputs[i]);
  free(inputs); EVP_MD_CTX_free(digest); tw_bundle_release(bundle); return error;
}
static void tw_control_fail(tw_provider *provider, int error);
static void tw_snapshot_fail(tw_provider *provider) {
  atomic_store_explicit(&provider->snapshot_error, -EIO, memory_order_release);
  tw_control_fail(provider, -EIO);
}
static tw_bundle *tw_provider_snapshot(tw_provider *provider) {
  if (atomic_load_explicit(&provider->snapshot_error, memory_order_acquire)) return NULL;
  if (!CRYPTO_THREAD_read_lock(provider->lock)) { tw_snapshot_fail(provider); return NULL; }
  tw_bundle *bundle = provider->current;
  if (atomic_load(&provider->closed) || !bundle) bundle = NULL;
  if (bundle) {
    unsigned count = atomic_load_explicit(&bundle->references, memory_order_relaxed);
    do { if (!count || count == UINT_MAX) { bundle = NULL; break; } }
    while (!atomic_compare_exchange_weak_explicit(&bundle->references, &count, count + 1,
                                                   memory_order_relaxed, memory_order_relaxed));
  }
  if (!CRYPTO_THREAD_unlock(provider->lock)) {
    tw_snapshot_fail(provider); tw_bundle_release(bundle); return NULL;
  }
  return bundle;
}
static int tw_provider_wake(tw_provider *provider) {
#ifdef _WIN32
  return SetEvent(provider->wake) ? 0 : -ln_windows_errno(GetLastError());
#else
  int error = pthread_cond_signal(&provider->reload_condition); return error ? -error : 0;
#endif
}
static void tw_reload_complete(tw_provider *provider, uint64_t ticket) {
  uint_fast64_t prior = atomic_load_explicit(&provider->completed, memory_order_relaxed);
  while (prior < ticket && !atomic_compare_exchange_weak_explicit(&provider->completed, &prior, ticket,
             memory_order_release, memory_order_relaxed)) {}
}
static void tw_control_fail(tw_provider *provider, int error) {
  int expected = 0;
  if (atomic_compare_exchange_strong_explicit(&provider->control_error, &expected, error,
        memory_order_acq_rel, memory_order_acquire)) atomic_fetch_add(&provider->failures, 1);
  int recorded = atomic_load_explicit(&provider->control_error, memory_order_acquire);
  atomic_store_explicit(&provider->last_error, recorded, memory_order_release);
  tw_reload_complete(provider, atomic_load_explicit(&provider->requested, memory_order_acquire));
}
static int tw_reload_clock(uint64_t *value) {
#ifdef _WIN32
  *value = GetTickCount64(); return 0;
#else
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return -errno;
  *value = (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000; return 0;
#endif
}
static void tw_reload_once(tw_provider *provider) {
  atomic_fetch_add(&provider->attempts, 1); ERR_clear_error(); tw_bundle *candidate = NULL;
  int error = tw_snapshot_load(provider, &candidate);
  if (!error && candidate) {
    if (atomic_load(&provider->generation) == INT64_MAX) error = -EOVERFLOW;
    else if (!CRYPTO_THREAD_write_lock(provider->lock)) { tw_snapshot_fail(provider); error = -EIO; }
    else {
      tw_bundle *previous = provider->current; provider->current = candidate; candidate = NULL;
      atomic_fetch_add(&provider->generation, 1); atomic_fetch_add(&provider->publications, 1);
      int unlocked = CRYPTO_THREAD_unlock(provider->lock);
      /* The new current owns its reference even when unlock reports failure;
       * the replaced current reference is still retired exactly once. */
      tw_bundle_release(previous);
      if (!unlocked) { tw_snapshot_fail(provider); error = -EIO; }
    }
  }
  tw_bundle_release(candidate);
  if (error) atomic_fetch_add(&provider->failures, 1);
  atomic_store_explicit(&provider->last_error, error, memory_order_release);
  int control = atomic_load_explicit(&provider->control_error, memory_order_acquire);
  if (control) atomic_store_explicit(&provider->last_error, control, memory_order_release);
  ERR_clear_error();
}
#ifndef _WIN32
static int tw_control_wait(tw_provider *provider, uint64_t requested, unsigned milliseconds) {
  int error = pthread_mutex_lock(&provider->reload_mutex); if (error) return -error;
  if (requested == atomic_load_explicit(&provider->requested, memory_order_acquire) &&
      !atomic_load(&provider->stop) && !atomic_load(&provider->control_error)) {
    struct timespec timeout;
#ifdef __APPLE__
    timeout.tv_sec = (time_t)(milliseconds / 1000); timeout.tv_nsec = (long)(milliseconds % 1000) * 1000000;
    error = pthread_cond_timedwait_relative_np(&provider->reload_condition, &provider->reload_mutex, &timeout);
#else
    if (clock_gettime(CLOCK_MONOTONIC, &timeout) < 0) error = errno;
    else {
      timeout.tv_sec += (time_t)(milliseconds / 1000);
      timeout.tv_nsec += (long)(milliseconds % 1000) * 1000000;
      if (timeout.tv_nsec >= 1000000000) { ++timeout.tv_sec; timeout.tv_nsec -= 1000000000; }
      error = pthread_cond_timedwait(&provider->reload_condition, &provider->reload_mutex, &timeout);
    }
#endif
    if (error == ETIMEDOUT) error = 0;
  }
  int unlocked = pthread_mutex_unlock(&provider->reload_mutex);
  return error ? -error : unlocked ? -unlocked : 0;
}
static int tw_control_create(tw_provider *provider) {
  int error = pthread_mutex_init(&provider->reload_mutex, NULL); if (error) return -error;
#ifdef __APPLE__
  error = pthread_cond_init(&provider->reload_condition, NULL);
#else
  pthread_condattr_t attributes;
  error = pthread_condattr_init(&attributes);
  if (!error) {
    error = pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC);
    if (!error) error = pthread_cond_init(&provider->reload_condition, &attributes);
    int destroyed = pthread_condattr_destroy(&attributes);
    if (!error && destroyed) {
      int closed = pthread_cond_destroy(&provider->reload_condition);
      error = closed ? closed : destroyed;
    }
  }
#endif
  if (error) {
    int closed = pthread_mutex_destroy(&provider->reload_mutex); return closed ? -closed : -error;
  }
  provider->control_initialized = 1; return 0;
}
static int tw_control_destroy(tw_provider *provider) {
  if (!provider->control_initialized) return 0;
  provider->control_initialized = 0;
  int first = pthread_cond_destroy(&provider->reload_condition);
  int second = pthread_mutex_destroy(&provider->reload_mutex);
  return first ? -first : second ? -second : 0;
}
#endif
static void tw_reload_run(tw_provider *provider) {
  atomic_store(&provider->loader_threads, 1);
  uint64_t now = 0;
  int clock_error = tw_reload_clock(&now);
  if (clock_error) tw_control_fail(provider, clock_error);
  uint64_t deadline = provider->interval_ms ? now + provider->interval_ms : UINT64_MAX;
  while (!atomic_load_explicit(&provider->stop, memory_order_acquire)) {
    int control = atomic_load_explicit(&provider->control_error, memory_order_acquire);
    if (control) { tw_control_fail(provider, control); break; }
    uint64_t requested = atomic_load_explicit(&provider->requested, memory_order_acquire);
    clock_error = tw_reload_clock(&now);
    if (clock_error) { tw_control_fail(provider, clock_error); break; }
    if (requested != atomic_load(&provider->completed) || now >= deadline) {
      tw_reload_once(provider); tw_reload_complete(provider, requested);
      clock_error = tw_reload_clock(&now);
      if (clock_error) { tw_control_fail(provider, clock_error); break; }
      deadline = provider->interval_ms ? now + provider->interval_ms : UINT64_MAX; continue;
    }
    uint64_t wait = deadline > now ? deadline - now : 0; if (wait > 100) wait = 100;
#ifdef _WIN32
    if (!ResetEvent(provider->wake)) { tw_control_fail(provider, -ln_windows_errno(GetLastError())); break; }
    if (requested == atomic_load_explicit(&provider->requested, memory_order_acquire) && !atomic_load(&provider->stop))
    {
      DWORD result = WaitForSingleObject(provider->wake, (DWORD)wait);
      if (result != WAIT_OBJECT_0 && result != WAIT_TIMEOUT) {
        tw_control_fail(provider, result == WAIT_FAILED ? -ln_windows_errno(GetLastError()) : -EIO); break;
      }
    }
#else
    int result = tw_control_wait(provider, requested, (unsigned)wait);
    if (result) { tw_control_fail(provider, result); break; }
#endif
  }
  OPENSSL_thread_stop(); atomic_store(&provider->loader_threads, 0);
}
#ifdef _WIN32
static DWORD WINAPI tw_reload_entry(LPVOID value) { tw_reload_run(value); return 0; }
#else
static void *tw_reload_entry(void *value) { tw_reload_run(value); return NULL; }
#endif
static void tw_provider_release(tw_provider *provider) {
  if (atomic_fetch_sub(&provider->references, 1) != 1) return;
  tw_bundle_release(provider->current);
  for (uint32_t i = 0; provider->paths && i < provider->count; ++i) {
    free(provider->paths[i].name); free(provider->paths[i].certificate); free(provider->paths[i].private_key);
  }
  free(provider->paths); if (provider->lock) CRYPTO_THREAD_lock_free(provider->lock); free(provider);
}
lean_object *lean_tlsw_bundle_new(b_lean_obj_arg cert, b_lean_obj_arg key,
    b_lean_obj_arg names, b_lean_obj_arg certs, b_lean_obj_arg keys, uint8_t tickets) {
  size_t count = lean_array_size(names);
  if (count >= TW_MAX_CERTS || count != lean_array_size(certs) || count != lean_array_size(keys) || tickets > 1)
    return tw_handle(-EINVAL, "invalid TLS certificate table");
  tw_provider *provider = calloc(1, sizeof(*provider));
  if (!provider) return tw_handle(-ENOMEM, "allocating TLS provider");
  atomic_init(&provider->references, 1); atomic_init(&provider->stop, 0); atomic_init(&provider->closed, 0);
  atomic_init(&provider->control_error, 0);
  atomic_init(&provider->snapshot_error, 0);
  atomic_init(&provider->live_versions, 0); atomic_init(&provider->loader_threads, 0);
  atomic_init(&provider->generation, 1); atomic_init(&provider->attempts, 0); atomic_init(&provider->publications, 0);
  atomic_init(&provider->failures, 0); atomic_init(&provider->requested, 0); atomic_init(&provider->completed, 0); atomic_init(&provider->last_error, 0);
  provider->count = (uint32_t)count + 1; provider->tickets = tickets;
  provider->lock = CRYPTO_THREAD_lock_new(); provider->paths = calloc(provider->count, sizeof(*provider->paths));
  int error = -ENOMEM; char message[256] = "TLS provider allocation failed";
  if (!provider->lock || !provider->paths) goto failure;
  for (uint32_t i = 0; i < provider->count; ++i) {
    tw_path *path = &provider->paths[i];
    path->certificate = tw_copy_text(i ? lean_array_uget_borrowed(certs, i - 1) : cert);
    path->private_key = tw_copy_text(i ? lean_array_uget_borrowed(keys, i - 1) : key);
    if (!path->certificate || !path->private_key) { error = -EINVAL; goto failure; }
    if (i) {
      lean_object *name = lean_array_uget_borrowed(names, i - 1); char normalized[254];
      if (!tw_hostname((const unsigned char *)lean_string_cstr(name), lean_string_size(name) - 1, normalized)) { error = -EINVAL; goto failure; }
      path->name = strdup(normalized); if (!path->name) { error = -ENOMEM; goto failure; }
      for (uint32_t prior = 1; prior < i; ++prior) if (!strcmp(path->name, provider->paths[prior].name)) { error = -EINVAL; goto failure; }
    }
  }
  error = tw_snapshot_load(provider, &provider->current);
  if (error || !provider->current) { if (!error) error = -EIO; goto failure; }
  if ((uintptr_t)provider > INT64_MAX) { error = -EOVERFLOW; goto failure; }
  return tw_handle((int64_t)(uintptr_t)provider, "");
failure:
  tw_diagnostic(message, "invalid TLS certificate, key, validity interval or SNI identity");
  tw_provider_release(provider); return tw_handle(error, message);
}
lean_object *lean_tlsw_bundle_reload_start(uint64_t handle, uint64_t interval) {
  if (!handle || interval > INT64_MAX) return tw_result(-EINVAL);
  tw_provider *provider = (tw_provider *)(uintptr_t)handle;
  if (atomic_load(&provider->closed)) return tw_result(-ECANCELED);
  int control = atomic_load_explicit(&provider->control_error, memory_order_acquire);
  if (control) return tw_result(control);
#ifdef _WIN32
  if (provider->loader) return tw_result(-EALREADY);
  provider->wake = CreateEventW(NULL, TRUE, FALSE, NULL); if (!provider->wake) return tw_result(-ln_windows_errno(GetLastError()));
  provider->interval_ms = interval;
  provider->loader = CreateThread(NULL, 0, tw_reload_entry, provider, 0, NULL);
  if (!provider->loader) {
    int error = -ln_windows_errno(GetLastError());
    int closed = CloseHandle(provider->wake) ? 0 : -ln_windows_errno(GetLastError());
    provider->wake = NULL; return tw_result(closed ? closed : error);
  }
#else
  if (provider->loader_started) return tw_result(-EALREADY);
  int error = tw_control_create(provider); if (error) return tw_result(error);
  provider->interval_ms = interval;
  error = pthread_create(&provider->loader, NULL, tw_reload_entry, provider);
  if (error) { int closed = tw_control_destroy(provider); return tw_result(closed ? closed : -error); }
  provider->loader_started = 1;
#endif
  return tw_result(0);
}
lean_object *lean_tlsw_bundle_reload_request(uint64_t handle) {
  if (!handle) return tw_result(-EINVAL);
  tw_provider *provider = (tw_provider *)(uintptr_t)handle;
  if (atomic_load(&provider->closed)) return tw_result(-ECANCELED);
  int control = atomic_load_explicit(&provider->control_error, memory_order_acquire);
  if (control) return tw_result(control);
#ifdef _WIN32
  if (!provider->loader) return tw_result(-ENOTSUP);
#else
  if (!provider->loader_started) return tw_result(-ENOTSUP);
#endif
  uint_fast64_t old = atomic_load(&provider->requested);
  do { if (old == INT64_MAX) return tw_result(-EOVERFLOW); }
  while (!atomic_compare_exchange_weak_explicit(&provider->requested, &old, old + 1, memory_order_release, memory_order_relaxed));
  int error = tw_provider_wake(provider);
  if (error) tw_control_fail(provider, error);
  control = atomic_load_explicit(&provider->control_error, memory_order_acquire);
  if (control) { tw_control_fail(provider, control); return tw_result(control); }
  return tw_result((int64_t)old + 1);
}
lean_object *lean_tlsw_bundle_reload_stats(uint64_t handle) {
  if (!handle) return lean_io_result_mk_error(lean_mk_io_user_error(lean_mk_string("invalid TLS bundle")));
  tw_provider *provider = (tw_provider *)(uintptr_t)handle;
  /* Read acknowledgement first: observing a completed explicit request must
   * never return counters from before that request's publication/failure. */
  uint64_t completed = atomic_load_explicit(&provider->completed, memory_order_acquire);
  int control = atomic_load_explicit(&provider->control_error, memory_order_acquire);
  lean_object *stats = lean_alloc_ctor(0, 0, 9 * sizeof(uint64_t));
  uint64_t fields[9] = {atomic_load(&provider->generation), atomic_load(&provider->attempts),
    atomic_load(&provider->publications), atomic_load(&provider->failures),
    (uint64_t)(int64_t)(control ? control : atomic_load(&provider->last_error)), atomic_load(&provider->live_versions),
    atomic_load(&provider->loader_threads), atomic_load(&provider->requested), completed};
  for (unsigned i = 0; i < 9; ++i) lean_ctor_set_uint64(stats, i * sizeof(uint64_t), fields[i]);
  return lean_io_result_mk_ok(stats);
}
lean_object *lean_tlsw_bundle_free(uint64_t handle) {
  if (!handle) return tw_result(-EINVAL);
  tw_provider *provider = (tw_provider *)(uintptr_t)handle;
  atomic_store(&provider->closed, 1); atomic_store_explicit(&provider->stop, 1, memory_order_release);
#ifdef _WIN32
  if (provider->loader) {
    int error = tw_provider_wake(provider); if (error) tw_control_fail(provider, error);
    DWORD joined = WaitForSingleObject(provider->loader, INFINITE);
    if (joined != WAIT_OBJECT_0) return tw_result(joined == WAIT_FAILED ? -ln_windows_errno(GetLastError()) : -EIO);
    HANDLE thread = provider->loader, wake = provider->wake; provider->loader = provider->wake = NULL;
    int first = CloseHandle(thread) ? 0 : -ln_windows_errno(GetLastError());
    int second = CloseHandle(wake) ? 0 : -ln_windows_errno(GetLastError());
    tw_provider_release(provider); return tw_result(error ? error : first ? first : second);
  }
#else
  if (provider->loader_started) {
    int error = tw_provider_wake(provider); if (error) tw_control_fail(provider, error);
    int joined = pthread_join(provider->loader, NULL); if (joined) return tw_result(-joined);
    provider->loader_started = 0;
    int destroyed = tw_control_destroy(provider); tw_provider_release(provider);
    return tw_result(error ? error : destroyed);
  }
#endif
  tw_provider_release(provider); return tw_result(0);
}
#endif
