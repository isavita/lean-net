#ifndef _WIN32
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
static ssize_t tested_pread(int, void *, size_t, off_t);
static ssize_t tested_pwrite(int, const void *, size_t, off_t);
static int tested_close(int);
static struct dirent *tested_readdir(DIR *);
#define pread tested_pread
#define pwrite tested_pwrite
#define close tested_close
#define readdir tested_readdir
#else
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
static BOOL WINAPI tested_set_information(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD);
#define SetFileInformationByHandle tested_set_information
#endif
#define SC_NO_LEAN_FFI
#include "../c/static_catalog.c"
#ifndef _WIN32
#undef pread
#undef pwrite
#undef close
#undef readdir
#else
#undef SetFileInformationByHandle
#endif
#include "../c/reactor_file_impl.h"
#include <assert.h>
#ifndef _WIN32
#include <dirent.h>
#endif

#define REQUIRE(test)                                                                              \
  do {                                                                                             \
    if (!(test)) {                                                                                 \
      fprintf(stderr, "line%d: %s\n", __LINE__, #test);                                            \
      abort();                                                                                     \
    }                                                                                              \
  } while (0)
static sc_builder *observed;
#ifdef _WIN32
static unsigned unsupported_disposition;
static BOOL WINAPI tested_set_information(HANDLE file, FILE_INFO_BY_HANDLE_CLASS kind, LPVOID info,
                                          DWORD size) {
  if ((int)kind == 21 && unsupported_disposition) {
    --unsupported_disposition;
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
  }
  return SetFileInformationByHandle(file, kind, info, size);
}
#else
static unsigned inject_read, inject_write, short_writes, read_calls, write_calls;
static unsigned inject_enumeration, enumeration_calls;
static unsigned interrupt_final_close;
static int interrupt_close_fd = -1;
static uint64_t original_read_bytes;
static struct dirent *tested_readdir(DIR *directory) {
  ++enumeration_calls;
  if (inject_enumeration) {
    --inject_enumeration;
    errno = EINTR;
    return NULL;
  }
  return readdir(directory);
}
static ssize_t tested_pread(int fd, void *bytes, size_t n, off_t at) {
  ++read_calls;
  if (inject_read) {
    --inject_read;
    errno = EINTR;
    return -1;
  }
  ssize_t result = pread(fd, bytes, n, at);
  if (result > 0 && observed && fd == observed->source)
    original_read_bytes += (uint64_t)result;
  return result;
}
static ssize_t tested_pwrite(int fd, const void *bytes, size_t n, off_t at) {
  ++write_calls;
  if (inject_write) {
    --inject_write;
    errno = EINTR;
    return -1;
  }
  if (short_writes) {
    --short_writes;
    if (n > 7)
      n = 7;
  }
  return pwrite(fd, bytes, n, at);
}
static int tested_close(int fd) {
  int should_interrupt =
      interrupt_final_close && observed && observed->published && fd == interrupt_close_fd;
  int result = close(fd);
  if (should_interrupt && !result) {
    --interrupt_final_close;
    errno = EINTR;
    return -1;
  }
  return result;
}
#endif
static sc_builder *builder(const char *root, uint64_t maximum, uint32_t entries) {
  sc_builder *b = NULL;
  REQUIRE(sc_builder_new((const uint8_t *)root, strlen(root), maximum, maximum, entries, 0, 6, 5,
                         &b) == 0);
  return b;
}
static int64_t complete(sc_builder *b) {
  for (unsigned fuel = 0; fuel < 1000000; ++fuel) {
    int64_t result = sc_builder_step(b, 8192);
    if (result == -EINTR)
      continue;
    if (result)
      return result;
  }
  return -ETIMEDOUT;
}
static void dispose(sc_builder *b) {
  for (unsigned i = 0; i < 1000; ++i) {
    int result = sc_builder_free(b);
    if (result == -EINTR)
      continue;
    REQUIRE(result == 0);
    return;
  }
  abort();
}
static uint64_t pair(sc_builder *b, unsigned id, unsigned field) {
  int64_t low = sc_builder_field(b, id, field), high = sc_builder_field(b, id, field + 1);
  REQUIRE(low >= 0 && high >= 0);
  return (uint64_t)low | ((uint64_t)high << 32);
}
static void hash_hex(sc_builder *b, unsigned id, unsigned coding, char output[65]) {
  static const char hex[] = "0123456789abcdef";
  unsigned base = SC_FIELD_VARIANTS + coding * SC_VARIANT_FIELDS + SC_VARIANT_SHA256_WORD0;
  for (unsigned i = 0; i < 8; ++i) {
    int64_t value = sc_builder_field(b, id, base + i);
    REQUIRE(value >= 0);
    for (unsigned j = 0; j < 8; ++j)
      output[i * 8 + j] = hex[((uint32_t)value >> (28 - 4 * j)) & 15];
  }
  output[64] = 0;
}
static unsigned handles(void) {
#ifdef _WIN32
  DWORD count = 0;
  REQUIRE(GetProcessHandleCount(GetCurrentProcess(), &count));
  return count;
#else
  unsigned count = 0;
  for (int i = 0; i < 4096; ++i)
    if (fcntl(i, F_GETFD) >= 0)
      ++count;
  return count;
#endif
}
static void no_private_pack_name(const char *root) {
#ifdef _WIN32
  wchar_t *wide = sc_wide((const uint8_t *)root, strlen(root));
  REQUIRE(wide);
  size_t n = wcslen(wide);
  wchar_t *pattern = malloc((n + 3) * sizeof(*pattern));
  REQUIRE(pattern);
  memcpy(pattern, wide, n * sizeof(*pattern));
  memcpy(pattern + n, L"\\*", 3 * sizeof(*pattern));
  free(wide);
  WIN32_FIND_DATAW item;
  HANDLE search = FindFirstFileW(pattern, &item);
  free(pattern);
  REQUIRE(search != INVALID_HANDLE_VALUE);
  do {
    REQUIRE(wcsncmp(item.cFileName, L"lean-net-static-", 16) != 0);
  } while (FindNextFileW(search, &item));
  REQUIRE(GetLastError() == ERROR_NO_MORE_FILES);
  REQUIRE(FindClose(search));
#else
  DIR *directory = opendir(root);
  REQUIRE(directory);
  struct dirent *item;
  while ((item = readdir(directory)))
    REQUIRE(strncmp(item->d_name, "lean-net-static-", 16) != 0);
  REQUIRE(closedir(directory) == 0);
#endif
}
static uint32_t directory_kind(sc_directory_list *list, const char *name) {
  for (uint32_t i = 0; i < list->count; ++i)
    if (list->entries[i].length == strlen(name) &&
        !memcmp(list->entries[i].name, name, strlen(name)))
      return list->entries[i].kind;
  return 0;
}
static void check_enumeration(sc_builder *b) {
  unsigned before = handles();
  uint32_t expected_count = 0;
  for (unsigned repeat = 0; repeat < 10; ++repeat) {
    sc_directory_list list = {NULL, 0};
    REQUIRE(sc_builder_read_directory(b, NULL, 0, 16, &list) == 0);
    REQUIRE(list.count >= 5 && list.count <= 16);
    if (!repeat)
      expected_count = list.count;
    REQUIRE(list.count == expected_count);
    REQUIRE(directory_kind(&list, "sub") == SC_DIRECTORY);
    REQUIRE(directory_kind(&list, "data.bin") == SC_REGULAR);
    REQUIRE(directory_kind(&list, "unicode-\xce\xbb.txt") == SC_REGULAR);
#ifndef _WIN32
    REQUIRE(directory_kind(&list, "outside-link") == SC_LINK);
    REQUIRE(directory_kind(&list, "directory-link") == SC_LINK);
#endif
    sc_directory_list_free(&list);
    REQUIRE(!list.entries && !list.count);
  }
  sc_directory_list list = {NULL, 0};
  REQUIRE(sc_builder_read_directory(b, NULL, 0, 0, &list) == -ENOSPC);
  REQUIRE(!list.entries && !list.count);
  REQUIRE(sc_builder_read_directory(b, (const uint8_t *)"sub", 3, 0, &list) == 0);
  REQUIRE(!list.entries && !list.count);
  REQUIRE(sc_builder_read_directory(b, (const uint8_t *)"overflow", 8, 3, &list) == -ENOSPC);
  REQUIRE(!list.entries && !list.count);
  REQUIRE(sc_builder_read_directory(b, (const uint8_t *)"../outside", 10, 16, &list) == -EINVAL);
#ifndef _WIN32
  REQUIRE(sc_builder_read_directory(b, (const uint8_t *)"skipped", 7, 3, &list) == -ENOSPC);
  REQUIRE(!list.entries && !list.count);
  REQUIRE(sc_builder_read_directory(b, (const uint8_t *)"directory-link", 14, 16, &list) < 0);
  inject_enumeration = 1;
  enumeration_calls = 0;
  REQUIRE(sc_builder_read_directory(b, NULL, 0, 16, &list) == -EINTR);
  REQUIRE(enumeration_calls == 1 && !list.entries && !list.count);
  REQUIRE(sc_builder_read_directory(b, NULL, 0, 16, &list) == 0);
  REQUIRE(list.count == expected_count);
  sc_directory_list_free(&list);
#endif
  REQUIRE(handles() <= before);
}
int main(int argc, char **argv) {
  REQUIRE(argc == 3);
  const char *root = argv[1], *output = argv[2];
  REQUIRE(rn_file_prepare_residency_budget(8 * 1024 * 1024) == 0);
  no_private_pack_name(root);
#ifdef _WIN32
  unsigned failed_before = handles();
  sc_builder *unsupported = builder(root, 8192, 1);
  unsupported_disposition = 1;
  REQUIRE(sc_builder_prepare(unsupported) == -ENOTSUP);
  dispose(unsupported);
  no_private_pack_name(root);
  REQUIRE(handles() <= failed_before);
#endif
  sc_builder *b = builder(root, 8 * 1024 * 1024, 16);
  observed = b;
  REQUIRE(sc_builder_prepare(b) == 0);
  REQUIRE(b->initialized && !b->temporary);
  /* The harness deliberately puts TMP/TEMP/TMPDIR inside root. Retaining
     writable/read-only handles must not leave the catalog itself enumerable. */
  no_private_pack_name(root);
  REQUIRE(sc_builder_prepare(b) == 0);
  REQUIRE(sc_builder_check_directory(b, NULL, 0) == 0);
  REQUIRE(sc_builder_check_directory(b, (const uint8_t *)"sub", 3) == 0);
  REQUIRE(sc_builder_check_directory(b, (const uint8_t *)"../outside", 10) < 0);
  check_enumeration(b);
  REQUIRE(sc_builder_begin_bytes(b, (const uint8_t *)"abc", 3, 3) == 0);
#ifndef _WIN32
  inject_write = 1;
  write_calls = 0;
  REQUIRE(sc_builder_step(b, 8192) == -EINTR);
  REQUIRE(write_calls == 1);
#endif
  REQUIRE(complete(b) == 1);
  REQUIRE(sc_builder_field(b, 1, SC_FIELD_PRESENT) == 1);
  char hash[65];
  hash_hex(b, 1, 0, hash);
  REQUIRE(!strcmp(hash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  REQUIRE(sc_builder_begin_path(b, (const uint8_t *)"data.bin", 8, 3) == 0);
#ifndef _WIN32
  inject_read = 1;
  read_calls = 0;
  REQUIRE(sc_builder_step(b, 8192) == -EINTR);
  REQUIRE(read_calls == 1);
  short_writes = 17;
  original_read_bytes = 0;
#endif
  REQUIRE(complete(b) == 2);
  REQUIRE(sc_builder_field(b, 2, SC_FIELD_PRESENT) == 7);
#ifndef _WIN32
  REQUIRE(original_read_bytes == 1024 * 1024);
#endif
  REQUIRE(sc_builder_begin_path(b, (const uint8_t *)"unicode-\xce\xbb.txt", 14, 0) == 0);
  REQUIRE(complete(b) == 3);
  REQUIRE(sc_builder_field(b, 3, SC_FIELD_PRESENT) == 1);
  rn_file_source *source = NULL;
  REQUIRE(sc_builder_finish(b, 1, &source) == -ENOMEM && source == NULL);
#ifndef _WIN32
  interrupt_final_close = 1;
  interrupt_close_fd = b->readonly;
  REQUIRE(sc_builder_finish(b, 8 * 1024 * 1024, &source) == -EINTR && source == NULL);
  REQUIRE(interrupt_final_close == 0);
  int reused = open("/dev/null", O_RDONLY | O_CLOEXEC);
  REQUIRE(reused >= 0);
#endif
  REQUIRE(sc_builder_finish(b, 8 * 1024 * 1024, &source) == 0 && source);
#ifndef _WIN32
  REQUIRE(fcntl(reused, F_GETFD) >= 0);
  REQUIRE(close(reused) == 0);
  REQUIRE((fcntl((int)rn_file_source_handle(source), F_GETFL) & O_ACCMODE) == O_RDONLY);
#endif
  printf("{\"variants\":[");
  for (unsigned coding = 0; coding < 3; ++coding) {
    unsigned base = SC_FIELD_VARIANTS + coding * SC_VARIANT_FIELDS;
    uint64_t offset = pair(b, 2, base), length = pair(b, 2, base + 2);
    hash_hex(b, 2, coding, hash);
    const uint8_t *view = NULL;
    REQUIRE(length <= UINT32_MAX);
    REQUIRE(rn_file_source_view(source, offset, (uint32_t)length, &view) == 0);
    char path[4096];
    int used = snprintf(path, sizeof(path), "%s/%u.bin", output, coding);
    REQUIRE(used > 0 && (size_t)used < sizeof(path));
    FILE *file = fopen(path, "wb");
    REQUIRE(file);
    REQUIRE(fwrite(view, 1, (size_t)length, file) == length);
    REQUIRE(fclose(file) == 0);
    printf("%s{\"coding\":%u,\"offset\":%llu,\"length\":%llu,\"sha256\":\"%s\"}", coding ? "," : "",
           coding, (unsigned long long)offset, (unsigned long long)length, hash);
  }
  printf("]");
  uint64_t packed_size = rn_file_source_size(source);
  dispose(b);
  observed = NULL;
  char mutable_path[4096];
  int path_length = snprintf(mutable_path, sizeof(mutable_path), "%s/data.bin", root);
  REQUIRE(path_length > 0 && (size_t)path_length < sizeof(mutable_path));
  FILE *changed_original = fopen(mutable_path, "r+b");
  REQUIRE(changed_original);
  REQUIRE(fputc(255, changed_original) == 255);
  REQUIRE(fclose(changed_original) == 0);
  const uint8_t *original = NULL;
  REQUIRE(rn_file_source_view(source, 3, 1024 * 1024, &original) == 0);
  for (unsigned i = 0; i < 1024 * 1024; ++i)
    REQUIRE(original[i] == (uint8_t)i);
  REQUIRE(rn_file_source_release(source) == 0);
  b = builder(root, 16, 1);
  REQUIRE(sc_builder_begin_bytes(b, (const uint8_t *)"abc", 3, 0) == 0);
  REQUIRE(complete(b) == 1);
  REQUIRE(sc_builder_begin_bytes(b, (const uint8_t *)"x", 1, 0) == -ENOSPC);
  dispose(b);
  b = builder(root, 2, 1);
  REQUIRE(sc_builder_begin_bytes(b, (const uint8_t *)"abc", 3, 0) == -EFBIG);
  dispose(b);
  const char *bad[] = {"../data.bin", "/data.bin", "sub/../data.bin",
                       "data.bin/",   "NUL.txt",   "file:stream"};
  for (unsigned i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
    b = builder(root, 4096, 1);
    REQUIRE(sc_builder_begin_path(b, (const uint8_t *)bad[i], strlen(bad[i]), 0) == -EINVAL);
    dispose(b);
  }
#ifndef _WIN32
  b = builder(root, 8 * 1024 * 1024, 1);
  REQUIRE(sc_builder_begin_path(b, (const uint8_t *)"mutable.bin", 11, 0) == 0);
  REQUIRE(sc_builder_step(b, 1) == 0);
  REQUIRE(b->source != SC_INVALID);
  int changed = openat(b->root, "mutable.bin", O_WRONLY | O_CLOEXEC);
  REQUIRE(changed >= 0);
  uint8_t different = 42;
  REQUIRE(pwrite(changed, &different, 1, 0) == 1);
  struct timespec times[2] = {{0, UTIME_OMIT}, {b->original.modified, b->original.nanoseconds}};
  REQUIRE(futimens(changed, times) == 0);
  REQUIRE(close(changed) == 0);
  REQUIRE(complete(b) == -ESTALE);
  dispose(b);
  b = builder(root, 8 * 1024 * 1024, 1);
  REQUIRE(sc_builder_begin_path(b, (const uint8_t *)"outside-link", 12, 0) == 0);
  REQUIRE(complete(b) < 0);
  dispose(b);
#endif
  /* Empty catalogs/representations and failure cleanup must not accumulate a
   * source descriptor or retained pin over repeated startup/teardown. */
  unsigned before = handles();
  for (unsigned i = 0; i < 1000; ++i) {
    b = builder(root, 4096, 1);
    REQUIRE(sc_builder_begin_bytes(b, NULL, 0, 0) == 0);
    REQUIRE(complete(b) == 1);
    hash_hex(b, 1, 0, hash);
    REQUIRE(!strcmp(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    source = NULL;
    REQUIRE(sc_builder_finish(b, 0, &source) == 0 && source);
    dispose(b);
    REQUIRE(rn_file_source_release(source) == 0);
  }
  unsigned after = handles();
  REQUIRE(after <= before);
  printf(",\"packed_size\":%llu,\"cycles\":1000,\"handles_before\":%u,\"handles_after\":%u}\n",
         (unsigned long long)packed_size, before, after);
  return 0;
}
