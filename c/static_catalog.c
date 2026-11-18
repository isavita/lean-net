#ifndef _WIN32
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#else
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#endif
#include "static_catalog.h"
#include <brotli/encode.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <wchar.h>
#include <winternl.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#ifndef ESTALE
#define ESTALE EIO
#endif
#ifndef ELOOP
#define ELOOP EINVAL
#endif
#define SC_CHUNK 65536u

typedef struct {
  uint32_t h[8];
  uint64_t bytes;
  uint8_t data[64];
  size_t used;
} sc_sha;
static uint32_t sc_rotr(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
static void sc_sha_block(sc_sha *s, const uint8_t *p) {
  static const uint32_t k[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
      0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
      0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
      0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
      0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
      0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
      0xc67178f2};
  uint32_t w[64];
  for (unsigned i = 0; i < 16; ++i)
    w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 |
           p[4 * i + 3];
  for (unsigned i = 16; i < 64; ++i) {
    uint32_t a = w[i - 15], b = w[i - 2];
    w[i] = w[i - 16] + (sc_rotr(a, 7) ^ sc_rotr(a, 18) ^ (a >> 3)) + w[i - 7] +
           (sc_rotr(b, 17) ^ sc_rotr(b, 19) ^ (b >> 10));
  }
  uint32_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3], e = s->h[4], f = s->h[5],
           g = s->h[6], h = s->h[7];
  for (unsigned i = 0; i < 64; ++i) {
    uint32_t t =
        h + (sc_rotr(e, 6) ^ sc_rotr(e, 11) ^ sc_rotr(e, 25)) + ((e & f) ^ (~e & g)) + k[i] + w[i];
    uint32_t u = (sc_rotr(a, 2) ^ sc_rotr(a, 13) ^ sc_rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
    h = g;
    g = f;
    f = e;
    e = d + t;
    d = c;
    c = b;
    b = a;
    a = t + u;
  }
  s->h[0] += a;
  s->h[1] += b;
  s->h[2] += c;
  s->h[3] += d;
  s->h[4] += e;
  s->h[5] += f;
  s->h[6] += g;
  s->h[7] += h;
}
static void sc_sha_init(sc_sha *s) {
  static const uint32_t initial[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  memset(s, 0, sizeof(*s));
  memcpy(s->h, initial, sizeof(initial));
}
static void sc_sha_update(sc_sha *s, const uint8_t *p, size_t n) {
  s->bytes += n;
  while (n) {
    size_t take = 64 - s->used;
    if (take > n)
      take = n;
    memcpy(s->data + s->used, p, take);
    s->used += take;
    p += take;
    n -= take;
    if (s->used == 64) {
      sc_sha_block(s, s->data);
      s->used = 0;
    }
  }
}
static void sc_sha_final(sc_sha *s, uint8_t out[32]) {
  uint64_t bits = s->bytes * 8;
  s->data[s->used++] = 0x80;
  if (s->used > 56) {
    memset(s->data + s->used, 0, 64 - s->used);
    sc_sha_block(s, s->data);
    s->used = 0;
  }
  memset(s->data + s->used, 0, 56 - s->used);
  for (unsigned i = 0; i < 8; ++i)
    s->data[63 - i] = (uint8_t)(bits >> (8 * i));
  sc_sha_block(s, s->data);
  for (unsigned i = 0; i < 8; ++i)
    for (unsigned j = 0; j < 4; ++j)
      out[4 * i + j] = (uint8_t)(s->h[i] >> (24 - 8 * j));
}

#ifdef _WIN32
typedef HANDLE sc_fd;
#define SC_INVALID INVALID_HANDLE_VALUE
typedef wchar_t sc_path_char;
static int sc_win_error(DWORD e) {
  switch (e) {
  case ERROR_FILE_NOT_FOUND:
  case ERROR_PATH_NOT_FOUND:
    return -ENOENT;
  case ERROR_ACCESS_DENIED:
    return -EACCES;
  case ERROR_NOT_ENOUGH_MEMORY:
  case ERROR_OUTOFMEMORY:
    return -ENOMEM;
  case ERROR_DISK_FULL:
    return -ENOSPC;
  case ERROR_SHARING_VIOLATION:
    return -EBUSY;
  case ERROR_OPERATION_ABORTED:
    return -EINTR;
  case ERROR_CANT_ACCESS_FILE:
    return -ELOOP;
  case ERROR_FILENAME_EXCED_RANGE:
    return -ENAMETOOLONG;
  case ERROR_NOT_SUPPORTED:
  case ERROR_CALL_NOT_IMPLEMENTED:
    return -ENOTSUP;
  default:
    return -EIO;
  }
}
static int sc_close(sc_fd *fd) {
  HANDLE old = *fd;
  *fd = SC_INVALID;
  return old == SC_INVALID ? 0 : CloseHandle(old) ? 0 : sc_win_error(GetLastError());
}
static int sc_dup(sc_fd fd, sc_fd *out) {
  return DuplicateHandle(GetCurrentProcess(), fd, GetCurrentProcess(), out, 0, FALSE,
                         DUPLICATE_SAME_ACCESS)
             ? 0
             : sc_win_error(GetLastError());
}
static wchar_t *sc_wide(const uint8_t *s, size_t n) {
  if (n > INT_MAX)
    return NULL;
  int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)s, (int)n, NULL, 0);
  if (!count)
    return NULL;
  wchar_t *p = malloc(((size_t)count + 1) * sizeof(*p));
  if (!p)
    return NULL;
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)s, (int)n, p, count)) {
    free(p);
    return NULL;
  }
  p[count] = 0;
  return p;
}
static int sc_open_root(const char *path, sc_fd *out) {
  wchar_t *wide = sc_wide((const uint8_t *)path, strlen(path));
  if (!wide)
    return -EINVAL;
  HANDLE h =
      CreateFileW(wide, FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                  FILE_SHARE_READ, NULL, OPEN_EXISTING,
                  FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  free(wide);
  if (h == SC_INVALID)
    return sc_win_error(GetLastError());
  BY_HANDLE_FILE_INFORMATION info;
  if (!GetFileInformationByHandle(h, &info)) {
    int e = sc_win_error(GetLastError());
    CloseHandle(h);
    return e;
  }
  if (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
      (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
    CloseHandle(h);
    return -ELOOP;
  }
  *out = h;
  return 0;
}
static int sc_open_child(sc_fd parent, const uint8_t *name, size_t length, int directory,
                         sc_fd *out) {
  typedef NTSTATUS(NTAPI * create_fn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                      PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
  typedef ULONG(WINAPI * error_fn)(NTSTATUS);
  HMODULE module = GetModuleHandleW(L"ntdll.dll");
  create_fn create = NULL;
  error_fn error = NULL;
  FARPROC raw = GetProcAddress(module, "NtCreateFile");
  memcpy(&create, &raw, sizeof(create));
  raw = GetProcAddress(module, "RtlNtStatusToDosError");
  memcpy(&error, &raw, sizeof(error));
  if (!create || !error)
    return -ENOTSUP;
  wchar_t *wide = sc_wide(name, length);
  if (!wide)
    return -EINVAL;
  size_t count = wcslen(wide);
  if (count > 32767) {
    free(wide);
    return -ENAMETOOLONG;
  }
  UNICODE_STRING text;
  memset(&text, 0, sizeof(text));
  text.Buffer = wide;
  text.Length = (USHORT)(count * sizeof(wchar_t));
  text.MaximumLength = text.Length;
  OBJECT_ATTRIBUTES attrs;
  memset(&attrs, 0, sizeof(attrs));
  attrs.Length = sizeof(attrs);
  attrs.RootDirectory = parent;
  attrs.ObjectName = &text;
  attrs.Attributes = 0x40;
  /* A type-neutral no-follow open avoids relying on undocumented combinations
   * of FILE_DIRECTORY_FILE and FILE_OPEN_REPARSE_POINT. Check the handle type
   * below. Directory handles deny write/delete sharing while used as anchors. */
  IO_STATUS_BLOCK status;
  HANDLE h = SC_INVALID;
  ULONG options = 0x00200000u | 0x20u;
  ACCESS_MASK access = FILE_READ_ATTRIBUTES | SYNCHRONIZE |
                       (directory ? (FILE_LIST_DIRECTORY | FILE_TRAVERSE) : FILE_READ_DATA);
  NTSTATUS result = create(&h, access, &attrs, &status, NULL, FILE_ATTRIBUTE_NORMAL,
                           FILE_SHARE_READ, 1, options, NULL, 0);
  free(wide);
  if (result < 0)
    return sc_win_error(error(result));
  BY_HANDLE_FILE_INFORMATION info;
  if (!GetFileInformationByHandle(h, &info)) {
    int e = sc_win_error(GetLastError());
    CloseHandle(h);
    return e;
  }
  if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
      !!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != !!directory) {
    CloseHandle(h);
    return -ELOOP;
  }
  *out = h;
  return 0;
}
static int64_t sc_read_at(sc_fd fd, uint8_t *out, size_t n, uint64_t at) {
  LARGE_INTEGER pos;
  pos.QuadPart = (LONGLONG)at;
  DWORD got = 0;
  if (!SetFilePointerEx(fd, pos, NULL, FILE_BEGIN))
    return sc_win_error(GetLastError());
  if (!ReadFile(fd, out, (DWORD)n, &got, NULL))
    return sc_win_error(GetLastError());
  return got;
}
static int64_t sc_write_at(sc_fd fd, const uint8_t *data, size_t n, uint64_t at) {
  LARGE_INTEGER pos;
  pos.QuadPart = (LONGLONG)at;
  DWORD got = 0;
  if (!SetFilePointerEx(fd, pos, NULL, FILE_BEGIN))
    return sc_win_error(GetLastError());
  if (!WriteFile(fd, data, (DWORD)n, &got, NULL))
    return sc_win_error(GetLastError());
  return got;
}
static int sc_truncate(sc_fd fd, uint64_t size) {
  LARGE_INTEGER pos;
  pos.QuadPart = (LONGLONG)size;
  return SetFilePointerEx(fd, pos, NULL, FILE_BEGIN) && SetEndOfFile(fd)
             ? 0
             : sc_win_error(GetLastError());
}
#else
typedef int sc_fd;
#define SC_INVALID (-1)
typedef char sc_path_char;
static int sc_close(sc_fd *fd) {
  int old = *fd;
  *fd = -1;
  return old < 0 ? 0 : close(old) ? -errno : 0;
}
static int sc_dup(sc_fd fd, sc_fd *out) {
  int n = fcntl(fd, F_DUPFD_CLOEXEC, 0);
  if (n < 0)
    return -errno;
  *out = n;
  return 0;
}
static int sc_open_root(const char *path, sc_fd *out) {
  int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return -errno;
  *out = fd;
  return 0;
}
static int sc_open_child(sc_fd parent, const uint8_t *name, size_t length, int directory,
                         sc_fd *out) {
  char *path = malloc(length + 1);
  if (!path)
    return -ENOMEM;
  memcpy(path, name, length);
  path[length] = 0;
  int fd = openat(parent, path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | (directory ? O_DIRECTORY : 0));
  int error = errno;
  free(path);
  if (fd < 0)
    return -error;
  *out = fd;
  return 0;
}
static int64_t sc_read_at(sc_fd fd, uint8_t *out, size_t n, uint64_t at) {
  ssize_t r = pread(fd, out, n, (off_t)at);
  return r < 0 ? -errno : r;
}
static int64_t sc_write_at(sc_fd fd, const uint8_t *data, size_t n, uint64_t at) {
  ssize_t r = pwrite(fd, data, n, (off_t)at);
  return r < 0 ? -errno : r;
}
static int sc_truncate(sc_fd fd, uint64_t size) { return ftruncate(fd, (off_t)size) ? -errno : 0; }
#endif

typedef struct {
  uint64_t size, device, inode, change;
  int64_t modified;
  uint32_t nanoseconds;
} sc_stat;
static int sc_stat_file(sc_fd fd, sc_stat *out) {
#ifdef _WIN32
  BY_HANDLE_FILE_INFORMATION info;
  FILE_BASIC_INFO basic;
  if (!GetFileInformationByHandle(fd, &info) ||
      !GetFileInformationByHandleEx(fd, FileBasicInfo, &basic, sizeof(basic)))
    return sc_win_error(GetLastError());
  if (GetFileType(fd) != FILE_TYPE_DISK ||
      (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
    return -EINVAL;
  out->size = (uint64_t)info.nFileSizeHigh << 32 | info.nFileSizeLow;
  out->device = info.dwVolumeSerialNumber;
  out->inode = (uint64_t)info.nFileIndexHigh << 32 | info.nFileIndexLow;
  uint64_t ticks = (uint64_t)basic.LastWriteTime.QuadPart;
  out->modified = (int64_t)(ticks / 10000000) - INT64_C(11644473600);
  out->nanoseconds = (uint32_t)(ticks % 10000000) * 100;
  out->change = (uint64_t)basic.ChangeTime.QuadPart;
#else
  struct stat s;
  if (fstat(fd, &s))
    return -errno;
  if (!S_ISREG(s.st_mode) || s.st_size < 0)
    return -EINVAL;
  out->size = (uint64_t)s.st_size;
  out->device = (uint64_t)s.st_dev;
  out->inode = (uint64_t)s.st_ino;
#ifdef __APPLE__
  out->modified = s.st_mtimespec.tv_sec;
  out->nanoseconds = (uint32_t)s.st_mtimespec.tv_nsec;
  out->change = (uint64_t)s.st_ctimespec.tv_sec * 1000000000 + (uint32_t)s.st_ctimespec.tv_nsec;
#else
  out->modified = s.st_mtim.tv_sec;
  out->nanoseconds = (uint32_t)s.st_mtim.tv_nsec;
  out->change = (uint64_t)s.st_ctim.tv_sec * 1000000000 + (uint32_t)s.st_ctim.tv_nsec;
#endif
#endif
  return 0;
}
static int sc_same_stat(const sc_stat *a, const sc_stat *b) {
  return a->size == b->size && a->device == b->device && a->inode == b->inode &&
         a->modified == b->modified && a->nanoseconds == b->nanoseconds && a->change == b->change;
}

typedef struct {
  uint64_t offset, length;
  uint8_t hash[32];
} sc_variant;
typedef struct {
  uint32_t present;
  int64_t modified;
  sc_variant variants[3];
} sc_entry;
enum {
  SC_JOB_NONE,
  SC_JOB_OPEN,
  SC_JOB_STAT,
  SC_JOB_IDENTITY,
  SC_JOB_CHECK,
  SC_JOB_CODEC_INIT,
  SC_JOB_CODEC,
  SC_JOB_VARIANT_DONE,
  SC_JOB_TRUNCATE,
  SC_JOB_DONE
};
struct sc_builder {
  char *root_path;
  sc_path_char *temporary;
  sc_fd root, pack, readonly, walk, source;
  unsigned initialized, sealed, finished, poisoned, readonly_verified, cloexec;
  uint64_t maximum_file, maximum_pack, minimum_compress, size;
  uint32_t maximum_entries, gzip_level, brotli_quality, count;
  sc_entry *entries, pending;
  unsigned job, coding, mask, source_is_bytes, codec_finished, codec_eof, z_initialized;
  uint8_t *path, *bytes;
  size_t path_length, path_cursor, bytes_length, input_size, input_cursor, output_size,
      output_cursor;
  uint64_t source_offset, codec_offset;
  sc_stat original;
  sc_sha digest;
  uint8_t input[SC_CHUNK], output[SC_CHUNK];
  z_stream z;
  gz_header gzip_header;
  BrotliEncoderState *brotli;
  rn_file_source *published;
};

static int sc_unlink_temp(sc_builder *b, int preparing) {
  if (!b->temporary)
    return 0;
#ifdef _WIN32
  if (preparing) {
    /* Ordinary DeleteFile leaves the name visible until the retained pack
       handles close. Close a separate POSIX-delete handle before Catalog.walk
       can enumerate TMPDIR when it is inside the served root. */
    sc_fd deletion = CreateFileW(b->temporary, DELETE | FILE_READ_ATTRIBUTES,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                                 OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (deletion == SC_INVALID) {
      DWORD e = GetLastError();
      if (e != ERROR_FILE_NOT_FOUND)
        return sc_win_error(e);
    } else {
      sc_stat expected, actual;
      int error = sc_stat_file(b->pack, &expected);
      if (!error)
        error = sc_stat_file(deletion, &actual);
      if (!error && (expected.device != actual.device || expected.inode != actual.inode))
        error = -ESTALE;
      /* FileDispositionInfoEx and FILE_DISPOSITION_INFO_EX are hidden by
         older compile targets. Their Win10 ABI is class 21 and one DWORD;
         unsupported operating systems/filesystems fail startup explicitly. */
      struct {
        DWORD flags;
      } disposition = {0x00000001u | 0x00000002u};
      if (!error && !SetFileInformationByHandle(deletion, (FILE_INFO_BY_HANDLE_CLASS)21,
                                                &disposition, sizeof(disposition))) {
        DWORD e = GetLastError();
        error = e == ERROR_INVALID_PARAMETER ? -ENOTSUP : sc_win_error(e);
      }
      int closed = sc_close(&deletion);
      if (error)
        return error;
      if (closed)
        return closed;
    }
    DWORD attributes = GetFileAttributesW(b->temporary);
    if (attributes != INVALID_FILE_ATTRIBUTES)
      return -ENOTSUP;
    DWORD missing = GetLastError();
    if (missing != ERROR_FILE_NOT_FOUND)
      return missing == ERROR_ACCESS_DENIED ? -ENOTSUP : sc_win_error(missing);
  } else if (!DeleteFileW(b->temporary) && GetLastError() != ERROR_FILE_NOT_FOUND) {
    /* Failed setup still closes every retained handle below, so conventional
       pending deletion is sufficient for cleanup, never publication. */
    return sc_win_error(GetLastError());
  }
#else
  (void)preparing;
  if (unlink(b->temporary) && errno != ENOENT)
    return -errno;
#endif
  free(b->temporary);
  b->temporary = NULL;
  return 0;
}
static int sc_create_pack(sc_builder *b) {
#ifdef _WIN32
  wchar_t temp[32768];
  DWORD n = GetTempPathW(32768, temp);
  if (!n || n >= 32768)
    return -ENAMETOOLONG;
  PSECURITY_DESCRIPTOR security = NULL;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;OW)", SDDL_REVISION_1,
                                                            &security, NULL))
    return sc_win_error(GetLastError());
  SECURITY_ATTRIBUTES attrs = {sizeof(attrs), security, FALSE};
  HANDLE h = SC_INVALID;
  for (unsigned i = 0; i < 64; ++i) {
    wchar_t name[128];
    int used =
        swprintf(name, 128, L"lean-net-static-%lu-%llu-%u.tmp",
                 (unsigned long)GetCurrentProcessId(), (unsigned long long)GetTickCount64(), i);
    if (used < 0) {
      LocalFree(security);
      return -EINVAL;
    }
    size_t total = n + (size_t)used + 1;
    wchar_t *path = malloc(total * sizeof(*path));
    if (!path) {
      LocalFree(security);
      return -ENOMEM;
    }
    memcpy(path, temp, n * sizeof(*path));
    memcpy(path + n, name, ((size_t)used + 1) * sizeof(*path));
    h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &attrs, CREATE_NEW,
                    FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (h != SC_INVALID) {
      b->temporary = path;
      break;
    }
    DWORD e = GetLastError();
    free(path);
    if (e != ERROR_FILE_EXISTS && e != ERROR_ALREADY_EXISTS) {
      LocalFree(security);
      return sc_win_error(e);
    }
  }
  LocalFree(security);
  if (h == SC_INVALID)
    return -EEXIST;
  b->pack = h;
#else
  const char *directory = getenv("TMPDIR");
  if (!directory || !*directory)
    directory = "/tmp";
  size_t n = strlen(directory);
  if (n > SIZE_MAX - 40)
    return -ENAMETOOLONG;
  char *path = malloc(n + 40);
  if (!path)
    return -ENOMEM;
  memcpy(path, directory, n);
  memcpy(path + n, "/lean-net-static-XXXXXX", sizeof("/lean-net-static-XXXXXX"));
  int fd = mkstemp(path);
  if (fd < 0) {
    int error = -errno;
    free(path);
    return error;
  }
  b->temporary = path;
  b->pack = fd;
#endif
  return 0;
}
static int sc_initialize(sc_builder *b) {
  int error;
  if (b->root == SC_INVALID) {
    error = sc_open_root(b->root_path, &b->root);
    if (error)
      return error;
  }
  if (b->pack == SC_INVALID) {
    error = sc_create_pack(b);
    if (error)
      return error;
  }
#ifndef _WIN32
  if (!b->cloexec) {
    if (fcntl(b->pack, F_SETFD, FD_CLOEXEC) < 0)
      return -errno;
    b->cloexec = 1;
  }
#endif
  if (b->readonly == SC_INVALID) {
#ifdef _WIN32
    b->readonly =
        CreateFileW(b->temporary, GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OVERLAPPED |
                        FILE_FLAG_SEQUENTIAL_SCAN,
                    NULL);
    if (b->readonly == SC_INVALID)
      return sc_win_error(GetLastError());
#else
    b->readonly = open(b->temporary, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (b->readonly < 0)
      return -errno;
#endif
  }
  if (!b->readonly_verified) {
    sc_stat a, c;
    error = sc_stat_file(b->pack, &a);
    if (!error)
      error = sc_stat_file(b->readonly, &c);
    if (error)
      return error;
    if (a.device != c.device || a.inode != c.inode)
      return -ESTALE;
    b->readonly_verified = 1;
  }
  error = sc_unlink_temp(b, 1);
  if (error)
    return error;
  b->initialized = 1;
  return 0;
}

static int sc_utf8(const uint8_t *p, size_t n) {
  for (size_t i = 0; i < n;) {
    uint32_t value = p[i++];
    unsigned extra = 0;
    uint32_t minimum = 0;
    if (value < 128)
      continue;
    if (value >= 0xc2 && value <= 0xdf) {
      extra = 1;
      minimum = 0x80;
      value &= 31;
    } else if (value >= 0xe0 && value <= 0xef) {
      extra = 2;
      minimum = 0x800;
      value &= 15;
    } else if (value >= 0xf0 && value <= 0xf4) {
      extra = 3;
      minimum = 0x10000;
      value &= 7;
    } else
      return 0;
    if (extra > n - i)
      return 0;
    for (unsigned j = 0; j < extra; ++j) {
      uint8_t c = p[i++];
      if ((c & 0xc0) != 0x80)
        return 0;
      value = (value << 6) | (c & 63);
    }
    if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
      return 0;
  }
  return 1;
}
static int sc_valid_path(const uint8_t *p, size_t n) {
  if (!p || !n || n > 65536 || !sc_utf8(p, n))
    return 0;
  size_t start = 0;
  for (size_t i = 0; i <= n; ++i) {
    if (i < n) {
      uint8_t c = p[i];
      if (c < 32 || c == 127 || c == '\\' || c == ':')
        return 0;
      if (c != '/')
        continue;
    }
    size_t length = i - start;
    if (!length || length > 255 || (length == 1 && p[start] == '.') ||
        (length == 2 && p[start] == '.' && p[start + 1] == '.') || p[i - 1] == ' ' ||
        p[i - 1] == '.')
      return 0;
    char stem[5] = {0};
    size_t end = start;
    while (end < i && p[end] != '.')
      ++end;
    while (end > start && p[end - 1] == ' ')
      --end;
    size_t take = end - start;
    for (size_t j = 0; j < take && j < 4; ++j) {
      uint8_t c = p[start + j];
      stem[j] = (char)(c >= 'A' && c <= 'Z' ? c + 32 : c);
    }
    if ((take == 3 && (!strcmp(stem, "con") || !strcmp(stem, "prn") || !strcmp(stem, "aux") ||
                       !strcmp(stem, "nul"))) ||
        (take == 4 && (!memcmp(stem, "com", 3) || !memcmp(stem, "lpt", 3)) && stem[3] >= '1' &&
         stem[3] <= '9'))
      return 0;
    start = i + 1;
  }
  return 1;
}
static int sc_failure(sc_builder *b, int error) {
  if (error != -EINTR)
    b->poisoned = 1;
  return error;
}
int sc_builder_prepare(sc_builder *b) {
  if (!b || b->job != SC_JOB_NONE || b->poisoned || b->sealed || b->finished)
    return -EINVAL;
  if (b->initialized)
    return 0;
  int error = sc_initialize(b);
  return error ? sc_failure(b, error) : 0;
}
static void sc_end_codec(sc_builder *b) {
  if (b->z_initialized) {
    (void)deflateEnd(&b->z);
    b->z_initialized = 0;
  }
  if (b->brotli) {
    BrotliEncoderDestroyInstance(b->brotli);
    b->brotli = NULL;
  }
}
static void sc_clear_job(sc_builder *b) {
  sc_end_codec(b);
  free(b->path);
  b->path = NULL;
  free(b->bytes);
  b->bytes = NULL;
  b->job = SC_JOB_NONE;
}

int sc_builder_new(const uint8_t *root, size_t root_length, uint64_t maximum_file,
                   uint64_t maximum_pack, uint32_t maximum_entries, uint64_t minimum_compress,
                   uint32_t gzip_level, uint32_t brotli_quality, sc_builder **out) {
  if (!out)
    return -EINVAL;
  *out = NULL;
  if (!root || !root_length || root_length > 131072 || memchr(root, 0, root_length) ||
      !sc_utf8(root, root_length) || maximum_file > UINT64_MAX / 8 || maximum_pack > INT64_MAX ||
      !maximum_entries || maximum_entries > 1000000 || gzip_level > 9 || brotli_quality > 11)
    return -EINVAL;
  sc_builder *b = calloc(1, sizeof(*b));
  if (!b)
    return -ENOMEM;
  b->root = b->pack = b->readonly = b->walk = b->source = SC_INVALID;
  b->root_path = malloc(root_length + 1);
  b->entries = calloc(maximum_entries, sizeof(*b->entries));
  if (!b->root_path || !b->entries) {
    free(b->root_path);
    free(b->entries);
    free(b);
    return -ENOMEM;
  }
  memcpy(b->root_path, root, root_length);
  b->root_path[root_length] = 0;
  b->maximum_file = maximum_file;
  b->maximum_pack = maximum_pack;
  b->maximum_entries = maximum_entries;
  b->minimum_compress = minimum_compress;
  b->gzip_level = gzip_level;
  b->brotli_quality = brotli_quality;
  *out = b;
  return 0;
}
static int sc_begin(sc_builder *b, uint32_t mask) {
  if (!b || b->job != SC_JOB_NONE || b->poisoned || b->sealed || b->finished || mask > 3)
    return -EINVAL;
  if (b->count == b->maximum_entries)
    return -ENOSPC;
  memset(&b->pending, 0, sizeof(b->pending));
  b->pending.variants[0].offset = b->size;
  b->pending.present = 1;
  b->mask = mask;
  b->coding = 0;
  b->source_offset = b->codec_offset = 0;
  b->path_cursor = 0;
  b->input_size = b->input_cursor = b->output_size = b->output_cursor = 0;
  b->codec_finished = b->codec_eof = 0;
  sc_sha_init(&b->digest);
  return 0;
}
int sc_builder_begin_path(sc_builder *b, const uint8_t *path, size_t length, uint32_t mask) {
  if (!sc_valid_path(path, length))
    return -EINVAL;
  int error = sc_begin(b, mask);
  if (error)
    return error;
  b->path = malloc(length);
  if (!b->path)
    return -ENOMEM;
  memcpy(b->path, path, length);
  b->path_length = length;
  b->source_is_bytes = 0;
  b->job = SC_JOB_OPEN;
  return 0;
}
int sc_builder_begin_bytes(sc_builder *b, const uint8_t *bytes, size_t length, uint32_t mask) {
  if (length && !bytes)
    return -EINVAL;
  int error = sc_begin(b, mask);
  if (error)
    return error;
  if (length > b->maximum_file || length > b->maximum_pack - b->size)
    return -EFBIG;
  b->bytes = malloc(length ? length : 1);
  if (!b->bytes)
    return -ENOMEM;
  if (length)
    memcpy(b->bytes, bytes, length);
  b->bytes_length = length;
  b->source_is_bytes = 1;
  memset(&b->original, 0, sizeof(b->original));
  b->original.size = length;
  b->job = SC_JOB_IDENTITY;
  return 0;
}
int sc_builder_check_directory(sc_builder *b, const uint8_t *path, size_t length) {
  if (!b || b->job != SC_JOB_NONE || b->poisoned || b->finished ||
      (length && !sc_valid_path(path, length)))
    return -EINVAL;
  int error = 0;
  if (b->root == SC_INVALID) {
    error = sc_open_root(b->root_path, &b->root);
    if (error)
      return error;
  }
  sc_fd current = SC_INVALID;
  error = sc_dup(b->root, &current);
  if (error)
    return error;
  size_t start = 0;
  while (start < length) {
    size_t stop = start;
    while (stop < length && path[stop] != '/')
      ++stop;
    sc_fd next = SC_INVALID;
    error = sc_open_child(current, path + start, stop - start, 1, &next);
    if (error)
      break;
    sc_fd old = current;
    current = next;
    error = sc_close(&old);
    if (error)
      break;
    start = stop + 1;
  }
  int closed = sc_close(&current);
  return error ? error : closed;
}

void sc_directory_list_free(sc_directory_list *list) {
  if (!list)
    return;
  for (uint32_t i = 0; i < list->count; ++i)
    free(list->entries[i].name);
  free(list->entries);
  list->entries = NULL;
  list->count = 0;
}
static int sc_directory_add(sc_directory_list *list, uint32_t *capacity, uint32_t limit,
                            const uint8_t *name, size_t length, uint32_t kind) {
  /* Count before allocating a name, even when this kind will later be skipped.
     1024 bytes also bounds names which the portable path policy will reject. */
  if (list->count == limit)
    return -ENOSPC;
  if (!length || length > 1024)
    return -ENAMETOOLONG;
  if (list->count == *capacity) {
    uint32_t next = *capacity ? *capacity * 2 : 4;
    if (next > limit)
      next = limit;
    sc_directory_entry *entries = realloc(list->entries, next * sizeof(*entries));
    if (!entries)
      return -ENOMEM;
    list->entries = entries;
    *capacity = next;
  }
  uint8_t *copy = malloc(length);
  if (!copy)
    return -ENOMEM;
  memcpy(copy, name, length);
  list->entries[list->count++] = (sc_directory_entry){copy, length, kind};
  return 0;
}
static int sc_directory_open(sc_builder *b, const uint8_t *path, size_t length, sc_fd *out) {
  int error;
  if (b->root == SC_INVALID) {
    error = sc_open_root(b->root_path, &b->root);
    if (error)
      return error;
  }
  sc_fd current = SC_INVALID;
  error = sc_dup(b->root, &current);
  if (error)
    return error;
  size_t start = 0;
  while (start < length) {
    size_t stop = start;
    while (stop < length && path[stop] != '/')
      ++stop;
    sc_fd next = SC_INVALID;
    error = sc_open_child(current, path + start, stop - start, 1, &next);
    if (error)
      break;
    sc_fd old = current;
    current = next;
    error = sc_close(&old);
    if (error)
      break;
    start = stop + 1;
  }
#ifndef _WIN32
  /* dup shares the directory cursor with the root anchor. An anchored open of
     dot creates an independent open-file description for each enumeration. */
  if (!error) {
    sc_fd independent = SC_INVALID;
    error = sc_open_child(current, (const uint8_t *)".", 1, 1, &independent);
    int closed = sc_close(&current);
    current = independent;
    if (!error)
      error = closed;
  }
#endif
  if (error) {
    int closed = sc_close(&current);
    (void)closed;
    return error;
  }
  *out = current;
  return 0;
}
int sc_builder_read_directory(sc_builder *b, const uint8_t *path, size_t length, uint32_t limit,
                              sc_directory_list *out) {
  if (!out)
    return -EINVAL;
  memset(out, 0, sizeof(*out));
  if (!b || b->job != SC_JOB_NONE || b->poisoned || b->sealed || b->finished ||
      limit > b->maximum_entries || (length && !sc_valid_path(path, length)))
    return -EINVAL;
  sc_fd directory = SC_INVALID;
  int error = sc_directory_open(b, path, length, &directory);
  if (error)
    return error;
  sc_directory_list list = {NULL, 0};
  uint32_t capacity = 0;
#ifdef _WIN32
  union {
    uint64_t alignment;
    uint8_t bytes[65536];
  } buffer;
  int restart = 1;
  while (!error) {
    if (!GetFileInformationByHandleEx(
            directory, restart ? FileIdBothDirectoryRestartInfo : FileIdBothDirectoryInfo,
            buffer.bytes, sizeof(buffer.bytes))) {
      DWORD e = GetLastError();
      if (e != ERROR_NO_MORE_FILES)
        error = sc_win_error(e);
      break;
    }
    restart = 0;
    size_t offset = 0;
    for (;;) {
      size_t base = offsetof(FILE_ID_BOTH_DIR_INFO, FileName);
      if (offset > sizeof(buffer.bytes) - base) {
        error = -EIO;
        break;
      }
      FILE_ID_BOTH_DIR_INFO *item = (FILE_ID_BOTH_DIR_INFO *)(buffer.bytes + offset);
      size_t bytes = item->FileNameLength;
      if (bytes % sizeof(wchar_t) || bytes > sizeof(buffer.bytes) - offset - base) {
        error = -EIO;
        break;
      }
      size_t characters = bytes / sizeof(wchar_t);
      int dot = characters == 1 && item->FileName[0] == L'.';
      int dotdot = characters == 2 && item->FileName[0] == L'.' && item->FileName[1] == L'.';
      if (!dot && !dotdot) {
        if (list.count == limit) {
          error = -ENOSPC;
          break;
        }
        int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, item->FileName,
                                         (int)characters, NULL, 0, NULL, NULL);
        if (!needed || needed > 1024) {
          error = needed > 1024 ? -ENAMETOOLONG : -EINVAL;
          break;
        }
        uint8_t name[1024];
        if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, item->FileName, (int)characters,
                                 (char *)name, needed, NULL, NULL)) {
          error = sc_win_error(GetLastError());
          break;
        }
        uint32_t kind = item->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT ? SC_LINK
                        : item->FileAttributes & FILE_ATTRIBUTE_DIRECTORY   ? SC_DIRECTORY
                        : item->FileAttributes & FILE_ATTRIBUTE_DEVICE      ? SC_OTHER
                                                                            : SC_REGULAR;
        error = sc_directory_add(&list, &capacity, limit, name, (size_t)needed, kind);
        if (error)
          break;
      }
      if (!item->NextEntryOffset)
        break;
      if (item->NextEntryOffset < base + bytes || item->NextEntryOffset % 8 ||
          item->NextEntryOffset > sizeof(buffer.bytes) - offset) {
        error = -EIO;
        break;
      }
      offset += item->NextEntryOffset;
    }
  }
  int closed = sc_close(&directory);
#else
  DIR *stream = NULL;
  if (!error) {
    stream = fdopendir(directory);
    if (!stream)
      error = -errno;
    else
      directory = SC_INVALID; /* fdopendir consumes ownership only on success. */
  }
  while (!error) {
    errno = 0;
    struct dirent *item = readdir(stream);
    if (!item) {
      if (errno)
        error = -errno;
      break;
    }
    if (!strcmp(item->d_name, ".") || !strcmp(item->d_name, ".."))
      continue;
    if (list.count == limit) {
      error = -ENOSPC;
      break;
    }
    struct stat status;
    if (fstatat(dirfd(stream), item->d_name, &status, AT_SYMLINK_NOFOLLOW)) {
      error = -errno;
      break;
    }
    uint32_t kind = S_ISLNK(status.st_mode)   ? SC_LINK
                    : S_ISDIR(status.st_mode) ? SC_DIRECTORY
                    : S_ISREG(status.st_mode) ? SC_REGULAR
                                              : SC_OTHER;
    error = sc_directory_add(&list, &capacity, limit, (const uint8_t *)item->d_name,
                             strlen(item->d_name), kind);
  }
  int closed;
  if (stream) {
    DIR *owned = stream;
    stream = NULL;
    closed = closedir(owned) ? -errno : 0; /* Never retry a consumed descriptor. */
  } else {
    closed = sc_close(&directory);
  }
#endif
  if (!error)
    error = closed;
  if (error) {
    sc_directory_list_free(&list);
    return error;
  }
  *out = list;
  return 0;
}
static int sc_walk(sc_builder *b) {
  if (b->walk == SC_INVALID) {
    int error = sc_dup(b->root, &b->walk);
    if (error)
      return error;
  }
  size_t stop = b->path_cursor;
  while (stop < b->path_length && b->path[stop] != '/')
    ++stop;
  int directory = stop < b->path_length;
  sc_fd next = SC_INVALID;
  int error =
      sc_open_child(b->walk, b->path + b->path_cursor, stop - b->path_cursor, directory, &next);
  if (error)
    return error;
  sc_fd old = b->walk;
  b->walk = directory ? next : SC_INVALID;
  if (!directory) {
    b->source = next;
    b->job = SC_JOB_STAT;
  }
  b->path_cursor = stop + 1;
  return sc_close(&old);
}
static int sc_write_pending(sc_builder *b, uint32_t *budget, int identity) {
  const uint8_t *buffer = identity ? b->input : b->output;
  size_t *cursor = identity ? &b->input_cursor : &b->output_cursor;
  size_t size = identity ? b->input_size : b->output_size;
  size_t count = size - *cursor;
  if (count > *budget)
    count = *budget;
  if (!count)
    return 0;
  if (count > b->maximum_pack - b->size)
    return -ENOSPC;
  int64_t wrote = sc_write_at(b->pack, buffer + *cursor, count, b->size);
  if (wrote < 0)
    return (int)wrote;
  if (!wrote)
    return -EIO;
  sc_sha_update(&b->digest, buffer + *cursor, (size_t)wrote);
  *cursor += (size_t)wrote;
  b->size += (uint64_t)wrote;
  b->pending.variants[b->coding].length += (uint64_t)wrote;
  *budget -= (uint32_t)wrote;
  return 0;
}
static int sc_identity(sc_builder *b, uint32_t *budget) {
  if (b->input_cursor < b->input_size)
    return sc_write_pending(b, budget, 1);
  if (b->source_offset == b->original.size) {
    b->job = SC_JOB_CHECK;
    return 0;
  }
  size_t count = (size_t)(b->original.size - b->source_offset);
  if (count > SC_CHUNK)
    count = SC_CHUNK;
  int64_t got;
  if (b->source_is_bytes) {
    memcpy(b->input, b->bytes + (size_t)b->source_offset, count);
    got = (int64_t)count;
  } else
    got = sc_read_at(b->source, b->input, count, b->source_offset);
  if (got < 0)
    return (int)got;
  if (!got)
    return -ESTALE;
  b->source_offset += (uint64_t)got;
  b->input_size = (size_t)got;
  b->input_cursor = 0;
  return 0;
}
static int sc_codec_init(sc_builder *b) {
  while (b->coding < 3 &&
         (!(b->mask & (1u << (b->coding - 1))) || b->original.size < b->minimum_compress))
    ++b->coding;
  if (b->coding >= 3) {
    b->job = SC_JOB_DONE;
    return 0;
  }
  b->pending.variants[b->coding].offset = b->size;
  b->pending.variants[b->coding].length = 0;
  sc_sha_init(&b->digest);
  b->codec_offset = 0;
  b->input_size = b->input_cursor = b->output_size = b->output_cursor = 0;
  b->codec_finished = b->codec_eof = 0;
  if (b->coding == SC_GZIP) {
    memset(&b->z, 0, sizeof(b->z));
    int result =
        deflateInit2(&b->z, (int)b->gzip_level, Z_DEFLATED, MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY);
    if (result != Z_OK)
      return result == Z_MEM_ERROR ? -ENOMEM : -EIO;
    b->z_initialized = 1;
    memset(&b->gzip_header, 0, sizeof(b->gzip_header));
    b->gzip_header.os = 255;
    if (deflateSetHeader(&b->z, &b->gzip_header) != Z_OK)
      return -EIO;
  } else {
    b->brotli = BrotliEncoderCreateInstance(NULL, NULL, NULL);
    if (!b->brotli)
      return -ENOMEM;
    if (!BrotliEncoderSetParameter(b->brotli, BROTLI_PARAM_QUALITY, b->brotli_quality) ||
        !BrotliEncoderSetParameter(b->brotli, BROTLI_PARAM_LGWIN, 22))
      return -EINVAL;
  }
  b->job = SC_JOB_CODEC;
  return 0;
}
static int sc_codec(sc_builder *b, uint32_t *budget) {
  if (b->output_cursor < b->output_size)
    return sc_write_pending(b, budget, 0);
  if (b->codec_finished) {
    b->job = SC_JOB_VARIANT_DONE;
    return 0;
  }
  if (b->input_cursor == b->input_size && b->codec_offset < b->original.size) {
    size_t count = (size_t)(b->original.size - b->codec_offset);
    if (count > SC_CHUNK)
      count = SC_CHUNK;
    int64_t got =
        sc_read_at(b->pack, b->input, count, b->pending.variants[0].offset + b->codec_offset);
    if (got < 0)
      return (int)got;
    if (!got)
      return -EIO;
    b->codec_offset += (uint64_t)got;
    b->input_size = (size_t)got;
    b->input_cursor = 0;
  }
  b->codec_eof = b->codec_offset == b->original.size;
  size_t input = b->input_size - b->input_cursor, output = SC_CHUNK;
  const uint8_t *next_in = b->input + b->input_cursor;
  uint8_t *next_out = b->output;
  size_t previous = input;
  if (b->coding == SC_GZIP) {
    b->z.next_in = (Bytef *)(uintptr_t)next_in;
    b->z.avail_in = (uInt)input;
    b->z.next_out = next_out;
    b->z.avail_out = SC_CHUNK;
    int result = deflate(&b->z, b->codec_eof ? Z_FINISH : Z_NO_FLUSH);
    if (result != Z_OK && result != Z_STREAM_END)
      return result == Z_MEM_ERROR ? -ENOMEM : -EIO;
    input = b->z.avail_in;
    output = b->z.avail_out;
    b->codec_finished = result == Z_STREAM_END;
  } else {
    if (!BrotliEncoderCompressStream(
            b->brotli, b->codec_eof ? BROTLI_OPERATION_FINISH : BROTLI_OPERATION_PROCESS, &input,
            &next_in, &output, &next_out, NULL))
      return -EIO;
    b->codec_finished = BrotliEncoderIsFinished(b->brotli);
  }
  b->input_cursor += previous - input;
  b->output_cursor = 0;
  b->output_size = SC_CHUNK - output;
  if (!b->output_size && previous == input && !b->codec_finished)
    return -EIO;
  return 0;
}
int64_t sc_builder_step(sc_builder *b, uint32_t budget) {
  if (!b || !budget || b->job == SC_JOB_NONE || b->poisoned || b->sealed || b->finished)
    return -EINVAL;
  if (!b->initialized) {
    int error = sc_initialize(b);
    if (error)
      return sc_failure(b, error);
  }
  for (unsigned steps = 0; steps < 32 && budget; ++steps) {
    int error = 0;
    switch (b->job) {
    case SC_JOB_OPEN:
      error = sc_walk(b);
      break;
    case SC_JOB_STAT:
      error = sc_stat_file(b->source, &b->original);
      if (!error) {
        if (b->original.size > b->maximum_file || b->original.size > b->maximum_pack - b->size)
          error = -EFBIG;
        else {
          b->pending.modified = b->original.modified;
          b->job = SC_JOB_IDENTITY;
        }
      }
      break;
    case SC_JOB_IDENTITY:
      error = sc_identity(b, &budget);
      break;
    case SC_JOB_CHECK: {
      if (!b->source_is_bytes) {
        sc_stat after;
        error = sc_stat_file(b->source, &after);
        if (!error && !sc_same_stat(&b->original, &after))
          error = -ESTALE;
      }
      if (!error) {
        sc_sha_final(&b->digest, b->pending.variants[0].hash);
        b->coding = 1;
        b->job = SC_JOB_CODEC_INIT;
        error = sc_close(&b->source);
      }
      break;
    }
    case SC_JOB_CODEC_INIT:
      error = sc_codec_init(b);
      break;
    case SC_JOB_CODEC:
      error = sc_codec(b, &budget);
      break;
    case SC_JOB_VARIANT_DONE:
      sc_sha_final(&b->digest, b->pending.variants[b->coding].hash);
      sc_end_codec(b);
      if (b->pending.variants[b->coding].length >= b->original.size)
        b->job = SC_JOB_TRUNCATE;
      else {
        b->pending.present |= 1u << b->coding;
        ++b->coding;
        b->job = SC_JOB_CODEC_INIT;
      }
      break;
    case SC_JOB_TRUNCATE:
      error = sc_truncate(b->pack, b->pending.variants[b->coding].offset);
      if (!error) {
        b->size = b->pending.variants[b->coding].offset;
        memset(&b->pending.variants[b->coding], 0, sizeof(sc_variant));
        ++b->coding;
        b->job = SC_JOB_CODEC_INIT;
      }
      break;
    case SC_JOB_DONE:
      b->entries[b->count++] = b->pending;
      sc_clear_job(b);
      return b->count;
    default:
      return sc_failure(b, -EINVAL);
    }
    if (error)
      return sc_failure(b, error);
  }
  return 0;
}
int64_t sc_builder_field(sc_builder *b, uint32_t id, uint32_t field) {
  if (!b || !id || id > b->count || field >= SC_METADATA_FIELDS)
    return -EINVAL;
  sc_entry *entry = &b->entries[id - 1];
  if (field == SC_FIELD_PRESENT)
    return entry->present;
  if (field == SC_FIELD_MTIME_LOW)
    return (uint32_t)(uint64_t)entry->modified;
  if (field == SC_FIELD_MTIME_HIGH)
    return (uint32_t)((uint64_t)entry->modified >> 32);
  field -= SC_FIELD_VARIANTS;
  sc_variant *v = &entry->variants[field / SC_VARIANT_FIELDS];
  unsigned part = field % SC_VARIANT_FIELDS;
  if (part == 0)
    return (uint32_t)v->offset;
  if (part == 1)
    return (uint32_t)(v->offset >> 32);
  if (part == 2)
    return (uint32_t)v->length;
  if (part == 3)
    return (uint32_t)(v->length >> 32);
  const uint8_t *p = v->hash + 4 * (part - 4);
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
int sc_builder_finish(sc_builder *b, uint64_t resident_budget, rn_file_source **out) {
  if (!out)
    return -EINVAL;
  *out = NULL;
  if (!b || b->job != SC_JOB_NONE || b->poisoned || b->finished)
    return -EINVAL;
  if (!b->initialized) {
    int error = sc_initialize(b);
    if (error)
      return sc_failure(b, error);
  }
  if (!b->sealed) {
    b->sealed = 1;
    int error = sc_close(&b->pack);
    if (error)
      return error;
  }
  if (!b->published) {
    sc_fd duplicate = SC_INVALID;
    int error = sc_dup(b->readonly, &duplicate);
    if (error)
      return error;
    error = rn_file_source_publish((uintptr_t)duplicate, b->size, resident_budget, &b->published);
    if (error)
      return error;
  }
  /* Publication can succeed before close reports EINTR. Retain that Source
   * until Lean reenters finish; the cleared fd slot prevents a close retry. */
  int error = sc_close(&b->readonly);
  if (error)
    return error;
  b->finished = 1;
  *out = b->published;
  b->published = NULL;
  return 0;
}
int sc_builder_free(sc_builder *b) {
  if (!b)
    return 0;
  int error = sc_unlink_temp(b, 0);
  if (error == -EINTR)
    return error;
  int closed = sc_close(&b->walk);
  if (!error)
    error = closed;
  closed = sc_close(&b->source);
  if (!error)
    error = closed;
  closed = sc_close(&b->pack);
  if (!error)
    error = closed;
  closed = sc_close(&b->readonly);
  if (!error)
    error = closed;
  closed = sc_close(&b->root);
  if (!error)
    error = closed;
  if (b->published) {
    rn_file_source *source = b->published;
    b->published = NULL;
    int released = rn_file_source_release(source);
    if (!error)
      error = released;
  }
  if (error == -EINTR)
    return error;
  sc_clear_job(b);
  free(b->root_path);
  free(b->temporary);
  free(b->entries);
  free(b);
  return error;
}

#ifndef SC_NO_LEAN_FFI
#include <lean/lean.h>
static lean_object *sc_result(int64_t result) {
  return lean_io_result_mk_ok(lean_box_uint64((uint64_t)result));
}
lean_object *lean_sc_builder_new(b_lean_obj_arg root, uint64_t maximum_file, uint64_t maximum_pack,
                                 uint32_t maximum_entries, uint64_t minimum_compress,
                                 uint32_t gzip_level, uint32_t brotli_quality) {
  sc_builder *b = NULL;
  int error = sc_builder_new((const uint8_t *)lean_string_cstr(root), lean_string_size(root) - 1,
                             maximum_file, maximum_pack, maximum_entries, minimum_compress,
                             gzip_level, brotli_quality, &b);
  return sc_result(error ? error : (int64_t)(uintptr_t)b);
}
lean_object *lean_sc_builder_begin_path(uint64_t handle, b_lean_obj_arg path, uint32_t mask) {
  return sc_result(sc_builder_begin_path((sc_builder *)(uintptr_t)handle, lean_sarray_cptr(path),
                                         lean_sarray_size(path), mask));
}
lean_object *lean_sc_builder_prepare(uint64_t handle) {
  return sc_result(sc_builder_prepare((sc_builder *)(uintptr_t)handle));
}
lean_object *lean_sc_builder_begin_bytes(uint64_t handle, b_lean_obj_arg bytes, uint32_t mask) {
  return sc_result(sc_builder_begin_bytes((sc_builder *)(uintptr_t)handle, lean_sarray_cptr(bytes),
                                          lean_sarray_size(bytes), mask));
}
lean_object *lean_sc_builder_check_directory(uint64_t handle, b_lean_obj_arg path) {
  return sc_result(sc_builder_check_directory((sc_builder *)(uintptr_t)handle,
                                              lean_sarray_cptr(path), lean_sarray_size(path)));
}
lean_object *lean_sc_builder_read_directory(uint64_t handle, b_lean_obj_arg path, uint32_t limit) {
  sc_directory_list list = {NULL, 0};
  int error = sc_builder_read_directory((sc_builder *)(uintptr_t)handle, lean_sarray_cptr(path),
                                        lean_sarray_size(path), limit, &list);
  lean_object *entries = lean_mk_empty_array_with_capacity(lean_box(list.count));
  for (uint32_t i = 0; i < list.count; ++i) {
    sc_directory_entry *item = &list.entries[i];
    lean_object *name = lean_alloc_sarray(1, item->length, item->length);
    memcpy(lean_sarray_cptr(name), item->name, item->length);
    lean_object *entry = lean_alloc_ctor(0, 2, 0);
    lean_ctor_set(entry, 0, name);
    lean_ctor_set(entry, 1, lean_box_uint32(item->kind));
    entries = lean_array_push(entries, entry);
  }
  sc_directory_list_free(&list);
  lean_object *result = lean_alloc_ctor(0, 2, 0);
  lean_ctor_set(result, 0, lean_box_uint64((uint64_t)(int64_t)error));
  lean_ctor_set(result, 1, entries);
  return lean_io_result_mk_ok(result);
}
lean_object *lean_sc_builder_step(uint64_t handle, uint32_t budget) {
  return sc_result(sc_builder_step((sc_builder *)(uintptr_t)handle, budget));
}
lean_object *lean_sc_builder_field(uint64_t handle, uint32_t id, uint32_t field) {
  return sc_result(sc_builder_field((sc_builder *)(uintptr_t)handle, id, field));
}
lean_object *lean_sc_builder_finish(uint64_t handle, uint64_t budget) {
  rn_file_source *source = NULL;
  int error = sc_builder_finish((sc_builder *)(uintptr_t)handle, budget, &source);
  return sc_result(error ? error : (int64_t)(uintptr_t)source);
}
lean_object *lean_sc_builder_free(uint64_t handle) {
  return sc_result(sc_builder_free((sc_builder *)(uintptr_t)handle));
}
#endif
