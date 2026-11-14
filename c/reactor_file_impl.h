/* One backend includes this implementation. Catalog builders include only the
 * declaration header and link against the reactor's native object. */
#ifndef LEAN_NET_REACTOR_FILE_IMPL_H
#define LEAN_NET_REACTOR_FILE_IMPL_H
#include "reactor_file_internal.h"
#include <errno.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdlib.h>
#ifdef _WIN32
#include "windows_error.h"
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

struct rn_file_source {
    atomic_uint references;
    uintptr_t handle;
    uint64_t size;
    uint8_t *mapping;
#ifdef _WIN32
    HANDLE section;
#endif
};
int rn_file_prepare_residency_budget(uint64_t budget) {
#ifdef _WIN32
    static SRWLOCK lock = SRWLOCK_INIT;
    static SIZE_T original_minimum;
    SIZE_T minimum = 0, maximum = 0;
    AcquireSRWLockExclusive(&lock);
    if (!GetProcessWorkingSetSize(GetCurrentProcess(), &minimum, &maximum)) {
        int error = -ln_windows_errno(GetLastError()); ReleaseSRWLockExclusive(&lock); return error;
    }
    if (!original_minimum) original_minimum = minimum;
    if (budget > SIZE_MAX - original_minimum) { ReleaseSRWLockExclusive(&lock); return -EOVERFLOW; }
    SIZE_T wanted = original_minimum + (SIZE_T)budget;
    int error = 0;
    if (wanted > minimum &&
        !SetProcessWorkingSetSize(GetCurrentProcess(), wanted, maximum < wanted ? wanted : maximum))
        error = -ln_windows_errno(GetLastError());
    ReleaseSRWLockExclusive(&lock); return error;
#else
    (void)budget; return 0;
#endif
}
static int rn_file_close_handle(uintptr_t value) {
#ifdef _WIN32
    return CloseHandle((HANDLE)value) ? 0 : -ln_windows_errno(GetLastError());
#else
    return close((int)value) == 0 ? 0 : -errno;
#endif
}
int rn_file_source_publish(uintptr_t handle, uint64_t size, uint64_t budget,
                           rn_file_source **out) {
#ifdef _WIN32
    if (!handle || (HANDLE)handle == INVALID_HANDLE_VALUE) return -EINVAL;
#else
    if (handle > INT_MAX) return -EINVAL;
#endif
    int error = 0;
    rn_file_source *source = NULL;
    if (!out || size > INT64_MAX || size > SIZE_MAX) { error = -EINVAL; goto failure; }
    *out = NULL;
    uint64_t page;
#ifdef _WIN32
    SYSTEM_INFO system; GetSystemInfo(&system); page = system.dwPageSize;
    BY_HANDLE_FILE_INFORMATION info;
    if (GetFileType((HANDLE)handle) != FILE_TYPE_DISK ||
        !GetFileInformationByHandle((HANDLE)handle, &info)) { error = -EIO; goto failure; }
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (((uint64_t)info.nFileSizeHigh << 32) | info.nFileSizeLow) != size) { error = -EINVAL; goto failure; }
#else
    long native_page = sysconf(_SC_PAGESIZE);
    if (native_page <= 0) { error = -EIO; goto failure; }
    page = (uint64_t)native_page;
    int flags = fcntl((int)handle, F_GETFL);
    struct stat info;
    if (flags < 0 || fstat((int)handle, &info) < 0) { error = -errno; goto failure; }
    if ((flags & O_ACCMODE) != O_RDONLY || !S_ISREG(info.st_mode) ||
        info.st_size < 0 || (uint64_t)info.st_size != size) { error = -EINVAL; goto failure; }
#endif
    uint64_t charged = size ? ((size - 1) / page + 1) * page : 0;
    if (charged > budget) { error = -ENOMEM; goto failure; }
    source = calloc(1, sizeof(*source));
    if (!source) { error = -ENOMEM; goto failure; }
    atomic_init(&source->references, 1); source->handle = handle; source->size = size;
    if (size) {
#ifdef _WIN32
        source->section = CreateFileMappingW((HANDLE)handle, NULL, PAGE_READONLY, 0, 0, NULL);
        if (!source->section) { error = -ln_windows_errno(GetLastError()); goto failure; }
        source->mapping = MapViewOfFile(source->section, FILE_MAP_READ, 0, 0, (SIZE_T)size);
        if (!source->mapping) { error = -ln_windows_errno(GetLastError()); goto failure; }
        if (!VirtualLock(source->mapping, (SIZE_T)size)) {
            DWORD native_error = GetLastError();
            error = native_error == ERROR_WORKING_SET_QUOTA ? -ENOMEM : -ln_windows_errno(native_error);
            goto failure;
        }
#else
        void *mapped = mmap(NULL, (size_t)size, PROT_READ, MAP_SHARED, (int)handle, 0);
        if (mapped == MAP_FAILED) { error = -errno; goto failure; }
        source->mapping = mapped;
        if (mlock(source->mapping, (size_t)size) < 0) { error = -errno; goto failure; }
#endif
    }
    *out = source; return 0;
failure:
    if (source) {
        if (source->mapping) {
#ifdef _WIN32
            if (!UnmapViewOfFile(source->mapping)) error = -ln_windows_errno(GetLastError());
#else
            if (munmap(source->mapping, (size_t)source->size) < 0) error = -errno;
#endif
        }
#ifdef _WIN32
        if (source->section && !CloseHandle(source->section)) error = -ln_windows_errno(GetLastError());
#endif
        free(source);
    }
    { int closed = rn_file_close_handle(handle); return closed ? closed : error; }
}
int rn_file_source_retain(rn_file_source *source) {
    if (!source) return -EINVAL;
    unsigned old = atomic_load_explicit(&source->references, memory_order_relaxed);
    do {
        if (!old || old == UINT_MAX) return -EOVERFLOW;
    } while (!atomic_compare_exchange_weak_explicit(&source->references, &old, old + 1,
                                                   memory_order_relaxed, memory_order_relaxed));
    return 0;
}
int rn_file_source_release(rn_file_source *source) {
    if (!source) return -EINVAL;
    if (atomic_fetch_sub_explicit(&source->references, 1, memory_order_acq_rel) != 1) return 0;
    int error = 0;
    if (source->mapping) {
#ifdef _WIN32
        if (!VirtualUnlock(source->mapping, (SIZE_T)source->size)) error = -ln_windows_errno(GetLastError());
        if (!UnmapViewOfFile(source->mapping) && !error) error = -ln_windows_errno(GetLastError());
#else
        if (munlock(source->mapping, (size_t)source->size) < 0) error = -errno;
        if (munmap(source->mapping, (size_t)source->size) < 0 && !error) error = -errno;
#endif
    }
#ifdef _WIN32
    if (source->section && !CloseHandle(source->section) && !error) error = -ln_windows_errno(GetLastError());
#endif
    int closed = rn_file_close_handle(source->handle); if (!error) error = closed;
    free(source); return error;
}
uint64_t rn_file_source_size(const rn_file_source *source) { return source ? source->size : 0; }
int rn_file_source_view(const rn_file_source *source, uint64_t offset, uint32_t length,
                        const uint8_t **out) {
    if (!source || !out || offset > source->size || length > source->size - offset) return -EINVAL;
    *out = source->mapping ? source->mapping + (size_t)offset : NULL; return 0;
}
uintptr_t rn_file_source_handle(const rn_file_source *source) { return source ? source->handle : UINTPTR_MAX; }
int rn_file_source_duplicate(const rn_file_source *source, uintptr_t *out) {
    if (!source || !out) return -EINVAL;
#ifdef _WIN32
    HANDLE copy = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), (HANDLE)source->handle, GetCurrentProcess(), &copy,
                         0, FALSE, DUPLICATE_SAME_ACCESS)) return -ln_windows_errno(GetLastError());
    *out = (uintptr_t)copy;
#else
    int copy = fcntl((int)source->handle, F_DUPFD_CLOEXEC, 0);
    if (copy < 0) return -errno;
    *out = (uintptr_t)copy;
#endif
    return 0;
}
static inline int rn_files_init(rn_file_table *table, uint32_t capacity) {
    if (!table || table->entries || !capacity || capacity > 1000000u) return -EINVAL;
    static atomic_uint_fast64_t owners = ATOMIC_VAR_INIT(0);
    uint_fast64_t previous = atomic_load_explicit(&owners, memory_order_relaxed);
    do {
        if (previous == INT64_MAX) return -EOVERFLOW;
    } while (!atomic_compare_exchange_weak_explicit(&owners, &previous, previous + 1,
                                                   memory_order_relaxed, memory_order_relaxed));
    table->entries = calloc(capacity, sizeof(*table->entries));
    if (!table->entries) return -ENOMEM;
    table->capacity = capacity; table->owner = (uint64_t)previous + 1; return 0;
}
static inline int rn_files_get(rn_file_table *table, uint64_t token, rn_file_entry **out) {
    uint32_t index = (uint32_t)token - 1, generation = (uint32_t)(token >> 32);
    if (!table || !out || index >= table->capacity || !generation) return -EINVAL;
    rn_file_entry *entry = &table->entries[index];
    if (!entry->used || entry->generation != generation) return -EINVAL;
    *out = entry; return 0;
}
static inline int rn_files_import(rn_file_table *table, rn_file_source *source, uint64_t *out) {
    if (!table || !source || !out) return -EINVAL;
    for (uint32_t i = 0; i < table->capacity; ++i) {
        rn_file_entry *entry = &table->entries[i];
        if (entry->used || entry->generation == INT32_MAX) continue;
        uintptr_t handle; int error = rn_file_source_duplicate(source, &handle); if (error) return error;
        error = rn_file_source_retain(source);
        if (error) { int closed = rn_file_close_handle(handle); return closed ? closed : error; }
        entry->source = source; entry->handle = handle; entry->writes = 0; entry->used = 1; ++entry->generation;
        *out = ((uint64_t)entry->generation << 32) | ((uint64_t)i + 1); return 0;
    }
    return -EAGAIN;
}
static inline int rn_files_release(rn_file_table *table, uint64_t token) {
    rn_file_entry *entry; int error = rn_files_get(table, token, &entry); if (error) return error;
    if (entry->writes) return -EBUSY;
    entry->used = 0;
    error = rn_file_close_handle(entry->handle);
    int released = rn_file_source_release(entry->source); entry->source = NULL;
    return error ? error : released;
}
static inline int rn_files_pin(rn_file_table *table, uint64_t token, uint64_t offset,
                        uint32_t length, rn_file_source **out) {
    rn_file_entry *entry; int error = rn_files_get(table, token, &entry); const uint8_t *bytes;
    if (error || !out) return error ? error : -EINVAL;
    error = rn_file_source_view(entry->source, offset, length, &bytes); if (error) return error;
    error = rn_file_source_retain(entry->source); if (error) return error;
    *out = entry->source; return 0;
}
static inline int rn_files_destroy(rn_file_table *table) {
    int error = 0;
    for (uint32_t i = 0; i < table->capacity; ++i) if (table->entries[i].used) {
        rn_file_entry *entry = &table->entries[i];
        if (entry->writes && !error) error = -EBUSY;
        entry->writes = 0;
        int released = rn_files_release(table, ((uint64_t)entry->generation << 32) | ((uint64_t)i + 1));
        if (released && !error) error = released;
    }
    free(table->entries); table->entries = NULL; table->capacity = 0; table->owner = 0; return error;
}
#endif
