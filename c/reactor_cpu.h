#ifndef LEAN_NET_REACTOR_CPU_H
#define LEAN_NET_REACTOR_CPU_H
/* Startup-only Linux worker-count hint. Cgroup quotas constrain shared CPU
 * time, not CPU identities. Only namespace-visible ancestors can be observed;
 * this does not promise dedicated cores or account for sibling contention. */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RN_CPU_PATH_CAP 4096u
#define RN_CPU_CGROUP_CAP (64u * 1024u)
#define RN_CPU_MOUNT_CAP (1024u * 1024u)
#define RN_CPU_MAX_ANCESTORS 256u

typedef int (*rn_cpu_reader)(void *, const char *, char *, size_t);
typedef struct { const char *data; size_t size; } rn_cpu_field;
typedef struct {
    char root[RN_CPU_PATH_CAP], point[RN_CPU_PATH_CAP];
    int found;
} rn_cpu_mount;

/* Includes a NUL terminator in capacity. Positive short reads are progress;
 * every syscall error, including EINTR, is returned without retry. */
static inline int rn_cpu_read_file(void *context, const char *path, char *text, size_t capacity) {
    (void)context;
    if (capacity < 2) return -EINVAL;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    size_t used = 0;
    int error = 0;
    while (used < capacity - 1) {
        ssize_t count = read(fd, text + used, capacity - 1 - used);
        if (count < 0) { error = -errno; break; }
        if (count == 0) break;
        used += (size_t)count;
    }
    if (!error && used == capacity - 1) {
        char extra;
        ssize_t count = read(fd, &extra, 1);
        if (count < 0) error = -errno;
        else if (count != 0) error = -EOVERFLOW;
    }
    if (close(fd) < 0 && !error) error = -errno;
    text[used] = 0;
    if (!error && memchr(text, 0, used) != NULL) error = -EINVAL;
    return error;
}
static inline int rn_cpu_equal(rn_cpu_field field, const char *text) {
    return strlen(text) == field.size && memcmp(field.data, text, field.size) == 0;
}
static inline int rn_cpu_list_has(rn_cpu_field field, const char *name) {
    const char *end = field.data + field.size;
    for (const char *p = field.data; p < end;) {
        const char *comma = memchr(p, ',', (size_t)(end - p));
        const char *next = comma ? comma : end;
        if (rn_cpu_equal((rn_cpu_field){p, (size_t)(next - p)}, name)) return 1;
        p = comma ? comma + 1 : end;
    }
    return 0;
}
static inline int rn_cpu_path_valid(const char *path) {
    if (path[0] != '/') return 0;
    const char *p = path + 1;
    while (*p) {
        const char *slash = strchr(p, '/');
        size_t size = slash ? (size_t)(slash - p) : strlen(p);
        if (!size || (size == 1 && p[0] == '.') ||
            (size == 2 && p[0] == '.' && p[1] == '.')) return 0;
        p += size;
        if (*p) ++p;
        if (slash && !*p) return 0;
    }
    return 1;
}
static inline int rn_cpu_copy_path(rn_cpu_field field, char *out, int unescape) {
    size_t used = 0;
    for (size_t i = 0; i < field.size; ++i) {
        unsigned char byte = (unsigned char)field.data[i];
        if ((unescape & 1) && byte == '\\') {
            if (field.size - i < 4) return -EINVAL;
            byte = 0;
            for (unsigned n = 1; n <= 3; ++n) {
                char digit = field.data[i + n];
                if (digit < '0' || digit > '7') return -EINVAL;
                unsigned value = (unsigned)byte * 8 + (unsigned)(digit - '0');
                if (value > 255) return -EINVAL;
                byte = (unsigned char)value;
            }
            if (byte == 0 || byte == '/') return -EINVAL;
            i += 3;
        }
        if (byte == 0 || used + 1 >= RN_CPU_PATH_CAP) return -ENAMETOOLONG;
        out[used++] = (char)byte;
    }
    out[used] = 0;
    /* A namespace can render an inaccessible mount root as /../... . It
     * cannot match our normalized membership and must not be traversed. */
    return (unescape & 2) ? (out[0] == '/' ? 0 : -EINVAL) :
        rn_cpu_path_valid(out) ? 0 : -EINVAL;
}
static inline int rn_cpu_memberships(const char *text, char *v2, char *v1) {
    v2[0] = v1[0] = 0;
    for (const char *p = text; *p;) {
        const char *end = strchr(p, '\n');
        if (!end) end = p + strlen(p);
        const char *first = memchr(p, ':', (size_t)(end - p));
        const char *second = first ? memchr(first + 1, ':', (size_t)(end - first - 1)) : NULL;
        if (!first || !second || first == p) return -EINVAL;
        for (const char *id = p; id < first; ++id) if (*id < '0' || *id > '9') return -EINVAL;
        rn_cpu_field controllers = {first + 1, (size_t)(second - first - 1)};
        int unified = first == p + 1 && p[0] == '0' && controllers.size == 0;
        int cpu = rn_cpu_list_has(controllers, "cpu");
        if (unified || cpu) {
            char *destination = unified ? v2 : v1;
            if (*destination) return -EINVAL;
            int error = rn_cpu_copy_path((rn_cpu_field){second + 1, (size_t)(end - second - 1)}, destination, 0);
            if (error) return error;
        }
        p = *end ? end + 1 : end;
    }
    return 0;
}
static inline int rn_cpu_next_field(const char **cursor, const char *end, rn_cpu_field *field) {
    const char *p = *cursor;
    while (p < end && *p == ' ') ++p;
    const char *start = p;
    while (p < end && *p != ' ') ++p;
    *cursor = p;
    *field = (rn_cpu_field){start, (size_t)(p - start)};
    return p > start;
}
static inline int rn_cpu_within(const char *path, const char *root) {
    size_t size = strlen(root);
    return root[0] == '/' && root[1] == 0 ? 1 :
        strncmp(path, root, size) == 0 && (path[size] == '/' || path[size] == 0);
}
static inline int rn_cpu_find_mount(const char *text, const char *membership, int v2, rn_cpu_mount *out) {
    memset(out, 0, sizeof(*out));
    for (const char *p = text; *p;) {
        const char *end = strchr(p, '\n');
        if (!end) end = p + strlen(p);
        const char *cursor = p;
        rn_cpu_field fields[6], field = {0}, type, source, options;
        for (unsigned i = 0; i < 6; ++i)
            if (!rn_cpu_next_field(&cursor, end, &fields[i])) return -EINVAL;
        while (rn_cpu_next_field(&cursor, end, &field) && !rn_cpu_equal(field, "-")) {}
        if (!rn_cpu_equal(field, "-") ||
            !rn_cpu_next_field(&cursor, end, &type) ||
            !rn_cpu_next_field(&cursor, end, &source) ||
            !rn_cpu_next_field(&cursor, end, &options)) return -EINVAL;
        int matches = v2 ? rn_cpu_equal(type, "cgroup2") :
            rn_cpu_equal(type, "cgroup") && rn_cpu_list_has(options, "cpu");
        if (matches) {
            char root[RN_CPU_PATH_CAP], point[RN_CPU_PATH_CAP];
            int error = rn_cpu_copy_path(fields[3], root, 3);
            if (!error) error = rn_cpu_copy_path(fields[4], point, 1);
            if (error) return error;
            /* Prefer the broadest visible mount to include ancestor limits. */
            if (rn_cpu_within(membership, root) && (!out->found || strlen(root) < strlen(out->root))) {
                strcpy(out->root, root); strcpy(out->point, point); out->found = 1;
            }
        }
        p = *end ? end + 1 : end;
    }
    return 0;
}
static inline int rn_cpu_space(char byte) {
    return byte == ' ' || byte == '\t' || byte == '\n' || byte == '\r';
}
static inline int rn_cpu_number(const char **cursor, uint64_t *out) {
    const char *p = *cursor;
    if (*p < '0' || *p > '9') return -EINVAL;
    uint64_t value = 0;
    do {
        unsigned digit = (unsigned)(*p++ - '0');
        if (value > (UINT64_MAX - digit) / 10) return -EOVERFLOW;
        value = value * 10 + digit;
    } while (*p >= '0' && *p <= '9');
    *cursor = p; *out = value;
    return 0;
}
static inline int rn_cpu_quota(const char *text, int v2, uint64_t *quota, uint64_t *period) {
    const char *p = text;
    while (rn_cpu_space(*p)) ++p;
    int unlimited = v2 ? strncmp(p, "max", 3) == 0 : strncmp(p, "-1", 2) == 0;
    int error = 0;
    if (unlimited) { p += v2 ? 3 : 2; *quota = 0; }
    else if ((error = rn_cpu_number(&p, quota)) != 0 || *quota == 0) return error ? error : -EINVAL;
    if (v2) {
        if (!rn_cpu_space(*p)) return -EINVAL;
        while (rn_cpu_space(*p)) ++p;
        if ((error = rn_cpu_number(&p, period)) != 0 || *period == 0) return error ? error : -EINVAL;
    }
    while (rn_cpu_space(*p)) ++p;
    return *p ? -EINVAL : 0;
}
static inline int rn_cpu_limit_mount(const char *membership, const rn_cpu_mount *mount,
    int v2, rn_cpu_reader reader, void *context, uint32_t *hint) {
    if (!mount->found) return 0; /* Not visible in this mount/cgroup namespace. */
    const char *suffix = strcmp(membership, mount->root) == 0 ? "" :
        strcmp(mount->root, "/") == 0 ? membership : membership + strlen(mount->root);
    if (strcmp(mount->point, "/") == 0 && *suffix == '/') ++suffix;
    char directory[RN_CPU_PATH_CAP], path[RN_CPU_PATH_CAP], text[128];
    size_t base = strlen(mount->point), size = base + strlen(suffix);
    if (size >= sizeof(directory)) return -ENAMETOOLONG;
    strcpy(directory, mount->point); strcat(directory, suffix);
    for (unsigned depth = 0; depth < RN_CPU_MAX_ANCESTORS; ++depth) {
        const char *name = v2 ? "cpu.max" : "cpu.cfs_quota_us";
        size_t dir_size = strlen(directory), name_size = strlen(name);
        int separator = dir_size != 1;
        if (dir_size + (size_t)separator + name_size >= sizeof(path)) return -ENAMETOOLONG;
        strcpy(path, directory); if (separator) strcat(path, "/"); strcat(path, name);
        int error = reader(context, path, text, sizeof(text));
        if (error != -ENOENT) {
            if (error) return error;
            uint64_t quota = 0, period = 0;
            if ((error = rn_cpu_quota(text, v2, &quota, &period)) != 0) return error;
            if (!v2) {
                name = "cpu.cfs_period_us"; name_size = strlen(name);
                if (dir_size + (size_t)separator + name_size >= sizeof(path)) return -ENAMETOOLONG;
                strcpy(path, directory); if (separator) strcat(path, "/"); strcat(path, name);
                if ((error = reader(context, path, text, sizeof(text))) != 0) return error;
                const char *p = text;
                while (rn_cpu_space(*p)) ++p;
                if ((error = rn_cpu_number(&p, &period)) != 0 || period == 0) return error ? error : -EINVAL;
                while (rn_cpu_space(*p)) ++p;
                if (*p) return -EINVAL;
            }
            if (quota) {
                uint64_t ceiling = quota / period + (quota % period != 0);
                if (ceiling < *hint) *hint = (uint32_t)ceiling;
            }
        }
        if (strlen(directory) == base) return 0;
        char *slash = strrchr(directory, '/');
        size_t parent = slash == directory ? 1 : (size_t)(slash - directory);
        if (parent < base) return -EINVAL;
        directory[parent] = 0;
    }
    return -EOVERFLOW;
}
static inline int rn_cpu_hint_from_text(const char *groups, const char *mounts,
    rn_cpu_reader reader, void *context, uint32_t affinity, uint32_t *out) {
    if (!groups || !mounts || !reader || !affinity || !out) return -EINVAL;
    char v2[RN_CPU_PATH_CAP], v1[RN_CPU_PATH_CAP];
    int error = rn_cpu_memberships(groups, v2, v1);
    uint32_t hint = affinity;
    if (error) return error;
    for (unsigned version = 0; version < 2; ++version) {
        const char *membership = version == 0 ? v2 : v1;
        if (!*membership) continue;
        rn_cpu_mount mount;
        error = rn_cpu_find_mount(mounts, membership, version == 0, &mount);
        if (!error) error = rn_cpu_limit_mount(membership, &mount, version == 0, reader, context, &hint);
        if (error) return error;
    }
    *out = hint;
    return 0;
}
static inline int rn_cpu_quota_hint(uint32_t affinity, uint32_t *out) {
    if (!affinity || !out) return -EINVAL;
    char *groups = malloc(RN_CPU_CGROUP_CAP), *mounts = malloc(RN_CPU_MOUNT_CAP);
    if (!groups || !mounts) { free(groups); free(mounts); return -ENOMEM; }
    int error = rn_cpu_read_file(NULL, "/proc/self/cgroup", groups, RN_CPU_CGROUP_CAP);
    if (error == -ENOENT) { *out = affinity; error = 0; }
    else if (!error) {
        error = rn_cpu_read_file(NULL, "/proc/self/mountinfo", mounts, RN_CPU_MOUNT_CAP);
        if (!error) error = rn_cpu_hint_from_text(groups, mounts, rn_cpu_read_file, NULL, affinity, out);
    }
    free(groups); free(mounts);
    return error;
}
#endif
