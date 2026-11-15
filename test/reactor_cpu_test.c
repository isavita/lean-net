/* Cgroup fixtures exercise startup policy without changing host cgroups. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int read_fault, read_calls;
static ssize_t test_read(int fd, void *bytes, size_t size) {
    ++read_calls;
    if (read_fault) { errno = read_fault; return -1; }
    return read(fd, bytes, size);
}
#define read(...) test_read(__VA_ARGS__)
#include "../c/reactor_cpu.h"
#undef read

typedef struct { const char *path, *text; int error; } fixture_file;
typedef struct { const fixture_file *files; size_t count; unsigned reads; } fixture;
static void check(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "CPU quota test: %s\n", message); exit(1); }
}
static int read_fixture(void *context, const char *path, char *text, size_t capacity) {
    fixture *f = context;
    ++f->reads;
    for (size_t i = 0; i < f->count; ++i) {
        const fixture_file *file = &f->files[i];
        if (strcmp(file->path, path)) continue;
        if (file->error) return file->error;
        if (strlen(file->text) >= capacity) return -EOVERFLOW;
        strcpy(text, file->text); return 0;
    }
    return -ENOENT;
}
static const char *v2_mount = "36 25 0:32 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n";
static void hint(const char *group, const char *mounts, const fixture_file *files,
                 size_t count, uint32_t affinity, int error, uint32_t expected) {
    fixture f = {files, count, 0}; uint32_t result = 0xdeadbeef;
    check(rn_cpu_hint_from_text(group, mounts, read_fixture, &f, affinity, &result) == error,
          "hint errno");
    check(result == (error ? 0xdeadbeef : expected), "hint result/output unchanged on failure");
    check(f.reads <= RN_CPU_MAX_ANCESTORS * 4, "bounded ancestor reads");
}
static void test_v2(void) {
    const fixture_file files[] = {
        {"/sys/fs/cgroup/team/service/cpu.max", "150000 100000\n", 0},
        {"/sys/fs/cgroup/team/cpu.max", "max 100000\n", 0},
        {"/sys/fs/cgroup/cpu.max", "max 100000\n", 0}
    };
    hint("0::/team/service\n", v2_mount, files, 3, 8, 0, 2);
    hint("0::/team/service\n", v2_mount, files, 3, 1, 0, 1);
    const fixture_file parent[] = {
        {"/sys/fs/cgroup/team/service/cpu.max", "800000 100000", 0},
        {"/sys/fs/cgroup/team/cpu.max", "25000 100000", 0}
    };
    hint("0::/team/service\n", v2_mount, parent, 2, 8, 0, 1);
    hint("0::/\n", v2_mount, NULL, 0, 7, 0, 7); /* Root has no cpu.max. */
    hint("0::/team/service\n", "36 25 0:32 /team /bound rw shared:3 - cgroup2 cgroup rw\n",
         (const fixture_file[]){{"/bound/service/cpu.max", "300000 200000", 0},
                                {"/bound/cpu.max", "100000 100000", 0}}, 2, 8, 0, 1);
    hint("0::/team/service\n",
         "36 25 0:32 /team /bound rw - cgroup2 cgroup rw\n"
         "37 25 0:32 / /wide rw - cgroup2 cgroup rw\n",
         (const fixture_file[]){{"/bound/service/cpu.max", "100000 100000", 0},
                                {"/wide/team/cpu.max", "400000 100000", 0}}, 2, 8, 0, 4);
    hint("0::/team space/service\n", "36 25 0:32 /team\\040space /sys/cg\\040space rw - cgroup2 cgroup rw\n",
         (const fixture_file[]){{"/sys/cg space/service/cpu.max", "100001 100000", 0}}, 1, 8, 0, 2);
    hint("0::/\n", "36 25 0:32 /../hidden /cg rw - cgroup2 cgroup rw\n", NULL, 0, 8, 0, 8);
    hint("0::/other\n", "36 25 0:32 /team /cg rw - cgroup2 cgroup rw\n", NULL, 0, 8, 0, 8);
    hint("0::/\n", v2_mount,
         (const fixture_file[]){{"/sys/fs/cgroup/cpu.max", "18446744073709551615 1", 0}}, 1, 8, 0, 8);
}
static void test_v1_hybrid(void) {
    const char *mounts = "36 25 0:32 /team /cpu rw - cgroup cgroup rw,cpu,cpuacct\n"
                         "37 25 0:33 / /v2 rw - cgroup2 cgroup rw\n";
    const fixture_file files[] = {
        {"/cpu/service/cpu.cfs_quota_us", "-1\n", 0},
        {"/cpu/service/cpu.cfs_period_us", "100000\n", 0},
        {"/cpu/cpu.cfs_quota_us", "125000\n", 0},
        {"/cpu/cpu.cfs_period_us", "100000\n", 0},
        {"/v2/team/service/cpu.max", "50000 100000", 0}
    };
    hint("2:cpu,cpuacct:/team/service\n", mounts, files, 5, 8, 0, 2);
    hint("2:cpu,cpuacct:/team/service\n0::/team/service\n", mounts, files, 5, 8, 0, 1);
    hint("2:cpuacct:/team/service\n", mounts, files, 5, 8, 0, 8);
    hint("2:cpu:/team/service\n", mounts,
         (const fixture_file[]){{"/cpu/service/cpu.cfs_quota_us", "30000", 0},
                                {"/cpu/service/cpu.cfs_period_us", "100000", 0}}, 2, 8, 0, 1);
}
static void test_invalid(void) {
    static const char *bad[] = {"", "0 100000", "-2 100000", "max", "max 0", "100000 0",
        "100000 100000 extra", "18446744073709551616 100000", "1.5 100000", "maxx 100000"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        fixture_file file = {"/sys/fs/cgroup/cpu.max", bad[i], 0};
        hint("0::/\n", v2_mount, &file, 1, 8, i == 7 ? -EOVERFLOW : -EINVAL, 0);
    }
    hint("0::/../escape\n", v2_mount, NULL, 0, 8, -EINVAL, 0);
    hint("0::/x\n0::/y\n", v2_mount, NULL, 0, 8, -EINVAL, 0);
    hint("0::/x\n", "bad mountinfo\n", NULL, 0, 8, -EINVAL, 0);
    hint("0::/x\n", "36 25 0:32 / /bad\\0400\\invalid rw - cgroup2 cgroup rw\n", NULL, 0, 8, -EINVAL, 0);
    const int errors[] = {-EINTR, -EACCES, -EIO, -EOVERFLOW};
    for (unsigned i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        fixture_file file = {"/sys/fs/cgroup/x/cpu.max", NULL, errors[i]};
        fixture f = {&file, 1, 0}; uint32_t out = 8;
        check(rn_cpu_hint_from_text("0::/x\n", v2_mount, read_fixture, &f, 8, &out) == errors[i] &&
              f.reads == 1 && out == 8, "quota read errors surface once without retry");
    }
    char deep[RN_CPU_PATH_CAP] = "0::/";
    for (unsigned n = 0; n < RN_CPU_MAX_ANCESTORS; ++n) strcat(deep, "a/");
    strcat(deep, "leaf\n");
    hint(deep, v2_mount, NULL, 0, 8, -EOVERFLOW, 0);
}
static void test_reader(void) {
    char name[] = "/tmp/lean-net-cpu-reader-XXXXXX";
    int fd = mkstemp(name);
    check(fd >= 0 && write(fd, "1234", 4) == 4 && close(fd) == 0, "owned read fixture");
    char text[8];
    check(rn_cpu_read_file(NULL, name, text, sizeof(text)) == 0 && strcmp(text, "1234") == 0,
          "bounded file reader");
    check(rn_cpu_read_file(NULL, name, text, 4) == -EOVERFLOW, "oversized file is rejected");
    read_fault = EINTR; read_calls = 0;
    check(rn_cpu_read_file(NULL, name, text, sizeof(text)) == -EINTR && read_calls == 1,
          "read EINTR is not retried");
    read_fault = EIO; read_calls = 0;
    check(rn_cpu_read_file(NULL, name, text, sizeof(text)) == -EIO && read_calls == 1,
          "read failure is not retried");
    read_fault = 0;
    check(unlink(name) == 0, "owned read fixture removed");
    check(rn_cpu_quota_hint(0, NULL) == -EINVAL, "startup argument validation");
}
int main(void) {
    test_v2(); test_v1_hybrid(); test_invalid(); test_reader();
    puts("reactor CPU quota fixtures passed");
    return 0;
}
