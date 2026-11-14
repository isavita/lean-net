#ifndef LEAN_NET_REACTOR_FILE_INTERNAL_H
#define LEAN_NET_REACTOR_FILE_INTERNAL_H
#include "reactor_file.h"
typedef struct rn_file_entry {
    rn_file_source *source;
    uintptr_t handle;
    uint32_t generation, writes;
    uint8_t used;
} rn_file_entry;
typedef struct rn_file_table {
    rn_file_entry *entries;
    uint32_t capacity;
    uint64_t owner;
} rn_file_table;
#endif
