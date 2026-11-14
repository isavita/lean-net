#ifndef LEAN_NET_STATIC_CATALOG_H
#define LEAN_NET_STATIC_CATALOG_H
#include "reactor_file.h"
#include <stddef.h>
#include <stdint.h>

typedef struct sc_builder sc_builder;
enum { SC_IDENTITY = 0, SC_GZIP = 1, SC_BROTLI = 2 };
enum { SC_GENERATE_GZIP = 1, SC_GENERATE_BROTLI = 2 };
enum {
  SC_FIELD_PRESENT = 0,
  SC_FIELD_MTIME_LOW = 1,
  SC_FIELD_MTIME_HIGH = 2,
  SC_FIELD_VARIANTS = 3,
  SC_VARIANT_FIELDS = 12,
  SC_METADATA_FIELDS = 39
};
enum {
  SC_VARIANT_OFFSET_LOW = 0,
  SC_VARIANT_OFFSET_HIGH = 1,
  SC_VARIANT_LENGTH_LOW = 2,
  SC_VARIANT_LENGTH_HIGH = 3,
  SC_VARIANT_SHA256_WORD0 = 4
};

/* Startup-only, single-owner builder. Paths are UTF-8 and relative to its
 * anchored root. A failed operation other than EINTR poisons the builder.
 * Free must still be called. No syscall is retried on EINTR inside C. */
int sc_builder_new(const uint8_t *root, size_t root_length, uint64_t max_file_bytes,
                   uint64_t max_pack_bytes, uint32_t max_entries, uint64_t min_compress_bytes,
                   uint32_t gzip_level, uint32_t brotli_quality, sc_builder **out);
/* Initialize/unlink the private pack before the caller snapshots/enumerates
 * its root. Idempotent, and resumable on EINTR. */
int sc_builder_prepare(sc_builder *builder);
int sc_builder_begin_path(sc_builder *builder, const uint8_t *path, size_t path_length,
                          uint32_t compression_mask);
int sc_builder_begin_bytes(sc_builder *builder, const uint8_t *bytes, size_t length,
                           uint32_t compression_mask);
/* Non-mutating anchored directory validation. Empty means the catalog root.
 * EINTR can restart the whole check; no file content or pack bytes are read. */
int sc_builder_check_directory(sc_builder *builder, const uint8_t *path, size_t path_length);
enum { SC_DIRECTORY = 1, SC_REGULAR = 2, SC_LINK = 3, SC_OTHER = 4 };
typedef struct {
  uint8_t *name;
  size_t length;
  uint32_t kind;
} sc_directory_entry;
typedef struct {
  sc_directory_entry *entries;
  uint32_t count;
} sc_directory_list;
/* Bounded, anchored, no-follow enumeration. Every non-dot entry counts toward
 * limit, including links and unsupported file types. Names are raw UTF-8 bytes;
 * the caller still applies its portable URL/name policy. On error out is empty.
 * This non-mutating operation can be retried wholesale after EINTR. */
int sc_builder_read_directory(sc_builder *builder, const uint8_t *path, size_t path_length,
                              uint32_t limit, sc_directory_list *out);
void sc_directory_list_free(sc_directory_list *list);
/* 0 = pending, positive = completed entry ID (one-based). EINTR preserves
 * progress and permits the owning Lean policy to call step again. */
int64_t sc_builder_step(sc_builder *builder, uint32_t byte_budget);
/* Each field is an unsigned 32-bit scalar, so negative Int64 remains an
 * unambiguous error. mtime preserves signed Int64 bits in two words. Variant
 * SHA-256 fields are eight big-endian words, followed in digest order. */
int64_t sc_builder_field(sc_builder *builder, uint32_t entry_id, uint32_t field);
/* Close every writable alias, then publish a duplicate of a retained read-only
 * handle. EINTR permits another finish call without losing the packed file.
 * Success transfers the returned FileSource ownership to the caller. */
int sc_builder_finish(sc_builder *builder, uint64_t resident_budget, rn_file_source **out);
/* EINTR retains the builder for another free call; cleared descriptor slots
 * ensure that close is never retried. All other results consume the builder. */
int sc_builder_free(sc_builder *builder);

#endif
