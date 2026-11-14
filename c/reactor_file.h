#ifndef LEAN_NET_REACTOR_FILE_H
#define LEAN_NET_REACTOR_FILE_H
#include <stddef.h>
#include <stdint.h>

typedef struct rn_file_source rn_file_source;
/* Explicit startup opt-in; Windows raises the process working-set floor by at
 * most the largest requested catalog budget above its original floor. */
int rn_file_prepare_residency_budget(uint64_t resident_budget);
/* Startup-only publication. A valid read-only fd/HANDLE is consumed on both
 * success and failure. Every writable alias must already have been closed.
 * The immutable source owns its eager, page-rounded resident mapping. */
int rn_file_source_publish(uintptr_t owned_readonly_handle, uint64_t size,
                           uint64_t resident_budget, rn_file_source **out);
int rn_file_source_retain(rn_file_source *source);
int rn_file_source_release(rn_file_source *source);
uint64_t rn_file_source_size(const rn_file_source *source);
int rn_file_source_view(const rn_file_source *source, uint64_t offset,
                        uint32_t length, const uint8_t **out);
/* Internal native helpers; OS handles never cross a public Lean boundary. */
int rn_file_source_duplicate(const rn_file_source *source, uintptr_t *out);
uintptr_t rn_file_source_handle(const rn_file_source *source);

#endif
