#ifndef LEAN_NET_ACCESS_LOG_H
#define LEAN_NET_ACCESS_LOG_H
#include <stddef.h>
#include <stdint.h>

#define OB_METRICS 42u
#define OB_SNAPSHOT_FIELDS 47u
#define OB_METHOD_BYTES 32u
#define OB_TARGET_BYTES 256u
#define OB_REMOTE_BYTES 64u
#define OB_TRACE_BYTES 16u
#define OB_ROUTE_BYTES 128u
#define OB_REASON_BYTES 32u
#define OB_MAX_MEMORY (64u * 1024u * 1024u)
typedef struct ob_hub ob_hub;
typedef struct {
  uint64_t timestamp_ms, duration_us, bytes_sent;
  uint32_t status, protocol, outcome;
  const uint8_t *method, *target;
  size_t method_length, target_length;
  /* Optional: textual peer address and a 16-byte W3C trace-id. */
  const uint8_t *remote, *trace;
  size_t remote_length, trace_length;
  /* Optional gate labels from configuration: route pattern, reject reason. */
  const uint8_t *route, *reason;
  size_t route_length, reason_length;
} ob_record;
/* All allocation/spawn work occurs before serving. Control operations are
 * serialized. Metrics-only hubs pass empty path/helper and capacity0. Exactly
 * one helper may run per process. After resource acquisition, startup failures
 * return an error-bearing Hub: ready reports it, and its bracket still frees. */
int ob_new(uint32_t workers, uint32_t capacity, const char *path, const char *helper,
           uint64_t file_bytes, uint32_t files, uint32_t poll_ms, ob_hub **out);
/* Single producer per worker; bounded copies and lock-free atomics only.
 * 0 queued,1 dropped,2 logging disabled; negative errno denotes bad API use. */
int ob_emit(ob_hub *, uint32_t worker, const ob_record *);
int ob_publish(ob_hub *, uint32_t worker, const uint64_t fields[OB_METRICS]);
int ob_snapshot(ob_hub *, uint64_t fields[OB_SNAPSHOT_FIELDS]);
/* ready is serialized startup control (0/1/-errno). check is worker-safe,
 * read-only process observation plus atomic error publication (0/-errno). */
int ob_ready(ob_hub *);
int ob_check(ob_hub *);
/* Persistent writer/startup error, distinct from transient waitpid EINTR. */
int ob_last_error(ob_hub *);
int ob_stop(ob_hub *, uint64_t timeout_ms);
/* Nonblocking join step:0 pending,1 joined,-EINTR retryable, other errors
 * terminal. At deadline a stalled helper is terminated. Its independent map
 * protects its access after parent cleanup. A kernel-stalled orphan reserves
 * the single process slot until a later startup can reap it. */
int ob_join_step(ob_hub *);
/* Cleanup covers failed stop/join too: a live helper is terminated/transferred
 * to the bounded orphan slot. EINTR retains Hub for explicit caller retry;
 * descriptor slots clear before close and are never closed twice. All other
 * results consume Hub. Producers must already have joined. */
int ob_free(ob_hub *);
int ob_helper_main(int argc, char **argv);
#endif
