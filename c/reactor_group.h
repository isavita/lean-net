#ifndef LEAN_NET_REACTOR_GROUP_H
#define LEAN_NET_REACTOR_GROUP_H
#include "reactor.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rn_group rn_group;
typedef struct rn_endpoint_claim rn_endpoint_claim;

/* A group borrows an immutable set of reactors. Creation/free/installation are
 * serialized on the owning control thread. Reactors must outlive the group;
 * workers must be joined before uninstall/free. Stop and wake do not access
 * Lean objects or per-connection state. No hot-path mutex is introduced. */
int rn_group_new(rn_reactor *const *reactors, size_t count, rn_group **out);
int rn_group_install(rn_group *group);
/* Sets the stop flag and attempts one wake per reactor, never retrying EINTR.
 * Returns the first wake failure after attempting every reactor. */
int rn_group_request_stop(rn_group *group);
/* Returns 0 or 1, or negative errno for an invalid argument. */
int rn_group_stopping(const rn_group *group);
/* Atomically fetch-and-clear the first signal-handler wake failure, 0 if none.
 * The Lean control thread owns any retry decision. */
int rn_group_take_wake_error(rn_group *group);
/* Process-wide count of SIGHUP deliveries while a group was installed (always
 * zero on Windows). Callers act when the value differs from the last seen. */
uint64_t rn_group_reload_requests(void);
/* 1 while the installed group (if any) is stopping, else 0. Thread-safe. */
int rn_group_process_stopping(void);
/* Restores the prior SIGINT/SIGTERM/SIGHUP handlers / removes the Windows console handler,
 * unpublishes the group, then waits for all in-flight readers before return.
 * The registry is deactivated even if OS restoration fails; the error is
 * returned and future registrations are rejected for this process. */
int rn_group_uninstall(rn_group *group);
/* Uninstalls if necessary, then consumes the group even on restoration error.
 * After return no handler can access this group or its borrowed reactors. */
int rn_group_free(rn_group *group);
int rn_group_cpu_count(uint32_t *out);
int rn_pin_current_thread(uint32_t index);
int64_t rn_process_resident_bytes(void);
int64_t rn_process_open_fds(void);

/* One process-level claim encloses all SO_REUSEPORT workers. Claims are scoped
 * to the TCP port (all addresses), per effective user on POSIX. POSIX lockfiles
 * are stable, private, close-on-exec, and intentionally never unlinked: unlink
 * would let another process lock a different inode while the old one is live.
 * release consumes its handle even when an OS cleanup failure is reported. */
int rn_endpoint_acquire(uint16_t port, rn_endpoint_claim **out);
int rn_endpoint_release(rn_endpoint_claim *claim);

#ifdef __cplusplus
}
#endif
#endif
