#ifndef LEAN_NET_SOCKET_WINDOWS_BRIDGE_H
#define LEAN_NET_SOCKET_WINDOWS_BRIDGE_H
#include <stdint.h>
/* Native compatibility adapter only. Borrow until the owner closes its checked
 * legacy descriptor; callers must not close or transfer the underlying handle. */
int ln_windows_socket_borrow(int64_t token, uintptr_t *socket, int *nonblocking);
#endif
