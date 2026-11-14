/* Legacy socket API on Windows. The production reactor uses IOCP separately.
 * SOCKET is pointer-sized, whereas the old poll wire format has uint32 IDs.
 * A checked generation table preserves that format without truncating handles.
 * As on POSIX, a descriptor must not be closed concurrently with another use.
 */
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#include "socket_shim.h"
#include "windows_error.h"
#include "socket_windows_bridge.h"
#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define LN_LEGACY_SLOTS 65536u
typedef struct ln_legacy_socket {
  SOCKET socket;
  uint16_t generation;
  uint8_t used, nonblocking;
} ln_legacy_socket;
static ln_legacy_socket ln_sockets[LN_LEGACY_SLOTS];
static SRWLOCK ln_sockets_lock = SRWLOCK_INIT;
static INIT_ONCE ln_wsa_once = INIT_ONCE_STATIC_INIT;
static int ln_wsa_error;

static void ln_wsa_cleanup(void) { (void)WSACleanup(); }
static BOOL CALLBACK ln_start_wsa(PINIT_ONCE once, PVOID parameter,
                                  PVOID *context) {
  (void)once;
  (void)parameter;
  (void)context;
  WSADATA data;
  ln_wsa_error = ln_windows_errno((DWORD)WSAStartup(MAKEWORD(2, 2), &data));
  if (!ln_wsa_error && atexit(ln_wsa_cleanup) != 0) {
    (void)WSACleanup();
    ln_wsa_error = ENOMEM;
  }
  return TRUE;
}
static int ln_wsa_initialize(void) {
  if (!InitOnceExecuteOnce(&ln_wsa_once, ln_start_wsa, NULL, NULL))
    return ln_windows_errno(GetLastError());
  return ln_wsa_error;
}
static lean_object *mk_i64_ok(int64_t value) {
  return lean_io_result_mk_ok(lean_box_uint64((uint64_t)value));
}
static lean_object *empty_ba(void) { return lean_alloc_sarray(1, 0, 0); }
static lean_object *mk_count_ba_ok(int64_t count, lean_object *bytes) {
  lean_object *pair = lean_alloc_ctor(0, 2, 0);
  lean_ctor_set(pair, 0, lean_box_uint64((uint64_t)count));
  lean_ctor_set(pair, 1, bytes);
  return lean_io_result_mk_ok(pair);
}
static lean_object *mk_result_stage_ok(int64_t result, uint8_t stage) {
  lean_object *pair = lean_alloc_ctor(0, 2, 0);
  lean_ctor_set(pair, 0, lean_box_uint64((uint64_t)result));
  lean_ctor_set(pair, 1, lean_box(stage));
  return lean_io_result_mk_ok(pair);
}
static int ln_socket_lookup(int64_t token, SOCKET *socket, int *nonblocking) {
  if (token <= 0 || token > INT_MAX)
    return EBADF;
  uint32_t index = (uint32_t)token & 0xffffu;
  if (!index)
    return EBADF;
  AcquireSRWLockShared(&ln_sockets_lock);
  ln_legacy_socket *slot = &ln_sockets[index];
  int valid = slot->used && slot->generation == (uint32_t)token >> 16;
  if (valid) {
    *socket = slot->socket;
    if (nonblocking)
      *nonblocking = slot->nonblocking;
  }
  ReleaseSRWLockShared(&ln_sockets_lock);
  return valid ? 0 : EBADF;
}
int ln_windows_socket_borrow(int64_t token, uintptr_t *out, int *nonblocking) {
  if (!out) return -EINVAL;
  SOCKET socket = INVALID_SOCKET;
  int error = ln_socket_lookup(token, &socket, nonblocking);
  if (error) return -error;
  *out = (uintptr_t)socket;
  return 0;
}
static int64_t ln_socket_register(SOCKET socket, int nonblocking) {
  int64_t result = -EMFILE;
  AcquireSRWLockExclusive(&ln_sockets_lock);
  for (uint32_t i = 1; i < LN_LEGACY_SLOTS; ++i) {
    ln_legacy_socket *slot = &ln_sockets[i];
    /* Retire exhausted slots so no stale token can become valid again. */
    if (slot->used || slot->generation == 0x7fff)
      continue;
    ++slot->generation;
    slot->socket = socket;
    slot->used = 1;
    slot->nonblocking = (uint8_t)nonblocking;
    result = ((int64_t)slot->generation << 16) | i;
    break;
  }
  ReleaseSRWLockExclusive(&ln_sockets_lock);
  return result;
}
static int ln_socket_nonblocking(int64_t token, int enabled) {
  SOCKET socket;
  int error = ln_socket_lookup(token, &socket, NULL);
  if (error)
    return error;
  u_long mode = (u_long)enabled;
  if (ioctlsocket(socket, FIONBIO, &mode) == SOCKET_ERROR)
    return ln_windows_errno(WSAGetLastError());
  AcquireSRWLockExclusive(&ln_sockets_lock);
  ln_sockets[(uint32_t)token & 0xffffu].nonblocking = (uint8_t)enabled;
  ReleaseSRWLockExclusive(&ln_sockets_lock);
  return 0;
}
static int ln_close_failure(SOCKET socket, int error) {
  return closesocket(socket) == SOCKET_ERROR
             ? ln_windows_errno(WSAGetLastError())
             : error;
}
lean_object *shim_tcp_listen(b_lean_obj_arg host, uint16_t port) {
  int error = ln_wsa_initialize();
  if (error)
    return mk_i64_ok(-error);
  ADDRINFOA hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  char service[6];
  snprintf(service, sizeof(service), "%u", (unsigned)port);
  ADDRINFOA *addresses = NULL;
  const char *name = lean_string_cstr(host);
  error = getaddrinfo(name[0] ? name : NULL, service, &hints, &addresses);
  if (error)
    return mk_i64_ok(-(100000 + (int64_t)error));
  int64_t result = -EADDRNOTAVAIL;
  for (ADDRINFOA *address = addresses; address; address = address->ai_next) {
    SOCKET socket =
        WSASocketW(address->ai_family, address->ai_socktype,
                   address->ai_protocol, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (socket == INVALID_SOCKET) {
      result = -ln_windows_errno(WSAGetLastError());
      continue;
    }
    int one = 1;
    /* Windows SO_REUSEADDR allows unsafe listener takeover. Exclusive bind
     * gives the same port-collision guarantee as the POSIX library contract. */
    if (setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&one,
                   sizeof(one)) == SOCKET_ERROR ||
        bind(socket, address->ai_addr, (int)address->ai_addrlen) ==
            SOCKET_ERROR ||
        listen(socket, 4096) == SOCKET_ERROR) {
      error = ln_windows_errno(WSAGetLastError());
      result = -ln_close_failure(socket, error);
      if (result != -error)
        break;
      continue;
    }
    result = ln_socket_register(socket, 0);
    if (result < 0)
      result = -ln_close_failure(socket, (int)-result);
    break;
  }
  freeaddrinfo(addresses);
  return mk_i64_ok(result);
}
static int64_t ln_accept(int64_t listener, int force_blocking, uint8_t *stage) {
  SOCKET socket;
  int nonblocking = 0;
  int error = ln_socket_lookup(listener, &socket, &nonblocking);
  *stage = 1;
  if (error)
    return -error;
  SOCKET accepted = accept(socket, NULL, NULL);
  if (accepted == INVALID_SOCKET)
    return -ln_windows_errno(WSAGetLastError());
  int one = 1;
  if (setsockopt(accepted, IPPROTO_TCP, TCP_NODELAY, (const char *)&one,
                 sizeof(one)) == SOCKET_ERROR) {
    error = ln_windows_errno(WSAGetLastError());
    *stage = 2;
    int pending = 0, size = sizeof(pending);
    if (getsockopt(accepted, SOL_SOCKET, SO_ERROR, (char *)&pending, &size) ==
            0 &&
        (pending == WSAECONNRESET || pending == WSAECONNABORTED ||
         pending == WSAENOTCONN || pending == WSAETIMEDOUT)) {
      error = ln_windows_errno((DWORD)pending);
      *stage = 4;
    }
    if (closesocket(accepted) == SOCKET_ERROR) {
      error = ln_windows_errno(WSAGetLastError());
      *stage = 3;
    }
    return -error;
  }
  if (force_blocking) {
    u_long mode = 0;
    if (ioctlsocket(accepted, FIONBIO, &mode) == SOCKET_ERROR) {
      error = ln_windows_errno(WSAGetLastError());
      *stage = 2;
      return -ln_close_failure(accepted, error);
    }
    nonblocking = 0;
  }
  int64_t token = ln_socket_register(accepted, nonblocking);
  if (token < 0) {
    *stage = 2;
    return -ln_close_failure(accepted, (int)-token);
  }
  *stage = 0;
  return token;
}
lean_object *shim_tcp_accept(int64_t listener) {
  uint8_t stage;
  return mk_i64_ok(ln_accept(listener, 0, &stage));
}
lean_object *shim_tcp_accept_staged(int64_t listener) {
  uint8_t stage;
  int64_t result = ln_accept(listener, 0, &stage);
  return mk_result_stage_ok(result, stage);
}
lean_object *shim_tcp_recv(int64_t token, size_t maximum) {
  if (!maximum)
    return mk_count_ba_ok(-EINVAL, empty_ba());
  SOCKET socket;
  int error = ln_socket_lookup(token, &socket, NULL);
  if (error)
    return mk_count_ba_ok(-error, empty_ba());
  int capacity = maximum > INT_MAX ? INT_MAX : (int)maximum;
  lean_object *bytes = lean_alloc_sarray(1, 0, (size_t)capacity);
  int count = recv(socket, (char *)lean_sarray_cptr(bytes), capacity, 0);
  if (count == SOCKET_ERROR) {
    error = ln_windows_errno(WSAGetLastError());
    lean_dec(bytes);
    return mk_count_ba_ok(-error, empty_ba());
  }
  lean_sarray_set_size(bytes, (size_t)count);
  return mk_count_ba_ok(count, bytes);
}
lean_object *shim_tcp_send_offset(int64_t token, b_lean_obj_arg bytes,
                                  size_t offset, size_t length) {
  size_t size = lean_sarray_size(bytes);
  if (offset > size || length > size - offset)
    return mk_i64_ok(-EINVAL);
  SOCKET socket;
  int error = ln_socket_lookup(token, &socket, NULL);
  if (error)
    return mk_i64_ok(-error);
  if (!length)
    return mk_i64_ok(0);
  int count = length > INT_MAX ? INT_MAX : (int)length;
  int result =
      send(socket, (const char *)lean_sarray_cptr(bytes) + offset, count, 0);
  return mk_i64_ok(result == SOCKET_ERROR ? -ln_windows_errno(WSAGetLastError())
                                          : result);
}
lean_object *shim_tcp_send(int64_t token, b_lean_obj_arg bytes, size_t length) {
  size_t size = lean_sarray_size(bytes);
  return shim_tcp_send_offset(token, bytes, 0, length < size ? length : size);
}
static int ln_socket_close(int64_t token) {
  if (token <= 0 || token > INT_MAX || !((uint32_t)token & 0xffffu))
    return EBADF;
  AcquireSRWLockExclusive(&ln_sockets_lock);
  ln_legacy_socket *slot = &ln_sockets[(uint32_t)token & 0xffffu];
  if (!slot->used || slot->generation != (uint32_t)token >> 16) {
    ReleaseSRWLockExclusive(&ln_sockets_lock);
    return EBADF;
  }
  SOCKET socket = slot->socket;
  slot->used = 0;
  ReleaseSRWLockExclusive(&ln_sockets_lock);
  return closesocket(socket) == SOCKET_ERROR
             ? ln_windows_errno(WSAGetLastError())
             : 0;
}
lean_object *shim_close(int64_t token) {
  return mk_i64_ok(-ln_socket_close(token));
}
lean_object *shim_errno_name(int32_t error) {
  char message[256];
  if (strerror_s(message, sizeof(message), error) != 0)
    snprintf(message, sizeof(message), "errno %d", (int)error);
  return lean_io_result_mk_ok(lean_mk_string(message));
}
#define LN_ERRNO(name, value)                                                  \
  lean_object *shim_errno_##name(void) { return mk_i64_ok(value); }
LN_ERRNO(eintr, EINTR)
LN_ERRNO(eagain, EAGAIN) LN_ERRNO(ewouldblock, EWOULDBLOCK)
    LN_ERRNO(ebadf, EBADF) LN_ERRNO(epipe, EPIPE)
        LN_ERRNO(econnreset, ECONNRESET) LN_ERRNO(econnaborted, ECONNABORTED)
            LN_ERRNO(etimedout, ETIMEDOUT) LN_ERRNO(enetreset, ENETRESET)
                LN_ERRNO(enetdown, ENETDOWN) LN_ERRNO(enetunreach, ENETUNREACH)
                    LN_ERRNO(ehostunreach, EHOSTUNREACH)
                        LN_ERRNO(econnrefused, ECONNREFUSED)
                            LN_ERRNO(enotconn, ENOTCONN) LN_ERRNO(enonet, 0)
                                LN_ERRNO(eproto, EPROTO)
                                    LN_ERRNO(enoprotoopt, ENOPROTOOPT)
                                        LN_ERRNO(ehostdown, 0)
                                            LN_ERRNO(eopnotsupp, EOPNOTSUPP)
#undef LN_ERRNO

    /* Console handlers run on another Windows thread. Reader barriers ensure a
     * handler cannot send through a closed or recycled wake socket during
     * teardown. */
    _Static_assert(ATOMIC_POINTER_LOCK_FREE == 2 && ATOMIC_INT_LOCK_FREE == 2,
                   "console wake requires lock-free atomics");
static atomic_uint ln_interrupt_readers;
static atomic_int ln_interrupt_active, ln_interrupt_requested;
static _Atomic(uintptr_t) ln_interrupt_writer = INVALID_SOCKET;
static SOCKET ln_interrupt_reader = INVALID_SOCKET;
static BOOL WINAPI ln_console_handler(DWORD type) {
  if (type != CTRL_C_EVENT && type != CTRL_BREAK_EVENT)
    return FALSE;
  atomic_fetch_add_explicit(&ln_interrupt_readers, 1, memory_order_seq_cst);
  SOCKET writer =
      (SOCKET)atomic_load_explicit(&ln_interrupt_writer, memory_order_seq_cst);
  if (writer != INVALID_SOCKET) {
    atomic_store_explicit(&ln_interrupt_requested, 1, memory_order_seq_cst);
    const char byte = 1;
    (void)send(writer, &byte, 1, 0);
  }
  atomic_fetch_sub_explicit(&ln_interrupt_readers, 1, memory_order_seq_cst);
  return writer != INVALID_SOCKET;
}
static void ln_interrupt_barrier(void) {
  while (atomic_load_explicit(&ln_interrupt_readers, memory_order_seq_cst))
    (void)SwitchToThread();
}
lean_object *shim_interrupt_begin(void) {
  int expected = 0;
  if (!atomic_compare_exchange_strong(&ln_interrupt_active, &expected, 1))
    return mk_i64_ok(-EBUSY);
  int error = ln_wsa_initialize();
  SOCKET reader = INVALID_SOCKET, writer = INVALID_SOCKET;
  if (error)
    goto failure;
  reader = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  writer = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (reader == INVALID_SOCKET || writer == INVALID_SOCKET) {
    error = ln_windows_errno(WSAGetLastError());
    goto failure;
  }
  struct sockaddr_in address;
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  int address_length = sizeof(address);
  u_long mode = 1;
  if (bind(reader, (const struct sockaddr *)&address, sizeof(address)) ==
          SOCKET_ERROR ||
      getsockname(reader, (struct sockaddr *)&address, &address_length) ==
          SOCKET_ERROR ||
      connect(writer, (const struct sockaddr *)&address, address_length) ==
          SOCKET_ERROR ||
      ioctlsocket(reader, FIONBIO, &mode) == SOCKET_ERROR ||
      ioctlsocket(writer, FIONBIO, &mode) == SOCKET_ERROR) {
    error = ln_windows_errno(WSAGetLastError());
    goto failure;
  }
  atomic_store(&ln_interrupt_requested, 0);
  ln_interrupt_reader = reader;
  atomic_store_explicit(&ln_interrupt_writer, (uintptr_t)writer,
                        memory_order_seq_cst);
  if (!SetConsoleCtrlHandler(ln_console_handler, TRUE)) {
    error = ln_windows_errno(GetLastError());
    atomic_store_explicit(&ln_interrupt_writer, INVALID_SOCKET,
                          memory_order_seq_cst);
    ln_interrupt_barrier();
    ln_interrupt_reader = INVALID_SOCKET;
    goto failure;
  }
  return mk_i64_ok(0);
failure:
  if (reader != INVALID_SOCKET)
    error = ln_close_failure(reader, error);
  if (writer != INVALID_SOCKET)
    error = ln_close_failure(writer, error);
  atomic_store(&ln_interrupt_active, 0);
  return mk_i64_ok(-error);
}
lean_object *shim_interrupt_requested(void) {
  return mk_i64_ok(atomic_load(&ln_interrupt_requested));
}
lean_object *shim_interrupt_end(void) {
  if (!atomic_load(&ln_interrupt_active))
    return mk_i64_ok(-EINVAL);
  if (!SetConsoleCtrlHandler(ln_console_handler, FALSE))
    return mk_i64_ok(-ln_windows_errno(GetLastError()));
  SOCKET writer = (SOCKET)atomic_exchange_explicit(
      &ln_interrupt_writer, INVALID_SOCKET, memory_order_seq_cst);
  ln_interrupt_barrier();
  int error = ln_close_failure(ln_interrupt_reader, 0);
  error = ln_close_failure(writer, error);
  ln_interrupt_reader = INVALID_SOCKET;
  atomic_store(&ln_interrupt_requested, 0);
  atomic_store(&ln_interrupt_active, 0);
  return mk_i64_ok(-error);
}
static int ln_wait_interruptible(SOCKET socket, short events) {
  if (!atomic_load(&ln_interrupt_active))
    return EINVAL;
  if (atomic_load(&ln_interrupt_requested))
    return EINTR;
  WSAPOLLFD fds[2] = {{socket, events, 0},
                      {ln_interrupt_reader, POLLRDNORM, 0}};
  int result = WSAPoll(fds, 2, -1);
  if (result == SOCKET_ERROR)
    return ln_windows_errno(WSAGetLastError());
  if (atomic_load(&ln_interrupt_requested))
    return EINTR;
  if (fds[1].revents)
    return (fds[1].revents & POLLNVAL) ? EBADF : EIO;
  return (fds[0].revents & POLLNVAL) ? EBADF : 0;
}
static int ln_interrupt_prepare(int64_t token, short events, int *restore) {
  SOCKET socket;
  int mode = 0;
  int error = ln_socket_lookup(token, &socket, &mode);
  *restore = 0;
  if (error)
    return error;
  if (!mode) {
    error = ln_socket_nonblocking(token, 1);
    if (error)
      return error;
    *restore = 1;
  }
  return ln_wait_interruptible(socket, events);
}
lean_object *shim_interruptible_accept(int64_t token) {
  int restore = 0;
  int error = ln_interrupt_prepare(token, POLLRDNORM, &restore);
  uint8_t stage;
  int64_t result = error ? -error : ln_accept(token, 1, &stage);
  if (restore && (error = ln_socket_nonblocking(token, 0)) != 0) {
    if (result >= 0) {
      int cleanup = ln_socket_close(result);
      if (cleanup)
        error = cleanup;
    }
    result = -error;
  }
  return mk_i64_ok(result);
}
lean_object *shim_interruptible_recv(int64_t token, size_t maximum) {
  if (!maximum)
    return mk_count_ba_ok(-EINVAL, empty_ba());
  int restore = 0;
  int error = ln_interrupt_prepare(token, POLLRDNORM, &restore);
  lean_object *result = error ? mk_count_ba_ok(-error, empty_ba())
                              : shim_tcp_recv(token, maximum);
  if (restore && (error = ln_socket_nonblocking(token, 0)) != 0) {
    lean_dec(result);
    result = mk_count_ba_ok(-error, empty_ba());
  }
  return result;
}
lean_object *shim_interruptible_send(int64_t token, b_lean_obj_arg bytes,
                                     size_t length) {
  if (!length || !lean_sarray_size(bytes))
    return mk_i64_ok(0);
  int restore = 0;
  int error = ln_interrupt_prepare(token, POLLWRNORM, &restore);
  lean_object *result =
      error ? mk_i64_ok(-error) : shim_tcp_send(token, bytes, length);
  if (restore && (error = ln_socket_nonblocking(token, 0)) != 0) {
    lean_dec(result);
    result = mk_i64_ok(-error);
  }
  return result;
}
lean_object *shim_set_nonblocking(int64_t token, uint8_t enabled) {
  return mk_i64_ok(enabled > 1 ? -EINVAL
                               : -ln_socket_nonblocking(token, enabled));
}
lean_object *shim_poll(b_lean_obj_arg entries, int32_t timeout) {
  size_t size = lean_sarray_size(entries), count = size / 5;
  if (size % 5 || timeout < -1 || count >= ULONG_MAX ||
      count > SIZE_MAX / sizeof(WSAPOLLFD) - 1)
    return mk_count_ba_ok(-EINVAL, empty_ba());
  if (!atomic_load(&ln_interrupt_active))
    return mk_count_ba_ok(-EINVAL, empty_ba());
  if (atomic_load(&ln_interrupt_requested))
    return mk_count_ba_ok(-EINTR, empty_ba());
  WSAPOLLFD *fds = calloc(count + 1, sizeof(*fds));
  if (!fds)
    return mk_count_ba_ok(-ENOMEM, empty_ba());
  const uint8_t *input = lean_sarray_cptr(entries);
  for (size_t i = 0; i < count; ++i) {
    const uint8_t *entry = input + i * 5;
    uint32_t token = entry[0] | ((uint32_t)entry[1] << 8) |
                     ((uint32_t)entry[2] << 16) | ((uint32_t)entry[3] << 24);
    if ((entry[4] & ~3u) || token > INT_MAX) {
      free(fds);
      return mk_count_ba_ok(-EINVAL, empty_ba());
    }
    if (ln_socket_lookup(token, &fds[i].fd, NULL)) {
      fds[i].fd = INVALID_SOCKET;
      fds[i].revents = POLLNVAL;
    }
    if (entry[4] & 1)
      fds[i].events |= POLLRDNORM;
    if (entry[4] & 2)
      fds[i].events |= POLLWRNORM;
  }
  fds[count].fd = ln_interrupt_reader;
  fds[count].events = POLLRDNORM;
  /* WSAPoll ignores INVALID_SOCKET entries; preserve their invalid masks and
   * report them immediately, matching poll(2), without submitting fake handles.
   */
  int invalid = 0;
  for (size_t i = 0; i < count; ++i)
    if (fds[i].fd == INVALID_SOCKET)
      invalid = 1;
  int result = WSAPoll(fds, (ULONG)(count + 1), invalid ? 0 : timeout);
  int error = result == SOCKET_ERROR ? ln_windows_errno(WSAGetLastError()) : 0;
  if (atomic_load(&ln_interrupt_requested))
    error = EINTR;
  if (!error && fds[count].revents)
    error = (fds[count].revents & POLLNVAL) ? EBADF : EIO;
  if (error) {
    free(fds);
    return mk_count_ba_ok(-error, empty_ba());
  }
  lean_object *bytes = lean_alloc_sarray(1, count, count);
  uint8_t *output = lean_sarray_cptr(bytes);
  int64_t ready = 0;
  for (size_t i = 0; i < count; ++i) {
    short flags = fds[i].revents;
    uint8_t mask = 0;
    if (flags & POLLRDNORM)
      mask |= 1;
    if (flags & POLLWRNORM)
      mask |= 2;
    if (flags & POLLHUP)
      mask |= 4;
    if (flags & POLLERR)
      mask |= 8;
    if ((flags & POLLNVAL) || fds[i].fd == INVALID_SOCKET)
      mask |= 16;
    output[i] = mask;
    if (mask)
      ++ready;
  }
  free(fds);
  return mk_count_ba_ok(ready, bytes);
}
#endif
