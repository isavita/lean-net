/* Keep Winsock and Win32 failures in the same errno domain as the Lean API. */
#ifndef LEAN_NET_WINDOWS_ERROR_H
#define LEAN_NET_WINDOWS_ERROR_H
#include <errno.h>
#include <windows.h>
#include <winsock2.h>

static inline int ln_windows_errno(DWORD error) {
  switch (error) {
  case ERROR_SUCCESS:
    return 0;
  case WSAEINTR:
    return EINTR;
  case WSAEWOULDBLOCK:
    return EAGAIN;
  case WSAEINVAL:
  case ERROR_INVALID_PARAMETER:
    return EINVAL;
  case WSAEBADF:
  case WSAENOTSOCK:
  case ERROR_INVALID_HANDLE:
    return EBADF;
  case WSAEACCES:
  case ERROR_ACCESS_DENIED:
    return EACCES;
  case WSAEADDRINUSE:
    return EADDRINUSE;
  case WSAEADDRNOTAVAIL:
    return EADDRNOTAVAIL;
  case WSAECONNABORTED:
  case ERROR_CONNECTION_ABORTED:
    return ECONNABORTED;
  case WSAECONNRESET:
  case ERROR_NETNAME_DELETED:
    return ECONNRESET;
  case WSAECONNREFUSED:
  case ERROR_CONNECTION_REFUSED:
    return ECONNREFUSED;
  case WSAENOTCONN:
    return ENOTCONN;
  case WSAETIMEDOUT:
  case ERROR_SEM_TIMEOUT:
  case WAIT_TIMEOUT:
    return ETIMEDOUT;
  case WSAENETRESET:
    return ENETRESET;
  case WSAENETDOWN:
    return ENETDOWN;
  case WSAENETUNREACH:
  case ERROR_NETWORK_UNREACHABLE:
    return ENETUNREACH;
  case WSAEHOSTUNREACH:
  case ERROR_HOST_UNREACHABLE:
    return EHOSTUNREACH;
  case WSAEHOSTDOWN:
    return EHOSTUNREACH;
  case WSAENOPROTOOPT:
    return ENOPROTOOPT;
  case WSAEPROTONOSUPPORT:
    return EPROTONOSUPPORT;
  case WSAEAFNOSUPPORT:
    return EAFNOSUPPORT;
  case WSAENOBUFS:
  case ERROR_NOT_ENOUGH_MEMORY:
  case ERROR_OUTOFMEMORY:
    return ENOMEM;
  case WSAEMFILE:
    return EMFILE;
  case ERROR_OPERATION_ABORTED:
    return ECANCELED;
  case WSAEOPNOTSUPP:
    return EOPNOTSUPP;
  case WSAESHUTDOWN:
    return EPIPE;
  default:
    return EIO;
  }
}
#endif
