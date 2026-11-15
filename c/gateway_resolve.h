/* Setup-side gateway DNS resolver. Never call from a reactor owner loop. */
#ifndef LEAN_NET_GATEWAY_RESOLVE_H
#define LEAN_NET_GATEWAY_RESOLVE_H

#include <lean/lean.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#endif

static int gateway_ascii_alnum(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z');
}

static int gateway_parse_ip(int family, const char *host, void *out) {
#if defined(_WIN32)
    return InetPtonA(family, host, out) == 1;
#else
    return inet_pton(family, host, out) == 1;
#endif
}

/* Returns 4/16 address bytes or negative errno. Host is an ASCII DNS A-label
 * name or a numeric address, without port, brackets, zone, path, or scheme.
 * The getaddrinfo call can block and must be dispatched off the owner loop. */
static int gateway_resolve_ip(const char *host, size_t length, int prefer_ipv6,
                              uint8_t out[16]) {
    if (!host || !out || (prefer_ipv6 != 0 && prefer_ipv6 != 1) ||
        length == 0 || length > 253 || memchr(host, 0, length) || host[length])
        return -EINVAL;
    int colon = 0, dotted_numeric = 1, dot = 0;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)host[i];
        if (c == ':') colon = 1;
        if (c == '%') return -EINVAL; /* A scope ID cannot fit the raw IP API. */
        if (c == '.') dot = 1;
        if (c != '.' && (c < '0' || c > '9')) dotted_numeric = 0;
        if (c < 33 || c > 126) return -EINVAL;
    }
    if (colon) return gateway_parse_ip(AF_INET6, host, out) ? 16 : -EINVAL;
    if (gateway_parse_ip(AF_INET, host, out)) return 4;
    if (dot && dotted_numeric) return -EINVAL;

    size_t label_start = 0;
    for (size_t i = 0; i <= length; ++i) {
        if (i == length && label_start == length && host[length - 1] == '.')
            break; /* The DNS root dot terminates the last valid label. */
        if (i == length || host[i] == '.') {
            size_t label_length = i - label_start;
            if (label_length == 0 || label_length > 63 ||
                !gateway_ascii_alnum((unsigned char)host[label_start]) ||
                !gateway_ascii_alnum((unsigned char)host[i - 1])) return -EINVAL;
            label_start = i + 1;
        } else if (!gateway_ascii_alnum((unsigned char)host[i]) && host[i] != '-')
            return -EINVAL;
    }
#if defined(_WIN32)
    ADDRINFOA hints, *addresses = NULL;
#else
    struct addrinfo hints, *addresses = NULL;
#endif
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    int gai = getaddrinfo(host, NULL, &hints, &addresses);
    if (gai) {
#ifdef EAI_AGAIN
        if (gai == EAI_AGAIN) return -EAGAIN;
#endif
#ifdef EAI_MEMORY
        if (gai == EAI_MEMORY) return -ENOMEM;
#endif
        return -EHOSTUNREACH;
    }
    uint8_t fallback[16]; int selected = 0, fallback_length = 0;
#if defined(_WIN32)
    for (const ADDRINFOA *a = addresses; a; a = a->ai_next) {
#else
    for (const struct addrinfo *a = addresses; a; a = a->ai_next) {
#endif
        const uint8_t *bytes = NULL; int count = 0;
        if (a->ai_family == AF_INET && a->ai_addrlen >= sizeof(struct sockaddr_in)) {
            bytes = (const uint8_t *)&((const struct sockaddr_in *)a->ai_addr)->sin_addr;
            count = 4;
        } else if (a->ai_family == AF_INET6 &&
                   a->ai_addrlen >= sizeof(struct sockaddr_in6)) {
            bytes = (const uint8_t *)&((const struct sockaddr_in6 *)a->ai_addr)->sin6_addr;
            count = 16;
        }
        if (!bytes) continue;
        if ((count == 16) == prefer_ipv6) {
            memcpy(out, bytes, (size_t)count); selected = count; break;
        }
        if (!fallback_length) {
            memcpy(fallback, bytes, (size_t)count); fallback_length = count;
        }
    }
    if (!selected && fallback_length) {
        selected = fallback_length;
        memcpy(out, fallback, (size_t)selected);
    }
    freeaddrinfo(addresses);
    return selected ? selected : -EHOSTUNREACH;
}

static lean_object *gateway_resolve_result(int64_t status, lean_object *bytes) {
    lean_object *pair = lean_alloc_ctor(0, 2, 0);
    lean_ctor_set(pair, 0, lean_box_uint64((uint64_t)status));
    lean_ctor_set(pair, 1, bytes);
    return lean_io_result_mk_ok(pair);
}

/* Status 0 success, 1 invalid host, negative errno lookup failure. */
lean_object *shim_gateway_resolve(b_lean_obj_arg host, uint8_t prefer_ipv6) {
    const char *text = lean_string_cstr(host);
    size_t size = lean_string_size(host);
    uint8_t address[16];
    int result = size ? gateway_resolve_ip(text, size - 1, prefer_ipv6, address) : -EINVAL;
    if (result < 0) return gateway_resolve_result(result == -EINVAL ? 1 : result,
                                                  lean_alloc_sarray(1, 0, 0));
    lean_object *bytes = lean_alloc_sarray(1, (size_t)result, (size_t)result);
    memcpy(lean_sarray_cptr(bytes), address, (size_t)result);
    return gateway_resolve_result(0, bytes);
}

#endif
