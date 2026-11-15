#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#include "../c/gateway_resolve.h"
#include <stdio.h>

void lean_initialize_runtime_module(void);

static void check(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "gateway resolver: %s\n", message); exit(1); }
}

int main(void) {
    lean_initialize_runtime_module();
    uint8_t address[16];
    const uint8_t v4[4] = {127, 0, 0, 1};
    const uint8_t v6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    check(gateway_resolve_ip("127.0.0.1", 9, 0, address) == 4 &&
          memcmp(address, v4, 4) == 0, "numeric IPv4");
    check(gateway_resolve_ip("::1", 3, 1, address) == 16 &&
          memcmp(address, v6, 16) == 0, "numeric IPv6");
    int localhost = gateway_resolve_ip("localhost", 9, 0, address);
    check(localhost == 4 || localhost == 16, "DNS localhost");
    int absolute = gateway_resolve_ip("localhost.", 10, 0, address);
    check(absolute == 4 || absolute == 16, "absolute DNS localhost");
    const char embedded[] = {'l', 'o', 'c', 0, 'x', 0};
    check(gateway_resolve_ip(embedded, 5, 0, address) == -EINVAL,
          "embedded NUL");
    char oversized[255]; memset(oversized, 'a', 254); oversized[254] = 0;
    check(gateway_resolve_ip(oversized, 254, 0, address) == -EINVAL,
          "oversized hostname");
    const char *bad[] = {"", "a..b", "-bad.example", "bad-.example",
                         "http://example.com", "example.com:443", "[::1]",
                         "fe80::1%en0", "999.999.999.999", "foo_bar",
                         "a/b", "a b", ".", "a.."};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        if (gateway_resolve_ip(bad[i], strlen(bad[i]), 0, address) != -EINVAL) {
            fprintf(stderr, "gateway resolver accepted: %s\n", bad[i]);
            exit(1);
        }
    }
    check(gateway_resolve_ip("localhost", 9, 2, address) == -EINVAL,
          "invalid family preference");
    puts("gateway resolver tests passed");
    return 0;
}
