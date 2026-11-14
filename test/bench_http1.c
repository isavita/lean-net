/* Verified fixed-count HTTP/1.1 closed-loop client. One outstanding request per
 * persistent connection, no pipelining. Every response status, framing length
 * and body byte is checked before counting a completed request. */
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#define HEADER_LIMIT 8192u
struct client { int fd; size_t sent, received, head, checked, completed; double started; unsigned char *wire; };
static double now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) { perror("clock_gettime"); exit(2); }
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}
static void fail(const char *message) { fprintf(stderr, "%s\n", message); exit(2); }
static int compare_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}
static size_t number(const char *s, const char *name, size_t max) {
    char *end = NULL; errno = 0;
    unsigned long long n = strtoull(s, &end, 10);
    if (errno || end == s || *end || n == 0 || n > max) { fprintf(stderr, "invalid %s\n", name); exit(2); }
    return (size_t)n;
}
static int hex(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    fail("invalid expected body hex"); return 0;
}
static int equal_name(const char *actual, const char *wanted) {
    for (; *actual && *wanted; ++actual, ++wanted) {
        unsigned char a = (unsigned char)*actual, b = (unsigned char)*wanted;
        if (a >= 'A' && a <= 'Z') a = (unsigned char)(a + 32);
        if (b >= 'A' && b <= 'Z') b = (unsigned char)(b + 32);
        if (a != b) return 0;
    }
    return *actual == *wanted;
}
static int token(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || strchr("!#$%&'*+-.^_`|~", c) != NULL;
}
static void parse_head(struct client *c, size_t expected) {
    if (c->head) return;
    size_t end = 0;
    for (size_t i = 0; i + 3 < c->received; ++i)
        if (memcmp(c->wire + i, "\r\n\r\n", 4) == 0) { end = i + 4; break; }
    if (!end) { if (c->received >= HEADER_LIMIT) fail("response header exceeded limit"); return; }
    if (end > HEADER_LIMIT || end < 17 || memcmp(c->wire, "HTTP/1.1 200 ", 13) != 0) fail("unexpected response status or version");
    char header[HEADER_LIMIT + 1u]; memcpy(header, c->wire, end); header[end] = 0;
    if (strlen(header) != end) fail("NUL in response header");
    char *line = strstr(header, "\r\n");
    if (!line) fail("missing status line terminator");
    for (char *byte = header + 13; byte < line; ++byte)
        if ((unsigned char)*byte != 9 && ((unsigned char)*byte < 32 || (unsigned char)*byte == 127)) fail("invalid response reason phrase");
    line += 2;
    unsigned lengths = 0;
    while (*line && !(line[0] == '\r' && line[1] == '\n')) {
        char *stop = strstr(line, "\r\n"), *colon = strchr(line, ':');
        if (!stop || !colon || colon == line || colon > stop) fail("malformed response field");
        *stop = 0; *colon = 0;
        for (char *name = line; *name; ++name) if (!token((unsigned char)*name)) fail("invalid response field name");
        char *value = colon + 1;
        while (*value == ' ' || *value == '\t') ++value;
        char *last = stop;
        while (last > value && (last[-1] == ' ' || last[-1] == '\t')) *--last = 0;
        for (char *byte = value; *byte; ++byte)
            if ((unsigned char)*byte != 9 && ((unsigned char)*byte < 32 || (unsigned char)*byte == 127)) fail("invalid response field value");
        if (equal_name(line, "transfer-encoding")) fail("benchmark requires explicit length, not transfer coding");
        if (equal_name(line, "content-length")) {
            if (++lengths != 1 || !*value) fail("missing or duplicate Content-Length");
            size_t length = 0;
            for (char *digit = value; *digit; ++digit) {
                if (*digit < '0' || *digit > '9') fail("invalid response Content-Length");
                length = length * 10 + (size_t)(*digit - '0');
                if (length > expected) fail("response Content-Length mismatch");
            }
            if (length != expected) fail("response Content-Length mismatch");
        }
        line = stop + 2;
    }
    if (lengths != 1) fail("response has no explicit Content-Length");
    c->head = end;
}
int main(int argc, char **argv) {
    if (argc != 6) fail("usage: http1-bench PORT CONNECTIONS REQUESTS PATH EXPECTED_BODY_HEX");
    size_t port = number(argv[1], "port", 65535), count = number(argv[2], "connections", 4096);
    size_t requests = number(argv[3], "requests", 10000000), hex_size = strlen(argv[5]);
    if (requests < count || !hex_size || hex_size % 2 || hex_size > 2097152) fail("invalid request/body sizes");
    if (argv[4][0] != '/' || strlen(argv[4]) > 2048) fail("invalid request path");
    for (const unsigned char *p = (const unsigned char *)argv[4]; *p; ++p) if (*p < 33 || *p > 126) fail("invalid request path");
    size_t bytes = hex_size / 2, capacity = HEADER_LIMIT + bytes;
    unsigned char *expected = malloc(bytes);
    struct client *clients = calloc(count, sizeof(*clients));
    struct pollfd *fds = calloc(count, sizeof(*fds));
    double *latency = malloc(requests * sizeof(*latency));
    if (!expected || !clients || !fds || !latency) fail("allocation failed");
    for (size_t i = 0; i < bytes; ++i) expected[i] = (unsigned char)(hex((unsigned char)argv[5][i * 2]) * 16 + hex((unsigned char)argv[5][i * 2 + 1]));
    char request[4096];
    int request_length = snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: localhost\r\n\r\n", argv[4]);
    if (request_length <= 0 || (size_t)request_length >= sizeof(request)) fail("request is too long");
    for (size_t i = 0; i < count; ++i) {
        int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
        if (fd < 0 || setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) { perror("socket/TCP_NODELAY"); return 2; }
#ifdef SO_NOSIGPIPE
        if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) < 0) { perror("SO_NOSIGPIPE"); return 2; }
#endif
        struct sockaddr_in address; memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET; address.sin_port = htons((uint16_t)port); address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) { perror("connect"); return 2; }
        int flags = fcntl(fd, F_GETFL);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) { perror("nonblocking"); return 2; }
        clients[i].fd = fd; clients[i].wire = malloc(capacity);
        if (!clients[i].wire) fail("response allocation failed");
        fds[i].fd = fd; fds[i].events = POLLIN | POLLOUT;
    }
    double start = now(); size_t issued = count, completed = 0, early = 0;
    for (size_t i = 0; i < count; ++i) clients[i].started = start;
    while (completed < requests) {
        int ready = poll(fds, (nfds_t)count, 10000);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) fail("load client made no progress");
        for (size_t i = 0; i < count; ++i) {
            struct client *c = &clients[i];
            if (c->fd < 0 || fds[i].revents == 0) continue;
            if (fds[i].revents & POLLNVAL) fail("invalid client descriptor");
            if (c->sent < (size_t)request_length && (fds[i].revents & POLLOUT)) {
#ifdef MSG_NOSIGNAL
                int flags = MSG_NOSIGNAL;
#else
                int flags = 0;
#endif
                ssize_t n = send(c->fd, request + c->sent, (size_t)request_length - c->sent, flags);
                if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { perror("send"); return 2; }
                if (n > 0) c->sent += (size_t)n;
                if (c->sent == (size_t)request_length) fds[i].events = POLLIN;
            }
            if (fds[i].revents & (POLLIN | POLLHUP | POLLERR)) {
                if (c->received == capacity) fail("response exceeded limit");
                ssize_t n = recv(c->fd, c->wire + c->received, capacity - c->received, 0);
                if (n == 0) fail("unexpected server EOF");
                if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { perror("recv"); return 2; }
                if (n > 0) c->received += (size_t)n;
                parse_head(c, bytes);
                if (c->head) {
                    size_t body = c->received - c->head;
                    if (body > bytes || memcmp(c->wire + c->head + c->checked, expected + c->checked, body - c->checked) != 0) fail("response body mismatch");
                    c->checked = body;
                    if (body == bytes && c->sent == (size_t)request_length) {
                        double finished = now(); latency[completed++] = (finished - c->started) * 1e6;
                        if (!c->completed && finished - start <= 1.0) ++early;
                        ++c->completed;
                        if (issued < requests) {
                            ++issued; c->sent = c->received = c->head = c->checked = 0; c->started = finished; fds[i].events = POLLIN | POLLOUT;
                        } else {
                            if (close(c->fd) < 0) { perror("close"); return 2; }
                            c->fd = -1; fds[i].fd = -1; fds[i].events = 0;
                        }
                    }
                }
            }
        }
        if (now() - start > 120.0) fail("benchmark exceeded120seconds");
    }
    double elapsed = now() - start;
    qsort(latency, requests, sizeof(*latency), compare_double);
    printf("{\"requests\":%zu,\"connections\":%zu,\"body_bytes\":%zu,\"seconds\":%.6f,\"requests_per_second\":%.2f,\"latency_us_p50\":%.2f,\"latency_us_p95\":%.2f,\"latency_us_p99\":%.2f,\"latency_us_max\":%.2f,\"clients_progressed_in_first_second\":%zu,\"verified_responses\":%zu}\n", requests, count, bytes, elapsed, requests / elapsed, latency[requests / 2], latency[requests * 95 / 100], latency[requests * 99 / 100], latency[requests - 1], early, completed);
    for (size_t i = 0; i < count; ++i) free(clients[i].wire);
    free(latency); free(fds); free(clients); free(expected); return 0;
}
