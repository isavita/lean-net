/* Nonblocking, closed-loop echo load generator. One outstanding request per
 * connection; validates every byte and reports completion latency in JSON.
 * Build through bench_echo.py, or cc -O3 -std=c11 -Wall -Wextra -Wpedantic. */
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
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

struct client { int fd; size_t sent, received, completed; double started; };
static double now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) { perror("clock_gettime"); exit(2); }
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}
static int compare_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}
static size_t number(const char *s, const char *name, size_t max) {
    char *end = NULL; errno = 0;
    unsigned long long n = strtoull(s, &end, 10);
    if (errno || end == s || *end || n == 0 || n > max) {
        fprintf(stderr, "invalid %s\n", name); exit(2);
    }
    return (size_t)n;
}
int main(int argc, char **argv) {
    if (argc != 5) { fprintf(stderr, "usage: echo-bench PORT CONNECTIONS REQUESTS PAYLOAD_BYTES\n"); return 2; }
    size_t port = number(argv[1], "port", 65535);
    size_t count = number(argv[2], "connections", 4096);
    size_t requests = number(argv[3], "requests", 10000000);
    size_t bytes = number(argv[4], "payload bytes", 1048576);
    if (requests < count) { fprintf(stderr, "requests must be at least connections\n"); return 2; }
    struct client *clients = calloc(count, sizeof(*clients));
    struct pollfd *fds = calloc(count, sizeof(*fds));
    unsigned char *payload = malloc(bytes), *buffer = malloc(bytes);
    double *latency = malloc(requests * sizeof(*latency));
    if (!clients || !fds || !payload || !buffer || !latency) { perror("allocate"); return 2; }
    for (size_t i = 0; i < bytes; ++i) payload[i] = (unsigned char)(i * 31u + 7u);
    for (size_t i = 0; i < count; ++i) {
        int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
        if (fd < 0) { perror("socket"); return 2; }
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) { perror("TCP_NODELAY"); return 2; }
#ifdef SO_NOSIGPIPE
        if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) < 0) { perror("SO_NOSIGPIPE"); return 2; }
#endif
        struct sockaddr_in address; memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET; address.sin_port = htons((uint16_t)port);
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) { perror("connect"); return 2; }
        int flags = fcntl(fd, F_GETFL);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) { perror("nonblocking"); return 2; }
        clients[i].fd = fd; fds[i].fd = fd; fds[i].events = POLLIN | POLLOUT;
    }
    double start = now();
    for (size_t i = 0; i < count; ++i) clients[i].started = start;
    size_t issued = count, completed = 0, active_during_first_second = 0;
    while (completed < requests) {
        int ready = poll(fds, (nfds_t)count, 10000);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) { if (ready < 0) perror("poll"); else fprintf(stderr, "no progress for 10 seconds\n"); return 2; }
        for (size_t i = 0; i < count; ++i) {
            struct client *c = &clients[i];
            if (c->fd < 0 || fds[i].revents == 0) continue;
            if (fds[i].revents & POLLNVAL) { fprintf(stderr, "invalid client descriptor\n"); return 2; }
            if (c->sent < bytes && (fds[i].revents & POLLOUT)) {
#ifdef MSG_NOSIGNAL
                int send_flags = MSG_NOSIGNAL;
#else
                int send_flags = 0;
#endif
                ssize_t n = send(c->fd, payload + c->sent, bytes - c->sent, send_flags);
                if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { perror("send"); return 2; }
                if (n > 0) c->sent += (size_t)n;
                if (c->sent == bytes) fds[i].events = POLLIN;
            }
            if (fds[i].revents & (POLLIN | POLLHUP | POLLERR)) {
                ssize_t n = recv(c->fd, buffer, bytes - c->received, 0);
                if (n == 0) { fprintf(stderr, "unexpected EOF\n"); return 2; }
                if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { perror("recv"); return 2; }
                if (n > 0) {
                    if (memcmp(buffer, payload + c->received, (size_t)n) != 0) { fprintf(stderr, "echo data mismatch\n"); return 2; }
                    c->received += (size_t)n;
                }
                if (c->received == bytes && c->sent == bytes) {
                    double finished = now(); latency[completed++] = (finished - c->started) * 1e6;
                    if (c->completed == 0 && finished - start <= 1.0) active_during_first_second++;
                    c->completed++;
                    if (issued < requests) {
                        issued++; c->sent = 0; c->received = 0; c->started = finished; fds[i].events = POLLIN | POLLOUT;
                    } else {
                        if (close(c->fd) < 0) { perror("close"); return 2; }
                        c->fd = -1; fds[i].fd = -1; fds[i].events = 0;
                    }
                }
            }
        }
        if (now() - start > 120.0) { fprintf(stderr, "benchmark exceeded 120 seconds\n"); return 2; }
    }
    double elapsed = now() - start;
    qsort(latency, requests, sizeof(*latency), compare_double);
    printf("{\"requests\":%zu,\"connections\":%zu,\"payload_bytes\":%zu,\"seconds\":%.6f,\"requests_per_second\":%.2f,\"latency_us_p50\":%.2f,\"latency_us_p95\":%.2f,\"latency_us_p99\":%.2f,\"latency_us_max\":%.2f,\"clients_progressed_in_first_second\":%zu}\n", requests, count, bytes, elapsed, requests / elapsed, latency[requests / 2], latency[(requests * 95) / 100], latency[(requests * 99) / 100], latency[requests - 1], active_during_first_second);
    free(latency); free(buffer); free(payload); free(fds); free(clients);
    return 0;
}
