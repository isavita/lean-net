#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#include "../c/reactor_posix.c"

void lean_initialize_runtime_module(void);

static void check(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "reactor connect: %s\n", message); exit(1); }
}

int main(void) {
    lean_initialize_runtime_module();
    rn_config config = {8, 16, 8, 8, 0, 0, 1};
    rn_reactor *r = NULL;
    check(rn_new(&config, &r) == 0, "create");
    uint64_t listener = 0, outbound = 0;
    check(rn_listen(r, "127.0.0.1", 0, 0, &listener) == 0, "listen");
    struct sockaddr_in bound; socklen_t bound_length = sizeof(bound);
    check(getsockname(r->connections[rn_index(listener)].fd,
                      (struct sockaddr *)&bound, &bound_length) == 0, "bound port");
    const uint8_t loopback[4] = {127, 0, 0, 1};
    check(rn_socket_new(r, &outbound) == 0, "allocate outbound slot");
    check(rn_connect(r, outbound, loopback, 3, ntohs(bound.sin_port)) == -EINVAL,
          "reject invalid address size");
    check(rn_connect(r, outbound, loopback, 4, 0) == -EINVAL,
          "reject zero port");
    check(rn_connect(r, outbound, loopback, 4, ntohs(bound.sin_port)) == 0,
          "start nonblocking connect");
    check(rn_connection_live(r, outbound) == 0, "connecting is not connected");
    check(rn_arm_timer(r, outbound, 2, rn_now_ms() + 5000) == 0, "arm connect timer");
    uint64_t inbound = 0;
    int connected = 0, accepted = 0;
    for (int round = 0; round < 100 && (!connected || !accepted); ++round) {
        int count = rn_step(r, 20);
        check(count >= 0, "poll successful connect");
        for (int i = 0; i < count; ++i) {
            const rn_event *event = rn_event_at(r, (uint32_t)i);
            if (event->kind == RN_CONNECT_COMPLETE) {
                check(event->connection == outbound && !connected,
                      "one distinct outbound completion");
                connected = 1;
            } else if (event->kind == RN_ACCEPTED) {
                check(!accepted, "one inbound accept");
                inbound = event->connection; accepted = 1;
            } else if (event->kind == RN_ERROR) {
                check(0, "unexpected connect or accept error");
            }
        }
    }
    check(connected && accepted && rn_connection_live(r, outbound) == 1,
          "connected socket live");
    check(rn_cancel_timer(r, outbound, 2) == 0, "cancel connect timer");
    uint64_t canceled = 0;
    check(rn_socket_new(r, &canceled) == 0, "allocate canceled connect");
    check(rn_connect(r, canceled, loopback, 4, ntohs(bound.sin_port)) == 0,
          "start canceled connect");
    check(rn_close_connection(r, canceled) == 0, "cancel pending connect");
    int canceled_closed = 0;
    for (int round = 0; round < 20; ++round) {
        int count = rn_step(r, 5);
        check(count >= 0, "poll canceled connect");
        for (int i = 0; i < count; ++i) {
            const rn_event *event = rn_event_at(r, (uint32_t)i);
            check(event->kind != RN_CONNECT_COMPLETE || event->connection != canceled,
                  "canceled connection completed");
            if (event->kind == RN_CLOSED && event->connection == canceled)
                ++canceled_closed;
            if (event->kind == RN_ACCEPTED)
                check(rn_close_connection(r, event->connection) == 0,
                      "close peer of canceled connect");
        }
    }
    check(canceled_closed == 1, "canceled socket closed once");
    check(rn_close_connection(r, outbound) == 0, "close outbound");
    check(rn_connection_live(r, outbound) == 0, "closed token not live");
    check(rn_close_connection(r, inbound) == 0, "close inbound");
    check(rn_close_connection(r, listener) == 0, "close listener");
    unsigned closed = 0;
    for (int round = 0; round < 20 && closed != 7; ++round) {
        int count = rn_step(r, 0);
        check(count >= 0, "poll closures");
        for (int i = 0; i < count; ++i) {
            const rn_event *event = rn_event_at(r, (uint32_t)i);
            if (event->kind == RN_CLOSED && event->connection == outbound) closed |= 1;
            if (event->kind == RN_CLOSED && event->connection == inbound) closed |= 2;
            if (event->kind == RN_CLOSED && event->connection == listener) closed |= 4;
        }
    }
    check(closed == 7, "three owned sockets closed");
    uint64_t replacement = 0;
    check(rn_socket_new(r, &replacement) == 0 && replacement != outbound,
          "slot generation changed");
    check(rn_connect(r, outbound, loopback, 4, ntohs(bound.sin_port)) == -EBADF,
          "stale generation cannot connect");
    check(rn_close_connection(r, replacement) == 0, "close replacement");
    uint64_t refused = 0;
    check(rn_socket_new(r, &refused) == 0, "allocate refused connect");
    int started = rn_connect(r, refused, loopback, 4, ntohs(bound.sin_port));
    if (started == 0) {
        int failed = 0, refused_closed = 0;
        for (int round = 0; round < 100 && (!failed || !refused_closed); ++round) {
            int count = rn_step(r, 20);
            check(count >= 0, "poll refused connect");
            for (int i = 0; i < count; ++i) {
                const rn_event *event = rn_event_at(r, (uint32_t)i);
                check(event->kind != RN_CONNECT_COMPLETE || event->connection != refused,
                      "closed listener accepted outbound connection");
                if (event->kind == RN_ERROR && event->connection == refused) {
                    check(event->result == -ECONNREFUSED, "refusal errno");
                    ++failed;
                }
                if (event->kind == RN_CLOSED && event->connection == refused)
                    ++refused_closed;
            }
        }
        check(failed == 1 && refused_closed == 1, "refused connection retires once");
    } else {
        check(started == -ECONNREFUSED, "synchronous refusal errno");
        check(rn_close_connection(r, refused) == 0, "close sync failed slot");
    }
    check(rn_free(r) == 0, "free reactor");
    puts("reactor outbound connect tests passed");
    return 0;
}
