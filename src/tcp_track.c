#include "../include/tcp_track.h"
#include <string.h>
#include <sys/socket.h>

#define MAX_CONNS 128
#define IDLE_SECONDS 120
static struct tcp_conn conns[MAX_CONNS];

void tcp_track_reset(void) { memset(conns, 0, sizeof conns); }
static double elapsed(const struct timespec *a, const struct timespec *b) {
    return (b->tv_sec - a->tv_sec) * 1000.0 + (b->tv_nsec - a->tv_nsec) / 1000000.0;
}
struct tcp_conn *tcp_track_ip(int family, const unsigned char *src, const unsigned char *dst,
                           uint16_t sport, uint16_t dport, uint8_t flags,
                           const struct timespec *now) {
    struct tcp_conn *slot = NULL, *oldest = &conns[0];
    for (size_t i = 0; i < MAX_CONNS; i++) {
        struct tcp_conn *c = &conns[i];
        if (c->active && now->tv_sec - c->seen > IDLE_SECONDS) c->active = 0;
        if (!c->active) { if (!slot) slot = c; continue; }
        if (c->seen < oldest->seen) oldest = c;
        if (c->family != family) continue;
        int forward = !memcmp(c->client, src, family == AF_INET ? 4 : 16) && !memcmp(c->server, dst, family == AF_INET ? 4 : 16) &&
                      c->client_port == sport && c->server_port == dport;
        int reverse = !memcmp(c->server, src, family == AF_INET ? 4 : 16) && !memcmp(c->client, dst, family == AF_INET ? 4 : 16) &&
                      c->server_port == sport && c->client_port == dport;
        if (!forward && !reverse) continue;
        c->seen = now->tv_sec;
        if (reverse && (flags & 0x12) == 0x12 && c->syn_seen && !c->synack_seen) {
            c->synack_seen = 1;
            c->synack_ms = elapsed(&c->syn_time, now);
        }
        if (flags & 0x05) c->active = 0;
        return c;
    }
    if ((flags & 0x12) != 0x02) return NULL;
    struct tcp_conn *c = slot ? slot : oldest;
    memset(c, 0, sizeof *c);
    c->active = c->syn_seen = 1;
    c->seen = now->tv_sec;
    c->syn_time = *now;
    c->family = family;
    memcpy(c->client, src, family == AF_INET ? 4 : 16); memcpy(c->server, dst, family == AF_INET ? 4 : 16);
    c->client_port = sport; c->server_port = dport;
    return c;
}
void tcp_track_hello(struct tcp_conn *c, const struct timespec *now, int server) {
    if (!c) return;
    if (!server && !c->hello_seen) { c->hello_seen = 1; c->hello_time = *now; }
    if (server && c->hello_seen && !c->server_seen) {
        c->server_seen = 1;
        c->hello_server_ms = elapsed(&c->hello_time, now);
    }
}

struct tcp_conn *tcp_track(const unsigned char *src, const unsigned char *dst, uint16_t sport, uint16_t dport, uint8_t flags, const struct timespec *now) { return tcp_track_ip(AF_INET, src, dst, sport, dport, flags, now); }
