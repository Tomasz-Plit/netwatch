#ifndef TCP_TRACK_H
#define TCP_TRACK_H
#include <stdint.h>
#include <time.h>

struct tcp_conn {
    int active, syn_seen, synack_seen, hello_seen, server_seen;
    unsigned char client[4], server[4];
    uint16_t client_port, server_port;
    struct timespec syn_time, hello_time;
    double synack_ms, hello_server_ms;
    time_t seen;
};
struct tcp_conn *tcp_track(const unsigned char *src, const unsigned char *dst,
                           uint16_t sport, uint16_t dport, uint8_t flags,
                           const struct timespec *now);
void tcp_track_hello(struct tcp_conn *c, const struct timespec *now, int server);
void tcp_track_reset(void);
#endif
