#ifndef ARP_PARSING_H
#define ARP_PARSING_H

#include <signal.h>
#include <stddef.h>

#define MAX_SPOOF_TARGETS 64
struct arp_spoof_ctx {
    int sockfd;
    unsigned char our_mac[6];
    unsigned char our_ip[4];
    unsigned char target_mac[6];
    unsigned char target_ip[4];
    unsigned char gateway_mac[6];
    unsigned char gateway_ip[4];
    int active;
};
struct discovered_host {
    unsigned char ip[4];
    unsigned char mac[6];
};
extern struct arp_spoof_ctx spoof_ctx[MAX_SPOOF_TARGETS];
extern size_t spoof_count;
extern volatile sig_atomic_t running;

int get_own_mac(const char *ifname, unsigned char *mac);
int get_own_ip(const char *ifname, unsigned char *ip);
int parse_ipv4(const char *s, unsigned char *ip);
int get_default_gateway(const char *ifname, unsigned char gateway_ip[4]);
int arp_resolve(int sockfd, int ifindex,
			const unsigned char *our_mac, const unsigned char *our_ip,
			const unsigned char *target_ip, unsigned char *target_mac);
int discover_hosts(const char *ifname, int ifindex,
			struct discovered_host found[], size_t capacity);
void arp_restore_all(struct arp_spoof_ctx *ctxs, size_t count, int ifindex);
void arp_spoof_tick(struct arp_spoof_ctx *ctx, int ifindex);
int get_ip_forward(int *enabled);
int set_ip_forward(int enabled);
void sigint_handler(int sig);

#endif
