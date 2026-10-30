#include "../include/arp_parsing.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/select.h>
#include <unistd.h>
#include "../include/packet_logging.h"
#include "../include/port_lock.h"
#include "../include/statistic.h"

#define IFNAME "wlp0s20f3"
#define MAX_SCAN_HOSTS 4096

int main(int argc, char *argv[]) {
    int do_spoof = 0;
    int do_discover = 0;
    int do_all = 0;
    unsigned port_filter = 0;
    const char *target_ip_strs[MAX_SPOOF_TARGETS];
    const char *gateway_ip_str = NULL;
    char generated_targets[MAX_SPOOF_TARGETS][16];
    char generated_gateway[16];
    unsigned char generated_target_macs[MAX_SPOOF_TARGETS][6];
    unsigned char generated_gateway_mac[6];
    int have_scanned_gateway_mac = 0;
    int original_ip_forward = 0;
    int forwarding_state_saved = 0;
    int spoof_lock_fd = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-all") == 0 || strcmp(argv[i], "--all") == 0) {
            do_all = 1;
        } else if (strcmp(argv[i], "--scan") == 0) {
            do_discover = 1;
        } else if (strcmp(argv[i], "--restrict-port") == 0) {
            if (port_filter || i + 1 >= argc || argv[i + 1][0] < '0' || argv[i + 1][0] > '9') {
                fprintf(stderr, "usage: --restrict-port <1-65535>\n"); return 1;
            }
            char *end;
            unsigned long value = strtoul(argv[++i], &end, 10);
            if (*end || value == 0 || value > 65535) {
                fprintf(stderr, "invalid port: %s\n", argv[i]); return 1;
            }
            port_filter = (unsigned)value;
        } else if (strcmp(argv[i], "--spoof") == 0) {
            if (i + 2 >= argc) {
                fprintf(stderr, "usage: --spoof <target-ip> <gateway-ip> [target-ip ...]\n");
                return 1;
            }
            if (do_spoof) {
                fprintf(stderr, "use --spoof once and list all target IPs after the gateway\n");
                return 1;
            }
            target_ip_strs[spoof_count++] = argv[++i];
            gateway_ip_str = argv[++i];
            do_spoof = 1;
            while (i + 1 < argc && argv[i + 1][0] != '-') {
                if (spoof_count == MAX_SPOOF_TARGETS) {
                    fprintf(stderr, "too many targets (maximum %d)\n", MAX_SPOOF_TARGETS);
                    return 1;
                }
                target_ip_strs[spoof_count++] = argv[++i];
            }
        }
    }

    if (do_all && (do_discover || do_spoof)) {
        fprintf(stderr, "-all cannot be combined with --scan or --spoof\n");
        return 1;
    }

    if (do_discover && do_spoof) {
        fprintf(stderr, "--scan cannot be combined with --spoof\n");
        return 1;
    }
    if (port_filter && (do_all || do_spoof || do_discover)) {
        fprintf(stderr, "--restrict-port cannot be combined with scan or spoof modes\n");
        return 1;
    }

    if (do_discover) {
        int ifindex = (int)if_nametoindex(IFNAME);
        if (ifindex == 0) { fprintf(stderr, "unknown interface: %s\n", IFNAME); return 1; }
        struct discovered_host found[MAX_SCAN_HOSTS];
        return discover_hosts(IFNAME, ifindex, found, MAX_SCAN_HOSTS) < 0 ? 1 : 0;
    }

    if (do_all) {
        int ifindex = (int)if_nametoindex(IFNAME);
        unsigned char our_ip[4], gateway_ip[4];
        struct discovered_host found[MAX_SCAN_HOSTS];
        if (ifindex == 0) { fprintf(stderr, "unknown interface: %s\n", IFNAME); return 1; }
        if (!get_own_ip(IFNAME, our_ip) || !get_default_gateway(IFNAME, gateway_ip)) return 1;
        int found_count = discover_hosts(IFNAME, ifindex, found, MAX_SCAN_HOSTS);
        if (found_count < 0) return 1;
        for (int i = 0; i < found_count; i++) {
            if (memcmp(found[i].ip, our_ip, 4) == 0) continue;
            if (memcmp(found[i].ip, gateway_ip, 4) == 0) {
                memcpy(generated_gateway_mac, found[i].mac, 6);
                have_scanned_gateway_mac = 1;
                continue;
            }
            if (spoof_count == MAX_SPOOF_TARGETS) {
                fprintf(stderr, "-all found more than %d client targets; refusing to start\n",
                        MAX_SPOOF_TARGETS);
                return 1;
            }
            snprintf(generated_targets[spoof_count], sizeof generated_targets[spoof_count],
                     "%u.%u.%u.%u", found[i].ip[0], found[i].ip[1],
                     found[i].ip[2], found[i].ip[3]);
            target_ip_strs[spoof_count] = generated_targets[spoof_count];
            memcpy(generated_target_macs[spoof_count], found[i].mac, 6);
            spoof_count++;
        }
        if (spoof_count == 0) {
            fprintf(stderr, "no reachable client targets found\n");
            return 0;
        }
        snprintf(generated_gateway, sizeof generated_gateway, "%u.%u.%u.%u",
                 gateway_ip[0], gateway_ip[1], gateway_ip[2], gateway_ip[3]);
        gateway_ip_str = generated_gateway;
        printf("\nTargets to spoof:\n");
        for (size_t i = 0; i < spoof_count; i++) printf("%s\n", target_ip_strs[i]);
        fflush(stdout);
        do_spoof = 1;
        fprintf(stderr, "[arp] -all selected %zu client target(s); gateway %s excluded\n",
                spoof_count, gateway_ip_str);
    }

    if (do_spoof) {
        unsigned char gateway_ip[4], target_ip[4];
        if (!parse_ipv4(gateway_ip_str, gateway_ip)) {
            fprintf(stderr, "bad gateway IP: %s\n", gateway_ip_str); return 1;
        }
        for (size_t i = 0; i < spoof_count; i++) {
            if (!parse_ipv4(target_ip_strs[i], target_ip)) {
                fprintf(stderr, "bad target IP: %s\n", target_ip_strs[i]); return 1;
            }
            if (memcmp(target_ip, gateway_ip, sizeof target_ip) == 0) {
                fprintf(stderr, "target IP cannot be the gateway IP\n"); return 1;
            }
            for (size_t j = 0; j < i; j++) {
                unsigned char previous_ip[4];
                if (!parse_ipv4(target_ip_strs[j], previous_ip)) return 1;
                if (memcmp(target_ip, previous_ip, sizeof target_ip) == 0) {
                    fprintf(stderr, "duplicate target IP: %s\n", target_ip_strs[i]); return 1;
                }
            }
        }
    }

    if (do_spoof) {
        spoof_lock_fd = open("/run/lock/netwatch-spoof.lock", O_CREAT | O_RDWR, 0600);
        if (spoof_lock_fd < 0) {
            perror("open spoof lock");
            return 1;
        }
        if (flock(spoof_lock_fd, LOCK_EX | LOCK_NB) < 0) {
            fprintf(stderr, "another netwatch spoof process is already running\n");
            close(spoof_lock_fd);
            return 1;
        }
    }

    signal(SIGINT, sigint_handler);

    int sockfd = open_raw_socket(IFNAME);
    if (sockfd == -1) return 1;
    if (do_spoof || port_filter) {
        struct timeval receive_timeout = { .tv_sec = 1, .tv_usec = 0 };
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
                       &receive_timeout, sizeof receive_timeout) < 0) {
            perror("setsockopt (capture timeout)"); close(sockfd); return 1;
        }
    }

    int ifindex = (int)if_nametoindex(IFNAME);
    FILE *logfile = fopen("netwatch.log", "w");
    if (!logfile) { perror("fopen"); close(sockfd); return 1; }
    setvbuf(logfile, NULL, _IOLBF, 0);
    int port_control = -1;
    pid_t port_watcher = -1;
    if (port_filter && !port_lock_start(port_filter, &port_control, &port_watcher)) {
        fclose(logfile); close(sockfd); return 1;
    }
    if (port_filter) fprintf(stderr, "[port] outgoing TCP from local port %u allowed; DNS and existing connections remain available; Ctrl+C restores access\n", port_filter);

    int arp_sockfd = -1;
    if (do_spoof) {
        fprintf(stderr,
            "=== WARNING ===\n"
            "ARP spoofing mode. Use only on YOUR OWN network\n"
            "against YOUR OWN devices.\n"
            "===============\n\n");

        unsigned char our_mac[6], our_ip[4], gateway_ip[4], gateway_mac[6];
        if (!parse_ipv4(gateway_ip_str, gateway_ip) ||
            !get_own_mac(IFNAME, our_mac) || !get_own_ip(IFNAME, our_ip)) return 1;

        fprintf(stderr, "[arp] our MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                our_mac[0], our_mac[1], our_mac[2], our_mac[3], our_mac[4], our_mac[5]);
        fprintf(stderr, "[arp] our IP:  %u.%u.%u.%u\n",
                our_ip[0], our_ip[1], our_ip[2], our_ip[3]);

        arp_sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (arp_sockfd < 0) { perror("socket (ARP)"); return 1; }

        fprintf(stderr, "[arp] resolving gateway %s ...\n", gateway_ip_str);
        if (do_all && have_scanned_gateway_mac) {
            memcpy(gateway_mac, generated_gateway_mac, sizeof gateway_mac);
        } else if (!arp_resolve(arp_sockfd, ifindex, our_mac, our_ip,
                                gateway_ip, gateway_mac)) {
            fprintf(stderr, "could not resolve gateway MAC\n"); return 1;
        }
        fprintf(stderr, "[arp] gateway MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                gateway_mac[0], gateway_mac[1], gateway_mac[2],
                gateway_mac[3], gateway_mac[4], gateway_mac[5]);

        for (size_t i = 0; i < spoof_count; i++) {
            struct arp_spoof_ctx *ctx = &spoof_ctx[i];
            ctx->sockfd = arp_sockfd;
            memcpy(ctx->our_mac, our_mac, sizeof our_mac);
            memcpy(ctx->our_ip, our_ip, sizeof our_ip);
            memcpy(ctx->gateway_ip, gateway_ip, sizeof gateway_ip);
            memcpy(ctx->gateway_mac, gateway_mac, sizeof gateway_mac);
            if (!parse_ipv4(target_ip_strs[i], ctx->target_ip)) return 1;
            if (do_all) {
                memcpy(ctx->target_mac, generated_target_macs[i], sizeof ctx->target_mac);
            } else {
                fprintf(stderr, "[arp] resolving target %s ...\n", target_ip_strs[i]);
                if (!arp_resolve(arp_sockfd, ifindex, our_mac, our_ip,
                                 ctx->target_ip, ctx->target_mac)) {
                    fprintf(stderr, "could not resolve target %s\n", target_ip_strs[i]); return 1;
                }
            }
            fprintf(stderr, "[arp] target %s MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    target_ip_strs[i], ctx->target_mac[0], ctx->target_mac[1],
                    ctx->target_mac[2], ctx->target_mac[3], ctx->target_mac[4],
                    ctx->target_mac[5]);
        }

        // Enable IP forwarding so we don't black-hole traffic
        if (!get_ip_forward(&original_ip_forward)) return 1;
        forwarding_state_saved = 1;
        if (!original_ip_forward && !set_ip_forward(1)) return 1;

        for (size_t i = 0; i < spoof_count; i++) spoof_ctx[i].active = 1;
        for (size_t i = 0; i < spoof_count; i++) arp_spoof_tick(&spoof_ctx[i], ifindex);
        fprintf(stderr, "[arp] spoofing %zu target(s) — press Ctrl+C to stop and restore\n\n",
                spoof_count);
    }

    unsigned char buffer[65535];
    time_t last_print = time(NULL);
    time_t last_spoof = time(NULL);

    while (running) {
        ssize_t rec = recieve_packet(sockfd, buffer, sizeof(buffer));
        if (rec < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) continue;
        if (rec > 0) log_packet(logfile, buffer, rec, port_filter);

        time_t now = time(NULL);
        if (now - last_print > 10) { stats_print(stdout); last_print = now; }

        if (do_spoof && now - last_spoof >= 2) {
            for (size_t i = 0; i < spoof_count; i++)
                arp_spoof_tick(&spoof_ctx[i], ifindex);
            last_spoof = now;
        }
    }

    if (do_spoof) {
        arp_restore_all(spoof_ctx, spoof_count, ifindex);
        if (forwarding_state_saved && !original_ip_forward) set_ip_forward(0);
        close(arp_sockfd);
    }

    fclose(logfile);
    close(sockfd);
    if (port_filter && !port_lock_stop(port_control, port_watcher)) return 1;
    if (spoof_lock_fd >= 0) close(spoof_lock_fd);
    fprintf(stderr, "[netwatch] clean shutdown\n");
    return 0;
}
