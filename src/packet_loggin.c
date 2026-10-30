#include "../include/packet_logging.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../include/helpers.h"
#include "../include/tls_parsing.h"
#include "../include/quic_parsing.h"
#include "../include/statistic.h"

#define MAX_DUMP 256

int open_raw_socket(const char *ifname){
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {perror("socket"); close(sockfd); return -1;}
    struct sockaddr_ll address;
    memset(&address, 0, sizeof(address));
    address.sll_family = AF_PACKET;
    address.sll_protocol = htons(ETH_P_ALL);
    address.sll_ifindex = if_nametoindex(ifname);
    if (address.sll_ifindex == 0) { perror("if_nametoindex"); return -1; }
    if (bind(sockfd, (struct sockaddr *)&address, sizeof address) == -1) {
        perror("bind"); close(sockfd);
        return -1;
    }
    return sockfd;
}

ssize_t recieve_packet(int sockfd, unsigned char *buf, size_t size){
    ssize_t rec = recvfrom(
        sockfd, buf, size, 0, NULL, NULL
    );
    if (rec == -1 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
        perror("recvfrom");
    return rec;
}

static void print_payload(FILE *f, const unsigned char *p, size_t len){
    size_t shown = len > MAX_DUMP ? MAX_DUMP : len;

    for(size_t off = 0; off < shown; off += 16){
        fprintf(f, "\t%04zx ", off);

        for(size_t i = 0; i < 16; i++){
            if(off + i < shown) fprintf(f, "%02x ", p[off + i]);
            else                fprintf(f, "   ");
        }

        fprintf(f, " ");
        for(size_t i = 0; i < 16 && off + i < shown; i++){
            unsigned char c = p[off + i];
            fprintf(f, "%c", (c >= 32 && c < 127) ? c : '.');
        }
        fprintf(f, "\n");
    }
    if(len > shown) fprintf(f, "\t... %zu more bytes not shown\n", len - shown);
}

static void print_macs(FILE *f, const unsigned char *buf){
    fprintf(f, "Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]);
    fprintf(f, "Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);

}

void log_packet(FILE *f, const unsigned char *buf, ssize_t rec, unsigned port_filter){
    if(rec < 14) return;
    if(rd16(buf + 12) != 0x0800) {print_macs(f, buf); fprintf(f, "not an IPv4 \n\n"); return;}
    if(rec < 14 + 20) return;
    size_t n = (size_t)rec;
    const unsigned char *ip = buf + 14;
    size_t ihl = (ip[0] & 0x0f) * 4;
    uint16_t total = rd16(ip + 2);
    uint8_t proto = ip[9];
    uint16_t id = rd16(ip + 4);
    uint16_t check_sum = rd16(ip + 10);
    uint16_t flags = rd16(ip + 6);
    int df = (flags >> 14) & 1;
    int mf = (flags >> 13) & 1;
    uint16_t frag_of = flags & 0x1FFF;
    const unsigned char *l4 = ip + ihl;
    if(ihl < 20 || n < 14 + ihl) return;

    if(proto == 6 && frag_of == 0){
        if(total < ihl + 20 || n < 14 + ihl + 20) return;
        size_t thdr = (l4[12] >> 4) * 4;
        if(thdr < 20 || ihl + thdr > total || 14 + ihl + thdr > n) return;
        if(total == ihl + thdr && !(l4[13] & 0x07)) return;
    }
    if (port_filter && (proto != 6 || frag_of != 0 ||
        (rd16(l4) != port_filter && rd16(l4 + 2) != port_filter))) return;

    print_macs(f, buf);
    fprintf(f, "IP Header: IPv4\n\t");
    fprintf(f, "Header length: %ld\n \tTotal length: %u\n \tTTL: %u\n \tProtocol: %u\n",
        ihl, total, ip[8], proto);
    fprintf(f, "\tid: %u\n \tcheck_sum: %u\n", id, check_sum);
    fprintf(f, "\tSrc IP: %u.%u.%u.%u \n", ip[12], ip[13], ip[14], ip[15]);
    fprintf(f, "\tDst IP: %u.%u.%u.%u \n", ip[16], ip[17], ip[18], ip[19]);
    fprintf(f, "\tFlags: DF:%d MF %d\n", df, mf);
    fprintf(f, "\tFragment offset %u (%u bytes)\n\n", frag_of, frag_of * 8);

    size_t hdr = 0;
    const unsigned char *payload = NULL;
    size_t payload_len = 0;
    if(proto == 6){
        hdr = (l4[12] >> 4) * 4;
        if(total < ihl + 20 || ihl + 14 + 20 > n) return;
        if(hdr < 20 || ihl + hdr > total || 14 + ihl + hdr > n) return;

        uint16_t sport = rd16(l4);
        uint16_t dport = rd16(l4 + 2);
        uint32_t seq = rd32(l4+4);
        uint32_t ack = rd32(l4 + 8);
        uint8_t fl = l4[13];
        uint16_t window = rd16(l4 + 14);
        uint16_t tcp_ck = rd16(l4 + 16);
        uint16_t urgent = rd16(l4+18);
        fprintf(f, "TCP Header:\n\t Src port: %u\n\t Dst port: %u\n", sport, dport);
        fprintf(f, "\t Sequence number: %u\n\t Acknowledgement number: %u\n\t Header length: %zu bytes\n",
        seq, ack, hdr);
        fprintf(f, "\t Flags: 0x%02x [%s%s%s%s%s%s%s%s]\n", fl,
            (fl & 0x80) ? "CWR " : "",
            (fl & 0x40) ? "ECE " : "",
            (fl & 0x20) ? "URG " : "",
            (fl & 0x10) ? "ACK " : "",
            (fl & 0x08) ? "PSH " : "",
            (fl & 0x04) ? "RST " : "",
            (fl & 0x02) ? "SYN " : "",
            (fl & 0x01) ? "FIN " : "");
        fprintf(f, "\t Window size: %u\n\t Checksum: 0x%04x\n\t Urgent pointer: %u\n",
            window, tcp_ck, urgent);

        if(hdr > 20){
            fprintf(f, "\tOptions (%zu bytes): ", hdr - 20);
            for(size_t i = 20; i < hdr; i++){
                fprintf(f, "%02x", l4[i]);
            }
            fprintf(f, "\n");
        }
    }
    else if(proto == 17){
        if(total < ihl + 8 || 14 + ihl + 8 > (size_t)rec) return;

        uint16_t sport = rd16(l4);
        uint16_t dport = rd16(l4+ 2);
        uint16_t udp_len = rd16(l4 + 4);
        uint16_t udp_ck = rd16(l4 + 6);

        fprintf(f, "UDP Header: \n\t Src port: %u\n\t Dst port: %u\n\t Length: %u\n\t Checksum: 0x%04x\n",
        sport, dport, udp_len, udp_ck);
        hdr = 8;
    }
    else{
        fprintf(f, "Other protocol: %u (skipped)\n\n", proto);
        fprintf(f, "----------------------------------------------------");
        return;
    }

    payload = l4 + hdr;
    if (total < ihl + hdr) return;
    payload_len = total - ihl - hdr;
    size_t avail = (size_t)rec - 14 - ihl - hdr;
    if (payload_len > avail) payload_len = avail;
    if (proto == 6 && payload_len > 0) {
        char host[256];
        if (extract_sni(payload, payload_len, host, sizeof host)){
            fprintf(f, "Website: %s\n", host);
            host_seen(host, ip + 12);
        }
    }

    if (proto == 17 && payload_len > 0 && rd16(l4 + 2) == 443) {
        struct quic_initial q;
        if (parse_quic_initial(payload, payload_len, &q)) {
            fprintf(f, "QUIC Initial: version %u, DCID length %zu, length field %llu\n",
                    q.version, q.dcid_len, (unsigned long long)q.length);

            struct quic_keys k;
            unsigned char first;
            size_t pn_len;
            uint32_t pn;
            if (derive_initial_keys(q.dcid, q.dcid_len, &k) &&
                quic_unprotect_header(payload, payload_len, &q, k.hp, &first, &pn_len, &pn)) {
                fprintf(f, "\tfirst byte 0x%02x, packet number %u (%zu bytes)\n",
                        first, pn, pn_len);

                unsigned char plain[2048];
                size_t plain_len = 0;
                if (quic_decrypt_initial(payload, payload_len, &q, &k, first, pn_len, pn,
                                         plain, sizeof plain, &plain_len)) {
                    fprintf(f, "\tQUIC decrypted: %zu bytes of frames\n", plain_len);
                    print_payload(f, plain, plain_len);
                    char host[256];
                    if (quic_find_sni(plain, plain_len, q.dcid, q.dcid_len, host, sizeof host)){
                        fprintf(f, "Website (QUIC): %s\n", host);
                        host_seen(host, ip + 12);
                    }
                }
                else {
                    fprintf(f, "\tQUIC decryption failed\n");
                }
            }
        }
    }
    fprintf(f, "Message (%zu bytes):\n", payload_len);
    if(payload_len > 0){
        print_payload(f, payload, payload_len);
    }

    fprintf(f, "\n ---------------------------------------------\n");
    return;
}
