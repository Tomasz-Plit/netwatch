#include "../include/packet_logging.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../include/helpers.h"
#include "../include/tls_parsing.h"
#include "../include/tcp_track.h"
#include "../include/tls_json.h"
#include <time.h>
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
    if (rec == -1 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR){
        int saved_errno = errno;
        perror("recvfrom");
        errno = saved_errno;
    }
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

void log_packet(FILE *f, FILE *jsonf, const unsigned char *buf, ssize_t rec, unsigned port_filter){
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    if(rec < 14) return;
    size_t n = (size_t)rec;
    const unsigned char *ip = buf + 14, *src, *dst;
    size_t ihl, total;
    uint8_t proto;
    int family;
    uint16_t frag_of;
    if (rd16(buf + 12) == 0x0800) {
        if (n < 34 || (ip[0] >> 4) != 4) return;
        family = AF_INET; ihl = (ip[0] & 15) * 4; total = rd16(ip + 2);
        if (ihl < 20 || n < 14 + ihl || total < ihl) return;
        proto = ip[9]; src = ip + 12; dst = ip + 16;
        frag_of = rd16(ip + 6) & 0x1fff;
        if (frag_of || (rd16(ip + 6) & 0x2000)) return;
    } else if (rd16(buf + 12) == 0x86dd) {
        if (n < 54 || (ip[0] >> 4) != 6) return;
        family = AF_INET6; ihl = 40; total = 40 + rd16(ip + 4);
        if (total == 40) return; /* IPv6 jumbograms are not supported. */
        proto = ip[6]; src = ip + 8; dst = ip + 24;
        while (proto == 0 || proto == 43 || proto == 60 || proto == 51) {
            if (ihl + 2 > total || 14 + ihl + 2 > n) return;
            size_t ext = proto == 51 ? (ip[ihl + 1] + 2u) * 4 : (ip[ihl + 1] + 1u) * 8;
            if (ext < 8 || ext > total - ihl || ext > n - 14 - ihl) return;
            proto = ip[ihl]; ihl += ext;
        }
        if (proto == 44) return; /* Fragment reassembly is not supported. */
    } else {
        if (!port_filter) { print_macs(f, buf); fprintf(f, "not an IP packet\n\n"); }
        return;
    }
    const unsigned char *l4 = ip + ihl;
    size_t available = n - 14 - ihl;
    size_t ip_payload = total - ihl;
    if (proto == 6) {
        if (ip_payload < 20 || available < 20) return;
        size_t thdr = (l4[12] >> 4) * 4;
        if (thdr < 20 || thdr > ip_payload || thdr > available) return;
        if (ip_payload == thdr && !(l4[13] & 0x07)) return;
    }
    if (port_filter && (proto != 6 || (rd16(l4) != port_filter && rd16(l4 + 2) != port_filter))) return;
    char src_text[INET6_ADDRSTRLEN], dst_text[INET6_ADDRSTRLEN];
    if (!inet_ntop(family, src, src_text, sizeof src_text) ||
        !inet_ntop(family, dst, dst_text, sizeof dst_text)) return;
    print_macs(f, buf);
    fprintf(f, "IP Header: IPv%d\n\tHeader length: %zu\n \tTotal length: %zu\n \t%s: %u\n \tProtocol: %u\n\tSrc IP: %s\n\tDst IP: %s\n",
            family == AF_INET ? 4 : 6, ihl, total, family == AF_INET ? "TTL" : "Hop Limit",
            family == AF_INET ? ip[8] : ip[7], proto, src_text, dst_text);

    struct tcp_conn *conn = NULL;
    size_t hdr = 0;
    const unsigned char *payload = NULL;
    size_t payload_len = 0;

    // TCP HEADER
    if(proto == 6){
        hdr = (l4[12] >> 4) * 4;
        if(total < ihl + 20 || ihl + 14 + 20 > n) return;
        if(hdr < 20 || ihl + hdr > total || 14 + ihl + hdr > n) return;

        uint16_t sport = rd16(l4);
        uint16_t dport = rd16(l4 + 2);
        uint32_t seq = rd32(l4+4);
        uint32_t ack = rd32(l4 + 8);
        uint8_t fl = l4[13];
        conn = tcp_track_ip(family, src, dst, sport, dport, fl, &ts);
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
        struct tls_event events[8];
        size_t count;
        uint32_t next_seq = rd32(l4 + 4) + (uint32_t)payload_len;
        size_t feed_len = payload_len;
        do {
            count = tls_feed_ip(family, src, dst, rd16(l4), rd16(l4 + 2),
                             feed_len ? rd32(l4 + 4) : next_seq, payload, feed_len, events, 8);
            feed_len = 0;
            for (size_t i = 0; i < count; i++) {
                struct tls_event *ev = &events[i];
                switch (ev->type) {
                case TLS_CLIENT_HELLO:
                    fprintf(f, "TLS ClientHello: SNI %s\n", ev->data.client.sni);
                    if (ev->data.client.sni[0]) host_seen_ip(ev->data.client.sni, family, src);
                    tcp_track_hello(conn, &ts, 0);
                    break;
                case TLS_SERVER_HELLO:
                    tcp_track_hello(conn, &ts, 1);
                    fprintf(f, "TLS ServerHello: version 0x%04x, cipher 0x%04x\n",
                            ev->data.server.version ? ev->data.server.version : ev->data.server.legacy_version,
                            ev->data.server.cipher);
                    break;
                case TLS_CCS: fprintf(f, "TLS ChangeCipherSpec\n"); break;
                case TLS_ALERT:
                    fprintf(f, "TLS Alert: level %u, description %u\n",
                            ev->data.alert.level, ev->data.alert.description);
                    break;
                case TLS_ENCRYPTED_RECORD:
                    fprintf(f, "TLS encrypted record: %u bytes (%s)\n", ev->length,
                            ev->direction ? "server to client" : "client to server");
                    break;
                }
                tls_json_write_ip(jsonf, ev, family, src, dst, rd16(l4), rd16(l4 + 2),
                               &ts, conn ? conn->synack_ms : 0,
                               conn ? conn->hello_server_ms : 0);
            }
        } while (count == 8);
    }

    if (proto == 17 && payload_len > 0 && (rd16(l4 + 2) == 443 || rd16(l4) == 443)) {
        struct quic_initial q;
        if (parse_quic_initial(payload, payload_len, &q)) {
            fprintf(f, "QUIC Initial: version %u, DCID length %zu, length field %llu\n",
                    q.version, q.dcid_len, (unsigned long long)q.length);

            struct quic_keys k;
            unsigned char first;
            size_t pn_len;
            uint32_t pn;
            int is_server = (rd16(l4) == 443 && rd16(l4 + 2) != 443);
            const unsigned char *key_dcid = NULL;
            size_t key_dcid_len = 0;
            if (is_server){
                struct ch *slot = quic_server_slot(&q);
                if(slot != NULL){
                    key_dcid = slot->dcid;
                    key_dcid_len = slot->dcid_len;
                }
            } else{
                key_dcid = q.dcid;
                key_dcid_len = q.dcid_len;
            }
            if (key_dcid != NULL && derive_initial_keys(key_dcid, key_dcid_len, is_server, &k) &&
                quic_unprotect_header(payload, payload_len, &q, k.hp, &first, &pn_len, &pn)) {
                fprintf(f, "\tfirst byte 0x%02x, packet number %u (%zu bytes)\n",
                        first, pn, pn_len);

                unsigned char plain[2048];
                size_t plain_len = 0;
                if (quic_decrypt_initial(payload, payload_len, &q, &k, first, pn_len, pn,
                                         plain, sizeof plain, &plain_len)) {
                    if(is_server) fprintf(f, "\tQUIC server Initial decrypted: %zu bytes\n", plain_len);
                    else fprintf(f, "\tQUIC client Initial decrypted: %zu bytes\n", plain_len);
                    print_payload(f, plain, plain_len);
                    if(!is_server){
                        struct tls_event ev = { .type = TLS_CLIENT_HELLO };
                        int found_hello = quic_find_client_hello(plain, plain_len, q.dcid, q.dcid_len, &ev.data.client);
                        quic_client_slot(&q);
                        if (found_hello){
                            if (ev.data.client.sni[0]) {
                                fprintf(f, "Website (QUIC): %s\n", ev.data.client.sni);
                                host_seen_ip(ev.data.client.sni, family, src);
                            }
                            quic_json_write_ip(jsonf, &ev, family, src, dst, rd16(l4), rd16(l4 + 2), &ts);
                        }
                    } else{
                        struct tls_event ev = { .type = TLS_SERVER_HELLO, .direction = 1 };
                        if(quic_find_server_hello(plain, plain_len, &q, &ev.data.server)){
                            fprintf(f, "QUIC ServerHello: version 0x%04x, cipher 0x%04x\n", ev.data.server.version ? ev.data.server.version : ev.data.server.legacy_version, ev.data.server.cipher);
                            quic_json_write_ip(jsonf, &ev, family, src, dst, rd16(l4), rd16(l4 + 2), &ts);
                        }
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
