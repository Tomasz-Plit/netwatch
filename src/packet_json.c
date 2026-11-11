#include "../include/packet_json.h"
#include "../include/helpers.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <time.h>

void packet_json_write(FILE *out, const unsigned char *frame, size_t length) {
    if (!out || length < 14) return;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint16_t ether = rd16(frame + 12);
    const char *protocol = "Ethernet";
    char src[INET6_ADDRSTRLEN] = "", dst[INET6_ADDRSTRLEN] = "";
    unsigned sport = 0, dport = 0, operation = 0;
    size_t offset = 14;
    size_t end = length;
    unsigned next = 0;
    if (ether == 0x0806 && length >= 42 && rd16(frame + 14) == 1 &&
        rd16(frame + 16) == 0x0800 && frame[18] == 6 && frame[19] == 4) {
        protocol = "ARP";
        operation = rd16(frame + 20);
        inet_ntop(AF_INET, frame + 28, src, sizeof src);
        inet_ntop(AF_INET, frame + 38, dst, sizeof dst);
    } else if (ether == 0x0800 && length >= 34 && (frame[14] >> 4) == 4) {
        size_t ihl = (frame[14] & 15u) * 4;
        size_t total = rd16(frame + 16);
        if (ihl >= 20 && ihl <= length - 14 && total >= ihl) {
            protocol = "IPv4";
            if (total < end - 14) end = 14 + total;
            inet_ntop(AF_INET, frame + 26, src, sizeof src);
            inet_ntop(AF_INET, frame + 30, dst, sizeof dst);
            next = frame[23];
            if (rd16(frame + 20) & 0x1fff) next = 0;
            offset += ihl;
        }
    } else if (ether == 0x86dd && length >= 54 && (frame[14] >> 4) == 6) {
        protocol = "IPv6";
        size_t total = 40u + rd16(frame + 18);
        if (total < end - 14) end = 14 + total;
        inet_ntop(AF_INET6, frame + 22, src, sizeof src);
        inet_ntop(AF_INET6, frame + 38, dst, sizeof dst);
        next = frame[20];
        offset += 40;
        while ((next == 0 || next == 43 || next == 60 || next == 51) && offset + 2 <= end) {
            size_t ext = next == 51 ? (frame[offset + 1] + 2u) * 4 : (frame[offset + 1] + 1u) * 8;
            if (ext > end - offset) { next = 0; break; }
            next = frame[offset]; offset += ext;
        }
    }
    if ((next == 6 || next == 17) && offset <= end && end - offset >= (next == 6 ? 20u : 8u)) {
        protocol = next == 6 ? "TCP" : "UDP";
        sport = rd16(frame + offset); dport = rd16(frame + offset + 2);
    }
    fprintf(out, "{\"ts\":%lld.%09ld,\"length\":%zu,\"protocol\":\"%s\",\"src\":\"%s\",\"dst\":\"%s\","
            "\"src_mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"dst_mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
            "\"sport\":%u,\"dport\":%u,\"arp_op\":%u,\"hex\":\"",
            (long long)ts.tv_sec, ts.tv_nsec, length, protocol, src, dst,
            frame[6], frame[7], frame[8], frame[9], frame[10], frame[11],
            frame[0], frame[1], frame[2], frame[3], frame[4], frame[5], sport, dport, operation);
    size_t shown = length < 96 ? length : 96;
    for (size_t i = 0; i < shown; i++) fprintf(out, "%02x", frame[i]);
    fputs("\"}\n", out);
}
