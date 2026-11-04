#include "../include/tls_parsing.h"
#include <stdio.h>
#include <string.h>
#include "../include/helpers.h"
#define MAX_FLOWS 64
#define FLOW_BUFFER 8192

struct tls_flow {
    int active;
    unsigned char src_ip[4], dst_ip[4];
    uint16_t src_port, dst_port;
    uint32_t next_seq;
    unsigned char bytes[FLOW_BUFFER];
    size_t used;
    size_t record_pos;
    unsigned char handshake[FLOW_BUFFER];
    size_t handshake_used;
};
static struct tls_flow flows[MAX_FLOWS];

int extract_sni_hs(const unsigned char *p, size_t len, char *out, size_t outsz) {
    if (len < 4 + 2 + 32 + 1 || p[0] != 0x01) return 0;
    size_t i = 4 + 2 + 32;

    i += 1 + p[i];
    if (i + 2 > len) return 0;
    i += 2 + rd16(p + i);
    if (i + 1 > len) return 0;
    i += 1 + p[i];
    if (i + 2 > len) return 0;
    size_t end = i + 2 + rd16(p + i);
    i += 2;
    if (end > len) end = len;

    while (i + 4 <= end) {
        uint16_t type = rd16(p + i);
        uint16_t elen = rd16(p + i + 2);
        i += 4;
        if (i + elen > end) return 0;

        if (type == 0x0000) {
            if (elen < 5) return 0;
            uint16_t nlen = rd16(p + i + 3);
            if (5 + nlen > elen || nlen >= outsz) return 0;
            for (uint16_t k = 0; k < nlen; k++) {
                unsigned char c = p[i + 5 + k];
                if (c <= 32 || c >= 127) return 0;
            }
            memcpy(out, p + i + 5, nlen);
            out[nlen] = '\0';
            return 1;
        }
        i += elen;
    }
    return 0;
}

int extract_sni(const unsigned char *p, size_t len, char *out, size_t outsz) {
    if (len < 9 || p[0] != 0x16 || p[1] != 0x03) return 0;
    return extract_sni_hs(p + 5, len - 5, out, outsz);
}
static int server_hello(const unsigned char *p, size_t len, char *out, size_t outsz) {
    if (len < 4 + 2 + 32 + 1 + 2 + 1 || p[0] != 0x02) return 0;
    size_t body_len = ((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3];
    if (body_len != len - 4) return 0;

    size_t i = 4;
    uint16_t legacy_version = rd16(p + i);
    i += 2 + 32;
    size_t session_id_len = p[i++];
    if (session_id_len > 32 || session_id_len > len - i) return 0;
    i += session_id_len;
    if (len - i < 3) return 0;
    uint16_t cipher_suite = rd16(p + i);
    i += 2;
    if (p[i++] != 0) return 0;
    if (i < len) {
        if (len - i < 2 || rd16(p + i) != len - i - 2) return 0;
    }
    if (outsz == 0) return 0;
    snprintf(out, outsz, "legacy version 0x%04x, cipher suite 0x%04x",
             legacy_version, cipher_suite);
    return 1;
}

int tls_feed(const unsigned char *src_ip, const unsigned char *dst_ip, uint16_t src_port, uint16_t dst_port, uint32_t seq, const unsigned char *payload,
            size_t payload_len, char *host, size_t host_size){
    struct tls_flow *flow = NULL;
    for (int i = 0; i < MAX_FLOWS; i++) {
        if(flows[i].active && memcmp(flows[i].src_ip, src_ip, 4) == 0 && memcmp(flows[i].dst_ip, dst_ip, 4) == 0 && flows[i].src_port == src_port && flows[i].dst_port == dst_port){
            flow = &flows[i];
            break;
        }
    }
    if(flow == NULL) {
        for(int i = 0; i < MAX_FLOWS; i++){
            if(!flows[i].active) {
                flow = &flows[i];
                memset(flow, 0, sizeof *flow);
                memcpy(flows[i].src_ip, src_ip, 4);
                memcpy(flows[i].dst_ip, dst_ip, 4);
                flow->src_port = src_port;
                flow->dst_port = dst_port;
                flow->next_seq = seq;
                flow->active = 1;
                break;
            }
        }
    }
    if (flow == NULL) return 0;
    if(seq != flow->next_seq) return 0;
    if(payload_len > sizeof flow->bytes - flow->used) {
        flow->active = 0;
        return 0;
    }

    memcpy(flow->bytes + flow->used, payload, payload_len);
    flow->used += payload_len;
    flow->next_seq += (uint32_t)payload_len;

    for (;;) {
        size_t available = flow->used - flow->record_pos;
        if (available < 5) return 0;
        const unsigned char *record = flow->bytes + flow->record_pos;
        if (record[0] != 0x16 || record[1] != 0x03) {
            flow->active = 0;
            return 0;
        }
        size_t record_len = rd16(record + 3);
        if (record_len > sizeof flow->handshake - flow->handshake_used) {
            flow->active = 0;
            return 0;
        }
        if (available < 5 + record_len) return 0;
        memcpy(flow->handshake + flow->handshake_used, record + 5, record_len);
        flow->handshake_used += record_len;
        flow->record_pos += 5 + record_len;

        if (flow->handshake_used < 4) continue;
        const unsigned char *msg = flow->handshake;
        size_t msg_len = ((size_t)msg[1] << 16) | ((size_t)msg[2] << 8) | msg[3];
        if (msg_len > sizeof flow->handshake - 4) {
            flow->active = 0;
            return 0;
        }
        if (flow->handshake_used < 4 + msg_len) continue;

        int result = 0;
        if (msg[0] == 0x01)
            result = extract_sni_hs(msg, 4 + msg_len, host, host_size) ? 1 : 0;
        else if (msg[0] == 0x02)
            result = server_hello(msg, 4 + msg_len, host, host_size) ? 2 : 0;
        flow->active = 0;
        return result;
    }
}
