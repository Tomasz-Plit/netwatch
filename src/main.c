#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <sys/socket.h>
#include <bits/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/types.h>
#include <unistd.h>

// ===================== config and data types =====================

#define MAX_DUMP 256
#define CH_MAX 4096
#define MAX_HOSTS 256

static struct {
    unsigned char dcid[20];
    size_t dcid_len;
    unsigned char data[CH_MAX];
    unsigned char have[CH_MAX];
    int done;
} ch;

struct quic_initial {
    uint32_t version;
    const unsigned char *dcid; 
    size_t dcid_len;
    size_t pn_offset;
    uint64_t length;
};

struct quic_keys{
    unsigned char key[16];
    unsigned char iv[12];
    unsigned char hp[16];
};

struct host_stat{
    char name[256];
    unsigned long count;
    time_t last_seen;
};

static struct host_stat hosts[MAX_HOSTS];
static size_t nhosts;

// ===================== helpers: byte readers =====================

static uint16_t rd16(const unsigned char *p){ return (p[0] << 8) | p[1]; }
static uint32_t rd32(const unsigned char *p){
    return ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3]);
}
// ===================== capture: raw socket =====================

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
    if(rec == -1) {perror("recvfrom");}
    return rec;
}
// ===================== output helpers =====================

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
// ----- helper: QUIC variant -----

static int read_variant(const unsigned char *p, size_t len, size_t *pos, uint64_t *out){
    if (*pos >= len) return 0;
    size_t n = (size_t)1 << (p[*pos] >> 6);          // 1, 2, 4 or 8 bytes
    if (*pos + n > len) return 0;
    uint64_t v = p[*pos] & 0x3f;                     // drop the 2 length bits
    for (size_t k = 1; k < n; k++) v = (v << 8) | p[*pos + k];
    *pos += n;
    *out = v;
    return 1;
}
// ===================== QUIC (Initial packets) =====================

static int parse_quic_initial(const unsigned char *p, size_t len, struct quic_initial *q){
    if (len < 7) return 0;
    if ((p[0] & 0xC0) != 0xC0) return 0;             
    if (((p[0] >> 4) & 3) != 0) return 0;            
    q->version = rd32(p + 1);
    if (q->version != 1) return 0;                   // We do not process any other versions at least for now

    size_t i = 5;
    size_t dcil = p[i++];
    if (dcil > 20 || i + dcil + 1 > len) return 0;
    q->dcid = p + i;  q->dcid_len = dcil;
    i += dcil;

    size_t scil = p[i++];
    if (scil > 20 || i + scil > len) return 0;
    i += scil;

    uint64_t tok;
    if (!read_variant(p, len, &i, &tok) || tok > len - i) return 0;
    i += tok;

    if (!read_variant(p, len, &i, &q->length)) return 0;
    if (q->length > len - i) return 0;               
    q->pn_offset = i;
    return 1;
}

static int hkdf_expand_label(const unsigned char *secret, const char *label, unsigned char *out, size_t outlen) {
    unsigned char info[64];
    size_t ll = strlen(label), n = 0;

    info[n++] = 0;                       // output length, high byte
    info[n++] = (unsigned char)outlen;   // output length, low byte
    info[n++] = (unsigned char)(6 + ll); // length of "tls13 " + label
    memcpy(info + n, "tls13 ", 6); n += 6;
    memcpy(info + n, label, ll);   n += ll;
    info[n++] = 0;                       // empty context
    info[n++] = 1;                       // HKDF-Expand counter

    unsigned char t[32];
    unsigned int tl = 0;
    if (!HMAC(EVP_sha256(), secret, 32, info, n, t, &tl)) return 0;
    memcpy(out, t, outlen);
    return 1;
}

static int derive_initial_keys(const unsigned char *dcid, size_t dcid_len, struct quic_keys *k) {
    static const unsigned char salt[20] = {
        0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,
        0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a };   // QUIC v1 salt
    
    
    unsigned char initial[32], client[32];
    unsigned int len = 0;


    if (!HMAC(EVP_sha256(), salt, sizeof salt, dcid, dcid_len, initial, &len)) return 0;
    if (!hkdf_expand_label(initial, "client in", client, 32)) return 0;
    if (!hkdf_expand_label(client, "quic key", k->key, 16)) return 0;
    if (!hkdf_expand_label(client, "quic iv",  k->iv,  12)) return 0;
    if (!hkdf_expand_label(client, "quic hp",  k->hp,  16)) return 0;
    return 1;
}

static int quic_unprotect_header(const unsigned char *p, size_t len, const struct quic_initial *q,
            const unsigned char *hp, unsigned char *first, size_t *pn_len, uint32_t *pn) {
    if (q->length < 20) return 0;                    // 4 (max pn) + 16 (sample)
    size_t sample_off = q->pn_offset + 4;
    if (sample_off + 16 > len) return 0;

    unsigned char mask[16];
    int outl = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, hp, NULL)
          && EVP_CIPHER_CTX_set_padding(ctx, 0)
          && EVP_EncryptUpdate(ctx, mask, &outl, p + sample_off, 16)
          && outl == 16;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return 0;

    *first  = p[0] ^ (mask[0] & 0x0f);
    *pn_len = (size_t)(*first & 0x03) + 1;

    uint32_t v = 0;
    for (size_t i = 0; i < *pn_len; i++)
        v = (v << 8) | (p[q->pn_offset + i] ^ mask[1 + i]);
    *pn = v;
    return 1;
}

static int quic_decrypt_initial(const unsigned char *p, size_t len, const struct quic_initial *q,
            const struct quic_keys *k,unsigned char first, size_t pn_len, uint32_t pn,
            unsigned char *out, size_t outsz, size_t *out_len) {
    size_t hdr_len = q->pn_offset + pn_len;           // header ends after the packet number
    if (hdr_len > 512 || hdr_len > len) return 0;
    if (q->length < pn_len + 16) return 0;            
    size_t ct_len = q->length - pn_len - 16;
    if (ct_len > outsz) return 0;
    if (hdr_len + ct_len + 16 > len) return 0;

    // 1. nonce = iv XOR packet number
    unsigned char nonce[12];
    memcpy(nonce, k->iv, 12);
    for (int i = 0; i < 4; i++)
        nonce[11 - i] ^= (unsigned char)(pn >> (8 * i));

    // 2. AAD = header with the real first byte and real packet number
    unsigned char aad[512];
    memcpy(aad, p, hdr_len);
    aad[0] = first;
    for (size_t i = 0; i < pn_len; i++)
        aad[q->pn_offset + pn_len - 1 - i] = (unsigned char)(pn >> (8 * i));

    // 3. ciphertext and tag
    const unsigned char *ct  = p + hdr_len;
    unsigned char tag[16];
    memcpy(tag, ct + ct_len, 16);

    // 4. AES-128-GCM decrypt
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int l = 0, l2 = 0;
    int ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)
          && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)
          && EVP_DecryptInit_ex(ctx, NULL, NULL, k->key, nonce)
          && EVP_DecryptUpdate(ctx, NULL, &l, aad, (int)hdr_len)
          && EVP_DecryptUpdate(ctx, out, &l, ct, (int)ct_len)
          && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)
          && EVP_DecryptFinal_ex(ctx, out + l, &l2) > 0;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return 0;

    *out_len = (size_t)(l + l2);
    return 1;
}
// ===================== TLS / SNI =====================

static int extract_sni_hs(const unsigned char *p, size_t len, char *out, size_t outsz) {
    if (len < 4 + 2 + 32 + 1 || p[0] != 0x01) return 0;   // ClientHello + room for the fixed part
    size_t i = 4 + 2 + 32;                                // handshake header + version + random

    i += 1 + p[i];                                        // session ID
    if (i + 2 > len) return 0;
    i += 2 + rd16(p + i);                                 // cipher suites
    if (i + 1 > len) return 0;
    i += 1 + p[i];                                        // compression methods
    if (i + 2 > len) return 0;
    size_t end = i + 2 + rd16(p + i);                     // end of extensions
    i += 2;
    if (end > len) end = len;                             // ClientHello may be cut off

    while (i + 4 <= end) {
        uint16_t type = rd16(p + i);
        uint16_t elen = rd16(p + i + 2);
        i += 4;
        if (i + elen > end) return 0;

        if (type == 0x0000) {                             // server_name
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

static int extract_sni(const unsigned char *p, size_t len, char *out, size_t outsz) {
    if (len < 9 || p[0] != 0x16 || p[1] != 0x03) return 0;   // TLS record header
    return extract_sni_hs(p + 5, len - 5, out, outsz);       // skip it
}
// ----- QUIC: ClientHello reassembly (needs extract_sni_hs above) -----

static int quic_find_sni(const unsigned char *pl, size_t len,
                         const unsigned char *dcid, size_t dcid_len,
                         char *out, size_t outsz) {
    // new connection (different DCID) -> start over
    if (ch.dcid_len != dcid_len || memcmp(ch.dcid, dcid, dcid_len) != 0) {
        memset(&ch, 0, sizeof ch);
        memcpy(ch.dcid, dcid, dcid_len);
        ch.dcid_len = dcid_len;
    }
    if (ch.done) return 0;

    size_t i = 0;
    while (i < len) {
        uint64_t type;
        if (!read_variant(pl, len, &i, &type)) break;
        if (type == 0x00 || type == 0x01) continue;      // padding, ping
        if (type != 0x06) break;                         // unknown frame: stop

        uint64_t off, clen;
        if (!read_variant(pl, len, &i, &off)) break;
        if (!read_variant(pl, len, &i, &clen)) break;
        if (clen > len - i) break;
        if (off <= CH_MAX && clen <= CH_MAX - off) {     // fits in our buffer
            memcpy(ch.data + off, pl + i, clen);
            memset(ch.have + off, 1, clen);
        }
        i += clen;
    }

    size_t prefix = 0;                                   // bytes received without a gap
    while (prefix < CH_MAX && ch.have[prefix]) prefix++;

    if (extract_sni_hs(ch.data, prefix, out, outsz)) {
        ch.done = 1;
        return 1;
    }
    return 0;
}
// ===================== statistics =====================

static void host_seen(const char *name){
    for(size_t i = 0; i < nhosts; i++){
        if(strcmp(hosts[i].name, name) == 0){
            hosts[i].count++;
            hosts[i].last_seen = time(NULL);
            return;
        }
    }
    if(nhosts == MAX_HOSTS) return;
    snprintf(hosts[nhosts].name, sizeof hosts[nhosts].name, "%s", name);
    hosts[nhosts].count = 1;
    hosts[nhosts].last_seen = time(NULL);
    nhosts++;
}

static void stats_print(FILE *out){
    fprintf(out, "\n === hosts seen: %zu ===\n", nhosts);
    fprintf(out, "%-6s %-40s %s\n", "COUNT", "HOST", "LAST SEEN");
    for (size_t i = 0; i < nhosts; i++) {
        char when[16];
        struct tm tmv;
        localtime_r(&hosts[i].last_seen, &tmv);
        strftime(when, sizeof when, "%H:%M:%S", &tmv);

        fprintf(out, "%-6lu %-40s %s\n", hosts[i].count, hosts[i].name, when);
    fflush(out);
    }    
}
// ===================== packet logging =====================

static void print_macs(FILE *f, const unsigned char *buf){
    fprintf(f, "Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]);
    fprintf(f, "Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
 
}

void log_packet(FILE *f, const unsigned char *buf, ssize_t rec){
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
    // silent filter, ACK provide no vale so we silent them
    if(proto == 6 && frag_of == 0){
        if(total < ihl + 20 || n < 14 + ihl + 20) return;
        size_t thdr = (l4[12] >> 4) * 4;
        if(thdr < 20 || ihl + thdr > total || 14 + ihl + thdr > (size_t)rec) return;
        if(total == ihl + thdr && !(l4[13] & 0x07)) return;  // no data, no SYN/FIN/RST
    }

    print_macs(f, buf);
    fprintf(f, "IP Header: IPv4\n\t");
    fprintf(f, "Header length: %ld\n \tTotal length: %u\n \tTTL: %u\n \tProtocol: %u\n",
        ihl, total, ip[8], proto);
    fprintf(f, "\tid: %u\n \tcheck_sum: %u\n", id, check_sum);
    fprintf(f, "\tSrc IP: %u.%u.%u.%u \n", ip[12], ip[13], ip[14], ip[15]);
    fprintf(f, "\tDst IP: %u.%u.%u.%u \n", ip[16], ip[17], ip[18], ip[19]);
    fprintf(f, "\tFlags: DF:%d MF %d\n", df, mf);
    fprintf(f, "\tFragment offset %u (%u bytes)\n\n", frag_of, frag_of * 8);
    //------------ End of ip -----------
    size_t l4_len = total - ihl;
    size_t hdr = 0;
    const unsigned char *payload = NULL;
    size_t payload_len = 0;
    if(proto == 6){
        hdr = (l4[12] >> 4) * 4;
        if(total < ihl + 20 || ihl + 14 + 20 > rec) return;
        if(hdr < 20 || ihl + hdr > total || 14 + ihl + hdr > rec) return;

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
    // Getting the address in TCP Header
    payload = l4 + hdr;
    if (total < ihl + hdr) return;                  // guard against underflow
    payload_len = total - ihl - hdr;
    size_t avail = (size_t)rec - 14 - ihl - hdr;
    if (payload_len > avail) payload_len = avail;
    if (proto == 6 && payload_len > 0) {
        char host[256];
        if (extract_sni(payload, payload_len, host, sizeof host)){
            fprintf(f, "Website: %s\n", host);
            host_seen(host);
        }
    }
    // Getting the address in UDP Header
    if (proto == 17 && payload_len > 0 && rd16(l4 + 2) == 443) {   // client -> server only
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
                        host_seen(host);
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
// ===================== main =====================

int main(void){
    int sockfd = open_raw_socket("wlp0s20f3");
    if(sockfd == -1) return 1;

    FILE *logfile = fopen("netwatch.log", "w");
    if(!logfile){perror("fopen"); return 1;}
    setvbuf(logfile, NULL, _IOLBF, 0);

    unsigned char buffer[65535];

    time_t last_print = time(NULL);
    while(1){
        ssize_t rec = recieve_packet(sockfd, buffer, sizeof(buffer));  
        if (rec == -1) continue; 
        log_packet(logfile, buffer, rec);

        time_t now = time(NULL);
        if(now - last_print > 10){ stats_print(stdout); last_print = now; }
    }
    return 0;
}