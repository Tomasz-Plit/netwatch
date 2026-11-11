#include "../include/tls_json.h"
#include <arpa/inet.h>

static void string(FILE *f, const char *s) {
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '"' || *p == '\\') fprintf(f, "\\%c", *p);
        else if (*p < 32) fprintf(f, "\\u%04x", *p);
        else fputc(*p, f);
    }
    fputc('"', f);
}
static void list(FILE *f, const char *name, const uint16_t *items, size_t n) {
    fprintf(f, ",\"%s\":[", name);
    for (size_t i = 0; i < n; i++) fprintf(f, "%s\"0x%04x\"", i ? "," : "", items[i]);
    fputc(']', f);
}

/* Common IANA TLS parameters. Unknown values stay available as hex codes. */
struct tls_name { uint16_t id; const char *name; };
static const struct tls_name versions[] = {
    {0x0301, "TLS 1.0"}, {0x0302, "TLS 1.1"}, {0x0303, "TLS 1.2"}, {0x0304, "TLS 1.3"}
};
static const struct tls_name ciphers[] = {
    {0x1301, "TLS_AES_128_GCM_SHA256"}, {0x1302, "TLS_AES_256_GCM_SHA384"},
    {0x1303, "TLS_CHACHA20_POLY1305_SHA256"}, {0x1304, "TLS_AES_128_CCM_SHA256"},
    {0x1305, "TLS_AES_128_CCM_8_SHA256"},
    {0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
    {0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
    {0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
    {0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
    {0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
    {0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
    {0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256"}, {0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384"},
    {0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA"}, {0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"}
};
static const struct tls_name groups[] = {
    {0x0017, "secp256r1"}, {0x0018, "secp384r1"}, {0x0019, "secp521r1"},
    {0x001d, "x25519"}, {0x001e, "x448"}, {0x0100, "ffdhe2048"},
    {0x0101, "ffdhe3072"}, {0x0102, "ffdhe4096"}, {0x0103, "ffdhe6144"},
    {0x0104, "ffdhe8192"}, {0x11ec, "X25519MLKEM768"}
};
static const struct tls_name signatures[] = {
    {0x0201, "rsa_pkcs1_sha1"}, {0x0203, "ecdsa_sha1"},
    {0x0401, "rsa_pkcs1_sha256"}, {0x0501, "rsa_pkcs1_sha384"}, {0x0601, "rsa_pkcs1_sha512"},
    {0x0403, "ecdsa_secp256r1_sha256"}, {0x0503, "ecdsa_secp384r1_sha384"},
    {0x0603, "ecdsa_secp521r1_sha512"}, {0x0804, "rsa_pss_rsae_sha256"},
    {0x0805, "rsa_pss_rsae_sha384"}, {0x0806, "rsa_pss_rsae_sha512"},
    {0x0807, "ed25519"}, {0x0808, "ed448"}, {0x0809, "rsa_pss_pss_sha256"},
    {0x080a, "rsa_pss_pss_sha384"}, {0x080b, "rsa_pss_pss_sha512"}
};
#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static const char *lookup(uint16_t id, const struct tls_name *table, size_t count) {
    if ((id & 0x0f0f) == 0x0a0a && (id >> 8) == (id & 0xff)) return "GREASE";
    for (size_t i = 0; i < count; i++) if (table[i].id == id) return table[i].name;
    return NULL;
}

static void named_list(FILE *f, const char *name, const uint16_t *items, size_t n,
                       const struct tls_name *table, size_t count) {
    list(f, name, items, n);
    fprintf(f, ",\"%s_names\":[", name);
    for (size_t i = 0; i < n; i++) {
        if (i) fputc(',', f);
        const char *value = lookup(items[i], table, count);
        if (value) string(f, value); else fputs("null", f);
    }
    fputc(']', f);
}
void hostname_json_write(FILE *f, const char *hostname, int family,
                         const unsigned char *src, const unsigned char *dst,
                         uint16_t sport, uint16_t dport, const struct timespec *ts) {
    if (!f || !hostname || !*hostname) return;
    char source[INET6_ADDRSTRLEN], destination[INET6_ADDRSTRLEN];
    if (!inet_ntop(family, src, source, sizeof source) || !inet_ntop(family, dst, destination, sizeof destination)) return;
    fprintf(f, "{\"event\":\"quic_hostname\",\"ts\":%lld.%09ld,\"src\":\"%s\",\"dst\":\"%s\",\"sport\":%u,\"dport\":%u,\"sni\":",
            (long long)ts->tv_sec, ts->tv_nsec, source, destination, sport, dport);
    string(f, hostname);
    fputs("}\n", f);
}
static void write_event(FILE *f, const struct tls_event *ev, int family,
                    const unsigned char *src, const unsigned char *dst,
                    uint16_t sport, uint16_t dport, const struct timespec *ts,
                    double synack_ms, double hello_server_ms, int quic) {
    if (!f) return;
    char src_text[INET6_ADDRSTRLEN], dst_text[INET6_ADDRSTRLEN];
    if (!inet_ntop(family, src, src_text, sizeof src_text) || !inet_ntop(family, dst, dst_text, sizeof dst_text)) return;
    fprintf(f, "{\"ts\":%lld.%09ld,\"src\":\"%s\",\"dst\":\"%s\",\"sport\":%u,\"dport\":%u,\"dir\":\"%s\"",
            (long long)ts->tv_sec, ts->tv_nsec, src_text, dst_text, sport, dport, ev->direction ? "s2c" : "c2s");
    if (quic) fputs(",\"transport\":\"QUIC\"", f);
    switch (ev->type) {
    case TLS_CLIENT_HELLO: {
        const struct tls_client_hello *c = &ev->data.client;
        fputs(",\"event\":\"client_hello\"", f);
        if (c->sni[0]) { fputs(",\"sni\":", f); string(f, c->sni); }
        named_list(f, "versions", c->versions, c->num_versions, versions, COUNT(versions));
        named_list(f, "ciphers", c->ciphers, c->num_ciphers, ciphers, COUNT(ciphers));
        named_list(f, "groups", c->groups, c->num_groups, groups, COUNT(groups));
        named_list(f, "sig_algs", c->sig_algs, c->num_sig_algs, signatures, COUNT(signatures));
        named_list(f, "key_shares", c->key_shares, c->num_key_shares, groups, COUNT(groups));
        fputs(",\"alpn\":[", f);
        for (size_t i = 0; i < c->num_alpn; i++) { if (i) fputc(',', f); string(f, c->alpn[i]); }
        fputc(']', f);
        break;
    }
    case TLS_SERVER_HELLO: {
        const struct tls_server_hello *s = &ev->data.server;
        fprintf(f, ",\"event\":\"server_hello\",\"legacy_version\":\"0x%04x\",\"version\":\"0x%04x\",\"cipher\":\"0x%04x\"",
                s->legacy_version, s->version ? s->version : s->legacy_version, s->cipher);
        const char *version_name = lookup(s->version ? s->version : s->legacy_version, versions, COUNT(versions));
        const char *cipher_name = lookup(s->cipher, ciphers, COUNT(ciphers));
        if (version_name) { fputs(",\"version_name\":", f); string(f, version_name); }
        if (cipher_name) { fputs(",\"cipher_name\":", f); string(f, cipher_name); }
        if (s->has_key_share) fprintf(f, ",\"key_share_group\":\"0x%04x\"", s->key_share_group);
        const char *group_name = s->has_key_share ? lookup(s->key_share_group, groups, COUNT(groups)) : NULL;
        if (group_name) { fputs(",\"key_share_group_name\":", f); string(f, group_name); }
        break;
    }
    case TLS_CCS: fputs(",\"event\":\"change_cipher_spec\"", f); break;
    case TLS_ALERT:
        fprintf(f, ",\"event\":\"alert\",\"level\":%u,\"desc\":%u",
                ev->data.alert.level, ev->data.alert.description);
        break;
    case TLS_ENCRYPTED_RECORD:
        fprintf(f, ",\"event\":\"encrypted_record\",\"length\":%u,\"direction_bytes\":%llu,\"direction_records\":%llu",
                ev->length, (unsigned long long)ev->total_bytes, (unsigned long long)ev->total_records);
        break;
    }
    if (synack_ms > 0) fprintf(f, ",\"syn_to_synack_ms\":%.3f", synack_ms);
    if (hello_server_ms > 0) fprintf(f, ",\"client_to_server_hello_ms\":%.3f", hello_server_ms);
    fputs("}\n", f);
}

void tls_json_write_ip(FILE *f, const struct tls_event *ev, int family,
                       const unsigned char *src, const unsigned char *dst,
                       uint16_t sport, uint16_t dport, const struct timespec *ts,
                       double synack_ms, double hello_server_ms) {
    write_event(f, ev, family, src, dst, sport, dport, ts, synack_ms, hello_server_ms, 0);
}

void quic_json_write_ip(FILE *f, const struct tls_event *ev, int family,
                        const unsigned char *src, const unsigned char *dst,
                        uint16_t sport, uint16_t dport, const struct timespec *ts) {
    write_event(f, ev, family, src, dst, sport, dport, ts, 0, 0, 1);
}

void tls_json_write(FILE *f, const struct tls_event *ev, const unsigned char *src, const unsigned char *dst, uint16_t sport, uint16_t dport, const struct timespec *ts, double synack_ms, double hello_server_ms) { tls_json_write_ip(f, ev, AF_INET, src, dst, sport, dport, ts, synack_ms, hello_server_ms); }
