#include "../include/tls_json.h"

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
void tls_json_write(FILE *f, const struct tls_event *ev,
                    const unsigned char *src, const unsigned char *dst,
                    uint16_t sport, uint16_t dport, const struct timespec *ts,
                    double synack_ms, double hello_server_ms) {
    if (!f) return;
    fprintf(f, "{\"ts\":%lld.%09ld,\"src\":\"%u.%u.%u.%u\",\"dst\":\"%u.%u.%u.%u\",\"sport\":%u,\"dport\":%u,\"dir\":\"%s\"",
            (long long)ts->tv_sec, ts->tv_nsec,
            src[0], src[1], src[2], src[3], dst[0], dst[1], dst[2], dst[3],
            sport, dport, ev->direction ? "s2c" : "c2s");
    switch (ev->type) {
    case TLS_CLIENT_HELLO: {
        const struct tls_client_hello *c = &ev->data.client;
        fputs(",\"event\":\"client_hello\"", f);
        if (c->sni[0]) { fputs(",\"sni\":", f); string(f, c->sni); }
        list(f, "versions", c->versions, c->num_versions);
        list(f, "ciphers", c->ciphers, c->num_ciphers);
        list(f, "groups", c->groups, c->num_groups);
        list(f, "sig_algs", c->sig_algs, c->num_sig_algs);
        list(f, "key_shares", c->key_shares, c->num_key_shares);
        fputs(",\"alpn\":[", f);
        for (size_t i = 0; i < c->num_alpn; i++) { if (i) fputc(',', f); string(f, c->alpn[i]); }
        fputc(']', f);
        break;
    }
    case TLS_SERVER_HELLO: {
        const struct tls_server_hello *s = &ev->data.server;
        fprintf(f, ",\"event\":\"server_hello\",\"legacy_version\":\"0x%04x\",\"version\":\"0x%04x\",\"cipher\":\"0x%04x\"",
                s->legacy_version, s->version ? s->version : s->legacy_version, s->cipher);
        if (s->has_key_share) fprintf(f, ",\"key_share_group\":\"0x%04x\"", s->key_share_group);
        break;
    }
    case TLS_CCS: fputs(",\"event\":\"change_cipher_spec\"", f); break;
    case TLS_ALERT:
        fprintf(f, ",\"event\":\"alert\",\"level\":%u,\"desc\":%u",
                ev->data.alert.level, ev->data.alert.description);
        break;
    case TLS_ENCRYPTED_RECORD:
        fprintf(f, ",\"event\":\"encrypted_record\",\"length\":%u", ev->length);
        break;
    }
    if (synack_ms > 0) fprintf(f, ",\"syn_to_synack_ms\":%.3f", synack_ms);
    if (hello_server_ms > 0) fprintf(f, ",\"client_to_server_hello_ms\":%.3f", hello_server_ms);
    fputs("}\n", f);
}
