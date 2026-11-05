#include "../include/tls_parsing.h"
#include "../include/helpers.h"
#include <string.h>
#include <time.h>

#define MAX_FLOWS 64
#define BUFFER 18432
#define IDLE_SECONDS 120

struct stream {
    uint32_t next_seq;
    int seq_set;
    unsigned char bytes[BUFFER], handshake[BUFFER];
    size_t used, hs_used;
};
struct flow {
    int active;
    unsigned char client[4], server[4];
    uint16_t client_port, server_port;
    time_t seen;
    struct stream dir[2];
    uint64_t bytes[2], records[2];
};
static struct flow flows[MAX_FLOWS];

void tls_reset_all(void) { memset(flows, 0, sizeof flows); }

static int list16(const unsigned char *p, size_t n, uint16_t *out, size_t cap, size_t *count) {
    if (n < 2 || rd16(p) != n - 2 || ((n - 2) & 1)) return 0;
    *count = 0;
    for (size_t i = 2; i < n && *count < cap; i += 2) out[(*count)++] = rd16(p + i);
    return 1;
}

static int client_hello(const unsigned char *p, size_t n, struct tls_client_hello *ch) {
    if (n < 4 + 2 + 32 + 1 || p[0] != 1 ||
        (((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3]) != n - 4) return 0;
    memset(ch, 0, sizeof *ch);
    size_t i = 4 + 2 + 32;
    size_t sid = p[i++];
    if (sid > 32 || sid > n - i || n - i - sid < 2) return 0;
    i += sid;
    size_t cs = rd16(p + i); i += 2;
    if (!cs || (cs & 1) || cs > n - i) return 0;
    for (size_t j = 0; j < cs && ch->num_ciphers < 64; j += 2)
        ch->ciphers[ch->num_ciphers++] = rd16(p + i + j);
    i += cs;
    if (i >= n || p[i] > n - i - 1) return 0;
    i += 1 + p[i];
    if (i == n) return 1;
    if (n - i < 2 || rd16(p + i) != n - i - 2) return 0;
    i += 2;
    while (i < n) {
        if (n - i < 4) return 0;
        uint16_t type = rd16(p + i), len = rd16(p + i + 2);
        i += 4;
        if (len > n - i) return 0;
        const unsigned char *e = p + i;
        switch (type) {
        case 0:
            if (len < 5 || rd16(e) != len - 2 || e[2] != 0 || rd16(e + 3) != len - 5 || (size_t)len - 5 >= sizeof ch->sni) return 0;
            for (size_t j = 5; j < len; j++) if (e[j] <= 32 || e[j] >= 127) return 0;
            memcpy(ch->sni, e + 5, len - 5);
            break;
        case 10:
            if (!list16(e, len, ch->groups, 16, &ch->num_groups)) return 0;
            break;
        case 13:
            if (!list16(e, len, ch->sig_algs, 32, &ch->num_sig_algs)) return 0;
            break;
        case 16: {
            if (len < 2 || rd16(e) != len - 2) return 0;
            size_t j = 2;
            while (j < len) {
                size_t z = e[j++];
                if (!z || z > len - j) return 0;
                if (ch->num_alpn < 8 && z < 32) {
                    memcpy(ch->alpn[ch->num_alpn], e + j, z);
                    ch->num_alpn++;
                }
                j += z;
            }
            break;
        }
        case 43:
            if (len < 1 || e[0] != len - 1 || ((len - 1) & 1)) return 0;
            for (size_t j = 1; j < len && ch->num_versions < 16; j += 2)
                ch->versions[ch->num_versions++] = rd16(e + j);
            break;
        case 51: {
            if (len < 2 || rd16(e) != len - 2) return 0;
            size_t j = 2;
            while (j < len) {
                if (len - j < 4) return 0;
                uint16_t z = rd16(e + j + 2);
                if (z > len - j - 4) return 0;
                if (ch->num_key_shares < 8) ch->key_shares[ch->num_key_shares++] = rd16(e + j);
                j += 4 + z;
            }
            break;
        }
        }
        i += len;
    }
    return 1;
}

int extract_sni_hs(const unsigned char *p, size_t n, char *out, size_t cap) {
    struct tls_client_hello ch;
    if (!client_hello(p, n, &ch) || !ch.sni[0] || strlen(ch.sni) >= cap) return 0;
    strcpy(out, ch.sni);
    return 1;
}
int extract_sni(const unsigned char *p, size_t n, char *out, size_t cap) {
    if (n < 5 || p[0] != 22 || p[1] != 3 || rd16(p + 3) > n - 5) return 0;
    return extract_sni_hs(p + 5, rd16(p + 3), out, cap);
}

static int server_hello(const unsigned char *p, size_t n, struct tls_server_hello *sh) {
    if (n < 42 || p[0] != 2 ||
        (((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3]) != n - 4) return 0;
    memset(sh, 0, sizeof *sh);
    size_t i = 4;
    sh->legacy_version = rd16(p + i); i += 34;
    size_t sid = p[i++];
    if (sid > 32 || sid > n - i || n - i - sid < 3) return 0;
    i += sid;
    sh->cipher = rd16(p + i); i += 2;
    if (p[i++]) return 0;
    if (i == n) return 1;
    if (n - i < 2 || rd16(p + i) != n - i - 2) return 0;
    i += 2;
    while (i < n) {
        if (n - i < 4) return 0;
        uint16_t type = rd16(p + i), len = rd16(p + i + 2);
        i += 4;
        if (len > n - i) return 0;
        if (type == 43) { if (len != 2) return 0; sh->version = rd16(p + i); }
        if (type == 51) { if (len < 4 || rd16(p + i + 2) != len - 4) return 0;
            sh->key_share_group = rd16(p + i); sh->has_key_share = 1; }
        i += len;
    }
    return 1;
}

static struct flow *find_flow(const unsigned char *src, const unsigned char *dst,
                              uint16_t sport, uint16_t dport, int *direction) {
    time_t now = time(NULL);
    struct flow *free_slot = NULL, *oldest = &flows[0];
    for (size_t i = 0; i < MAX_FLOWS; i++) {
        struct flow *f = &flows[i];
        if (f->active && now - f->seen > IDLE_SECONDS) f->active = 0;
        if (!f->active) { if (!free_slot) free_slot = f; continue; }
        if (f->seen < oldest->seen) oldest = f;
        if (!memcmp(f->client, src, 4) && !memcmp(f->server, dst, 4) &&
            f->client_port == sport && f->server_port == dport) { *direction = 0; f->seen = now; return f; }
        if (!memcmp(f->server, src, 4) && !memcmp(f->client, dst, 4) &&
            f->server_port == sport && f->client_port == dport) { *direction = 1; f->seen = now; return f; }
    }
    struct flow *f = free_slot ? free_slot : oldest;
    memset(f, 0, sizeof *f);
    f->active = 1; f->seen = now;
    memcpy(f->client, src, 4); memcpy(f->server, dst, 4);
    f->client_port = sport; f->server_port = dport;
    *direction = 0;
    return f;
}

static size_t pending_hello(struct stream *s, int direction,
                            struct tls_event *events, size_t cap) {
    size_t count = 0;
    while (s->hs_used >= 4 && count < cap) {
        size_t msg = ((size_t)s->handshake[1] << 16) | ((size_t)s->handshake[2] << 8) | s->handshake[3];
        if (msg > BUFFER - 4) { s->hs_used = 0; break; }
        if (s->hs_used < msg + 4) break;
        struct tls_event *ev = &events[count];
        memset(ev, 0, sizeof *ev);
        ev->direction = direction;
        if (s->handshake[0] == 1 && client_hello(s->handshake, msg + 4, &ev->data.client))
            ev->type = TLS_CLIENT_HELLO, count++;
        else if (s->handshake[0] == 2 && server_hello(s->handshake, msg + 4, &ev->data.server))
            ev->type = TLS_SERVER_HELLO, count++;
        memmove(s->handshake, s->handshake + msg + 4, s->hs_used - msg - 4);
        s->hs_used -= msg + 4;
    }
    return count;
}

size_t tls_feed(const unsigned char *src, const unsigned char *dst,
                uint16_t sport, uint16_t dport, uint32_t seq,
                const unsigned char *payload, size_t len,
                struct tls_event *events, size_t cap) {
    if (!cap) return 0;
    int direction;
    struct flow *f = find_flow(src, dst, sport, dport, &direction);
    struct stream *s = &f->dir[direction];
    if (!s->seq_set) { s->next_seq = seq; s->seq_set = 1; }
    if (seq != s->next_seq) {
        uint32_t behind = s->next_seq - seq;
        if (behind <= len) { payload += behind; len -= behind; }
        else return 0;
    }
    if (len > BUFFER - s->used) { f->active = 0; return 0; }
    if (len) memcpy(s->bytes + s->used, payload, len);
    s->used += len;
    s->next_seq += (uint32_t)len;
    size_t count = pending_hello(s, direction, events, cap), pos = 0;
    while (count < cap && s->used - pos >= 5) {
        const unsigned char *r = s->bytes + pos;
        uint16_t size = rd16(r + 3);
        if (r[1] != 3 || r[0] < 20 || r[0] > 23 || size > 16384 + 256) { f->active = 0; break; }
        if (s->used - pos < 5u + size) break;
        struct tls_event *ev = &events[count];
        memset(ev, 0, sizeof *ev);
        ev->direction = direction; ev->length = size;
        if (r[0] == 22) {
            if (size > BUFFER - s->hs_used) { f->active = 0; break; }
            memcpy(s->handshake + s->hs_used, r + 5, size);
            s->hs_used += size;
            count += pending_hello(s, direction, events + count, cap - count);
        } else if (r[0] == 20 && size == 1 && r[5] == 1) {
            ev->type = TLS_CCS; count++;
        } else if (r[0] == 21 && size >= 2) {
            ev->type = TLS_ALERT; ev->data.alert.level = r[5]; ev->data.alert.description = r[6]; count++;
        } else if (r[0] == 23) {
            ev->type = TLS_ENCRYPTED_RECORD;
            ev->total_bytes = (f->bytes[direction] += size);
            ev->total_records = ++f->records[direction];
            count++;
        }
        pos += 5 + size;
        if (!f->active) break;
    }
    memmove(s->bytes, s->bytes + pos, s->used - pos);
    s->used -= pos;
    return count;
}
