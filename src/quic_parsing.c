#include "../include/quic_parsing.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>
#include "../include/helpers.h"
#include "../include/tls_parsing.h"

#define CH_MAX 4096

static struct {
    unsigned char dcid[20];
    size_t dcid_len;
    unsigned char data[CH_MAX];
    unsigned char have[CH_MAX];
    int done;
} ch;

static int read_variant(const unsigned char *p, size_t len, size_t *pos, uint64_t *out){
    if (*pos >= len) return 0;
    size_t n = (size_t)1 << (p[*pos] >> 6);
    if (*pos + n > len) return 0;
    uint64_t v = p[*pos] & 0x3f;
    for (size_t k = 1; k < n; k++) v = (v << 8) | p[*pos + k];
    *pos += n;
    *out = v;
    return 1;
}

int parse_quic_initial(const unsigned char *p, size_t len, struct quic_initial *q){
    if (len < 7) return 0;
    if ((p[0] & 0xC0) != 0xC0) return 0;
    if (((p[0] >> 4) & 3) != 0) return 0;
    q->version = rd32(p + 1);
    if (q->version != 1) return 0;

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

static int hkdf_expand_label(const unsigned char *secret, const char *label, unsigned char *out, size_t outlen){
    unsigned char info[64];
    size_t ll = strlen(label), n = 0;

    info[n++] = 0;
    info[n++] = (unsigned char)outlen;
    info[n++] = (unsigned char)(6 + ll);
    memcpy(info + n, "tls13 ", 6); n += 6;
    memcpy(info + n, label, ll);   n += ll;
    info[n++] = 0;
    info[n++] = 1;

    unsigned char t[32];
    unsigned int tl = 0;
    if (!HMAC(EVP_sha256(), secret, 32, info, n, t, &tl)) return 0;
    memcpy(out, t, outlen);
    return 1;
}

int derive_initial_keys(const unsigned char *dcid, size_t dcid_len, struct quic_keys *k) {
    static const unsigned char salt[20] = {
        0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,
        0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a };

    unsigned char initial[32], client[32];
    unsigned int len = 0;

    if (!HMAC(EVP_sha256(), salt, sizeof salt, dcid, dcid_len, initial, &len)) return 0;
    if (!hkdf_expand_label(initial, "client in", client, 32)) return 0;
    if (!hkdf_expand_label(client, "quic key", k->key, 16)) return 0;
    if (!hkdf_expand_label(client, "quic iv",  k->iv,  12)) return 0;
    if (!hkdf_expand_label(client, "quic hp",  k->hp,  16)) return 0;
    return 1;
}

int quic_unprotect_header(const unsigned char *p, size_t len, const struct quic_initial *q,
			const unsigned char *hp, unsigned char *first, size_t *pn_len, uint32_t *pn) {
    if (q->length < 20) return 0;
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

int quic_decrypt_initial(const unsigned char *p, size_t len, const struct quic_initial *q,
			const struct quic_keys *k, unsigned char first, size_t pn_len, uint32_t pn,
			unsigned char *out, size_t outsz, size_t *out_len) {
    size_t hdr_len = q->pn_offset + pn_len;
    if (hdr_len > 512 || hdr_len > len) return 0;
    if (q->length < pn_len + 16) return 0;
    size_t ct_len = q->length - pn_len - 16;
    if (ct_len > outsz) return 0;
    if (hdr_len + ct_len + 16 > len) return 0;

    unsigned char nonce[12];
    memcpy(nonce, k->iv, 12);
    for (int i = 0; i < 4; i++)
        nonce[11 - i] ^= (unsigned char)(pn >> (8 * i));

    unsigned char aad[512];
    memcpy(aad, p, hdr_len);
    aad[0] = first;
    for (size_t i = 0; i < pn_len; i++)
        aad[q->pn_offset + pn_len - 1 - i] = (unsigned char)(pn >> (8 * i));

    const unsigned char *ct  = p + hdr_len;
    unsigned char tag[16];
    memcpy(tag, ct + ct_len, 16);

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

int quic_find_sni(const unsigned char *pl, size_t len,
			const unsigned char *dcid, size_t dcid_len,
			char *out, size_t outsz) {

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
        if (type == 0x00 || type == 0x01) continue;
        if (type != 0x06) break;

        uint64_t off, clen;
        if (!read_variant(pl, len, &i, &off)) break;
        if (!read_variant(pl, len, &i, &clen)) break;
        if (clen > len - i) break;
        if (off <= CH_MAX && clen <= CH_MAX - off) {
            memcpy(ch.data + off, pl + i, clen);
            memset(ch.have + off, 1, clen);
        }
        i += clen;
    }

    size_t prefix = 0;
    while (prefix < CH_MAX && ch.have[prefix]) prefix++;

    if (extract_sni_hs(ch.data, prefix, out, outsz)) {
        ch.done = 1;
        return 1;
    }
    return 0;
}
