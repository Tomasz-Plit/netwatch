#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

struct quic_keys {
    unsigned char key[16];
    unsigned char iv[12];
    unsigned char hp[16];
};

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

static void print_hex(const char *name, const unsigned char *p, size_t n) {
    printf("%-4s ", name);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

int main(void) {
    const unsigned char dcid[8] = {0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08};
    struct quic_keys k;

    if (!derive_initial_keys(dcid, sizeof dcid, &k)) {
        printf("derivation failed\n");
        return 1;
    }
    print_hex("key", k.key, sizeof k.key);
    print_hex("iv",  k.iv,  sizeof k.iv);
    print_hex("hp",  k.hp,  sizeof k.hp);
    return 0;
}