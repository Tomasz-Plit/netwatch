#ifndef TLS_PARSING_H
#define TLS_PARSING_H
#include <stddef.h>
#include <stdint.h>

struct tls_client_hello {
    char sni[256];
    uint16_t versions[16], ciphers[64], groups[16], sig_algs[32], key_shares[8];
    size_t num_versions, num_ciphers, num_groups, num_sig_algs, num_key_shares;
    char alpn[8][32];
    size_t num_alpn;
};
struct tls_server_hello {
    uint16_t legacy_version, version, cipher, key_share_group;
    int has_key_share;
};
enum tls_event_type { TLS_CLIENT_HELLO, TLS_SERVER_HELLO, TLS_CCS, TLS_ALERT, TLS_ENCRYPTED_RECORD };
struct tls_event {
    enum tls_event_type type;
    int direction;
    uint16_t length;
    union {
        struct tls_client_hello client;
        struct tls_server_hello server;
        struct { uint8_t level, description; } alert;
    } data;
};

int extract_sni_hs(const unsigned char *p, size_t len, char *out, size_t outsz);
int extract_sni(const unsigned char *p, size_t len, char *out, size_t outsz);
size_t tls_feed(const unsigned char *src_ip, const unsigned char *dst_ip,
                uint16_t src_port, uint16_t dst_port, uint32_t seq,
                const unsigned char *payload, size_t payload_len,
                struct tls_event *events, size_t max_events);
void tls_reset_all(void);
#endif
