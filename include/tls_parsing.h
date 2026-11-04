#ifndef TLS_PARSING_H
#define TLS_PARSING_H
#include <stddef.h>
#include <stdint.h>

int extract_sni_hs(const unsigned char *p, size_t len, char *out, size_t outsz);
int extract_sni(const unsigned char *p, size_t len, char *out, size_t outsz);
int tls_feed(const unsigned char *src_ip, const unsigned char *dst_ip, uint16_t src_port, uint16_t dst_port, uint32_t seq, const unsigned char *payload,
            size_t payload_len, char *host, size_t host_size);
#endif
