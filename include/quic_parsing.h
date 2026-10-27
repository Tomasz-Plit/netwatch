#ifndef QUIC_PARSING_H
#define QUIC_PARSING_H

#include <stddef.h>
#include <stdint.h>

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

int parse_quic_initial(const unsigned char *p, size_t len, struct quic_initial *q);
int derive_initial_keys(const unsigned char *dcid, size_t dcid_len, struct quic_keys *k);
int quic_unprotect_header(const unsigned char *p, size_t len, const struct quic_initial *q,
			const unsigned char *hp, unsigned char *first, size_t *pn_len, uint32_t *pn);
int quic_decrypt_initial(const unsigned char *p, size_t len, const struct quic_initial *q,
			const struct quic_keys *k, unsigned char first, size_t pn_len, uint32_t pn,
			unsigned char *out, size_t outsz, size_t *out_len);
int quic_find_sni(const unsigned char *pl, size_t len,
			const unsigned char *dcid, size_t dcid_len,
			char *out, size_t outsz);

#endif
