#ifndef TLS_PARSING_H
#define TLS_PARSING_H

#include <stddef.h>

int extract_sni_hs(const unsigned char *p, size_t len, char *out, size_t outsz);
int extract_sni(const unsigned char *p, size_t len, char *out, size_t outsz);
#endif
