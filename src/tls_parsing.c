#include "../include/tls_parsing.h"
#include <string.h>
#include "../include/helpers.h"

int extract_sni_hs(const unsigned char *p, size_t len, char *out, size_t outsz) {
    if (len < 4 + 2 + 32 + 1 || p[0] != 0x01) return 0;
    size_t i = 4 + 2 + 32;

    i += 1 + p[i];
    if (i + 2 > len) return 0;
    i += 2 + rd16(p + i);
    if (i + 1 > len) return 0;
    i += 1 + p[i];
    if (i + 2 > len) return 0;
    size_t end = i + 2 + rd16(p + i);
    i += 2;
    if (end > len) end = len;

    while (i + 4 <= end) {
        uint16_t type = rd16(p + i);
        uint16_t elen = rd16(p + i + 2);
        i += 4;
        if (i + elen > end) return 0;

        if (type == 0x0000) {
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

int extract_sni(const unsigned char *p, size_t len, char *out, size_t outsz) {
    if (len < 9 || p[0] != 0x16 || p[1] != 0x03) return 0;
    return extract_sni_hs(p + 5, len - 5, out, outsz);
}
