#include "../include/tls_parsing.h"
#include <assert.h>
#include <string.h>

int main(void) {
    unsigned char src[4] = {1, 2, 3, 4}, dst[4] = {5, 6, 7, 8};
    unsigned char msg[42] = {0x02, 0, 0, 38, 0x03, 0x03};
    msg[39] = 0x13;
    msg[40] = 0x01;
    unsigned char first[15] = {0x16, 0x03, 0x03, 0, 10};
    unsigned char second[37] = {0x16, 0x03, 0x03, 0, 32};
    memcpy(first + 5, msg, 10);
    memcpy(second + 5, msg + 10, 32);

    char result[256];
    assert(tls_feed(src, dst, 443, 45000, 1000, first, 7, result, sizeof result) == 0);
    assert(tls_feed(src, dst, 443, 45000, 1007, first + 7, 8, result, sizeof result) == 0);
    assert(tls_feed(src, dst, 443, 45000, 1015, second, sizeof second, result, sizeof result) == 2);
    assert(strcmp(result, "legacy version 0x0303, cipher suite 0x1301") == 0);
    return 0;
}
