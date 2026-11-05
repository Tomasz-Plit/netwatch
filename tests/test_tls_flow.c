#include "../include/tls_parsing.h"
#include <assert.h>
#include <string.h>

int main(void) {
    tls_reset_all();
    unsigned char src[4] = {1, 2, 3, 4}, dst[4] = {5, 6, 7, 8};
    unsigned char msg[42] = {2, 0, 0, 38, 3, 3};
    msg[39] = 0x13; msg[40] = 1;
    unsigned char first[15] = {22, 3, 3, 0, 10};
    unsigned char second[37] = {22, 3, 3, 0, 32};
    memcpy(first + 5, msg, 10);
    memcpy(second + 5, msg + 10, 32);
    struct tls_event events[2];
    assert(tls_feed(src, dst, 443, 45000, 1000, first, 7, events, 2) == 0);
    assert(tls_feed(src, dst, 443, 45000, 1007, first + 7, 8, events, 2) == 0);
    assert(tls_feed(src, dst, 443, 45000, 1015, second, sizeof second, events, 2) == 1);
    assert(events[0].type == TLS_SERVER_HELLO);
    assert(events[0].data.server.cipher == 0x1301);
    unsigned char data[] = {23, 3, 3, 0, 3, 1, 2, 3};
    assert(tls_feed(src, dst, 443, 45000, 1052, data, sizeof data, events, 2) == 1);
    assert(events[0].type == TLS_ENCRYPTED_RECORD && events[0].length == 3);
    assert(tls_feed(src, dst, 443, 45000, 1052, data, sizeof data, events, 2) == 0);
    return 0;
}
