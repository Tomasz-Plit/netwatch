#include "../include/packet_logging.h"
#include "../include/tcp_track.h"
#include "../include/statistic.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    unsigned char f[14 + 40 + 8 + 20 + 1] = {0};
    f[12] = 0x86; f[13] = 0xdd; f[14] = 0x60;
    f[19] = 29; f[20] = 0; f[21] = 64; /* hop-by-hop followed by TCP */
    f[22] = 0x20; f[23] = 1; f[37] = 1;
    f[38] = 0x20; f[39] = 1; f[53] = 2;
    f[54] = 6; f[55] = 0;
    f[62] = 0xaf; f[63] = 0xc8; f[64] = 1; f[65] = 0xbb;
    f[74] = 0x50; f[75] = 0x18;
    FILE *out = tmpfile(); assert(out);
    log_packet(out, NULL, f, sizeof f, 45000); assert(ftell(out) > 0);
    rewind(out); char text[4096] = {0}; fread(text, 1, sizeof text - 1, out);
    assert(strstr(text, "IPv6") && strstr(text, "2001::1") && strstr(text, "TCP Header"));
    fclose(out);
    out = tmpfile(); assert(out);
    log_packet(out, NULL, f, sizeof f, 45001); assert(ftell(out) == 0);
    f[55] = 255; log_packet(out, NULL, f, sizeof f, 0); assert(ftell(out) == 0);
    f[55] = 0; f[20] = 44; log_packet(out, NULL, f, sizeof f, 0); assert(ftell(out) == 0);
    fclose(out);
    unsigned char a[16] = {0x20, 1}, b[16] = {0x20, 1}, d[16] = {0x20, 1};
    a[15] = 1; b[15] = 2; d[15] = 3;
    struct timespec ts = {1, 0}; tcp_track_reset();
    struct tcp_conn *one = tcp_track_ip(AF_INET6, a, d, 1234, 443, 2, &ts);
    struct tcp_conn *two = tcp_track_ip(AF_INET6, b, d, 1234, 443, 2, &ts);
    assert(one && two && one != two);
    host_seen_ip("example.com", AF_INET6, a); host_seen_ip("example.com", AF_INET6, b);
    out = tmpfile(); assert(out); stats_print(out); rewind(out);
    memset(text, 0, sizeof text); fread(text, 1, sizeof text - 1, out);
    assert(strstr(text, "2001::1") && strstr(text, "2001::2")); fclose(out);
    return 0;
}
