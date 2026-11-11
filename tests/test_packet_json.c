#include "../include/packet_json.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    unsigned char arp[42] = {0};
    arp[12] = 0x08; arp[13] = 0x06; arp[15] = 1;
    arp[16] = 0x08; arp[18] = 6; arp[19] = 4; arp[21] = 1;
    arp[28] = 192; arp[29] = 168; arp[30] = 1; arp[31] = 2;
    arp[38] = 192; arp[39] = 168; arp[40] = 1; arp[41] = 1;
    FILE *f = tmpfile(); assert(f);
    packet_json_write(f, arp, sizeof arp);
    rewind(f);
    char text[1024] = {0}; assert(fgets(text, sizeof text, f));
    assert(strstr(text, "\"protocol\":\"ARP\""));
    assert(strstr(text, "\"src\":\"192.168.1.2\""));
    assert(strstr(text, "\"arp_op\":1"));
    fclose(f);
    unsigned char tcp[54] = {0};
    tcp[12] = 8; tcp[14] = 0x45; tcp[17] = 40; tcp[23] = 6;
    tcp[26] = 10; tcp[30] = 1; tcp[34] = 0x30; tcp[35] = 0x39; tcp[36] = 1; tcp[37] = 0xbb;
    f = tmpfile(); assert(f);
    packet_json_write(f, tcp, sizeof tcp);
    rewind(f); memset(text, 0, sizeof text); assert(fgets(text, sizeof text, f));
    assert(strstr(text, "\"protocol\":\"TCP\""));
    assert(strstr(text, "\"sport\":12345,\"dport\":443"));
    fclose(f);
    f = tmpfile(); assert(f); packet_json_write(f, tcp, 13); assert(ftell(f) == 0); fclose(f);
    return 0;
}
