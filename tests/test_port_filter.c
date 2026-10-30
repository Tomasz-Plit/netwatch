#include "../include/packet_logging.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    unsigned char frame[14 + 20 + 20 + 1] = {0};
    frame[12] = 0x08; frame[13] = 0x00;
    frame[14] = 0x45;
    frame[16] = 0; frame[17] = 41;
    frame[23] = 6;
    frame[34] = 0xaf; frame[35] = 0xc8; /* source port 45000 */
    frame[36] = 0x01; frame[37] = 0xbb; /* destination port 443 */
    frame[46] = 0x50; frame[47] = 0x18;
    FILE *out = tmpfile();
    assert(out);
    log_packet(out, frame, sizeof frame, 45000);
    assert(ftell(out) > 0);
    fclose(out);

    out = tmpfile();
    assert(out);
    frame[35] = 0xc9; /* another local port: 45001 */
    log_packet(out, frame, sizeof frame, 45000);
    assert(ftell(out) == 0);
    frame[35] = 0xc8;
    frame[23] = 17;
    log_packet(out, frame, sizeof frame, 45000);
    assert(ftell(out) == 0);
    fclose(out);
    return 0;
}
