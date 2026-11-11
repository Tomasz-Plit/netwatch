#include "../include/tls_parsing.h"
#include "../include/tls_json.h"
#include <assert.h>
#include <arpa/inet.h>
#include <string.h>

int main(void) {
    tls_reset_all();
    unsigned char a[4] = {1, 2, 3, 4}, b[4] = {5, 6, 7, 8};
    unsigned char ch[128] = {1, 0, 0, 0, 3, 3};
    size_t n = 38;
    ch[n++] = 0;
    ch[n++] = 0; ch[n++] = 2; ch[n++] = 0x13; ch[n++] = 1;
    ch[n++] = 1; ch[n++] = 0;
    size_t ext = n; n += 2;
    ch[n++] = 0; ch[n++] = 43; ch[n++] = 0; ch[n++] = 3;
    ch[n++] = 2; ch[n++] = 3; ch[n++] = 4;
    ch[n++] = 0; ch[n++] = 16; ch[n++] = 0; ch[n++] = 5;
    ch[n++] = 0; ch[n++] = 3; ch[n++] = 2; ch[n++] = 'h'; ch[n++] = '2';
    ch[ext] = (unsigned char)((n - ext - 2) >> 8);
    ch[ext + 1] = (unsigned char)(n - ext - 2);
    ch[3] = (unsigned char)(n - 4);
    unsigned char record[133] = {22, 3, 3};
    record[3] = (unsigned char)(n >> 8); record[4] = (unsigned char)n;
    memcpy(record + 5, ch, n);
    struct tls_event ev[4];
    assert(tls_feed(a, b, 50000, 443, 100, record, n + 5, ev, 4) == 1);
    assert(ev[0].type == TLS_CLIENT_HELLO);
    assert(ev[0].data.client.num_versions == 1 && ev[0].data.client.versions[0] == 0x0304);
    assert(strcmp(ev[0].data.client.alpn[0], "h2") == 0);
    unsigned char ccs[] = {20, 3, 3, 0, 1, 1};
    unsigned char data[] = {23, 3, 3, 0, 2, 8, 9};
    assert(tls_feed(b, a, 443, 50000, 200, ccs, sizeof ccs, ev, 4) == 1);
    assert(ev[0].type == TLS_CCS && ev[0].direction == 1);
    assert(tls_feed(b, a, 443, 50000, 206, data, sizeof data, ev, 4) == 1);
    assert(ev[0].type == TLS_ENCRYPTED_RECORD && ev[0].total_bytes == 2);
    assert(ev[0].total_records == 1);
    FILE *f = tmpfile(); assert(f);
    struct timespec ts = {1, 0};
    tls_json_write(f, &ev[0], b, a, 443, 50000, &ts, 0, 0);
    rewind(f);
    char line[512]; assert(fgets(line, sizeof line, f));
    assert(strstr(line, "\"direction_bytes\":2"));
    fclose(f);
    f = tmpfile(); assert(f);
    hostname_json_write(f, "ex\\\"ample.com", AF_INET, a, b, 12345, 443, &ts);
    rewind(f); memset(line, 0, sizeof line); assert(fgets(line, sizeof line, f));
    assert(strstr(line, "\"event\":\"quic_hostname\""));
    assert(strstr(line, "\"src\":\"1.2.3.4\""));
    assert(strstr(line, "\"dst\":\"5.6.7.8\",\"sport\":12345,\"dport\":443"));
    assert(strstr(line, "ex\\\\\\\"ample.com"));
    fclose(f);
    unsigned char alert[] = {21, 3, 3, 0, 2, 2, 40};
    assert(tls_feed(b, a, 443, 50000, 213, alert, sizeof alert, ev, 4) == 1);
    assert(ev[0].type == TLS_ALERT && ev[0].data.alert.description == 40);
    return 0;
}
