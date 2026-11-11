#include "../include/quic_parsing.h"
#include "../include/tls_parsing.h"
#include "../include/tls_json.h"
#include <arpa/inet.h>
#include <assert.h>
#include <string.h>

/* Build a small TLS ClientHello carrying the hostname example.com. */
static size_t client_hello(unsigned char *out) {
    static const char host[] = "example.com";
    memset(out, 0, 128);
    out[0] = 1; out[4] = 3; out[5] = 3;
    size_t n = 38;
    out[n++] = 0; /* Session ID */
    out[n++] = 0; out[n++] = 2; out[n++] = 0x13; out[n++] = 1;
    out[n++] = 1; out[n++] = 0; /* Compression */
    size_t extensions = n; n += 2;
    out[n++] = 0; out[n++] = 0; /* SNI extension */
    size_t extension_length = n; n += 2;
    out[n++] = 0; out[n++] = sizeof host + 2; /* ServerNameList length */
    out[n++] = 0; out[n++] = 0; out[n++] = sizeof host - 1;
    memcpy(out + n, host, sizeof host - 1); n += sizeof host - 1;
    out[extension_length + 1] = (unsigned char)(n - extension_length - 2);
    out[extensions + 1] = (unsigned char)(n - extensions - 2);
    out[3] = (unsigned char)(n - 4);
    return n;
}

static size_t crypto_frame(unsigned char *out, const unsigned char *hello, size_t size) {
    size_t n = 0;
    out[n++] = 0x06; /* CRYPTO */
    out[n++] = 0;    /* offset */
    if (size < 64) out[n++] = (unsigned char)size;
    else { out[n++] = (unsigned char)(0x40 | (size >> 8)); out[n++] = (unsigned char)size; }
    memcpy(out + n, hello, size);
    return n + size;
}

static void check_client(const unsigned char *ack, size_t ack_len, unsigned char id) {
    unsigned char hello[128], frames[256];
    size_t hello_len = client_hello(hello);
    memcpy(frames, ack, ack_len);
    size_t frame_len = ack_len + crypto_frame(frames + ack_len, hello, hello_len);
    char hostname[256] = {0};
    assert(quic_find_sni(frames, frame_len, &id, 1, hostname, sizeof hostname) == 1);
    assert(strcmp(hostname, "example.com") == 0);
}

int main(void) {
    const unsigned char ack[] = {0x02, 0, 0, 0, 0};
    const unsigned char ack_ranges[] = {0x02, 5, 0, 1, 0, 0, 0};
    const unsigned char ack_ecn[] = {0x03, 0, 0, 0, 0, 1, 2, 3};
    check_client(ack, sizeof ack, 1);
    check_client(ack_ranges, sizeof ack_ranges, 2);
    check_client(ack_ecn, sizeof ack_ecn, 3);

    /* An incomplete ACK must not prevent later valid frames in the same flow. */
    const unsigned char truncated[] = {0x02, 0, 0, 1, 0, 0};
    unsigned char id = 4, hello[128], frame[256];
    char hostname[256] = {0};
    assert(quic_find_sni(truncated, sizeof truncated, &id, 1, hostname, sizeof hostname) == 0);
    size_t hello_len = client_hello(hello);
    size_t frame_len = crypto_frame(frame, hello, hello_len);
    assert(quic_find_sni(frame, frame_len, &id, 1, hostname, sizeof hostname) == 1);
    assert(strcmp(hostname, "example.com") == 0);

    /* Exercise a server CRYPTO frame following an ACK as well. */
    unsigned char client_id = 5, client_scid = 6;
    struct quic_initial client = { .dcid = &client_id, .dcid_len = 1,
                                   .scid = &client_scid, .scid_len = 1 };
    assert(quic_find_sni(frame, frame_len, &client_id, 1, hostname, sizeof hostname) == 1);
    assert(quic_client_slot(&client));
    struct quic_initial server = { .dcid = &client_scid, .dcid_len = 1 };
    unsigned char server_hello[42] = {2, 0, 0, 38, 3, 3};
    server_hello[39] = 0x13; server_hello[40] = 1;
    memcpy(frame, ack, sizeof ack);
    frame_len = sizeof ack + crypto_frame(frame + sizeof ack, server_hello, sizeof server_hello);
    struct tls_server_hello parsed;
    assert(quic_find_server_hello(frame, frame_len, &server, &parsed) == 1);
    assert(parsed.cipher == 0x1301);

    /* The app receives the complete parsed client and server metadata. */
    unsigned char json_id = 7, src[4] = {192, 0, 2, 1}, dst[4] = {192, 0, 2, 2};
    frame_len = crypto_frame(frame, hello, hello_len);
    struct tls_event event = { .type = TLS_CLIENT_HELLO };
    assert(quic_find_client_hello(frame, frame_len, &json_id, 1, &event.data.client) == 1);
    assert(strcmp(event.data.client.sni, "example.com") == 0);
    assert(event.data.client.num_ciphers == 1 && event.data.client.ciphers[0] == 0x1301);
    FILE *out = tmpfile(); assert(out);
    struct timespec ts = {1, 0};
    quic_json_write_ip(out, &event, AF_INET, src, dst, 50000, 443, &ts);
    rewind(out);
    char line[2048]; assert(fgets(line, sizeof line, out));
    assert(strstr(line, "\"transport\":\"QUIC\""));
    assert(strstr(line, "\"event\":\"client_hello\""));
    assert(strstr(line, "\"sni\":\"example.com\""));
    assert(strstr(line, "\"ciphers\":[\"0x1301\"]"));
    assert(strstr(line, "\"ciphers_names\":[\"TLS_AES_128_GCM_SHA256\"]"));
    fclose(out);
    event.type = TLS_SERVER_HELLO; event.direction = 1; event.data.server = parsed;
    out = tmpfile(); assert(out);
    quic_json_write_ip(out, &event, AF_INET, dst, src, 443, 50000, &ts);
    rewind(out); assert(fgets(line, sizeof line, out));
    assert(strstr(line, "\"event\":\"server_hello\""));
    assert(strstr(line, "\"cipher\":\"0x1301\""));
    assert(strstr(line, "\"cipher_name\":\"TLS_AES_128_GCM_SHA256\""));
    fclose(out);

    /* A long capture must still track new connections after 64 slots. */
    for (unsigned i = 0; i < 70; i++) {
        unsigned char dcid[2] = {0xa0, (unsigned char)i};
        unsigned char scid[2] = {0xb0, (unsigned char)i};
        struct quic_initial request = { .dcid = dcid, .dcid_len = 2, .scid = scid, .scid_len = 2 };
        struct quic_initial reply = { .dcid = scid, .dcid_len = 2 };
        struct tls_client_hello new_client;
        assert(quic_find_client_hello(frame, frame_len, dcid, 2, &new_client) == 1);
        struct ch *slot = quic_client_slot(&request);
        assert(slot && quic_server_slot(&reply) == slot);
    }
    return 0;
}
