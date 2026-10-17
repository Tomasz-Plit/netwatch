#include <stdio.h>
#include <openssl/evp.h>

int main(void) {
    const unsigned char hp[16] = {
        0x9f,0x50,0x44,0x9e,0x04,0xa0,0xe8,0x10,
        0x28,0x3a,0x1e,0x99,0x33,0xad,0xed,0xd2 };
    const unsigned char sample[16] = {
        0xd1,0xb1,0xc9,0x8d,0xd7,0x68,0x9f,0xb8,
        0xec,0x11,0xd2,0x42,0xb1,0x23,0xdc,0x9b };

    unsigned char mask[16];
    int outl = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, hp, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, mask, &outl, sample, 16);
    EVP_CIPHER_CTX_free(ctx);

    printf("mask ");
    for (int i = 0; i < 16; i++) printf("%02x", mask[i]);
    printf("\n");

    // protected bytes from the RFC packet
    unsigned char first = 0xc0 ^ (mask[0] & 0x0f);
    size_t pn_len = (first & 0x03) + 1;
    const unsigned char pn_prot[4] = {0x7b,0x9a,0xec,0x34};
    uint32_t pn = 0;
    for (size_t i = 0; i < pn_len; i++) pn = (pn << 8) | (pn_prot[i] ^ mask[1 + i]);

    printf("first 0x%02x, pn_len %zu, pn %u\n", first, pn_len, pn);
    return 0;
}