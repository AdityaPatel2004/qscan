/* Planted weak crypto in C (OpenSSL API), so qscan has something to find. */
#include <openssl/evp.h>
#include <openssl/sha.h>

void hash_it(const unsigned char *d, size_t n, unsigned char *out) {
    SHA1(d, n, out);                                   /* SHA-1: broken today */
}

const EVP_CIPHER *pick_cipher(void) {
    return EVP_aes_128_ecb();                          /* AES-ECB: broken today */
}

EVP_PKEY_CTX *new_key_ctx(void) {
    return EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);     /* EC: quantum-vulnerable */
}
