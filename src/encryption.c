#include <assert.h>
#include "auto.h"
#include <endian.h>
#include <fcntl.h>
#include "internal.h"
#include <limits.h>
#include <openssl/evp.h>
#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "types.h"
#include <unistd.h>

passwand_error_t aes_encrypt_init(const k_t key, const iv_t iv, EVP_CIPHER_CTX *ctx) {

    if (EVP_EncryptInit(ctx, EVP_aes_256_ctr(), key, iv) != 1)
        return PW_CRYPTO;

    /* Disable padding as we pre-pad the input. */
    if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
        return PW_CRYPTO;

    return PW_OK;
}

passwand_error_t aes_encrypt(EVP_CIPHER_CTX *ctx, const ppt_t *pp, ct_t *c) {

    /* We require the plain text to be aligned to the block size because this permits a single
     * encrypting step with no implementation-introduced padding.
     */
    if (pp->length % AES_BLOCK_SIZE != 0)
        return PW_UNALIGNED;

    /* EVP_EncryptUpdate is documented as being able to write at most `inl + cipher_block_size - 1`.
     */
    if (SIZE_MAX - (AES_BLOCK_SIZE - 1) < pp->length)
        return PW_OVERFLOW;
    c->data = malloc(pp->length + (AES_BLOCK_SIZE - 1));
    if (c->data == NULL)
        return PW_NO_MEM;

    /* Argh, OpenSSL API. */
    int len;

    if (EVP_EncryptUpdate(ctx, c->data, &len, pp->data, pp->length) != 1) {
        free(c->data);
        return PW_CRYPTO;
    }
    c->length = len;
    assert(c->length <= pp->length + (AES_BLOCK_SIZE - 1));

    return PW_OK;
}

passwand_error_t aes_encrypt_deinit(EVP_CIPHER_CTX *ctx) {

    /* This finalisation should return no further data because we've disabled padding. */
    unsigned char temp[AES_BLOCK_SIZE];
    int excess;
    if (EVP_EncryptFinal(ctx, temp, &excess) != 1 || excess != 0) 
        return PW_CRYPTO;

    return PW_OK;
}

passwand_error_t aes_decrypt_init(const k_t key, const iv_t iv, EVP_CIPHER_CTX *ctx) {

    if (EVP_DecryptInit(ctx, EVP_aes_256_ctr(), key, iv) != 1)
        return PW_CRYPTO;

    /* Disable padding. */
    if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
        return PW_CRYPTO;

    return PW_OK;
}

/* Support for an RAII-erased secure buffer. */
typedef struct {
    uint8_t *data;
    size_t length;
} buffer_t;
static void auto_erase_buffer(void *p) {
    assert(p != NULL);
    buffer_t *b = *(buffer_t**)p;
    if (b != NULL) {
        if (b->data != NULL)
            passwand_secure_free(b->data, b->length);
        passwand_secure_free(b, sizeof *b);
    }
}

passwand_error_t aes_decrypt(EVP_CIPHER_CTX *ctx, const ct_t *c, ppt_t *pp) {

    /* EVP_DecryptUpdate is documented as writing at most `inl + cipher_block_size`. */
    if (SIZE_MAX - AES_BLOCK_SIZE < c->length)
        return PW_OVERFLOW;
    buffer_t *buffer __attribute__((cleanup(auto_erase_buffer))) = NULL;
    if (passwand_secure_malloc((void**)&buffer, sizeof *buffer) != 0)
        return PW_NO_MEM;
    buffer->data = NULL;
    if (passwand_secure_malloc((void**)&buffer->data, c->length + AES_BLOCK_SIZE) != 0)
        return PW_NO_MEM;
    buffer->length = c->length + AES_BLOCK_SIZE;

    int len;
    if (EVP_DecryptUpdate(ctx, buffer->data, &len, c->data, c->length) != 1)
        return PW_CRYPTO;
    assert(len >= 0);
    assert((size_t)len <= c->length + AES_BLOCK_SIZE);
    pp->length = len;

    /* Copy the internal buffer to the caller's packed plain text struct. We do
     * this to ensure the caller's idea of the "length" of the decrypted data
     * is suitable to pass to passwand_secure_free.
     */
    if (passwand_secure_malloc((void**)&pp->data, pp->length) != 0)
        return PW_NO_MEM;
    memcpy(pp->data, buffer->data, pp->length);

    return PW_OK;
}

passwand_error_t aes_decrypt_deinit(EVP_CIPHER_CTX *ctx) {

    /* We should not receive any further data because padding is disabled. */
    unsigned char temp[AES_BLOCK_SIZE];
    int len;
    if (EVP_DecryptFinal(ctx, temp, &len) != 1 || len != 0)
        return PW_CRYPTO;

    return PW_OK;
}
