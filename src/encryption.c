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

passwand_error_t aes_encrypt(const k_t *key, const iv_t *iv, const ppt_t *pp, ct_t *c) {

    /* We expect the key and IV to match the parameters of the algorithm we're going to use them in.
     */
    if (key->length != AES_KEY_SIZE)
        return PW_BAD_KEY_SIZE;
    if (iv->length != AES_BLOCK_SIZE)
        return PW_BAD_IV_SIZE;

    /* We require the plain text to be aligned to the block size because this permits a single
     * encrypting step with no implementation-introduced padding.
     */
    if (pp->length % AES_BLOCK_SIZE != 0)
        return PW_UNALIGNED;

    /* XXX: Move this comment to somewhere top-level.
     * We use AES128 here because it has a more well designed key schedule than
     * AES256. CTR mode is recommended by Agile Bits over CBC mode.
     */
    EVP_CIPHER_CTX ctx;
    if (EVP_EncryptInit(&ctx, EVP_aes_128_ctr(), key->data, iv->data) != 1)
        return PW_CRYPTO;

    /* EVP_EncryptUpdate is documented as being able to write at most `inl + cipher_block_size - 1`.
     */
    if (SIZE_MAX - (AES_BLOCK_SIZE - 1) < pp->length)
        return PW_OVERFLOW;
    c->data = malloc(pp->length + (AES_BLOCK_SIZE - 1));
    if (c->data == NULL)
        return PW_NO_MEM;

    /* Argh, OpenSSL API. */
    int len;

    if (EVP_EncryptUpdate(&ctx, c->data, &len, pp->data, pp->length) != 1) {
        free(c->data);
        return PW_CRYPTO;
    }
    c->length = len;
    assert(c->length <= pp->length + (AES_BLOCK_SIZE - 1));

    /* If we've got everything right, this finalisation should return no further data. */
    unsigned char *temp = malloc(pp->length + AES_BLOCK_SIZE - 1);
    if (temp == NULL) {
        free(c->data);
        return PW_NO_MEM;
    }
    int excess;
    int r = EVP_EncryptFinal(&ctx, temp, &excess);
    free(temp);
    if (r != 1 || excess != 0) {
        free(c->data);
        return PW_CRYPTO;
    }

    return PW_OK;
}

passwand_error_t aes_decrypt(const k_t *key, const iv_t *iv, const ct_t *c, ppt_t *pp) {

    /* Support for an RAII-erased secure buffer. */
    typedef struct {
        uint8_t *data;
        size_t length;
    } buffer_t;
    void auto_erase_buffer(void *p) {
        assert(p != NULL);
        buffer_t *b = *(buffer_t**)p;
        if (b != NULL) {
            if (b->data != NULL)
                passwand_secure_free(b->data, b->length);
            passwand_secure_free(b, sizeof *b);
        }
    }

    /* See comment in aes_encrypt. */
    if (key->length != AES_KEY_SIZE)
        return PW_BAD_KEY_SIZE;
    if (iv->length != AES_BLOCK_SIZE)
        return PW_BAD_IV_SIZE;

    EVP_CIPHER_CTX ctx;
    if (EVP_DecryptInit(&ctx, EVP_aes_128_ctr(), key->data, iv->data) != 1)
        return PW_CRYPTO;

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
    if (EVP_DecryptUpdate(&ctx, buffer->data, &len, c->data, c->length) != 1)
        return PW_CRYPTO;
    assert(len >= 0);
    assert((unsigned)len <= c->length + AES_BLOCK_SIZE);
    pp->length = len;

    /* It's OK to write more plain text bytes in this step. */
    if (EVP_DecryptFinal(&ctx, buffer->data + len, &len) != 1)
        return PW_CRYPTO;
    assert(len >= 0);
    if (SIZE_MAX - pp->length < (size_t)len)
        return PW_OVERFLOW;
    pp->length += len;
    assert(pp->length <= c->length + AES_BLOCK_SIZE);

    /* Copy the internal buffer to the caller's packed plain text struct. We do
     * this to ensure the caller's idea of the "length" of the decrypted data
     * is suitable to pass to passwand_secure_free.
     */
    if (passwand_secure_malloc((void**)&pp->data, pp->length) != 0)
        return PW_NO_MEM;
    memcpy(pp->data, buffer->data, pp->length);

    return PW_OK;
}
