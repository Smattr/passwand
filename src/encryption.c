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

static void ctxfree(void *p) {
    assert(p != NULL);
    EVP_CIPHER_CTX **ctx = p;
    if (*ctx != NULL)
        EVP_CIPHER_CTX_free(*ctx);
}

int aes_encrypt(const k_t *key, const iv_t *iv, const ppt_t *pp, ct_t *c) {

    /* We expect the key and IV to match the parameters of the algorithm we're going to use them in.
     */
    if (key->length != AES_KEY_SIZE || iv->length != AES_BLOCK_SIZE)
        return -1;

    /* We require the plain text to be aligned to the block size because this permits a single
     * encrypting step with no implementation-introduced padding.
     */
    if (pp->length % AES_BLOCK_SIZE != 0)
        return -1;

    EVP_CIPHER_CTX *ctx __attribute__((cleanup(ctxfree))) = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return -1;

    /* XXX: Move this comment to somewhere top-level.
     * We use AES128 here because it has a more well designed key schedule than
     * AES256. CTR mode is recommended by Agile Bits over CBC mode.
     */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key->data, iv->data) != 1)
        return -1;

    /* EVP_EncryptUpdate is documented as being able to write at most `inl + cipher_block_size - 1`.
     */
    if (SIZE_MAX - (AES_BLOCK_SIZE - 1) < pp->length)
        return -1;
    c->data = malloc(pp->length + (AES_BLOCK_SIZE - 1));
    if (c->data == NULL)
        return -1;

    /* Argh, OpenSSL API. */
    int len;

    if (EVP_EncryptUpdate(ctx, c->data, &len, pp->data, pp->length) != 1) {
        free(c->data);
        return -1;
    }
    c->length = len;
    assert(c->length <= pp->length + (AES_BLOCK_SIZE - 1));

    /* If we've got everything right, this finalisation should return no further data. XXX: don't
     * stack-allocate this here.
     */
    unsigned char temp[pp->length + AES_BLOCK_SIZE - 1];
    int excess;
    if (EVP_EncryptFinal_ex(ctx, temp, &excess) != 1 || excess != 0) {
        free(c->data);
        return -1;
    }

    return 0;
}

int aes_decrypt(const k_t *key, const iv_t *iv, const ct_t *c, ppt_t *pp) {

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
    if (key->length != AES_KEY_SIZE || iv->length != AES_BLOCK_SIZE)
        return -1;

    EVP_CIPHER_CTX *ctx __attribute__((cleanup(ctxfree))) = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key->data, iv->data) != 1)
        return -1;

    /* EVP_DecryptUpdate is documented as writing at most `inl + cipher_block_size`. */
    if (SIZE_MAX - AES_BLOCK_SIZE < c->length)
        return -1;
    buffer_t *buffer __attribute__((cleanup(auto_erase_buffer))) = NULL;
    if (passwand_secure_malloc((void**)&buffer, sizeof *buffer) != 0)
        return -1;
    if (passwand_secure_malloc((void**)&buffer->data, c->length + AES_BLOCK_SIZE) != 0)
        return -1;
    buffer->length = c->length + AES_BLOCK_SIZE;

    int len;
    if (EVP_DecryptUpdate(ctx, buffer->data, &len, c->data, c->length) != 1)
        return -1;
    assert(len >= 0);
    assert((unsigned)len <= c->length + AES_BLOCK_SIZE);
    pp->length = len;

    /* It's OK to write more plain text bytes in this step. */
    if (EVP_DecryptFinal_ex(ctx, buffer->data + len, &len) != 1)
        return -1;
    pp->length += len;
    assert(pp->length <= c->length + AES_BLOCK_SIZE);

    /* Copy the internal buffer to the caller's packed plain text struct. We do
     * this to ensure the caller's idea of the "length" of the decrypted data
     * is suitable to pass to passwand_secure_free.
     */
    if (passwand_secure_malloc((void**)&pp->data, pp->length) != 0)
        return -1;
    memcpy(pp->data, buffer->data, pp->length);

    return 0;
}
