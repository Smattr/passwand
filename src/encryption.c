/* XXX: libscrypt.h is busted and doesn't include the necessary headers for
 * uint8_t and size_t.
 */
#include <stddef.h>
#include <stdint.h>

#include <assert.h>
#include "encryption.h"
#include <fcntl.h>
#include <libscrypt.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* XXX: I think this is actually excessive. It seems to me like we generate a
 * 256-bit key, but then only use it for 128-bit AES.
 */
static const size_t KEY_SIZE = 32; // bytes

static const char HEADER[] = "oprime01";

static const size_t AES_BLOCK_SIZE = 16; // bytes
static const size_t AES_KEY_SIZE = 16; // bytes

int random_bytes(uint8_t *buffer, size_t buffer_len) {
    return !RAND_bytes(buffer, buffer_len);
}

static void ctxfree(void *p) {
    assert(p != NULL);
    EVP_CIPHER_CTX **ctx = p;
    if (*ctx != NULL)
        EVP_CIPHER_CTX_free(*ctx);
}

int aes_encrypt(uint8_t *key, size_t key_len, uint8_t *iv, size_t iv_len,
        uint8_t *plaintext, size_t plaintext_len, uint8_t **ciphertext,
        size_t *ciphertext_len) {

    /* We expect the key and IV to match the parameters of the algorithm we're
     * going to use them in.
     */
    if (key_len != AES_KEY_SIZE || iv_len != AES_BLOCK_SIZE)
        return -1;

    /* We require the plain text to be aligned to the block size because this
     * permits a single encrypting step with no implementation-introduced
     * padding.
     */
    if (plaintext_len % AES_BLOCK_SIZE != 0)
        return -1;

    EVP_CIPHER_CTX *ctx __attribute__((cleanup(ctxfree))) = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return -1;

    /* XXX: Move this comment to somewhere top-level.
     * We use AES128 here because it has a more well designed key schedule than
     * AES256. CTR mode is recommended by Agile Bits over CBC mode.
     */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv) != 1)
        return -1;

    /* EVP_EncryptUpdate is documented as being able to write at most
     * `inl + cipher_block_size - 1`.
     */
    *ciphertext = malloc(plaintext_len + AES_BLOCK_SIZE - 1);
    if (*ciphertext == NULL)
        return -1;

    /* Argh, OpenSSL API. */
    int len;

    if (EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len) != 1) {
        free(*ciphertext);
        return -1;
    }
    *ciphertext_len = len;
    assert(*ciphertext_len < plaintext_len + AES_BLOCK_SIZE);

    /* If we've got everything right, this finalisation should return no further
     * data.
     */
    unsigned char temp[plaintext_len + AES_BLOCK_SIZE - 1];
    int excess;
    if (EVP_EncryptFinal_ex(ctx, temp, &excess) != 1 || excess != 0) {
        free(*ciphertext);
        return -1;
    }

    return 0;
}

int aes_decrypt(uint8_t *key, size_t key_len, uint8_t *iv, size_t iv_len,
        uint8_t *ciphertext, size_t ciphertext_len, uint8_t **plaintext,
        size_t *plaintext_len) {

    /* See comment in aes_encrypt. */
    if (key_len != AES_KEY_SIZE || iv_len != AES_BLOCK_SIZE)
        return -1;

    EVP_CIPHER_CTX *ctx __attribute__((cleanup(ctxfree))) = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv) != 1)
        return -1;

    /* EVP_DecryptUpdate is documented as writing at most
     * `inl + cipher_block_size`. We leave extra space for a NUL byte.
     */
    *plaintext = malloc(ciphertext_len + AES_BLOCK_SIZE + 1);
    if (*plaintext == NULL)
        return -1;

    int len;
    if (EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len) != 1) {
        free(*plaintext);
        return -1;
    }
    assert(len >= 0);
    assert((unsigned)len <= ciphertext_len + AES_BLOCK_SIZE);
    *plaintext_len = len;

    /* It's OK to write more plain text bytes in this step. */
    if (EVP_DecryptFinal_ex(ctx, *plaintext + len, &len) != 1) {
        free(*plaintext);
        return -1;
    }
    *plaintext_len += len;
    assert(*plaintext_len < ciphertext_len + AES_BLOCK_SIZE + 1);
    (*plaintext)[*plaintext_len] = '\0';

    return 0;
}

int make_key(const uint8_t *master, size_t master_len, const uint8_t *salt,
        size_t salt_len, int work_factor, uint8_t *buffer) {

    if (work_factor == -1)
        work_factor = 14; // default value

    if (work_factor < 10 || work_factor > 31)
        return -1;

    static const uint32_t r = 8;
    static const uint32_t p = 1;

    if (libscrypt_scrypt(master, master_len, salt, salt_len,
            ((uint64_t)1) << work_factor, r, p, buffer, KEY_SIZE) != 0)
        return -1;

    return 0;
}

int mac(const uint8_t *master, size_t master_len, const uint8_t *data,
        size_t data_len, uint8_t **salt, uint8_t *auth, size_t *auth_len,
        int work_factor) {

    static const size_t SALT_LEN = 8;
    bool salt_malloced = false;

    if (*salt == NULL) {

        *salt = malloc(SALT_LEN);
        if (*salt == NULL)
            return -1;

        if (random_bytes(*salt, SALT_LEN) != 0) {
            free(*salt);
            return -1;
        }

        salt_malloced = true;
    }

    uint8_t key[KEY_SIZE];
    if (make_key(master, master_len, *salt, SALT_LEN, work_factor, key) != 0) {
        if (salt_malloced)
            free(*salt);
        return -1;
    }

    const EVP_MD *sha512 = EVP_sha512();

    //unsigned char md[EVP_MAX_MD_SIZE];
    unsigned md_len;
    if (HMAC(sha512, key, KEY_SIZE, data, data_len, auth, &md_len) == NULL) {
        if (salt_malloced)
            free(*salt);
        return -1;
    }

    *auth_len = (size_t)md_len;

    return 0;
}
