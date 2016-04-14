/* XXX: libscrypt.h is busted and doesn't include the necessary headers for
 * uint8_t and size_t.
 */
#include <stddef.h>
#include <stdint.h>

#include <assert.h>
#include "encryption.h"
#include <endian.h>
#include <fcntl.h>
#include <limits.h>
#include <libscrypt.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "random.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const char HEADER[] = "oprime01";

static const size_t AES_BLOCK_SIZE = 16; // bytes
static const size_t AES_KEY_SIZE = 16; // bytes

static void ctxfree(void *p) {
    assert(p != NULL);
    EVP_CIPHER_CTX **ctx = p;
    if (*ctx != NULL)
        EVP_CIPHER_CTX_free(*ctx);
}

int aes_encrypt(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
        const uint8_t *packed_plaintext, size_t packed_plaintext_len, uint8_t **ciphertext,
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
    if (packed_plaintext_len % AES_BLOCK_SIZE != 0)
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
    if (SIZE_MAX - (AES_BLOCK_SIZE - 1) < packed_plaintext_len)
        return -1;
    *ciphertext = malloc(packed_plaintext_len + (AES_BLOCK_SIZE - 1));
    if (*ciphertext == NULL)
        return -1;

    /* Argh, OpenSSL API. */
    int len;

    if (EVP_EncryptUpdate(ctx, *ciphertext, &len, packed_plaintext, packed_plaintext_len) != 1) {
        free(*ciphertext);
        return -1;
    }
    *ciphertext_len = len;
    assert(*ciphertext_len <= packed_plaintext_len + (AES_BLOCK_SIZE - 1));

    /* If we've got everything right, this finalisation should return no further
     * data. XXX: don't stack-allocate this here.
     */
    unsigned char temp[packed_plaintext_len + AES_BLOCK_SIZE - 1];
    int excess;
    if (EVP_EncryptFinal_ex(ctx, temp, &excess) != 1 || excess != 0) {
        free(*ciphertext);
        return -1;
    }

    return 0;
}

int aes_decrypt(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
        const uint8_t *ciphertext, size_t ciphertext_len, uint8_t **packed_plaintext,
        size_t *packed_plaintext_len) {

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
    if (SIZE_MAX - AES_BLOCK_SIZE - 1 < ciphertext_len)
        return -1;
    *packed_plaintext = malloc(ciphertext_len + AES_BLOCK_SIZE + 1);
    if (*packed_plaintext == NULL)
        return -1;

    int len;
    if (EVP_DecryptUpdate(ctx, *packed_plaintext, &len, ciphertext, ciphertext_len) != 1) {
        free(*packed_plaintext);
        return -1;
    }
    assert(len >= 0);
    assert((unsigned)len <= ciphertext_len + AES_BLOCK_SIZE);
    *packed_plaintext_len = len;

    /* It's OK to write more plain text bytes in this step. */
    if (EVP_DecryptFinal_ex(ctx, *packed_plaintext + len, &len) != 1) {
        free(*packed_plaintext);
        return -1;
    }
    *packed_plaintext_len += len;
    assert(*packed_plaintext_len < ciphertext_len + AES_BLOCK_SIZE + 1);
    (*packed_plaintext)[*packed_plaintext_len] = '\0';

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
            ((uint64_t)1) << work_factor, r, p, buffer, AES_KEY_SIZE) != 0)
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

    uint8_t key[AES_KEY_SIZE];
    if (make_key(master, master_len, *salt, SALT_LEN, work_factor, key) != 0) {
        if (salt_malloced)
            free(*salt);
        return -1;
    }

    const EVP_MD *sha512 = EVP_sha512();

    //unsigned char md[EVP_MAX_MD_SIZE];
    unsigned md_len;
    if (HMAC(sha512, key, sizeof key, data, data_len, auth, &md_len) == NULL) {
        if (salt_malloced)
            free(*salt);
        return -1;
    }

    *auth_len = (size_t)md_len;

    return 0;
}

int pack_data(const uint8_t *plaintext, size_t plaintext_len, const uint8_t *iv,
        size_t iv_len, uint8_t **packed_plaintext, size_t *packed_plaintext_len) {
    assert(packed_plaintext != NULL);
    assert(packed_plaintext_len != NULL);

    /* Calculate the final length of the unpadded data. */
    if (SIZE_MAX - strlen(HEADER) - sizeof(uint64_t) < iv_len)
        return -1;
    if (SIZE_MAX - strlen(HEADER) - sizeof(uint64_t) - iv_len < plaintext_len)
        return -1;
    size_t length = strlen(HEADER) + sizeof(uint64_t) + iv_len + plaintext_len;

    /* The padding needs to align the final data to a 16-byte boundary. */
    size_t padding_len = AES_BLOCK_SIZE - length % AES_BLOCK_SIZE;

    /* Generate the padding. Agile Bits considers the padding scheme from IETF
     * draft AEAD-AES-CBC-HMAC-SHA as a more suitable replacement, but I'm not
     * sure why. It involves deterministic bytes that seems inherently less
     * secure.
     */
    uint8_t padding[AES_BLOCK_SIZE];
    int r = random_bytes(padding, padding_len);
    if (r != 0)
        return -1;

    /* We're now ready to write the packed data. */

    if (SIZE_MAX - length < padding_len)
        return -1;
    *packed_plaintext_len = length + padding_len;
    assert(*packed_plaintext_len % AES_BLOCK_SIZE == 0);
    *packed_plaintext = malloc(*packed_plaintext_len);
    if (*packed_plaintext == NULL)
        return -1;

    size_t offset = 0;

    memcpy(*packed_plaintext, HEADER, strlen(HEADER));
    offset += strlen(HEADER);

    /* Pack the length of the plain text as a little endian 8-byte number. */
    uint64_t encoded_pt_len = htole64(plaintext_len);
    memcpy(*packed_plaintext + offset, &encoded_pt_len, sizeof(encoded_pt_len));
    offset += sizeof(encoded_pt_len);

    /* Pack the initialisation vector. */
    memcpy(*packed_plaintext + offset, iv, iv_len);
    offset += iv_len;

    /* Pack the padding, *prepending* the plain text. */
    memcpy(*packed_plaintext + offset, padding, padding_len);
    offset += padding_len;

    /* Pack the plain text itself. */
    memcpy(*packed_plaintext + offset, plaintext, plaintext_len);
    offset += plaintext_len;

    return 0;
}

int unpack_data(const uint8_t *packed_plaintext, size_t packed_plaintext_len,
        const uint8_t *iv, size_t iv_len, uint8_t **plaintext,
        size_t *plaintext_len) {
    assert(packed_plaintext != NULL);
    assert(iv != NULL);
    assert(plaintext != NULL);
    assert(plaintext_len != NULL);

    if (packed_plaintext_len % AES_BLOCK_SIZE != 0)
        return -1;

    /* Check we have the correct header. */
    if (packed_plaintext_len < strlen(HEADER) ||
            strncmp((const char*)packed_plaintext, HEADER, strlen(HEADER)) != 0)
        return -1;
    packed_plaintext += strlen(HEADER);
    packed_plaintext_len -= strlen(HEADER);

    /* Unpack the size of the original plain text. */
    uint64_t encoded_pt_len;
    if (packed_plaintext_len < sizeof(encoded_pt_len))
        return -1;
    memcpy(&encoded_pt_len, packed_plaintext, sizeof(encoded_pt_len));
    *plaintext_len = le64toh(encoded_pt_len);
    packed_plaintext += sizeof(encoded_pt_len);
    packed_plaintext_len -= sizeof(encoded_pt_len);

    /* Check the initialisation vector matches. */
    if (packed_plaintext_len < iv_len)
        return -1;
    if (memcmp(packed_plaintext, iv, iv_len) != 0)
        return -1;
    packed_plaintext += iv_len;
    packed_plaintext_len -= iv_len;

    /* Check we do indeed have enough space for the plain text left. */
    if (packed_plaintext_len < *plaintext_len)
        return -1;

    /* Check the data was padded correctly. */
    if (packed_plaintext_len - *plaintext_len > 16)
        return -1;

    /* Now we're ready to unpack it. */
    *plaintext = malloc(*plaintext_len);
    if (*plaintext == NULL)
        return -1;
    memcpy(*plaintext, packed_plaintext + packed_plaintext_len - *plaintext_len, *plaintext_len);

    return 0;
}
