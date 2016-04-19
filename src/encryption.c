/* XXX: libscrypt.h is busted and doesn't include the necessary headers for uint8_t and size_t. */
#include <stddef.h>
#include <stdint.h>

#include <assert.h>
#include "auto.h"
#include "encryption.h"
#include <endian.h>
#include <fcntl.h>
#include <limits.h>
#include <libscrypt.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <passwand/passwand.h>
#include "random.h"
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
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key->data, iv->data)
            != 1)
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
    uint8_t *buffer;
    size_t buffer_len = c->length + AES_BLOCK_SIZE;
    if (passwand_secure_malloc((void**)&buffer, buffer_len) != 0)
        return -1;

    int len;
    if (EVP_DecryptUpdate(ctx, buffer, &len, c->data, c->length) != 1) {
        passwand_secure_free(buffer, buffer_len);
        return -1;
    }
    assert(len >= 0);
    assert((unsigned)len <= c->length + AES_BLOCK_SIZE);
    pp->length = len;

    /* It's OK to write more plain text bytes in this step. */
    if (EVP_DecryptFinal_ex(ctx, buffer + len, &len) != 1) {
        passwand_secure_free(buffer, buffer_len);
        return -1;
    }
    pp->length += len;
    assert(pp->length <= c->length + AES_BLOCK_SIZE);

    /* Copy the internal buffer to the caller's packed plain text struct. We do
     * this to ensure the caller's idea of the "length" of the decrypted data
     * is suitable to pass to passwand_secure_free.
     */
    if (passwand_secure_malloc((void**)&pp->data, pp->length) != 0) {
        passwand_secure_free(buffer, buffer_len);
        return -1;
    }
    memcpy(pp->data, buffer, pp->length);
    passwand_secure_free(buffer, buffer_len);

    return 0;
}

passwand_error_t make_key(const m_t *master, const salt_t *salt, int work_factor, k_t *key) {

    assert(master != NULL);
    assert(salt != NULL);
    assert(key != NULL);
    assert(key->data != NULL);
    assert(key->length == make_key_length(master, salt, work_factor));

    if (work_factor == -1)
        work_factor = 14; // default value

    if (work_factor < 10 || work_factor > 31)
        return PW_BAD_WF;

    static const uint32_t r = 8;
    static const uint32_t p = 1;

    if (libscrypt_scrypt(master->data, master->length, salt->data, salt->length,
            ((uint64_t)1) << work_factor, r, p, key->data, key->length) != 0)
        return PW_CRYPTO;

    return PW_OK;
}

passwand_error_t hmac(const m_t *master, const data_t *data, const salt_t *salt, mac_t *mac,
        int work_factor) {

    AUTO_K_T(k);
    if (k == NULL)
        return PW_NO_MEM;
    passwand_error_t err = make_key(master, salt, work_factor, k);
    if (err != PW_OK)
        return err;

    const EVP_MD *sha512 = EVP_sha512();

    //unsigned char md[EVP_MAX_MD_SIZE];
    mac->data = malloc(EVP_MAX_MD_SIZE);
    if (mac->data == NULL)
        return PW_NO_MEM;
    unsigned md_len;
    unsigned char *r = HMAC(sha512, k->data, k->length, data->data, data->length, mac->data,
        &md_len);
    if (r == NULL) {
        free(mac->data);
        return PW_CRYPTO;
    }

    mac->length = md_len;

    return PW_OK;
}

passwand_error_t pack_data(const pt_t *p, const iv_t *iv, ppt_t *pp) {

    assert(pp != NULL);

    /* Calculate the final length of the unpadded data. */
    if (SIZE_MAX - strlen(HEADER) - sizeof(uint64_t) < iv->length)
        return PW_OVERFLOW;
    if (SIZE_MAX - strlen(HEADER) - sizeof(uint64_t) - iv->length < p->length)
        return PW_OVERFLOW;
    size_t length = strlen(HEADER) + sizeof(uint64_t) + iv->length + p->length;

    /* The padding needs to align the final data to a 16-byte boundary. */
    size_t padding_len = AES_BLOCK_SIZE - length % AES_BLOCK_SIZE;

    /* Generate the padding. Agile Bits considers the padding scheme from IETF draft
     * AEAD-AES-CBC-HMAC-SHA as a more suitable replacement, but I'm not sure why. It involves
     * deterministic bytes that seems inherently less secure.
     */
    uint8_t *padding;
    if (passwand_secure_malloc((void**)&padding, padding_len) != 0)
        return PW_NO_MEM;
    passwand_error_t r = random_bytes(padding, padding_len);
    if (r != PW_OK) {
        passwand_secure_free(padding, padding_len);
        return r;
    }

    /* We're now ready to write the packed data. */

    if (SIZE_MAX - length < padding_len) {
        passwand_secure_free(padding, padding_len);
        return PW_OVERFLOW;
    }
    pp->length = length + padding_len;
    assert(pp->length % AES_BLOCK_SIZE == 0);
    if (passwand_secure_malloc((void**)&pp->data, pp->length) != 0) {
        passwand_secure_free(padding, padding_len);
        return PW_NO_MEM;
    }

    size_t offset = 0;

    memcpy(pp->data, HEADER, strlen(HEADER));
    offset += strlen(HEADER);

    /* Pack the length of the plain text as a little endian 8-byte number. */
    uint64_t encoded_pt_len = htole64(p->length);
    memcpy(pp->data + offset, &encoded_pt_len, sizeof(encoded_pt_len));
    offset += sizeof(encoded_pt_len);

    /* Pack the initialisation vector. */
    memcpy(pp->data + offset, iv->data, iv->length);
    offset += iv->length;

    /* Pack the padding, *prepending* the plain text. */
    memcpy(pp->data + offset, padding, padding_len);
    offset += padding_len;
    passwand_secure_free(padding, padding_len);

    /* Pack the plain text itself. */
    memcpy(pp->data + offset, p->data, p->length);
    offset += p->length;

    return PW_OK;
}

passwand_error_t unpack_data(const ppt_t *pp, const iv_t *iv, pt_t *p) {

    assert(pp != NULL);
    assert(pp->data != NULL);
    assert(iv != NULL);
    assert(iv->data != NULL);
    assert(p != NULL);

    if (pp->length % AES_BLOCK_SIZE != 0)
        return PW_UNALIGNED;

    ppt_t d = *pp;

    /* Check we have the correct header. */
    if (d.length < strlen(HEADER) ||
            strncmp((const char*)d.data, HEADER, strlen(HEADER)) != 0)
        return PW_HEADER_MISMATCH;
    d.data += strlen(HEADER);
    d.length -= strlen(HEADER);

    /* Unpack the size of the original plain text. */
    uint64_t encoded_pt_len;
    if (d.length < sizeof(encoded_pt_len))
        return PW_TRUNCATED;
    memcpy(&encoded_pt_len, d.data, sizeof(encoded_pt_len));
    p->length = le64toh(encoded_pt_len);
    d.data += sizeof(encoded_pt_len);
    d.length -= sizeof(encoded_pt_len);

    /* Check the initialisation vector matches. */
    if (d.length < iv->length)
        return PW_TRUNCATED;
    if (memcmp(d.data, iv->data, iv->length) != 0)
        return PW_IV_MISMATCH;
    d.data += iv->length;
    d.length -= iv->length;

    /* Check we do indeed have enough space for the plain text left. */
    if (d.length < p->length)
        return PW_TRUNCATED;

    /* Check the data was padded correctly. */
    if (d.length - p->length > 16)
        return PW_BAD_PADDING;

    /* Now we're ready to unpack it. */
    if (passwand_secure_malloc((void**)&p->data, p->length) != 0)
        return PW_NO_MEM;
    memcpy(p->data, d.data + d.length - p->length, p->length);

    return PW_OK;
}
