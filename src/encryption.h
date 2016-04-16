#pragma once

#include <openssl/evp.h>
#include <passwand/passwand.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "types.h"

#define HEADER "oprime01"

enum {
    AES_BLOCK_SIZE = 16, // bytes
    AES_KEY_SIZE = 16, // bytes
};

/** Construct a key for use in AES encryption
 *
 * @param master      Master key
 * @param salt        Salt
 * @param work_factor Work factor to use in Scrypt (must be between 10 and 31
 *                    or -1 for the default)
 * @param[out] key    Generated key
 * @return            PW_OK on success
 */
passwand_error_t make_key(const m_t *master, const salt_t *salt, int work_factor, k_t *key)
    __attribute__((visibility("internal")));

static inline size_t make_key_length(const m_t *master __attribute__((unused)),
        const salt_t *salt __attribute__((unused)),
        int work_factor __attribute__((unused))) {
    return AES_KEY_SIZE;
}

/** Encrypt data
 *
 * This function uses AES128 in CTR mode.
 *
 * @param key    Encryption key
 * @param iv     Initialisation vector
 * @param pp     Data to encrypt (must be 16-byte aligned)
 * @param[out] c Encrypted data
 * @return       0 on success
 */
int aes_encrypt(const k_t *key, const iv_t *iv, const ppt_t *pp, ct_t *c)
    __attribute__((visibility("internal")));

static inline size_t aes_encrypt_length(const k_t *key __attribute__((unused)),
        const iv_t *iv __attribute__((unused)), const ppt_t *pp) {
    return pp->length + (AES_BLOCK_SIZE - 1);
}

/** Decrypt data
 *
 * This function uses AES128 in CTR mode.
 *
 * @param key     Encryption key (must be 16 bytes)
 * @param iv      Initialisation vector (must be 16 bytes)
 * @param c       Data to decrypt
 * @param[out] pp Decrypted data
 * @return        0 on success
 */
int aes_decrypt(const k_t *key, const iv_t *iv, const ct_t *c, ppt_t *pp)
    __attribute__((visibility("internal")));

static inline size_t aes_decrypt_length(const k_t *key __attribute__((unused)),
        const iv_t *iv __attribute__((unused)), const ct_t *c) {
    return c->length + AES_BLOCK_SIZE + 1;
}

/** Generate an authentication code
 *
 * @param master        Master key
 * @param data          Data to authenticate
 * @param salt          Salt
 * @param[out] mac      Authentication code
 * @param work_factor   Scrypt work factor (see above)
 * @return              PW_OK on success
 */
passwand_error_t hmac(const m_t *master, const data_t *data, const salt_t *salt,
    mac_t *mac, int work_factor) __attribute__((visibility("internal")));

static inline size_t hmac_length(const m_t *master __attribute__((unused)),
        const data_t *data __attribute__((unused)),
        const salt_t *salt __attribute__((unused)),
        int work_factor __attribute__((unused))) {
    return EVP_MAX_MD_SIZE;
}

/** Pack data with padding in preparation for encryption
 *
 * @param p       Raw data to encrypt
 * @param iv      Initialisation vector
 * @param[out] pp Packed data
 * @return        PW_OK on success
 */
passwand_error_t pack_data(const pt_t *p, const iv_t *iv, ppt_t *pp)
    __attribute__((visibility("internal")));

static inline size_t pack_data_length(const pt_t *p, const iv_t *iv) {
    size_t length = strlen(HEADER) + sizeof(uint64_t) + iv->length + p->length;
    size_t padding_len = AES_BLOCK_SIZE - length % AES_BLOCK_SIZE;
    return length + padding_len;
}

/** Unpack data that was produced by pack_data
 *
 * @param pp     Packed data to unpack
 * @param iv     Initialisation vector for validation
 * @param[out] p Data unpacked
 * @return       PW_OK on success
 */
passwand_error_t unpack_data(const ppt_t *pp, const iv_t *iv, pt_t *p)
    __attribute__((visibility("internal")));

static inline size_t unpack_data_length(const ppt_t *pp, const iv_t *iv) {
    return pp->length - strlen(HEADER) - sizeof(uint64_t) - iv->length;
}
