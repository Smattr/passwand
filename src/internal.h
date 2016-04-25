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

/** Encrypt data
 *
 * This function uses AES128 in CTR mode.
 *
 * @param key    Encryption key
 * @param iv     Initialisation vector
 * @param pp     Data to encrypt (must be 16-byte aligned)
 * @param[out] c Encrypted data
 * @return       PW_OK on success
 */
passwand_error_t aes_encrypt(const k_t *key, const iv_t *iv, const ppt_t *pp, ct_t *c)
    __attribute__((visibility("internal")));

/** Decrypt data
 *
 * This function uses AES128 in CTR mode.
 *
 * @param key     Encryption key (must be 16 bytes)
 * @param iv      Initialisation vector (must be 16 bytes)
 * @param c       Data to decrypt
 * @param[out] pp Decrypted data
 * @return        PW_OK on success
 */
passwand_error_t aes_decrypt(const k_t *key, const iv_t *iv, const ct_t *c, ppt_t *pp)
    __attribute__((visibility("internal")));

/** Generate an authentication code
 *
 * @param master        Master key
 * @param data          Data to authenticate
 * @param salt          Salt
 * @param[out] mac      Authentication code
 * @param work_factor   Scrypt work factor (see above)
 * @return              PW_OK on success
 */
passwand_error_t hmac(const m_t *master, const data_t *data, const salt_t *salt, mac_t *mac,
    int work_factor) __attribute__((visibility("internal")));

/** Pack data with padding in preparation for encryption
 *
 * @param p       Raw data to encrypt
 * @param iv      Initialisation vector
 * @param[out] pp Packed data
 * @return        PW_OK on success
 */
passwand_error_t pack_data(const pt_t *p, const iv_t *iv, ppt_t *pp)
    __attribute__((visibility("internal")));

/** Unpack data that was produced by pack_data
 *
 * @param pp     Packed data to unpack
 * @param iv     Initialisation vector for validation
 * @param[out] p Data unpacked
 * @return       PW_OK on success
 */
passwand_error_t unpack_data(const ppt_t *pp, const iv_t *iv, pt_t *p)
    __attribute__((visibility("internal")));

/** Generate some random bytes
 *
 * @param[out] buffer Random data
 * @param buffer_len  Number of bytes requested
 * @return            PW_OK on success
 */
passwand_error_t random_bytes(void *buffer, size_t buffer_len)
    __attribute__((visibility("internal")));

passwand_error_t encode(const uint8_t *s, size_t len, char **e)
    __attribute__((visibility("internal")));

passwand_error_t decode(const char *s, uint8_t **d, size_t *len)
    __attribute__((visibility("internal")));
