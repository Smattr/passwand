#pragma once

#include <stddef.h>
#include <stdint.h>
#include "types.h"

/** Construct a key for use in AES encryption
 *
 * @param master      Master key
 * @param salt        Salt
 * @param work_factor Work factor to use in Scrypt (must be between 10 and 31
 *                    or -1 for the default)
 * @param[out] buffer Generated key (must have at least 16 bytes accessible)
 * @return            0 on success
 */
int make_key(const m_t *master, const salt_t *salt, int work_factor,
    uint8_t *buffer) __attribute__((visibility("internal")));

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

/** Generate an authentication code
 *
 * @param master        Master key
 * @param data          Data to authenticate
 * @param[in/out] salt  Salt (if this is NULL it will be generated for you)
 * @param[out] auth     Authentication code
 * @param[out] auth_len Length of authentication code
 * @param work_factor   Scrypt work factor (see above)
 * @return              0 on success
 */
int mac(const m_t *master, const ppt_t *data, salt_t *salt, uint8_t *auth,
    size_t *auth_len, int work_factor) __attribute__((visibility("internal")));

/** Pack data with padding in preparation for encryption
 *
 * @param p       Raw data to encrypt
 * @param iv      Initialisation vector
 * @param[out] pp Packed data
 * @return        0 on success
 */
int pack_data(const pt_t *p, const iv_t *iv, ppt_t *pp)
    __attribute__((visibility("internal")));

/** Unpack data that was produced by pack_data
 *
 * @param pp     Packed data to unpack
 * @param iv     Initialisation vector for validation
 * @param[out] p Data unpacked
 * @return       0 on success
 */
int unpack_data(const ppt_t *pp, const iv_t *iv, pt_t *p)
    __attribute__((visibility("internal")));
