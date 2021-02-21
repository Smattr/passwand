#pragma once

#include "constants.h"
#include "types.h"
#include <openssl/evp.h>
#include <passwand/passwand.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/** Construct a key for use in AES encryption
 *
 * @param mainkey     Main key
 * @param salt        Salt
 * @param work_factor Work factor to use in Scrypt (must be between 10 and 31
 *                    or -1 for the default)
 * @param[out] key    Generated key
 * @return            PW_OK on success
 */
passwand_error_t make_key(const m_t *mainkey, const salt_t *salt,
                          int work_factor, k_t key)
    __attribute__((visibility("internal")));

/** Initialise an AES encryption context
 *
 * @param key    Encryption key
 * @param iv     Initialisation vector
 * @param ctx    Encryption context to initialise
 * @return       PW_OK on success
 */
passwand_error_t aes_encrypt_init(const k_t key, const iv_t iv,
                                  EVP_CIPHER_CTX *ctx)
    __attribute__((visibility("internal")));

/** Encrypt data
 *
 * This function uses AES128 in CTR mode.
 *
 * @param ctx    Encryption context
 * @param pp     Data to encrypt (must be 16-byte aligned)
 * @param[out] c Encrypted data
 * @return       PW_OK on success
 */
passwand_error_t aes_encrypt(EVP_CIPHER_CTX *ctx, const ppt_t *pp, ct_t *c)
    __attribute__((visibility("internal")));

/** Deinitialise encryption context
 *
 * @param ctx    Encryption context
 * @return       PW_OK on success
 */
passwand_error_t aes_encrypt_deinit(EVP_CIPHER_CTX *ctx)
    __attribute__((visibility("internal")));

/** Initialise decryption context
 *
 * @param key    Encryption key
 * @param iv     Initialisation vector
 * @param ctx    Decryption context to initialise
 * @return       PW_OK on success
 */
passwand_error_t aes_decrypt_init(const k_t key, const iv_t iv,
                                  EVP_CIPHER_CTX *ctx)
    __attribute__((visibility("internal")));

/** Decrypt data
 *
 * This function uses AES128 in CTR mode.
 *
 * @param ctx     Decryption context to initialise
 * @param c       Data to decrypt
 * @param[out] pp Decrypted data
 * @return        PW_OK on success
 */
passwand_error_t aes_decrypt(EVP_CIPHER_CTX *ctx, const ct_t *c, ppt_t *pp)
    __attribute__((visibility("internal")));

/** Deinitialise a decryption context
 *
 * @param ctx     Decryption context to initialise
 * @return        PW_OK on success
 */
passwand_error_t aes_decrypt_deinit(EVP_CIPHER_CTX *ctx)
    __attribute__((visibility("internal")));

/** Generate an authentication code
 *
 * @param mainkey       Main key
 * @param data          Data to authenticate
 * @param salt          Salt
 * @param[out] mac      Authentication code
 * @param work_factor   Scrypt work factor (see above)
 * @return              PW_OK on success
 */
passwand_error_t hmac(const m_t *mainkey, const data_t *data,
                      const salt_t *salt, mac_t *mac, int work_factor)
    __attribute__((visibility("internal")));

/** Pack data with padding in preparation for encryption
 *
 * @param p       Raw data to encrypt
 * @param iv      Initialisation vector
 * @param[out] pp Packed data
 * @return        PW_OK on success
 */
passwand_error_t pack_data(const pt_t *p, const iv_t iv, ppt_t *pp)
    __attribute__((visibility("internal")));

/** Unpack data that was produced by pack_data
 *
 * @param pp     Packed data to unpack
 * @param iv     Initialisation vector for validation
 * @param[out] p Data unpacked
 * @return       PW_OK on success
 */
passwand_error_t unpack_data(const ppt_t *pp, const iv_t iv, pt_t *p)
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
