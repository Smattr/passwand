#pragma once

#include <stddef.h>
#include <stdint.h>

/** Construct a key for use in AES encryption
 *
 * @param master      Master key
 * @param master_len  Length of master key
 * @param salt        Salt
 * @param salt_len    Length of salt
 * @param work_factor Work factor to use in Scrypt (must be between 10 and 31
 *                    or -1 for the default)
 * @param[out] buffer Generated key (must have at least 16 bytes accessible)
 * @return            0 on success
 */
int make_key(const uint8_t *master, size_t master_len, const uint8_t *salt,
    size_t salt_len, int work_factor, uint8_t *buffer)
    __attribute__((visibility("internal")));

/** Encrypt data
 *
 * This function uses AES128 in CTR mode.
 *
 * @param key                 Encryption key
 * @param key_len             Length of encryption key in bytes (must be 16)
 * @param iv                  Initialisation vector
 * @param iv_len              Length of initialisation vector (must be 16)
 * @param plaintext           Data to encrypt
 * @param plaintext_len       Length of data to encrypt (must be a multiple of
 *                            16)
 * @param[out] ciphertext     Encrypted data
 * @param[out] ciphertext_len Length of encrypted data
 *
 * @return                    0 on success
 */
int aes_encrypt(uint8_t *key, size_t key_len, uint8_t *iv, size_t iv_len,
    uint8_t *plaintext, size_t plaintext_len, uint8_t **ciphertext,
    size_t *ciphertext_len) __attribute__((visibility("internal")));

/** Decrypt data
 *
 * This function uses AES128 in CTR mode.
 *
 * @param key                 Encryption key
 * @param key_len             Length of encryption key in bytes (must be 16)
 * @param iv                  Initialisation vector
 * @param iv_len              Length of initialisation vector (must be 16)
 * @param ciphertext          Data to decrypt
 * @param ciphertext_len      Length of data to decrypt
 * @param[out] plaintext      Decrypted data
 * @param[out] plaintext_len  Length of decrypted data
 *
 * @return                    0 on success
 */
int aes_decrypt(uint8_t *key, size_t key_len, uint8_t *iv, size_t iv_len,
    uint8_t *ciphertext, size_t ciphertext_len, uint8_t **plaintext,
    size_t *plaintext_len) __attribute__((visibility("internal")));

/** Generate some random bytes
 *
 * @param[out] buffer Random data
 * @param buffer_len  Number of bytes requested
 * @return            0 on success
 */
int random_bytes(uint8_t *buffer, size_t buffer_len)
    __attribute__((visibility("internal")));

/** Generate an authentication code
 *
 * @param master        Master key
 * @param master_len    Length of master key
 * @param data          Data to authenticate
 * @param data_len      Length of data to authenticate
 * @param[in/out] salt  Salt (if this is NULL it will be generated for you)
 * @param[out] auth     Authentication code
 * @param[out] auth_len Length of authentication code
 * @param work_factor   Scrypt work factor (see above)
 * @return              0 on success
 */
int mac(const uint8_t *master, size_t master_len, const uint8_t *data,
    size_t data_len, uint8_t **salt, uint8_t *auth, size_t *auth_len,
    int work_factor) __attribute__((visibility("internal")));
