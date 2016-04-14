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
 * @param packed_plaintext           Data to encrypt
 * @param packed_plaintext_len       Length of data to encrypt (must be a multiple of
 *                            16)
 * @param[out] ciphertext     Encrypted data
 * @param[out] ciphertext_len Length of encrypted data
 *
 * @return                    0 on success
 */
int aes_encrypt(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
    const uint8_t *packed_plaintext, size_t packed_plaintext_len, uint8_t **ciphertext,
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
 * @param[out] packed_plaintext      Decrypted data
 * @param[out] packed_plaintext_len  Length of decrypted data
 *
 * @return                    0 on success
 */
int aes_decrypt(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
    const uint8_t *ciphertext, size_t ciphertext_len, uint8_t **packed_plaintext,
    size_t *packed_plaintext_len) __attribute__((visibility("internal")));

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

/** Pack data with padding in preparation for encryption
 *
 * @param plaintext                 Raw data to encrypt
 * @param plaintext_len             Length of raw data to encrypt
 * @param iv                        Initialisation vector
 * @param iv_len                    Length of initiailisation vector
 * @param[out] packed_plaintext     Packed data
 * @param[out] packed_plaintext_len Length of packed data.
 * @return                          0 on success
 */
int pack_data(const uint8_t *plaintext, size_t plaintext_len, const uint8_t *iv,
    size_t iv_len, uint8_t **packed_plaintext, size_t *packed_plaintext_len)
    __attribute__((visibility("internal")));

/** Unpack data that was produced by pack_data
 *
 * @param packed_plaintext     Packed data to unpack
 * @param packed_plaintext_len Length of packed data
 * @param iv                   Initialisation vector for validation
 * @param iv_len               Length of initialisation vector
 * @param[out] plaintext       Data unpacked
 * @param[out] plaintext_len   Length of data unpacked
 * @return                     0 on success
 */
int unpack_data(const uint8_t *packed_plaintext, size_t packed_plaintext_len,
    const uint8_t *iv, size_t iv_len, uint8_t **plaintext,
    size_t *plaintext_len) __attribute__((visibility("internal")));
