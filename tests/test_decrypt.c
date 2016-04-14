#include "../src/encryption.h"
#include <CUnit/CUnit.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "test.h"

TEST(decrypt_encrypted, "decrypt undoes encrypt") {

    /* First let's encrypt something. */

    const uint8_t key[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16 };
    const uint8_t iv[] = { 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        30, 31, 32 };

    const uint8_t ppt[] = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l',
        'd', 0, 0, 0, 0, 0 };

    uint8_t *ct;
    size_t ct_len;

    int r = aes_encrypt(key, sizeof key, iv, sizeof iv, ppt, sizeof ppt, &ct,
        &ct_len);
    CU_ASSERT_EQUAL_FATAL(r, 0);

    CU_ASSERT_EQUAL_FATAL(ct_len > 0, true);

    /* Now, decrypting it should give us the original packed plain text. */

    uint8_t *out;
    size_t out_len;

    r = aes_decrypt(key, sizeof key, iv, sizeof iv, ct, ct_len, &out,
        &out_len);
    CU_ASSERT_EQUAL_FATAL(r, 0);

    CU_ASSERT_EQUAL_FATAL(out_len, sizeof ppt);
    CU_ASSERT_EQUAL_FATAL(memcmp(ppt, out, out_len), 0);

    free(ct);
    free(out);
}

TEST(decrypt_bad_key, "decrypting with the wrong key") {
    uint8_t key[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16 };
    const uint8_t iv[] = { 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        30, 31, 32 };

    const uint8_t ppt[] = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l',
        'd', 0, 0, 0, 0, 0 };

    uint8_t *ct;
    size_t ct_len;

    int r = aes_encrypt(key, sizeof key, iv, sizeof iv, ppt, sizeof ppt, &ct,
        &ct_len);
    CU_ASSERT_EQUAL_FATAL(r, 0);

    CU_ASSERT_EQUAL_FATAL(ct_len > 0, true);

    /* Now modify the key and try to decrypt with it. */

    key[10] = 42;

    uint8_t *out;
    size_t out_len;

    r = aes_decrypt(key, sizeof key, iv, sizeof iv, ct, ct_len, &out,
        &out_len);

    /* Decrypting with a bad key should either (a) fail or (b) succeed but
     * return incorrect data.
     */

    if (r == 0) {
        CU_ASSERT_NOT_EQUAL_FATAL(memcmp(out, ppt, out_len), 0);

        free(out);
    }

    free(ct);
}

TEST(decrypt_bad_iv, "decrypting with the wrong initialisation vector") {
    const uint8_t key[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16 };
    uint8_t iv[] = { 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        30, 31, 32 };

    const uint8_t ppt[] = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l',
        'd', 0, 0, 0, 0, 0 };

    uint8_t *ct;
    size_t ct_len;

    int r = aes_encrypt(key, sizeof key, iv, sizeof iv, ppt, sizeof ppt, &ct,
        &ct_len);
    CU_ASSERT_EQUAL_FATAL(r, 0);

    CU_ASSERT_EQUAL_FATAL(ct_len > 0, true);

    /* Now modify the IV and try to decrypt with it. */

    iv[10] = 42;

    uint8_t *out;
    size_t out_len;

    r = aes_decrypt(key, sizeof key, iv, sizeof iv, ct, ct_len, &out,
        &out_len);

    /* Decrypting with a bad IV should either (a) fail or (b) succeed but
     * return incorrect data.
     */

    if (r == 0) {
        CU_ASSERT_NOT_EQUAL_FATAL(memcmp(out, ppt, out_len), 0);

        free(out);
    }

    free(ct);
}
