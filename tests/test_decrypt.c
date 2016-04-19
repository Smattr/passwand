#include "../src/encryption.h"
#include "../src/types.h"
#include <CUnit/CUnit.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "test.h"

TEST("decrypt undoes encrypt") {

    /* First let's encrypt something. */

    uint8_t _key[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16 };
    const k_t key = {
        .data = _key,
        .length = sizeof _key,
    };
    uint8_t _iv[] = { 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        30, 31, 32 };
    const iv_t iv = {
        .data = _iv,
        .length = sizeof _iv,
    };

    uint8_t _pp[] = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l',
        'd', 0, 0, 0, 0, 0 };
    const ppt_t pp = {
        .data = _pp,
        .length = sizeof _pp,
    };

    ct_t c;

    int r = aes_encrypt(&key, &iv, &pp, &c);
    CU_ASSERT_EQUAL_FATAL(r, 0);

    CU_ASSERT_EQUAL_FATAL(c.length > 0, true);

    /* Now, decrypting it should give us the original packed plain text. */

    ppt_t out;

    r = aes_decrypt(&key, &iv, &c, &out);
    CU_ASSERT_EQUAL_FATAL(r, 0);

    CU_ASSERT_EQUAL_FATAL(out.length, pp.length);
    CU_ASSERT_EQUAL_FATAL(memcmp(pp.data, out.data, out.length), 0);

    free(c.data);
    free(out.data);
}

TEST("decrypting with the wrong key") {
    uint8_t _key[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16 };
    k_t key = {
        .data = _key,
        .length = sizeof _key,
    };
    uint8_t _iv[] = { 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        30, 31, 32 };
    const iv_t iv = {
        .data = _iv,
        .length = sizeof _iv,
    };

    uint8_t _pp[] = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l',
        'd', 0, 0, 0, 0, 0 };
    const ppt_t pp = {
        .data = _pp,
        .length = sizeof _pp,
    };

    ct_t c;

    int r = aes_encrypt(&key, &iv, &pp, &c);
    CU_ASSERT_EQUAL_FATAL(r, 0);

    CU_ASSERT_EQUAL_FATAL(c.length > 0, true);

    /* Now modify the key and try to decrypt with it. */

    key.data[10] = 42;

    ppt_t out;

    r = aes_decrypt(&key, &iv, &c, &out);

    /* Decrypting with a bad key should either (a) fail or (b) succeed but
     * return incorrect data.
     */

    if (r == 0) {
        CU_ASSERT_NOT_EQUAL_FATAL(memcmp(out.data, pp.data, out.length), 0);

        free(out.data);
    }

    free(c.data);
}

TEST("decrypting with the wrong initialisation vector") {
    uint8_t _key[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16 };
    const k_t key = {
        .data = _key,
        .length = sizeof _key,
    };
    uint8_t _iv[] = { 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        30, 31, 32 };
    iv_t iv = {
        .data = _iv,
        .length = sizeof _iv,
    };

    uint8_t _pp[] = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l',
        'd', 0, 0, 0, 0, 0 };
    const ppt_t pp = {
        .data = _pp,
        .length = sizeof _pp,
    };

    ct_t c;

    int r = aes_encrypt(&key, &iv, &pp, &c);
    CU_ASSERT_EQUAL_FATAL(r, 0);

    CU_ASSERT_EQUAL_FATAL(c.length > 0, true);

    /* Now modify the IV and try to decrypt with it. */

    iv.data[10] = 42;

    ppt_t out;

    r = aes_decrypt(&key, &iv, &c, &out);

    /* Decrypting with a bad IV should either (a) fail or (b) succeed but
     * return incorrect data.
     */

    if (r == 0) {
        CU_ASSERT_NOT_EQUAL_FATAL(memcmp(out.data, pp.data, out.length), 0);

        free(out.data);
    }

    free(c.data);
}
