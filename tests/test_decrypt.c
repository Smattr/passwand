#include "../src/internal.h"
#include "../src/types.h"
#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "test.h"

TEST("decrypt: decrypt(encrypt(x)) == x") {

    /* First let's encrypt something. */

    const k_t key = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const iv_t iv = { 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };

    uint8_t _pp[] = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 0, 0, 0, 0, 0 };
    const ppt_t pp = {
        .data = _pp,
        .length = sizeof _pp,
    };

    ct_t c;

    EVP_CIPHER_CTX ctx;
    passwand_error_t err = aes_encrypt_init(key, iv, &ctx);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);

    err = aes_encrypt(&ctx, &pp, &c);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);

    err = aes_encrypt_deinit(&ctx);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);

    CU_ASSERT_EQUAL_FATAL(c.length > 0, true);

    /* Now, decrypting it should give us the original packed plain text. */

    ppt_t out;

    err = aes_decrypt_init(key, iv, &ctx);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);

    err = aes_decrypt(&ctx, &c, &out);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);

    err = aes_decrypt_deinit(&ctx);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);

    CU_ASSERT_EQUAL_FATAL(out.length, pp.length);
    CU_ASSERT_EQUAL_FATAL(memcmp(pp.data, out.data, out.length), 0);

    free(c.data);
    passwand_secure_free(out.data, out.length);
}

TEST("decrypt: with bad key") {

    k_t key = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const iv_t iv = { 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };

    uint8_t _pp[] = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 0, 0, 0, 0, 0 };
    const ppt_t pp = {
        .data = _pp,
        .length = sizeof _pp,
    };

    ct_t c;

    EVP_CIPHER_CTX ctx;
    passwand_error_t err = aes_encrypt_init(key, iv, &ctx);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);

    err = aes_encrypt(&ctx, &pp, &c);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);

    err = aes_encrypt_deinit(&ctx);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);

    CU_ASSERT_EQUAL_FATAL(c.length > 0, true);

    /* Now modify the key and try to decrypt with it. */

    key[10] = 42;

    ppt_t out;

    err = aes_decrypt_init(key, iv, &ctx);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);

    err = aes_decrypt(&ctx, &c, &out);

    /* Decrypting with a bad key should either (a) fail or (b) succeed but return incorrect data. */

    if (err == PW_OK) {

        err = aes_decrypt_deinit(&ctx);
        CU_ASSERT_EQUAL_FATAL(err, PW_OK);

        CU_ASSERT_NOT_EQUAL_FATAL(memcmp(out.data, pp.data, out.length), 0);

        passwand_secure_free(out.data, out.length);
    }

    free(c.data);
}

TEST("decrypt: with bad initialisation vector") {

    k_t key = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    iv_t iv = { 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };

    uint8_t _pp[] = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 0, 0, 0, 0, 0 };
    const ppt_t pp = {
        .data = _pp,
        .length = sizeof _pp,
    };

    ct_t c;

    EVP_CIPHER_CTX ctx;
    passwand_error_t err = aes_encrypt_init(key, iv, &ctx);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);

    err = aes_encrypt(&ctx, &pp, &c);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);

    err = aes_encrypt_deinit(&ctx);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);

    CU_ASSERT_EQUAL_FATAL(c.length > 0, true);

    /* Now modify the IV and try to decrypt with it. */

    iv[10] = 42;

    ppt_t out;

    err = aes_decrypt_init(key, iv, &ctx);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);

    err = aes_decrypt(&ctx, &c, &out);

    /* Decrypting with a bad IV should either (a) fail or (b) succeed but return incorrect data. */

    if (err == PW_OK) {

        err = aes_decrypt_deinit(&ctx);
        CU_ASSERT_EQUAL_FATAL(err, PW_OK);

        CU_ASSERT_NOT_EQUAL_FATAL(memcmp(out.data, pp.data, out.length), 0);

        passwand_secure_free(out.data, out.length);
    }

    free(c.data);
}
