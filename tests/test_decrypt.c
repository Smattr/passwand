#include "../src/internal.h"
#include "../src/types.h"
#include "test.h"
#include <openssl/evp.h>
#include <passwand/passwand.h>
#include <stdint.h>
#include <stdlib.h>

TEST("decrypt: decrypt(encrypt(x)) == x") {

  // first let us encrypt something

  const k_t key = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11,
                   12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                   23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
  const iv_t iv = {17, 18, 19, 20, 21, 22, 23, 24,
                   25, 26, 27, 28, 29, 30, 31, 32};

  uint8_t _pp[] = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o',
                   'r', 'l', 'd', 0,   0,   0,   0,   0};
  const ppt_t pp = {
      .data = _pp,
      .length = sizeof(_pp),
  };

  ct_t c;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ASSERT_NOT_NULL(ctx);

  int err = aes_encrypt_init(key, iv, ctx);
  ASSERT_EQ(err, PW_OK);

  err = aes_encrypt(ctx, &pp, &c);
  ASSERT_EQ(err, PW_OK);

  err = aes_encrypt_deinit(ctx);
  ASSERT_EQ(err, PW_OK);

  ASSERT_GT(c.length, 0ul);

  // now, decrypting it should give us the original packed plain text

  EVP_CIPHER_CTX_free(ctx);
  ctx = EVP_CIPHER_CTX_new();
  ASSERT_NOT_NULL(ctx);

  ppt_t out;

  err = aes_decrypt_init(key, iv, ctx);
  ASSERT_EQ(err, PW_OK);

  err = aes_decrypt(ctx, &c, &out);
  ASSERT_EQ(err, PW_OK);

  err = aes_decrypt_deinit(ctx);
  ASSERT_EQ(err, PW_OK);

  EVP_CIPHER_CTX_free(ctx);

  ASSERT_EQ(out.length, pp.length);
  ASSERT_EQ(memcmp(pp.data, out.data, out.length), 0);

  free(c.data);
  passwand_secure_free(out.data, out.length);
}

TEST("decrypt: with bad key") {

  k_t key = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
             17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
  const iv_t iv = {17, 18, 19, 20, 21, 22, 23, 24,
                   25, 26, 27, 28, 29, 30, 31, 32};

  uint8_t _pp[] = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o',
                   'r', 'l', 'd', 0,   0,   0,   0,   0};
  const ppt_t pp = {
      .data = _pp,
      .length = sizeof(_pp),
  };

  ct_t c;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ASSERT_NOT_NULL(ctx);

  int err = aes_encrypt_init(key, iv, ctx);
  ASSERT_EQ(err, PW_OK);

  err = aes_encrypt(ctx, &pp, &c);
  ASSERT_EQ(err, PW_OK);

  err = aes_encrypt_deinit(ctx);
  ASSERT_EQ(err, PW_OK);

  ASSERT_GT(c.length, 0ul);

  // now modify the key and try to decrypt with it

  EVP_CIPHER_CTX_free(ctx);
  ctx = EVP_CIPHER_CTX_new();
  ASSERT_NOT_NULL(ctx);

  key[10] = 42;

  ppt_t out;

  err = aes_decrypt_init(key, iv, ctx);
  ASSERT_EQ(err, PW_OK);

  err = aes_decrypt(ctx, &c, &out);

  // decrypting with a bad key should either (a) fail or (b) succeed but return
  // incorrect data

  if (err == PW_OK) {

    err = aes_decrypt_deinit(ctx);
    ASSERT_EQ(err, PW_OK);

    ASSERT_NE(memcmp(out.data, pp.data, out.length), 0);

    passwand_secure_free(out.data, out.length);
  }

  EVP_CIPHER_CTX_free(ctx);
  free(c.data);
}

TEST("decrypt: with bad initialisation vector") {

  k_t key = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
             17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
  iv_t iv = {17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

  uint8_t _pp[] = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o',
                   'r', 'l', 'd', 0,   0,   0,   0,   0};
  const ppt_t pp = {
      .data = _pp,
      .length = sizeof(_pp),
  };

  ct_t c;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ASSERT_NOT_NULL(ctx);

  int err = aes_encrypt_init(key, iv, ctx);
  ASSERT_EQ(err, PW_OK);

  err = aes_encrypt(ctx, &pp, &c);
  ASSERT_EQ(err, PW_OK);

  err = aes_encrypt_deinit(ctx);
  ASSERT_EQ(err, PW_OK);

  ASSERT_GT(c.length, 0ul);

  // now modify the IV and try to decrypt with it

  EVP_CIPHER_CTX_free(ctx);
  ctx = EVP_CIPHER_CTX_new();
  ASSERT_NOT_NULL(ctx);

  iv[10] = 42;

  ppt_t out;

  err = aes_decrypt_init(key, iv, ctx);
  ASSERT_EQ(err, PW_OK);

  err = aes_decrypt(ctx, &c, &out);

  // decrypting with a bad IV should either (a) fail or (b) succeed but return
  // incorrect data

  if (err == PW_OK) {

    err = aes_decrypt_deinit(ctx);
    ASSERT_EQ(err, PW_OK);

    ASSERT_NE(memcmp(out.data, pp.data, out.length), 0);

    passwand_secure_free(out.data, out.length);
  }

  EVP_CIPHER_CTX_free(ctx);
  free(c.data);
}
