#include "internal.h"
#include "types.h"
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

passwand_error_t aes_encrypt_init(const k_t key, const iv_t iv,
                                  EVP_CIPHER_CTX *ctx) {

  if (EVP_EncryptInit(ctx, EVP_aes_256_ctr(), key, iv) != 1)
    return PW_CRYPTO;

  // disable padding as we pre-pad the input
  if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
    return PW_CRYPTO;

  return PW_OK;
}

passwand_error_t aes_encrypt(EVP_CIPHER_CTX *ctx, const ppt_t *pp, ct_t *c) {

  // we require the plain text to be aligned to the block size because this
  // permits a single encrypting step with no implementation-introduced padding
  if (pp->length % AES_BLOCK_SIZE != 0)
    return PW_UNALIGNED;

  // EVP_EncryptUpdate is documented as being able to write at most `inl +
  // cipher_block_size - 1`
  if (SIZE_MAX - (AES_BLOCK_SIZE - 1) < pp->length)
    return PW_OVERFLOW;
  c->data = malloc(pp->length + (AES_BLOCK_SIZE - 1));
  if (c->data == NULL)
    return PW_NO_MEM;

  // argh, OpenSSL API
  int len;

  if (EVP_EncryptUpdate(ctx, c->data, &len, pp->data, pp->length) != 1) {
    free(c->data);
    return PW_CRYPTO;
  }
  c->length = len;
  assert(c->length <= pp->length + (AES_BLOCK_SIZE - 1));

  return PW_OK;
}

passwand_error_t aes_encrypt_deinit(EVP_CIPHER_CTX *ctx) {

  // this finalisation should return no further data because we have disabled
  // padding
  int excess;
  if (EVP_EncryptFinal(ctx, (unsigned char[AES_BLOCK_SIZE]){0}, &excess) != 1)
    return PW_CRYPTO;
  if (excess != 0)
    return PW_CRYPTO;

  return PW_OK;
}

passwand_error_t aes_decrypt_init(const k_t key, const iv_t iv,
                                  EVP_CIPHER_CTX *ctx) {

  if (EVP_DecryptInit(ctx, EVP_aes_256_ctr(), key, iv) != 1)
    return PW_CRYPTO;

  // disable padding
  if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
    return PW_CRYPTO;

  return PW_OK;
}

typedef struct {
  uint8_t *data;
  size_t length;
} buffer_t;

passwand_error_t aes_decrypt(EVP_CIPHER_CTX *ctx, const ct_t *c, ppt_t *pp) {

  buffer_t *buffer = NULL;
  passwand_error_t rc = -1;

  // EVP_DecryptUpdate is documented as writing at most `inl +
  // cipher_block_size`
  if (SIZE_MAX - AES_BLOCK_SIZE < c->length) {
    rc = PW_OVERFLOW;
    goto done;
  }
  buffer = passwand_secure_malloc(sizeof(*buffer));
  if (buffer == NULL) {
    rc = PW_NO_MEM;
    goto done;
  }
  *buffer = (buffer_t){0};
  buffer->data = passwand_secure_malloc(c->length + AES_BLOCK_SIZE);
  if (buffer->data == NULL) {
    rc = PW_NO_MEM;
    goto done;
  }
  buffer->length = c->length + AES_BLOCK_SIZE;

  int len;
  if (EVP_DecryptUpdate(ctx, buffer->data, &len, c->data, c->length) != 1) {
    rc = PW_CRYPTO;
    goto done;
  }
  assert(len >= 0);
  assert((size_t)len <= c->length + AES_BLOCK_SIZE);
  pp->length = len;

  // Copy the internal buffer to the caller’s packed plain text struct. We do
  // this to ensure the caller’s idea of the “length” of the decrypted data
  // is suitable to pass to passwand_secure_free.
  pp->data = passwand_secure_malloc(pp->length);
  if (pp->data == NULL && pp->length > 0) {
    rc = PW_NO_MEM;
    goto done;
  }
  if (pp->length > 0)
    memcpy(pp->data, buffer->data, pp->length);

  rc = PW_OK;

done:
  if (buffer != NULL) {
    if (buffer->data != NULL)
      passwand_secure_free(buffer->data, buffer->length);
    passwand_secure_free(buffer, sizeof(*buffer));
  }

  return rc;
}

passwand_error_t aes_decrypt_deinit(EVP_CIPHER_CTX *ctx) {

  // we should not receive any further data because padding is disabled
  int len;
  if (EVP_DecryptFinal(ctx, (unsigned char[AES_BLOCK_SIZE]){0}, &len) != 1)
    return PW_CRYPTO;
  if (len != 0)
    return PW_CRYPTO;

  return PW_OK;
}
