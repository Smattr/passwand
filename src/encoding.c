#include "internal.h"
#include <assert.h>
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

passwand_error_t encode(const uint8_t *s, size_t len, char **e) {

  assert(s != NULL);
  assert(e != NULL);

  if (len > (size_t)INT_MAX)
    return PW_OVERFLOW;

  // Create a base64 filter.
  BIO *b64 = BIO_new(BIO_f_base64());
  if (b64 == NULL)
    return PW_NO_MEM;
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

  passwand_error_t rc = PW_OK;

  // Create an in-memory sink to encode data into.
  BIO *out = BIO_new(BIO_s_mem());
  if (out == NULL) {
    rc = PW_NO_MEM;
    goto done;
  }

  b64 = BIO_push(b64, out);

  // Encode the data.
  if (BIO_write(b64, s, len) != (int)len) {
    rc = PW_IO;
    goto done;
  }
  BIO_flush(b64);

  // Extract it into a string.
  BUF_MEM *bptr;
  BIO_get_mem_ptr(out, &bptr);

  if (SIZE_MAX - 1 < bptr->length) {
    rc = PW_OVERFLOW;
    goto done;
  }
  *e = malloc(bptr->length + 1);
  if (*e == NULL) {
    rc = PW_NO_MEM;
    goto done;
  }

  if (bptr->length > 0)
    memcpy(*e, bptr->data, bptr->length);
  (*e)[bptr->length] = '\0';

done:
  BIO_free_all(b64);
  return rc;
}

passwand_error_t decode(const char *s, uint8_t **d, size_t *len) {

  assert(s != NULL);
  assert(d != NULL);

  *d = NULL;

  // Create a base64 filter.
  BIO *b64 = BIO_new(BIO_f_base64());
  if (b64 == NULL)
    return PW_NO_MEM;
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

  passwand_error_t rc = PW_OK;

  // Create a source to read encoded data from.
  BIO *in = BIO_new_mem_buf((void *)s, -1);
  if (in == NULL) {
    rc = PW_NO_MEM;
    goto done;
  }

  b64 = BIO_push(b64, in);

  // Figure out how much space we need to decode. Note that this
  // overestimates.
  BUF_MEM *pp __attribute__((unused));
  long sz = BIO_get_mem_data(b64, &pp);
  *d = malloc(sz);
  if (*d == NULL) {
    rc = PW_NO_MEM;
    goto done;
  }

  // Do the actual decoding.
  int read = BIO_read(b64, *d, sz);

  assert((long)read <= sz);
  if (read < 0) {
    rc = PW_IO;
    goto done;
  }
  *len = read;

done:
  if (rc != PW_OK) {
    free(*d);
    *d = NULL;
  }
  BIO_free_all(b64);
  return rc;
}
