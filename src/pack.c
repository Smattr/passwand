#include "internal.h"
#include "types.h"
#include <assert.h>
#include <limits.h>
#include <passwand/passwand.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#if defined(__linux__) || defined(__OpenBSD__)
#include <endian.h>
#elif defined(__DragonFly__) || defined(__FreeBSD__) || defined(__NetBSD__)
#include <sys/endian.h>
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#endif

static uint64_t htole64_(uint64_t host_64bits) {
#if defined(__APPLE__)
  return OSSwapHostToLittleInt64(host_64bits);
#else
  return htole64(host_64bits);
#endif
}

static uint64_t le64toh_(uint64_t little_endian_64bits) {
#if (__APPLE__)
  return OSSwapLittleToHostInt64(little_endian_64bits);
#else
  return le64toh(little_endian_64bits);
#endif
}

passwand_error_t pack_data(const pt_t *p, const iv_t iv, ppt_t *pp) {

  assert(p != NULL);
  assert(iv != NULL);
  assert(pp != NULL);

  /* Calculate the final length of the unpadded data. */
  if (SIZE_MAX - strlen(HEADER) < sizeof(uint64_t))
    return PW_OVERFLOW;
  if (SIZE_MAX - strlen(HEADER) - sizeof(uint64_t) < PW_IV_LEN)
    return PW_OVERFLOW;
  if (SIZE_MAX - strlen(HEADER) - sizeof(uint64_t) - PW_IV_LEN < p->length)
    return PW_OVERFLOW;
  size_t length = strlen(HEADER) + sizeof(uint64_t) + PW_IV_LEN + p->length;

  /* The padding needs to align the final data to a 16-byte boundary. */
  size_t padding_len = AES_BLOCK_SIZE - length % AES_BLOCK_SIZE;

  /* Allocate enough space for the packed data. */

  if (SIZE_MAX - length < padding_len)
    return PW_OVERFLOW;
  pp->length = length + padding_len;
  assert(pp->length % AES_BLOCK_SIZE == 0);
  if (passwand_secure_malloc((void **)&pp->data, pp->length) != 0)
    return PW_NO_MEM;

  /* We're now ready to write the packed data. */

  size_t offset = 0;

  memcpy(pp->data, HEADER, strlen(HEADER));
  offset += strlen(HEADER);

  /* Pack the length of the plain text as a little endian 8-byte number. */
  uint64_t encoded_pt_len = htole64_(p->length);
  memcpy(pp->data + offset, &encoded_pt_len, sizeof(encoded_pt_len));
  offset += sizeof(encoded_pt_len);

  /* Pack the initialisation vector. */
  memcpy(pp->data + offset, iv, PW_IV_LEN);
  offset += PW_IV_LEN;

  /* Generate the padding. Agile Bits considers the padding scheme from IETF
   * draft AEAD-AES-CBC-HMAC-SHA as a more suitable replacement, but I'm not
   * sure why. It involves deterministic bytes that seems inherently less
   * secure.
   */
  passwand_error_t r = random_bytes(pp->data + offset, padding_len);
  if (r != PW_OK) {
    passwand_secure_free(pp->data, pp->length);
    return r;
  }
  offset += padding_len;

  /* Pack the plain text itself. */
  if (p->length > 0)
    memcpy(pp->data + offset, p->data, p->length);
  offset += p->length;

  return PW_OK;
}

passwand_error_t unpack_data(const ppt_t *pp, const iv_t iv, pt_t *p) {

  assert(pp != NULL);
  assert(pp->data != NULL);
  assert(iv != NULL);
  assert(p != NULL);

  if (pp->length % AES_BLOCK_SIZE != 0)
    return PW_UNALIGNED;

  ppt_t d = *pp;

  /* Check we have the correct header. */
  if (d.length < strlen(HEADER) ||
      strncmp((const char *)d.data, HEADER, strlen(HEADER)) != 0)
    return PW_HEADER_MISMATCH;
  d.data += strlen(HEADER);
  d.length -= strlen(HEADER);

  /* Unpack the size of the original plain text. */
  uint64_t encoded_pt_len;
  if (d.length < sizeof(encoded_pt_len))
    return PW_TRUNCATED;
  memcpy(&encoded_pt_len, d.data, sizeof(encoded_pt_len));
  p->length = le64toh_(encoded_pt_len);
  d.data += sizeof(encoded_pt_len);
  d.length -= sizeof(encoded_pt_len);

  /* Check the initialisation vector matches. */
  if (d.length < PW_IV_LEN)
    return PW_TRUNCATED;
  if (memcmp(d.data, iv, PW_IV_LEN) != 0)
    return PW_IV_MISMATCH;
  d.data += PW_IV_LEN;
  d.length -= PW_IV_LEN;

  /* Check we do indeed have enough space for the plain text left. */
  if (d.length < p->length)
    return PW_TRUNCATED;

  /* Check the data was padded correctly. */
  if (d.length - p->length > AES_BLOCK_SIZE)
    return PW_BAD_PADDING;

  /* Now we're ready to unpack it. */
  if (passwand_secure_malloc((void **)&p->data, p->length) != 0)
    return PW_NO_MEM;
  if (p->length > 0)
    memcpy(p->data, d.data + d.length - p->length, p->length);

  return PW_OK;
}
