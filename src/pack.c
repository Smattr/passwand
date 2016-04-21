#include <assert.h>
#include "internal.h"
#include <limits.h>
#include <passwand/passwand.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "types.h"

passwand_error_t pack_data(const pt_t *p, const iv_t *iv, ppt_t *pp) {

    assert(p != NULL);
    assert(iv != NULL);
    assert(pp != NULL);

    /* Calculate the final length of the unpadded data. */
    if (SIZE_MAX - strlen(HEADER) < sizeof(uint64_t))
        return PW_OVERFLOW;
    if (SIZE_MAX - strlen(HEADER) - sizeof(uint64_t) < iv->length)
        return PW_OVERFLOW;
    if (SIZE_MAX - strlen(HEADER) - sizeof(uint64_t) - iv->length < p->length)
        return PW_OVERFLOW;
    size_t length = strlen(HEADER) + sizeof(uint64_t) + iv->length + p->length;

    /* The padding needs to align the final data to a 16-byte boundary. */
    size_t padding_len = AES_BLOCK_SIZE - length % AES_BLOCK_SIZE;

    /* Generate the padding. Agile Bits considers the padding scheme from IETF draft
     * AEAD-AES-CBC-HMAC-SHA as a more suitable replacement, but I'm not sure why. It involves
     * deterministic bytes that seems inherently less secure.
     */
    void *padding;
    if (passwand_secure_malloc(&padding, padding_len) != 0)
        return PW_NO_MEM;
    passwand_error_t r = random_bytes(padding, padding_len);
    if (r != PW_OK) {
        passwand_secure_free(padding, padding_len);
        return r;
    }

    /* We're now ready to write the packed data. */

    if (SIZE_MAX - length < padding_len) {
        passwand_secure_free(padding, padding_len);
        return PW_OVERFLOW;
    }
    pp->length = length + padding_len;
    assert(pp->length % AES_BLOCK_SIZE == 0);
    if (passwand_secure_malloc((void**)&pp->data, pp->length) != 0) {
        passwand_secure_free(padding, padding_len);
        return PW_NO_MEM;
    }

    size_t offset = 0;

    memcpy(pp->data, HEADER, strlen(HEADER));
    offset += strlen(HEADER);

    /* Pack the length of the plain text as a little endian 8-byte number. */
    uint64_t encoded_pt_len = htole64(p->length);
    memcpy(pp->data + offset, &encoded_pt_len, sizeof(encoded_pt_len));
    offset += sizeof(encoded_pt_len);

    /* Pack the initialisation vector. */
    memcpy(pp->data + offset, iv->data, iv->length);
    offset += iv->length;

    /* Pack the padding, *prepending* the plain text. */
    memcpy(pp->data + offset, padding, padding_len);
    offset += padding_len;
    passwand_secure_free(padding, padding_len);

    /* Pack the plain text itself. */
    memcpy(pp->data + offset, p->data, p->length);
    offset += p->length;

    return PW_OK;
}

passwand_error_t unpack_data(const ppt_t *pp, const iv_t *iv, pt_t *p) {

    assert(pp != NULL);
    assert(pp->data != NULL);
    assert(iv != NULL);
    assert(iv->data != NULL);
    assert(p != NULL);

    if (pp->length % AES_BLOCK_SIZE != 0)
        return PW_UNALIGNED;

    ppt_t d = *pp;

    /* Check we have the correct header. */
    if (d.length < strlen(HEADER) ||
            strncmp((const char*)d.data, HEADER, strlen(HEADER)) != 0)
        return PW_HEADER_MISMATCH;
    d.data += strlen(HEADER);
    d.length -= strlen(HEADER);

    /* Unpack the size of the original plain text. */
    uint64_t encoded_pt_len;
    if (d.length < sizeof(encoded_pt_len))
        return PW_TRUNCATED;
    memcpy(&encoded_pt_len, d.data, sizeof(encoded_pt_len));
    p->length = le64toh(encoded_pt_len);
    d.data += sizeof(encoded_pt_len);
    d.length -= sizeof(encoded_pt_len);

    /* Check the initialisation vector matches. */
    if (d.length < iv->length)
        return PW_TRUNCATED;
    if (memcmp(d.data, iv->data, iv->length) != 0)
        return PW_IV_MISMATCH;
    d.data += iv->length;
    d.length -= iv->length;

    /* Check we do indeed have enough space for the plain text left. */
    if (d.length < p->length)
        return PW_TRUNCATED;

    /* Check the data was padded correctly. */
    if (d.length - p->length > 16)
        return PW_BAD_PADDING;

    /* Now we're ready to unpack it. */
    if (passwand_secure_malloc((void**)&p->data, p->length) != 0)
        return PW_NO_MEM;
    memcpy(p->data, d.data + d.length - p->length, p->length);

    return PW_OK;
}
