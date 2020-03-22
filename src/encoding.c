#include <assert.h>
#include "internal.h"
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void autobiofree(void *p) {
    assert(p != NULL);
    BIO **b = p;
    if (*b != NULL)
        BIO_free_all(*b);
}

passwand_error_t encode(const uint8_t *s, size_t len, char **e) {

    assert(s != NULL);
    assert(e != NULL);

    if (len > (size_t)INT_MAX)
        return PW_OVERFLOW;

    /* Create a base64 filter. */
    BIO *b64 __attribute__((cleanup(autobiofree))) = BIO_new(BIO_f_base64());
    if (b64 == NULL)
        return PW_NO_MEM;
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    /* Create an in-memory sink to encode data into. */
    BIO *out = BIO_new(BIO_s_mem());
    if (out == NULL)
        return PW_NO_MEM;

    b64 = BIO_push(b64, out);

    /* Encode the data. */
    if (BIO_write(b64, s, len) != (int)len)
        return PW_IO;
    BIO_flush(b64);

    /* Extract it into a string. */
    BUF_MEM *bptr;
    BIO_get_mem_ptr(out, &bptr);

    if (SIZE_MAX - 1 < bptr->length)
        return PW_OVERFLOW;
    *e = malloc(bptr->length + 1);
    if (*e == NULL)
        return PW_NO_MEM;

    memcpy(*e, bptr->data, bptr->length);
    (*e)[bptr->length] = '\0';

    return PW_OK;
}

passwand_error_t decode(const char *s, uint8_t **d, size_t *len) {

    assert(s != NULL);
    assert(d != NULL);

    /* Create a base64 filter. */
    BIO *b64 __attribute__((cleanup(autobiofree))) = BIO_new(BIO_f_base64());
    if (b64 == NULL)
        return PW_NO_MEM;
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);


    /* Create a source to read encoded data from. */
    BIO *in = BIO_new_mem_buf((void*)s, -1);
    if (in == NULL)
        return PW_NO_MEM;

    b64 = BIO_push(b64, in);

    /* Figure out how much space we need to decode. Note that this
     * overestimates.
     */
    BUF_MEM *pp __attribute__((unused));
    long sz = BIO_get_mem_data(b64, &pp);
    *d = malloc(sz);
    if (*d == NULL)
        return PW_NO_MEM;

    /* Do the actual decoding. */
    int read = BIO_read(b64, *d, sz);

    assert((long)read <= sz);
    if (read < 0) {
        free(*d);
        *d = NULL;
        return PW_IO;
    }
    *len = read;

    return PW_OK;
}
