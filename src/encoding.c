#include "encoding.h"
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

char *encode(const char *s) {
    char *r = NULL;

    /* Create a base64 filter. */
    BIO *in = BIO_new(BIO_f_base64());
    if (in == NULL)
        goto fail;
    BIO_set_flags(in, BIO_FLAGS_BASE64_NO_NL);

    /* Create an in-memory sink to encode data into. */
    BIO *out = BIO_new(BIO_s_mem());
    if (out == NULL)
        goto fail;

    BIO_push(in, out);

    int len = strlen(s);

    /* Encode the data. */
    if (BIO_write(in, s, len) != len)
        goto fail;
    BIO_flush(in);

    /* Extract it into a string. */
    BUF_MEM *bptr;
    BIO_get_mem_ptr(out, &bptr);

    r = malloc(bptr->length + 1);
    if (r == NULL)
        goto fail;

    memcpy(r, bptr->data, bptr->length);
    r[bptr->length] = '\0';

fail:
    if (in != NULL)
        BIO_free_all(in);

    return r;
}
