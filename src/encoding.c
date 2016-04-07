#include <assert.h>
#include "encoding.h"
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

char *encode(const char *s) {

    assert(s != NULL);

    /* Create a base64 filter. */
    BIO *b64 = BIO_new(BIO_f_base64());
    if (b64 == NULL)
        return NULL;
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    /* Create an in-memory sink to encode data into. */
    BIO *out = BIO_new(BIO_s_mem());
    if (out == NULL) {
        BIO_free_all(b64);
        return NULL;
    }

    BIO *pipe = BIO_push(b64, out);

    int len = strlen(s);

    /* Encode the data. */
    if (BIO_write(pipe, s, len) != len) {
        BIO_free_all(pipe);
        return NULL;
    }
    BIO_flush(pipe);

    /* Extract it into a string. */
    BUF_MEM *bptr;
    BIO_get_mem_ptr(out, &bptr);

    char *r = malloc(bptr->length + 1);
    if (r == NULL) {
        BIO_free_all(b64);
        return NULL;
    }

    memcpy(r, bptr->data, bptr->length);
    r[bptr->length] = '\0';

    BIO_free_all(b64);

    return r;
}

char *decode(const char *s) {

    assert(s != NULL);

    /* Create a base64 filter. */
    BIO *b64 = BIO_new(BIO_f_base64());
    if (b64 == NULL)
        return NULL;
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);


    /* Create a source to read encoded data from. */
    BIO *in = BIO_new_mem_buf((void*)s, -1);
    if (in == NULL) {
        BIO_free_all(b64);
        return NULL;
    }

    BIO *pipe = BIO_push(b64, in);

    /* Figure out how much space we need to decode. Note that this
     * overestimates.
     */
    BUF_MEM *pp __attribute__((unused));
    long data_len = BIO_get_mem_data(pipe, &pp);
    char *r = malloc(data_len + 1);
    if (r == NULL) {
        BIO_free_all(pipe);
        return NULL;
    }

    /* Do the actual decoding. */
    int read = BIO_read(pipe, r, data_len);

    BIO_free_all(pipe);

    assert((long)read <= data_len);
    if (read < 0) {
        free(r);
        return NULL;
    }
    r[read] = '\0';

    return r;
}
