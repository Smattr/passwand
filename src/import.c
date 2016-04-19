#include <assert.h>
#include "internal.h"
#include <fcntl.h>
#include <json.h>
#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* The following are some helpers so we can use pervasive RAII in the import
 * function.
 */

static void autoclose(void *p) {
    assert(p != NULL);
    int *f = p;
    if (*f != -1)
        close(*f);
}

typedef struct {
    void *addr;
    size_t length;
} munmap_data_t;

static void autounmap(void *p) {
    assert(p != NULL);
    munmap_data_t *m = p;
    munmap(m->addr, m->length);
}

static void autojsonfree(void *p) {
    assert(p != NULL);
    json_tokener **tok = p;
    if (*tok != NULL)
        json_tokener_free(*tok);
}

static void autojsonput(void *p) {
    assert(p != NULL);
    json_object **j = p;
    if (*j != NULL)
        json_object_put(*j);
}

passwand_error_t passwand_import(const char *path, passwand_entry_t **entries,
        unsigned *entry_len) {

    assert(path != NULL);
    assert(entries != NULL);
    assert(entry_len != NULL);

    /* MMap the input so JSON-C can stream it. */
    int f __attribute__((cleanup(autoclose))) = open(path, O_RDONLY);
    if (f == -1)
        return PW_IO;

    struct stat st;
    if (fstat(f, &st) != 0)
        return PW_IO;

    void *p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, f, 0);
    if (p == MAP_FAILED)
        return PW_IO;
    munmap_data_t unmapper __attribute__((unused, cleanup(autounmap))) = {
        .addr = p,
        .length = st.st_size,
    };

    /* Read the outer list. This should be the only item in the file. */
    json_tokener *tok __attribute__((cleanup(autojsonfree))) = json_tokener_new();
    if (tok == NULL)
        return PW_NO_MEM;

    json_object *j __attribute__((cleanup(autojsonput)))
        = json_tokener_parse_ex(tok, p, st.st_size);
    if (j == NULL)
        return PW_BAD_JSON;

    if (!json_object_is_type(j, json_type_array))
        return PW_BAD_JSON;

    /* We're now ready to start reading the entries themselves. */

    *entry_len = json_object_array_length(j);
    *entries = calloc(*entry_len, sizeof(passwand_entry_t));
    if (*entries == NULL)
        return PW_NO_MEM;

    for (unsigned i = 0; i < *entry_len; i++) {

#define FREE_PRECEDING() \
    do { \
        for (unsigned j = 0; j <= i; j++) { \
            free((*entries)[j].space); \
            free((*entries)[j].key); \
            free((*entries)[j].value); \
            free((*entries)[j].hmac); \
            free((*entries)[j].hmac_salt); \
            free((*entries)[j].salt); \
            free((*entries)[j].iv); \
        } \
        free(*entries); \
    } while (0)

        json_object *m = json_object_array_get_idx(j, i);
        assert(m != NULL);
        if (!json_object_is_type(m, json_type_object)) {
            /* One of the array entries was not an object (dictionary). */
            FREE_PRECEDING();
            return PW_BAD_JSON;
        }

#define GET(field) \
    do { \
        json_object *v = json_object_object_get(m, #field); \
        if (v == NULL || !json_object_is_type(v, json_type_string)) { \
            /* The value of this member was not a string. */ \
            FREE_PRECEDING(); \
            return PW_BAD_JSON; \
        } \
        passwand_error_t err = decode(json_object_get_string(v), &((*entries)[i].field), &((*entries)[i].field##_len)); \
        if (err == PW_IO) { \
            /* The value was not valid base64 encoded. */ \
            FREE_PRECEDING(); \
            return PW_BAD_JSON; \
        } else if (err != PW_OK) { \
            FREE_PRECEDING(); \
            return err; \
        } \
    } while (0)

        GET(space);
        GET(key);
        GET(value);
        GET(hmac);
        GET(hmac_salt);
        GET(salt);
        GET(iv);

#undef GET

#undef FREE_PRECEDING

    }

    return PW_OK;
}
