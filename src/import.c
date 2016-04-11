#include <assert.h>
#include "encoding.h"
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

#if 0
char *read_file(const char *path) {
    assert(path != NULL);

    FILE *in __attribute__((cleanup(close))) = fopen(path, "r");
    if (in == NULL)
        return NULL;

    char *buffer;
    size_t buffer_len;
    FILE *out = open_memstream(&buffer, &buffer_len);
    if (out == NULL)
        return NULL;

    char buf[1024];
    size_t read;
    while ((read = fread(buf, 1, sizeof(buf), in)) != 0) {
        do {
            size_t written = fwrite(out, 1, read, out);
            if (written == 0) {
                fclose(out);
                free(buffer);
                return NULL;
            }
            assert(written <= read);
            read -= written;
        } while (read > 0);
    }

    fclose(out);

    if (!feof(in)) {
        free(buffer);
        return NULL;
    }

    return buffer;
}
#endif

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

int passwand_import(const char *path, passwand_entry_t **entries, unsigned *entry_len) {
    assert(entries != NULL);
    assert(entry_len != NULL);

    int f __attribute__((cleanup(autoclose))) = open(path, O_RDONLY);
    if (f == -1)
        return -1;

    struct stat st;
    if (fstat(f, &st) != 0)
        return -1;

    void *p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, f, 0);
    if (p == MAP_FAILED)
        return -1;
    munmap_data_t unmapper __attribute__((unused, cleanup(autounmap))) = {
        .addr = p,
        .length = st.st_size,
    };

    json_tokener *tok __attribute__((cleanup(autojsonfree))) = json_tokener_new();
    if (tok == NULL)
        return -1;

    json_object *j __attribute__((cleanup(autojsonput))) = json_tokener_parse_ex(tok, p, st.st_size);
    if (j == NULL)
        return -1;

    if (!json_object_is_type(j, json_type_array))
        return -1;

    *entry_len = json_object_array_length(j);
    *entries = calloc(*entry_len, sizeof(passwand_entry_t));
    if (*entries == NULL)
        return -1;

    for (unsigned i = 0; i < *entry_len; i++) {

        json_object *m = json_object_array_get_idx(j, i);
        assert(m != NULL);
        if (!json_object_is_type(m, json_type_object)) {
            free(*entries);
            return -1;
        }

#define GET(field) \
    do { \
        json_object *v = json_object_object_get(m, #field); \
        if (v == NULL || !json_object_is_type(v, json_type_string)) { \
            free(*entries); \
            return -1; \
        } \
        (*entries)[i].field = decode(json_object_get_string(v)); \
        if ((*entries)[i].field == NULL) { \
            free(*entries); \
            return -1; \
        } \
    } while (0)

        GET(space);
        GET(key);
        GET(value);
        GET(hmac);
        GET(hmac_salt);
        GET(salt);
        GET(iv);

        (*entries)[i].encrypted = true;
    }

    return 0;
}
