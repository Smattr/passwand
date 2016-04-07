#include <assert.h>
#include "encoding.h"
#include <json.h>
#include <passwand/passwand.h>
#include <stdio.h>
#include <stdlib.h>

/* Close a file. See usage of this below in cleanup attributes. */
static void close(void *p) {
    assert(p != NULL);
    FILE **f = p;
    if (*f != NULL)
        fclose(*f);
}

/* Free a JSON object. See usage of this below in cleanup attributes. */
static void disown(void *p) {
    assert(p != NULL);
    json_object **j = p;
    if (*j != NULL)
        json_object_put(*j);
}

/* Add a given key and value to a JSON dictionary. Returns 0 on success. */
static int add_to_dict(json_object *d, const char *key, const char *value) {

    /* First encode the value which may contain arbitrary data. */
    char *encoded = encode(value);
    if (encoded == NULL)
        return -1;

    /* Encapsulate the value in a JSON object. */
    json_object *v = json_object_new_string(encoded);
    free(encoded);
    if (v == NULL)
        return -1;

    /* Add the key and value to the dictionary. */
    json_object_object_add(d, key, v);

    return 0;
}

int passwand_export(const char *path, passwand_entry_t *entries, unsigned entry_len) {
    assert(path != NULL);
    assert(entries != NULL || entry_len == 0);

    /* Create a new array as the top level JSON object in the export file. */
    json_object *j __attribute__((cleanup(disown))) = json_object_new_array();
    if (j == NULL)
        return -1;

    for (unsigned i = 0; i < entry_len; i++) {

        /* We should only be exporting encrypted entries. */
        if (!entries[i].encrypted)
            return -1;

        /* Encapsulate each entry in a JSON dictionary. */
        json_object *d = json_object_new_object();
        if (d == NULL)
            return -1;

#define ADD(field) \
    do { \
        if (add_to_dict(d, #field, entries[i].field) != 0) { \
            json_object_put(d); \
            return -1; \
        } \
    } while (0)

        ADD(space);
        ADD(key);
        ADD(value);
        ADD(hmac);
        ADD(hmac_salt);
        ADD(salt);
        ADD(iv);

#undef ADD

        json_object_array_add(j, d);
    }

    /* Now write out the array to the given file. */

    FILE *f __attribute__((cleanup(close))) = fopen(path, "w");
    if (f == NULL)
        return -1;

    const char *json = json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN);
    if (fputs(json, f) == EOF)
        return -1;

    return 0;
}
