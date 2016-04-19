#include <assert.h>
#include "internal.h"
#include <json.h>
#include <passwand/passwand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Free a JSON object. See usage of this below in cleanup attributes. */
static void disown(void *p) {
    assert(p != NULL);
    json_object **j = p;
    if (*j != NULL)
        json_object_put(*j);
}

/* Add a given key and value to a JSON dictionary. Returns 0 on success. */
static passwand_error_t add_to_dict(json_object *d, const char *key, const uint8_t *value,
        size_t value_len) {

    /* First encode the value which may contain arbitrary data. */
    char *encoded;
    passwand_error_t err = encode(value, value_len, &encoded);
    if (err != PW_OK)
        return err;

    /* Encapsulate the value in a JSON object. */
    json_object *v = json_object_new_string(encoded);
    free(encoded);
    if (v == NULL)
        return PW_NO_MEM;

    /* Add the key and value to the dictionary. */
    json_object_object_add(d, key, v);

    return PW_OK;
}

passwand_error_t passwand_export(const char *path, passwand_entry_t *entries, unsigned entry_len) {

    assert(path != NULL);
    assert(entries != NULL || entry_len == 0);

    /* Create a new array as the top level JSON object in the export file. */
    json_object *j __attribute__((cleanup(disown))) = json_object_new_array();
    if (j == NULL)
        return PW_NO_MEM;

    for (unsigned i = 0; i < entry_len; i++) {

        /* Encapsulate each entry in a JSON dictionary. */
        json_object *d = json_object_new_object();
        if (d == NULL)
            return PW_NO_MEM;

#define ADD(field) \
    do { \
        passwand_error_t err = add_to_dict(d, #field, entries[i].field, entries[i].field##_len); \
        if (err != PW_OK) { \
            json_object_put(d); \
            return err; \
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

    char tmp[] = "/tmp/tmp.XXXXXX";
    int fd = mkstemp(tmp);
    if (fd == -1)
        return PW_IO;

    const char *json = json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN);
    size_t len = strlen(json);
    ssize_t written = write(fd, json, len);
    close(fd);
    if (written < 0 || (size_t)written != len) {
        unlink(tmp);
        return PW_IO;
    }

    if (rename(tmp, path) == -1) {
        unlink(tmp);
        return PW_IO;
    }

    return PW_OK;
}
