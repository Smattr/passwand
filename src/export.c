#include "internal.h"
#include <assert.h>
#include <fcntl.h>
#include <json.h>
#include <limits.h>
#include <passwand/passwand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// Add a given key and value to a JSON dictionary. Returns 0 on success.
static passwand_error_t add_to_dict(json_object *d, const char *key,
                                    const uint8_t *value, size_t value_len) {

  // first encode the value which may contain arbitrary data
  char *encoded;
  passwand_error_t err = encode(value, value_len, &encoded);
  if (err != PW_OK)
    return err;

  // encapsulate the value in a JSON object
  json_object *v = json_object_new_string(encoded);
  free(encoded);
  if (v == NULL)
    return PW_NO_MEM;

  // add the key and value to the dictionary
  json_object_object_add(d, key, v);

  return PW_OK;
}

passwand_error_t passwand_export(const char *path, passwand_entry_t *entries,
                                 size_t entry_len) {

  assert(path != NULL);
  assert(entries != NULL || entry_len == 0);

  json_object *j = NULL;
  char *tmp = NULL;
  passwand_error_t rc = -1;

  // create a new array as the top level JSON object in the export file
  j = json_object_new_array();
  if (j == NULL) {
    rc = PW_NO_MEM;
    goto done;
  }

  for (size_t i = 0; i < entry_len; i++) {

    // encapsulate each entry in a JSON dictionary
    json_object *d = json_object_new_object();
    if (d == NULL) {
      rc = PW_NO_MEM;
      goto done;
    }

#define ADD(field)                                                             \
  do {                                                                         \
    passwand_error_t err =                                                     \
        add_to_dict(d, #field, entries[i].field, entries[i].field##_len);      \
    if (err != PW_OK) {                                                        \
      json_object_put(d);                                                      \
      rc = err;                                                                \
      goto done;                                                               \
    }                                                                          \
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

  // now write out the array to the given file

  size_t path_len = strlen(path);
  if (SIZE_MAX - path_len < 2) {
    rc = PW_OVERFLOW;
    goto done;
  }
  tmp = malloc(strlen(path) + 2);
  if (tmp == NULL) {
    rc = PW_NO_MEM;
    goto done;
  }
  sprintf(tmp, "%s~", path);
  int fd = creat(tmp, 0600);
  if (fd == -1) {
    rc = PW_IO;
    goto done;
  }

  const char *json = json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN);
  size_t len = strlen(json);
  ssize_t written = write(fd, json, len);
  (void)close(fd);
  if (written < 0 || (size_t)written != len) {
    (void)unlink(tmp);
    rc = PW_IO;
    goto done;
  }

  if (rename(tmp, path) == -1) {
    (void)unlink(tmp);
    rc = PW_IO;
    goto done;
  }

  rc = PW_OK;

done:
  free(tmp);
  if (j != NULL)
    (void)json_object_put(j);

  return rc;
}
