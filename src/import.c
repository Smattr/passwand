#include "internal.h"
#include <assert.h>
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

passwand_error_t passwand_import(const char *path, passwand_entry_t **entries,
                                 size_t *entry_len) {

  assert(path != NULL);
  assert(entries != NULL);
  assert(entry_len != NULL);

  passwand_error_t rc = -1;
  int f = -1;
  void *p = MAP_FAILED;
  size_t size = 0;
  json_tokener *tok = NULL;
  json_object *j = NULL;
  passwand_entry_t *ent = NULL;
  size_t ent_len = 0;

  // mmap the input so JSON-C can stream it
  f = open(path, O_RDONLY | O_CLOEXEC);
  if (f == -1) {
    rc = PW_IO;
    goto done;
  }

  struct stat st;
  if (fstat(f, &st) != 0) {
    rc = PW_IO;
    goto done;
  }
  size = st.st_size;

  p = mmap(NULL, size, PROT_READ, MAP_PRIVATE, f, 0);
  if (p == MAP_FAILED) {
    rc = PW_IO;
    goto done;
  }

  // Read the outer list. This should be the only item in the file.
  tok = json_tokener_new();
  if (tok == NULL) {
    rc = PW_NO_MEM;
    goto done;
  }

  j = json_tokener_parse_ex(tok, p, size);
  if (j == NULL) {
    rc = PW_BAD_JSON;
    goto done;
  }

  if (!json_object_is_type(j, json_type_array)) {
    rc = PW_BAD_JSON;
    goto done;
  }

  // we are now ready to start reading the entries themselves

  ent_len = json_object_array_length(j);
  ent = calloc(ent_len, sizeof(ent[0]));
  if (ent == NULL && ent_len > 0) {
    ent_len = 0;
    rc = PW_NO_MEM;
    goto done;
  }

  for (size_t i = 0; i < ent_len; i++) {

    json_object *m = json_object_array_get_idx(j, i);
    assert(m != NULL);
    if (!json_object_is_type(m, json_type_object)) {
      // one of the array entries was not an object (dictionary)
      rc = PW_BAD_JSON;
      goto done;
    }

#define GET(field)                                                             \
  do {                                                                         \
    json_object *v;                                                            \
    if (!json_object_object_get_ex(m, #field, &v) ||                           \
        !json_object_is_type(v, json_type_string)) {                           \
      /* The value of this member was not a string. */                         \
      rc = PW_BAD_JSON;                                                        \
      goto done;                                                               \
    }                                                                          \
    passwand_error_t err = decode(json_object_get_string(v), &ent[i].field,    \
                                  &(ent[i].field##_len));                      \
    if (err == PW_IO) {                                                        \
      /* The value was not valid base64 encoded. */                            \
      rc = PW_BAD_JSON;                                                        \
      goto done;                                                               \
    } else if (err != PW_OK) {                                                 \
      rc = err;                                                                \
      goto done;                                                               \
    }                                                                          \
  } while (0)

    GET(space);
    GET(key);
    GET(value);
    GET(hmac);
    GET(hmac_salt);
    GET(salt);
    GET(iv);

#undef GET
  }

  *entries = ent;
  *entry_len = ent_len;
  ent = NULL;
  ent_len = 0;
  rc = PW_OK;

done:
  for (size_t i = 0; i < ent_len; ++i) {
    free(ent[i].space);
    free(ent[i].key);
    free(ent[i].value);
    free(ent[i].hmac);
    free(ent[i].hmac_salt);
    free(ent[i].salt);
    free(ent[i].iv);
  }
  free(ent);
  if (j != NULL)
    (void)json_object_put(j);
  if (tok != NULL)
    json_tokener_free(tok);
  if (p != MAP_FAILED)
    (void)munmap(p, size);
  if (f != -1)
    (void)close(f);

  return rc;
}
