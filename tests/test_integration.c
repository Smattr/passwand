#include "../common/streq.h"
#include "test.h"
#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

static void cleanup_entry(passwand_entry_t *e) {
  free(e->space);
  free(e->key);
  free(e->value);
  free(e->hmac);
  free(e->hmac_salt);
  free(e->salt);
  free(e->iv);
}

typedef struct {
  size_t index;
  bool failed;
} state_t;

static void body(void *state, const char *space, const char *key,
                 const char *value) {
  state_t *st = state;
  switch (st->index) {

  case 0:
    st->failed |= !(streq(space, "foo.com") && streq(key, "username") &&
                    streq(value, "bob"));
    break;

  case 1:
    st->failed |= !(streq(space, "foo.com") && streq(key, "password") &&
                    streq(value, "bob's password"));
    break;

  case 2:
    st->failed |= !(streq(space, "bar.com") && streq(key, "username") &&
                    streq(value, "alice"));
    break;

  case 3:
    st->failed |= !(streq(space, "bar.com") && streq(key, "password") &&
                    streq(value, "alice's password"));
    break;

  default:
    st->failed = true;
  }
  st->index++;
}

TEST("integration: basic lifecycle") {
  const char *mainpass = "hello world";

  size_t entry_len = 4;
  passwand_entry_t *entries = calloc(entry_len, sizeof(entries[0]));

  const int work_factor = 14;

  {
    const char *space = "foo.com";
    const char *key = "username";
    const char *value = "bob";

    int err = passwand_entry_new(&entries[0], mainpass, space, key, value,
                                 work_factor);
    ASSERT_EQ(err, PW_OK);
  }

  {
    const char *space = "foo.com";
    const char *key = "password";
    const char *value = "bob's password";

    int err = passwand_entry_new(&entries[1], mainpass, space, key, value,
                                 work_factor);
    ASSERT_EQ(err, PW_OK);
  }

  {
    const char *space = "bar.com";
    const char *key = "username";
    const char *value = "alice";

    int err = passwand_entry_new(&entries[2], mainpass, space, key, value,
                                 work_factor);
    ASSERT_EQ(err, PW_OK);
  }

  {
    const char *space = "bar.com";
    const char *key = "password";
    const char *value = "alice's password";

    int err = passwand_entry_new(&entries[3], mainpass, space, key, value,
                                 work_factor);
    ASSERT_EQ(err, PW_OK);
  }

  const char *const tmp = mkpath();
  {
    int err = passwand_export(tmp, entries, entry_len);
    ASSERT_EQ(err, PW_OK);
  }

  for (size_t i = 0; i < entry_len; i++)
    cleanup_entry(&entries[i]);
  free(entries);

  int err = passwand_import(tmp, &entries, &entry_len);
  ASSERT_EQ(err, PW_OK);

  ASSERT_EQ(entry_len, 4ul);

  for (size_t i = 0; i < entry_len; i++)
    entries[i].work_factor = work_factor;

  state_t st = {
      .index = 0,
      .failed = false,
  };
  for (size_t i = 0; i < entry_len; i++) {
    err = passwand_entry_do(mainpass, &entries[i], body, &st);
    ASSERT_EQ(err, PW_OK);
    ASSERT(!st.failed);
  }

  for (size_t i = 0; i < entry_len; i++)
    cleanup_entry(&entries[i]);
  free(entries);
}
