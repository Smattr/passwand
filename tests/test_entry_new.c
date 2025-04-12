#include "../common/streq.h"
#include "test.h"
#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static const char *mainpass = "hello world";
static const char *space = "space";
static const char *key = "key";
static const char *value = "value";

TEST("entry_new: basic functionality") {
  passwand_entry_t e = {0};
  int err = passwand_entry_new(&e, mainpass, space, key, value, 14);
  ASSERT_EQ(err, PW_OK);
  ASSERT_NOT_NULL(e.space);
  ASSERT_NOT_NULL(e.key);
  ASSERT_NOT_NULL(e.value);
  ASSERT_NOT_NULL(e.hmac);
  ASSERT_NOT_NULL(e.hmac_salt);
  free(e.space);
  free(e.key);
  free(e.value);
  free(e.hmac);
  free(e.hmac_salt);
  free(e.salt);
  free(e.iv);
}

TEST("entry_new: check_mac(entry_new(...))") {
  passwand_entry_t e;
  int err = passwand_entry_new(&e, mainpass, space, key, value, 14);
  ASSERT_EQ(err, PW_OK);

  err = passwand_entry_check_mac(mainpass, &e);
  ASSERT_EQ(err, PW_OK);

  free(e.space);
  free(e.key);
  free(e.value);
  free(e.hmac);
  free(e.hmac_salt);
  free(e.salt);
  free(e.iv);
}

static void check(void *state, const char *s, const char *k, const char *v) {
  bool *st = state;
  *st = streq(space, s) && streq(key, k) && streq(value, v);
}

TEST("entry_new: recoverable") {
  passwand_entry_t e;
  int err = passwand_entry_new(&e, mainpass, space, key, value, 14);
  ASSERT_EQ(err, PW_OK);

  bool checked = false;
  err = passwand_entry_do(mainpass, &e, check, &checked);
  ASSERT_EQ(err, PW_OK);
  ASSERT(checked);

  free(e.space);
  free(e.key);
  free(e.value);
  free(e.hmac);
  free(e.hmac_salt);
  free(e.salt);
  free(e.iv);
}
