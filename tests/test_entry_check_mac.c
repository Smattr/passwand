#include "test.h"
#include <passwand/passwand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void create_maced_entry(passwand_entry_t *e) {
  *e = (passwand_entry_t){0};
  e->space = (uint8_t *)"hello world";
  e->space_len = strlen("hello world");
  e->key = (uint8_t *)"hello world";
  e->key_len = strlen("hello world");
  e->value = (uint8_t *)"hello world";
  e->value_len = strlen("hello world");
  e->work_factor = 14;

  int err = passwand_entry_set_mac("foo bar", e);
  ASSERT_EQ(err, PW_OK);
}

TEST("entry_check_mac: basic functionality") {
  passwand_entry_t e;
  create_maced_entry(&e);

  // checking the MAC should work
  int err = passwand_entry_check_mac("foo bar", &e);
  ASSERT_EQ(err, PW_OK);

  free(e.hmac);
  free(e.hmac_salt);
}

TEST("entry_check_mac: bad password") {
  passwand_entry_t e;
  create_maced_entry(&e);

  // Checking the MAC with the wrong password should fail. Note that we cannot
  // actually detect an incorrect main password, and this failure will manifest
  // as a failed integrity check.
  int err = passwand_entry_check_mac("hello world", &e);
  ASSERT_NE(err, PW_OK);

  free(e.hmac);
  free(e.hmac_salt);
}

TEST("entry_check_mac: corrupted") {
  passwand_entry_t e;
  create_maced_entry(&e);

  // simulate entry corruption (or malicious modification)
  e.space_len--;

  // the HMAC check should now fail
  int err = passwand_entry_check_mac("foo bar", &e);
  ASSERT_NE(err, PW_OK);

  free(e.hmac);
  free(e.hmac_salt);
}
