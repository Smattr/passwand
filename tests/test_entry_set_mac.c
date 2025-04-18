#include "test.h"
#include <passwand/passwand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

TEST("entry_set_mac: basic functionality") {
  passwand_entry_t e = {
      .space = (uint8_t[]){"hello world"},
      .space_len = strlen("hello world"),
      .key = (uint8_t[]){"hello world"},
      .key_len = strlen("hello world"),
      .value = (uint8_t[]){"hello world"},
      .value_len = strlen("hello world"),
      .work_factor = 14,
  };

  int err = passwand_entry_set_mac("foo bar", &e);
  ASSERT_EQ(err, PW_OK);
  ASSERT_NOT_NULL(e.hmac);
  ASSERT_NOT_NULL(e.hmac_salt);
  free(e.hmac);
  free(e.hmac_salt);
}
