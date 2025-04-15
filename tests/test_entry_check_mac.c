#include "test.h"
#include <passwand/passwand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

TEST("entry_check_mac: basic functionality") {
  passwand_entry_t e = {
      .space = (uint8_t[]){"hello world"},
      .space_len = strlen("hello world"),
      .key = (uint8_t[]){"hello world"},
      .key_len = strlen("hello world"),
      .value = (uint8_t[]){"hello world"},
      .value_len = strlen("hello world"),
      .work_factor = 14,
  };

  {
    const int err = passwand_entry_set_mac("foo bar", &e);
    ASSERT_EQ(err, PW_OK);
  }

  {
    // checking the MAC should work
    const int err = passwand_entry_check_mac("foo bar", &e);
    ASSERT_EQ(err, PW_OK);
  }

  free(e.hmac);
  free(e.hmac_salt);
}

TEST("entry_check_mac: bad password") {
  passwand_entry_t e = {
      .space = (uint8_t[]){"hello world"},
      .space_len = strlen("hello world"),
      .key = (uint8_t[]){"hello world"},
      .key_len = strlen("hello world"),
      .value = (uint8_t[]){"hello world"},
      .value_len = strlen("hello world"),
      .work_factor = 14,
  };

  {
    const int err = passwand_entry_set_mac("foo bar", &e);
    ASSERT_EQ(err, PW_OK);
  }

  {
    // Checking the MAC with the wrong password should fail. Note that we cannot
    // actually detect an incorrect main password, and this failure will
    // manifest as a failed integrity check.
    const int err = passwand_entry_check_mac("hello world", &e);
    ASSERT_NE(err, PW_OK);
  }

  free(e.hmac);
  free(e.hmac_salt);
}

TEST("entry_check_mac: corrupted") {
  passwand_entry_t e = {
      .space = (uint8_t[]){"hello world"},
      .space_len = strlen("hello world"),
      .key = (uint8_t[]){"hello world"},
      .key_len = strlen("hello world"),
      .value = (uint8_t[]){"hello world"},
      .value_len = strlen("hello world"),
      .work_factor = 14,
  };

  {
    const int err = passwand_entry_set_mac("foo bar", &e);
    ASSERT_EQ(err, PW_OK);
  }

  // simulate entry corruption (or malicious modification)
  e.space_len--;

  {
    // the HMAC check should now fail
    const int err = passwand_entry_check_mac("foo bar", &e);
    ASSERT_NE(err, PW_OK);
  }

  free(e.hmac);
  free(e.hmac_salt);
}
