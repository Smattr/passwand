#include "../src/internal.h"
#include "test.h"
#include "util.h"
#include <passwand/passwand.h>
#include <stdlib.h>
#include <string.h>

TEST("encode: encode(\"\")") {
  const char *empty = "";
  char *r;
  int err = encode((const uint8_t *)empty, strlen(empty), &r);
  ASSERT_EQ(err, PW_OK);
  ASSERT_NOT_NULL(r);
  ASSERT_STREQ(empty, r);
  free(r);
}

TEST("encode: basic functionality") {
  const char *basic = "hello world";
  char *r;
  int err = encode((const uint8_t *)basic, strlen(basic), &r);
  ASSERT_EQ(err, PW_OK);
  ASSERT_NOT_NULL(r);
  ASSERT_STREQ(r, "aGVsbG8gd29ybGQ=");
  free(r);
}

TEST("encode: == base64") {
  char *output;
  int r = run("printf \"hello world\" | base64", &output);
  ASSERT_EQ(r, 0);
  ASSERT_STREQ(output, "aGVsbG8gd29ybGQ=\n");
  free(output);
}
