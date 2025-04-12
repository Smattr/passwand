#include "../src/internal.h"
#include "test.h"
#include "util.h"
#include <passwand/passwand.h>
#include <stdint.h>
#include <stdlib.h>

TEST("encode: encode(\"\")") {
  const uint8_t empty[] = {0};
  char *r;
  int err = encode(empty, sizeof(empty) - 1, &r);
  ASSERT_EQ(err, PW_OK);
  ASSERT_NOT_NULL(r);
  ASSERT_STREQ("", r);
  free(r);
}

TEST("encode: basic functionality") {
  const uint8_t basic[] = "hello world";
  char *r;
  int err = encode(basic, sizeof(basic) - 1, &r);
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
