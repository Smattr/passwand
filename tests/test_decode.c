#include "../src/internal.h"
#include "test.h"
#include "util.h"
#include <passwand/passwand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

TEST("decode: decode(\"\")") {
  const char *empty = "";
  uint8_t *r;
  size_t r_len;
  int err = decode(empty, &r, &r_len);
  ASSERT_EQ(err, PW_OK);
  ASSERT_NOT_NULL(r);
  ASSERT_EQ(r_len, 0ul);
  free(r);
}

TEST("decode: basic functionality") {
  const char *basic = "aGVsbG8gd29ybGQ=";
  uint8_t *r;
  size_t r_len;
  int err = decode(basic, &r, &r_len);
  ASSERT_EQ(err, PW_OK);
  ASSERT_NOT_NULL(r);
  ASSERT_EQ(r_len, strlen("hello world"));
  ASSERT_EQ(memcmp(r, "hello world", r_len), 0);
  free(r);
}

TEST("decode: == base64") {
  char *output;
  int r = run("printf \"aGVsbG8gd29ybGQ=\" | base64 --decode", &output);
  ASSERT_EQ(r, 0);
  ASSERT_STREQ(output, "hello world");
  free(output);
}

TEST("decode: decode(encode(x)) == x") {

  // some basic text to encode
  const uint8_t input[] =
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod "
      "tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim "
      "veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea "
      "commodo consequat. Duis aute irure dolor in reprehenderit in voluptate "
      "velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint "
      "occaecat cupidatat non proident, sunt in culpa qui officia deserunt "
      "mollit anim id est laborum.";

  // encode the text
  char *encoded;
  int err = encode(input, sizeof(input) - 1, &encoded);
  ASSERT_EQ(err, PW_OK);
  ASSERT_NOT_NULL(encoded);

  // now let us decode this
  uint8_t *output;
  size_t output_len;
  err = decode(encoded, &output, &output_len);
  ASSERT_EQ(err, PW_OK);
  ASSERT_NOT_NULL(output);

  free(encoded);

  // we should have got back what we put in
  ASSERT_EQ(output_len, sizeof(input) - 1);
  ASSERT_EQ(memcmp(output, input, output_len), 0);

  free(output);
}
