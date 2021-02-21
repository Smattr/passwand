#include "../src/internal.h"
#include "test.h"
#include "util.h"
#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

TEST("decode: decode(\"\")") {
  const char *empty = "";
  uint8_t *r;
  size_t r_len;
  passwand_error_t err = decode(empty, &r, &r_len);
  CU_ASSERT_EQUAL_FATAL(err, PW_OK);
  CU_ASSERT_PTR_NOT_NULL_FATAL(r);
  CU_ASSERT_EQUAL_FATAL(r_len, 0);
  free(r);
}

TEST("decode: basic functionality") {
  const char *basic = "aGVsbG8gd29ybGQ=";
  uint8_t *r;
  size_t r_len;
  passwand_error_t err = decode(basic, &r, &r_len);
  CU_ASSERT_EQUAL_FATAL(err, PW_OK);
  CU_ASSERT_PTR_NOT_NULL_FATAL(r);
  CU_ASSERT_EQUAL_FATAL(r_len, strlen("hello world"));
  CU_ASSERT_EQUAL_FATAL(strncmp((const char *)r, "hello world", r_len), 0);
  free(r);
}

TEST("decode: == base64") {
  char *output;
  int r = run("printf \"aGVsbG8gd29ybGQ=\" | base64 --decode", &output);
  CU_ASSERT_EQUAL_FATAL(r, 0);
  CU_ASSERT_STRING_EQUAL(output, "hello world");
  free(output);
}

TEST("decode: decode(encode(x)) == x") {

  // Some basic text to encode.
  const char *input =
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod "
      "tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim "
      "veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea "
      "commodo consequat. Duis aute irure dolor in reprehenderit in voluptate "
      "velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint "
      "occaecat cupidatat non proident, sunt in culpa qui officia deserunt "
      "mollit anim id est laborum.";

  // Encode the text.
  char *encoded;
  passwand_error_t err =
      encode((const uint8_t *)input, strlen(input), &encoded);
  CU_ASSERT_EQUAL_FATAL(err, PW_OK);
  CU_ASSERT_PTR_NOT_NULL_FATAL(encoded);

  // Now let's decode this.
  uint8_t *output;
  size_t output_len;
  err = decode(encoded, &output, &output_len);
  CU_ASSERT_EQUAL_FATAL(err, PW_OK);
  CU_ASSERT_PTR_NOT_NULL_FATAL(output);

  free(encoded);

  // We should have got back what we put in.
  CU_ASSERT_EQUAL_FATAL(output_len, strlen(input));
  CU_ASSERT_EQUAL_FATAL(strncmp((const char *)output, input, output_len), 0);

  free(output);
}
