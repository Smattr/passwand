#include "../src/internal.h"
#include "test.h"
#include "util.h"
#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stdlib.h>
#include <string.h>

TEST("encode: encode(\"\")") {
  const char *empty = "";
  char *r;
  passwand_error_t err = encode((const uint8_t *)empty, strlen(empty), &r);
  CU_ASSERT_EQUAL_FATAL(err, PW_OK);
  CU_ASSERT_PTR_NOT_NULL_FATAL(r);
  CU_ASSERT_STRING_EQUAL(empty, r);
  free(r);
}

TEST("encode: basic functionality") {
  const char *basic = "hello world";
  char *r;
  passwand_error_t err = encode((const uint8_t *)basic, strlen(basic), &r);
  CU_ASSERT_EQUAL_FATAL(err, PW_OK);
  CU_ASSERT_PTR_NOT_NULL_FATAL(r);
  CU_ASSERT_STRING_EQUAL(r, "aGVsbG8gd29ybGQ=");
  free(r);
}

TEST("encode: == base64") {
  char *output;
  int r = run("printf \"hello world\" | base64", &output);
  CU_ASSERT_EQUAL_FATAL(r, 0);
  CU_ASSERT_STRING_EQUAL(output, "aGVsbG8gd29ybGQ=\n");
  free(output);
}
