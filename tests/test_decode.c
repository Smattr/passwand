#include "../src/encoding.h"
#include <CUnit/CUnit.h>
#include <stdlib.h>
#include <string.h>
#include "test.h"
#include "util.h"

TEST(decode_empty, "decoding the empty string") {
    const char *empty = "";
    char *r = decode(empty);
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    CU_ASSERT_STRING_EQUAL(empty, r);
    free(r);
}

TEST(decode_basic, "basic functionality of decode") {
    const char *basic = "aGVsbG8gd29ybGQ=";
    char *blah = strdup(basic);
    char *r = decode(blah);
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    CU_ASSERT_STRING_EQUAL(r, "hello world");
    free(r);
}

TEST(decode_is_base64, "confirm that decoding does the same as the standard base64 utility") {
    char *output;
    int r = run("echo -n \"aGVsbG8gd29ybGQ=\" | base64 --decode", &output);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_STRING_EQUAL(output, "hello world");
    free(output);
}
