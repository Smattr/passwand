#include "../src/encoding.h"
#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stdlib.h>
#include "test.h"
#include "util.h"

TEST(encode_empty, "encoding the empty string") {
    const char *empty = "";
    char *r;
    passwand_error_t err = encode(empty, &r);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    CU_ASSERT_STRING_EQUAL(empty, r);
    free(r);
}

TEST(encode_basic, "basic functionality of encode") {
    const char *basic = "hello world";
    char *r;
    passwand_error_t err = encode(basic, &r);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    CU_ASSERT_STRING_EQUAL(r, "aGVsbG8gd29ybGQ=");
    free(r);
}

TEST(encode_is_base64, "confirm that encoding does the same as the standard base64 utility") {
    char *output;
    int r = run("echo -n \"hello world\" | base64", &output);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_STRING_EQUAL(output, "aGVsbG8gd29ybGQ=\n");
    free(output);
}
