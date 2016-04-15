#include "../src/encoding.h"
#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "test.h"
#include "util.h"

TEST(decode_empty, "decoding the empty string") {
    const char *empty = "";
    uint8_t *r;
    size_t r_len;
    passwand_error_t err = decode(empty, &r, &r_len);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    CU_ASSERT_EQUAL_FATAL(r_len, 0);
    free(r);
}

TEST(decode_basic, "basic functionality of decode") {
    const char *basic = "aGVsbG8gd29ybGQ=";
    uint8_t *r;
    size_t r_len;
    passwand_error_t err = decode(basic, &r, &r_len);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    CU_ASSERT_EQUAL_FATAL(r_len, strlen("hello world"));
    CU_ASSERT_EQUAL_FATAL(strncmp((const char*)r, "hello world", r_len), 0);
    free(r);
}

TEST(decode_is_base64, "confirm that decoding does the same as the standard base64 utility") {
    char *output;
    int r = run("echo -n \"aGVsbG8gd29ybGQ=\" | base64 --decode", &output);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_STRING_EQUAL(output, "hello world");
    free(output);
}
