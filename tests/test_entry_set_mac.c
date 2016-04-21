#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "test.h"

TEST("entry_set_mac: basic functionality") {
    passwand_entry_t e = {
        .space = (uint8_t*)"hello world",
        .space_len = strlen("hello world"),
        .key = (uint8_t*)"hello world",
        .key_len = strlen("hello world"),
        .value = (uint8_t*)"hello world",
        .value_len = strlen("hello world"),
        .work_factor = 14,
    };

    passwand_error_t err = passwand_entry_set_mac("foo bar", &e);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);
    CU_ASSERT_PTR_NOT_NULL_FATAL(e.hmac);
    CU_ASSERT_PTR_NOT_NULL_FATAL(e.hmac_salt);
    free(e.hmac);
    free(e.hmac_salt);
}
