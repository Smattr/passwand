#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stdlib.h>
#include "test.h"

TEST("entry_new: basic functionality") {
    passwand_entry_t e = { NULL };
    char *master = "hello world";
    char *space = "space";
    char *key = "key";
    char *value = "value";
    passwand_error_t err = passwand_entry_new(&e, master, space, key, value, 14);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);
    CU_ASSERT_PTR_NOT_NULL_FATAL(e.space);
    CU_ASSERT_PTR_NOT_NULL_FATAL(e.key);
    CU_ASSERT_PTR_NOT_NULL_FATAL(e.value);
    CU_ASSERT_PTR_NOT_NULL_FATAL(e.hmac);
    CU_ASSERT_PTR_NOT_NULL_FATAL(e.hmac_salt);
    free(e.space);
    free(e.key);
    free(e.value);
    free(e.hmac);
    free(e.hmac_salt);
}
