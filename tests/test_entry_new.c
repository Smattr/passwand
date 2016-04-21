#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stdlib.h>
#include "test.h"

TEST("entry_new: basic functionality") {
    passwand_entry_t e;
    char *master = "hello world";
    char *space = "space";
    char *key = "key";
    char *value = "value";
    passwand_error_t err = passwand_entry_new(&e, master, space, key, value, 14);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);
    free(e.space);
    free(e.key);
    free(e.value);
    free(e.hmac);
    free(e.hmac_salt);
}
