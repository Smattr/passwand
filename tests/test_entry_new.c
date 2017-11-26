#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "test.h"

static const char *master = "hello world";
static const char *space = "space";
static const char *key = "key";
static const char *value = "value";

TEST("entry_new: basic functionality") {
    passwand_entry_t e;
    memset(&e, 0, sizeof(e));
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

TEST("entry_new: check_mac(entry_new(...))") {
    passwand_entry_t e;
    passwand_error_t err = passwand_entry_new(&e, master, space, key, value, 14);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);

    err = passwand_entry_check_mac(master, &e);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);

    free(e.space);
    free(e.key);
    free(e.value);
    free(e.hmac);
    free(e.hmac_salt);
}

static void check(void *state, const char *s, const char *k, const char *v) {
    bool *st = state;
    *st = strcmp(space, s) == 0 && strcmp(key, k) == 0 && strcmp(value, v) == 0;
}

TEST("entry_new: recoverable") {
    passwand_entry_t e;
    passwand_error_t err = passwand_entry_new(&e, master, space, key, value, 14);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);

    bool checked = false;
    err = passwand_entry_do(master, &e, check, &checked);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);
    CU_ASSERT_EQUAL_FATAL(checked, true);

    free(e.space);
    free(e.key);
    free(e.value);
    free(e.hmac);
    free(e.hmac_salt);
}
