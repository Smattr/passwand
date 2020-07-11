#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "test.h"

static void create_maced_entry(passwand_entry_t *e) {
    memset(e, 0, sizeof(*e));
    e->space = (uint8_t*)"hello world";
    e->space_len = strlen("hello world");
    e->key = (uint8_t*)"hello world";
    e->key_len = strlen("hello world");
    e->value = (uint8_t*)"hello world";
    e->value_len = strlen("hello world");
    e->work_factor = 14;

    passwand_error_t err = passwand_entry_set_mac("foo bar", e);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);
}

TEST("entry_check_mac: basic functionality") {
    passwand_entry_t e;
    create_maced_entry(&e);

    /* Checking the MAC should work. */
    passwand_error_t err = passwand_entry_check_mac("foo bar", &e);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);

    free(e.hmac);
    free(e.hmac_salt);
}

TEST("entry_check_mac: bad password") {
    passwand_entry_t e;
    create_maced_entry(&e);

    /* Checking the MAC with the wrong password should fail. Note that we can't actually detect an
     * incorrect main password, and this failure will manifest as a failed integrity check.
     */
    passwand_error_t err = passwand_entry_check_mac("hello world", &e);
    CU_ASSERT_NOT_EQUAL_FATAL(err, PW_OK);

    free(e.hmac);
    free(e.hmac_salt);
}

TEST("entry_check_mac: corrupted") {
    passwand_entry_t e;
    create_maced_entry(&e);

    /* Simulate entry corruption (or malicious modification). */
    e.space_len--;

    /* The HMAC check should now fail. */
    passwand_error_t err = passwand_entry_check_mac("foo bar", &e);
    CU_ASSERT_NOT_EQUAL_FATAL(err, PW_OK);

    free(e.hmac);
    free(e.hmac_salt);
}
