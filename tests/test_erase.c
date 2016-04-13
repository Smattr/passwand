#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stddef.h>
#include <string.h>
#include "test.h"

TEST(erase_null, "test erasing NULL") {
    int r = passwand_erase(NULL);
    CU_ASSERT_EQUAL(r, 0);
}

TEST(erase_basic, "test basic funtionality of erase") {
    char basic[20];
    strcpy(basic, "hello world");
    int r = passwand_erase(basic);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_STRING_NOT_EQUAL(basic, "hello world");
}

TEST(erase_empty_string, "test erasing the empty string") {
    char empty[1];
    strcpy(empty, "");
    int r = passwand_erase(empty);
    CU_ASSERT_EQUAL(r, 0);
}
