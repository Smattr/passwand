#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "test.h"

TEST("test erasing NULL") {
    int r = passwand_erase(NULL, 10);
    CU_ASSERT_EQUAL(r, 0);
}

TEST("test basic funtionality of erase") {
    char basic[20];
    strcpy(basic, "hello world");
    int r = passwand_erase((uint8_t*)basic, strlen(basic));
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_STRING_NOT_EQUAL(basic, "hello world");
}

TEST("test erasing the empty string") {
    char empty[1];
    strcpy(empty, "");
    int r = passwand_erase((uint8_t*)empty, strlen(empty));
    CU_ASSERT_EQUAL(r, 0);
}
