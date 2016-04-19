#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stdbool.h>
#include <string.h>
#include "test.h"

TEST("malloc: basic functionality") {

    const char buffer[] = "hello world";

    void *p;
    int err = passwand_secure_malloc(&p, 10);
    CU_ASSERT_EQUAL_FATAL(err, 0);
    memcpy(p, buffer, 10);

    void *q;
    err = passwand_secure_malloc(&q, 100);
    CU_ASSERT_EQUAL_FATAL(err, 0);
    memcpy(q, buffer, sizeof buffer);

    /* The two pointers should not overlap. */
    CU_ASSERT_EQUAL_FATAL(p + 10 <= q || q + 100 <= p, true);

    passwand_secure_free(q, 100);

    /* The memory should have been wiped. */
    CU_ASSERT_NOT_EQUAL_FATAL(strncmp(q, buffer, sizeof buffer), 0);

    /* The first block of memory should not have been touched. */
    CU_ASSERT_EQUAL_FATAL(strncmp(p, buffer, 10), 0);

    passwand_secure_free(p, 10);
}
