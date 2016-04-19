#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test.h"
#include <unistd.h>

TEST("test exporting 0 entries") {

    /* Create a temporary path. */
    char tmp[sizeof("/tmp/tmp.XXXXXX")];
    strcpy(tmp, "/tmp/tmp.XXXXXX");
    int fd = mkstemp(tmp);
    CU_ASSERT_NOT_EQUAL_FATAL(fd, -1);
    close(fd);

    /* Export to this path. */
    int r = passwand_export(tmp, NULL, 0);
    if (r != 0)
        unlink(tmp);
    CU_ASSERT_EQUAL_FATAL(r, 0);

    /* Read back in the exported data. */
    FILE *f = fopen(tmp, "r");
    if (f == NULL)
        unlink(tmp);
    CU_ASSERT_PTR_NOT_NULL_FATAL(f);
    char buffer[100];
    char *p = fgets(buffer, sizeof(buffer), f);
    fclose(f);
    unlink(tmp);

    /* Check we got what we expect. */
    CU_ASSERT_PTR_NOT_NULL_FATAL(p);
    CU_ASSERT_STRING_EQUAL(buffer, "[]");
}

TEST("basic export functionality") {

    /* Create a temporary path. */
    char tmp[sizeof("/tmp/tmp.XXXXXX")];
    strcpy(tmp, "/tmp/tmp.XXXXXX");
    int fd = mkstemp(tmp);
    CU_ASSERT_NOT_EQUAL_FATAL(fd, -1);
    close(fd);

    /* Create an entry to export. */
    passwand_entry_t entries[] = {
        {
            .space = (uint8_t*)"hello world",
            .key = (uint8_t*)"hello world",
            .value = (uint8_t*)"hello world",
            .hmac = (uint8_t*)"hello world",
            .hmac_salt = (uint8_t*)"hello world",
            .salt = (uint8_t*)"hello world",
            .iv = (uint8_t*)"hello world",
            .encrypted = true,
            .work_factor = 0,
        },
    };

    /* Export to this path. */
    int r = passwand_export(tmp, entries, sizeof(entries) / sizeof(entries[0]));
    unlink(tmp);
    CU_ASSERT_EQUAL_FATAL(r, 0);
}

TEST("test that exporting an unencrypted entry fails") {

    /* Create a temporary path. */
    char tmp[sizeof("/tmp/tmp.XXXXXX")];
    strcpy(tmp, "/tmp/tmp.XXXXXX");
    int fd = mkstemp(tmp);
    CU_ASSERT_NOT_EQUAL_FATAL(fd, -1);
    close(fd);

    /* Create an entry to export. */
    passwand_entry_t entries[] = {
        {
            .space = (uint8_t*)"hello world",
            .key = (uint8_t*)"hello world",
            .value = (uint8_t*)"hello world",
            .hmac = (uint8_t*)"hello world",
            .hmac_salt = (uint8_t*)"hello world",
            .salt = (uint8_t*)"hello world",
            .iv = (uint8_t*)"hello world",
            .encrypted = false, /* <-- note, not encrypted */
            .work_factor = 0,
        },
    };

    /* Export to this path. */
    int r = passwand_export(tmp, entries, sizeof(entries) / sizeof(entries[0]));
    unlink(tmp);
    CU_ASSERT_NOT_EQUAL_FATAL(r, 0);
}
