#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test.h"
#include <unistd.h>

TEST("import: import(\"[]\")") {

    /* Create a temporary file. */
    char tmp[sizeof("/tmp/tmp.XXXXXX")];
    strcpy(tmp, "/tmp/tmp.XXXXXX");
    int fd = mkstemp(tmp);
    CU_ASSERT_NOT_EQUAL_FATAL(fd, -1);
    ssize_t written = write(fd, "[]", strlen("[]"));
    if (written != strlen("[]"))
        unlink(tmp);
    CU_ASSERT_EQUAL_FATAL(written, strlen("[]"));

    /* Now read in the entries */
    passwand_entry_t *entries;
    size_t entry_len;
    int r = passwand_import(tmp, &entries, &entry_len);
    unlink(tmp);
    CU_ASSERT_EQUAL_FATAL(r, 0);

    /* Check we got nothing */
    CU_ASSERT_EQUAL_FATAL(entry_len, 0);
}

TEST("import: with a missing field") {
    const char *data = "[{\"space\":\"aGVsbG8gd29ybGQ=\", \"key\":\"aGVsbG8gd29ybGQ=\", "
        "\"value\":\"aGVsbG8gd29ybGQ=\", \"hmac\":\"aGVsbG8gd29ybGQ=\", \"hmac_salt\":"
        "\"aGVsbG8gd29ybGQ=\", \"salt\":\"aGVsbG8gd29ybGQ=\"}]";

    /* Create a temporary file. */
    char tmp[sizeof("/tmp/tmp.XXXXXX")];
    strcpy(tmp, "/tmp/tmp.XXXXXX");
    int fd = mkstemp(tmp);
    CU_ASSERT_NOT_EQUAL_FATAL(fd, -1);
    ssize_t written = write(fd, data, strlen(data));
    if (written != (ssize_t)strlen(data))
        unlink(tmp);
    CU_ASSERT_EQUAL_FATAL(written, strlen(data));

    /* Now read in the entries */
    passwand_entry_t *entries;
    size_t entry_len;
    int r = passwand_import(tmp, &entries, &entry_len);
    unlink(tmp);
    CU_ASSERT_NOT_EQUAL_FATAL(r, 0);
}

TEST("import: basic functionality") {
    const char *data = "[{\"space\":\"aGVsbG8gd29ybGQ=\", \"key\":\"aGVsbG8gd29ybGQ=\", "
        "\"value\":\"aGVsbG8gd29ybGQ=\", \"hmac\":\"aGVsbG8gd29ybGQ=\", \"hmac_salt\":"
        "\"aGVsbG8gd29ybGQ=\", \"salt\":\"aGVsbG8gd29ybGQ=\", \"iv\":\"aGVsbG8gd29ybGQ=\"}]";

    /* Create a temporary file. */
    char tmp[sizeof("/tmp/tmp.XXXXXX")];
    strcpy(tmp, "/tmp/tmp.XXXXXX");
    int fd = mkstemp(tmp);
    CU_ASSERT_NOT_EQUAL_FATAL(fd, -1);
    ssize_t written = write(fd, data, strlen(data));
    if (written != (ssize_t)strlen(data))
        unlink(tmp);
    CU_ASSERT_EQUAL_FATAL(written, strlen(data));

    /* Now read in the entries */
    passwand_entry_t *entries;
    size_t entry_len;
    int r = passwand_import(tmp, &entries, &entry_len);
    unlink(tmp);
    CU_ASSERT_EQUAL_FATAL(r, 0);

    /* Check we got an entry */
    CU_ASSERT_EQUAL_FATAL(entry_len, 1);
    CU_ASSERT_EQUAL_FATAL(entries[0].space_len, strlen("hello world"));
    CU_ASSERT_EQUAL_FATAL(strncmp((const char*)entries[0].space, "hello world", entries[0].space_len), 0);
    CU_ASSERT_EQUAL_FATAL(entries[0].key_len, strlen("hello world"));
    CU_ASSERT_EQUAL_FATAL(strncmp((const char*)entries[0].key, "hello world", entries[0].key_len), 0);
    CU_ASSERT_EQUAL_FATAL(entries[0].value_len, strlen("hello world"));
    CU_ASSERT_EQUAL_FATAL(strncmp((const char*)entries[0].value, "hello world", entries[0].value_len), 0);
    CU_ASSERT_EQUAL_FATAL(entries[0].hmac_len, strlen("hello world"));
    CU_ASSERT_EQUAL_FATAL(strncmp((const char*)entries[0].hmac, "hello world", entries[0].hmac_len), 0);
    CU_ASSERT_EQUAL_FATAL(entries[0].hmac_salt_len, strlen("hello world"));
    CU_ASSERT_EQUAL_FATAL(strncmp((const char*)entries[0].hmac_salt, "hello world", entries[0].hmac_salt_len), 0);
    CU_ASSERT_EQUAL_FATAL(entries[0].salt_len, strlen("hello world"));
    CU_ASSERT_EQUAL_FATAL(strncmp((const char*)entries[0].salt, "hello world", entries[0].salt_len), 0);
    CU_ASSERT_EQUAL_FATAL(entries[0].iv_len, strlen("hello world"));
    CU_ASSERT_EQUAL_FATAL(strncmp((const char*)entries[0].iv, "hello world", entries[0].iv_len), 0);
}

TEST("import: with an extra field") {
    const char *data = "[{\"space\":\"aGVsbG8gd29ybGQ=\", \"key\":\"aGVsbG8gd29ybGQ=\", "
        "\"value\":\"aGVsbG8gd29ybGQ=\", \"hmac\":\"aGVsbG8gd29ybGQ=\", \"hmac_salt\":"
        "\"aGVsbG8gd29ybGQ=\", \"salt\":\"aGVsbG8gd29ybGQ=\", \"iv\":\"aGVsbG8gd29ybGQ=\","
        "\"extra\":\"blah blah\"}]";

    /* Create a temporary file. */
    char tmp[sizeof("/tmp/tmp.XXXXXX")];
    strcpy(tmp, "/tmp/tmp.XXXXXX");
    int fd = mkstemp(tmp);
    CU_ASSERT_NOT_EQUAL_FATAL(fd, -1);
    ssize_t written = write(fd, data, strlen(data));
    if (written != (ssize_t)strlen(data))
        unlink(tmp);
    CU_ASSERT_EQUAL_FATAL(written, strlen(data));

    /* Now read in the entries */
    passwand_entry_t *entries;
    size_t entry_len;
    int r = passwand_import(tmp, &entries, &entry_len);
    unlink(tmp);
    CU_ASSERT_EQUAL_FATAL(r, 0);

    /* Check we got an entry */
    CU_ASSERT_EQUAL_FATAL(entry_len, 1);
    CU_ASSERT_EQUAL_FATAL(entries[0].space_len, strlen("hello world"));
    CU_ASSERT_EQUAL_FATAL(strncmp((const char*)entries[0].space, "hello world", entries[0].space_len), 0);
    CU_ASSERT_EQUAL_FATAL(entries[0].key_len, strlen("hello world"));
    CU_ASSERT_EQUAL_FATAL(strncmp((const char*)entries[0].key, "hello world", entries[0].key_len), 0);
    CU_ASSERT_EQUAL_FATAL(entries[0].value_len, strlen("hello world"));
    CU_ASSERT_EQUAL_FATAL(strncmp((const char*)entries[0].value, "hello world", entries[0].value_len), 0);
    CU_ASSERT_EQUAL_FATAL(entries[0].hmac_len, strlen("hello world"));
    CU_ASSERT_EQUAL_FATAL(strncmp((const char*)entries[0].hmac, "hello world", entries[0].hmac_len), 0);
    CU_ASSERT_EQUAL_FATAL(entries[0].hmac_salt_len, strlen("hello world"));
    CU_ASSERT_EQUAL_FATAL(strncmp((const char*)entries[0].hmac_salt, "hello world", entries[0].hmac_salt_len), 0);
    CU_ASSERT_EQUAL_FATAL(entries[0].salt_len, strlen("hello world"));
    CU_ASSERT_EQUAL_FATAL(strncmp((const char*)entries[0].salt, "hello world", entries[0].salt_len), 0);
    CU_ASSERT_EQUAL_FATAL(entries[0].iv_len, strlen("hello world"));
    CU_ASSERT_EQUAL_FATAL(strncmp((const char*)entries[0].iv, "hello world", entries[0].iv_len), 0);
}

TEST("import: import(export(x)) == x") {

    /* First create a couple of entries that we're going to export. */
    passwand_entry_t entries[] = {
        {
            .space = (uint8_t*)"hello world",
            .space_len = strlen("hello world"),
            .key = (uint8_t*)"hello world",
            .key_len = strlen("hello world"),
            .value = (uint8_t*)"hello world",
            .value_len = strlen("hello world"),
            .hmac = (uint8_t*)"hello world",
            .hmac_len = strlen("hello world"),
            .hmac_salt = (uint8_t*)"hello world",
            .hmac_salt_len = strlen("hello world"),
            .salt = (uint8_t*)"hello world",
            .salt_len = strlen("hello world"),
            .iv = (uint8_t*)"hello world",
            .iv_len = strlen("hello world"),
            .work_factor = 14,
        }, {
            .space = (uint8_t*)"foo bar",
            .space_len = strlen("foo bar"),
            .key = (uint8_t*)"foo bar",
            .key_len = strlen("foo bar"),
            .value = (uint8_t*)"foo bar",
            .value_len = strlen("foo bar"),
            .hmac = (uint8_t*)"foo bar",
            .hmac_len = strlen("foo bar"),
            .hmac_salt = (uint8_t*)"foo bar",
            .hmac_salt_len = strlen("foo bar"),
            .salt = (uint8_t*)"foo bar",
            .salt_len = strlen("foo bar"),
            .iv = (uint8_t*)"foo bar",
            .iv_len = strlen("foo bar"),
            .work_factor = 15,
        },
    };
    size_t entry_len = sizeof entries / sizeof entries[0];

    /* Create a temporary file to export to. */
    char tmp[] = "/tmp/tmp.XXXXXX";
    int fd = mkstemp(tmp);
    CU_ASSERT_NOT_EQUAL_FATAL(fd, -1);
    close(fd);

    /* Perform the export. */
    passwand_error_t err = passwand_export(tmp, entries, entry_len);
    if (err != PW_OK)
        unlink(tmp);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);

    /* Now let's import them back in. */
    passwand_entry_t *new_entries;
    size_t new_entry_len;
    err = passwand_import(tmp, &new_entries, &new_entry_len);
    unlink(tmp);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);

    /* Now check we got back what we exported. */
    CU_ASSERT_EQUAL_FATAL(entry_len, new_entry_len);
    for (size_t i = 0; i < entry_len; i++) {
        CU_ASSERT_EQUAL_FATAL(entries[i].space_len, new_entries[i].space_len);
        CU_ASSERT_EQUAL_FATAL(strncmp((const char*)entries[i].space, (const char*)new_entries[i].space, entries[i].space_len), 0);
        CU_ASSERT_EQUAL_FATAL(entries[i].key_len, new_entries[i].key_len);
        CU_ASSERT_EQUAL_FATAL(strncmp((const char*)entries[i].key, (const char*)new_entries[i].key, entries[i].key_len), 0);
        CU_ASSERT_EQUAL_FATAL(entries[i].value_len, new_entries[i].value_len);
        CU_ASSERT_EQUAL_FATAL(strncmp((const char*)entries[i].value, (const char*)new_entries[i].value, entries[i].value_len), 0);
        CU_ASSERT_EQUAL_FATAL(entries[i].hmac_len, new_entries[i].hmac_len);
        CU_ASSERT_EQUAL_FATAL(strncmp((const char*)entries[i].hmac, (const char*)new_entries[i].hmac, entries[i].hmac_len), 0);
        CU_ASSERT_EQUAL_FATAL(entries[i].hmac_salt_len, new_entries[i].hmac_salt_len);
        CU_ASSERT_EQUAL_FATAL(strncmp((const char*)entries[i].hmac_salt, (const char*)new_entries[i].hmac_salt, entries[i].hmac_salt_len), 0);
        CU_ASSERT_EQUAL_FATAL(entries[i].salt_len, new_entries[i].salt_len);
        CU_ASSERT_EQUAL_FATAL(strncmp((const char*)entries[i].salt, (const char*)new_entries[i].salt, entries[i].salt_len), 0);
        CU_ASSERT_EQUAL_FATAL(entries[i].iv_len, new_entries[i].iv_len);
        CU_ASSERT_EQUAL_FATAL(strncmp((const char*)entries[i].iv, (const char*)new_entries[i].iv, entries[i].iv_len), 0);
    }

    /* Clean up. */
    for (size_t i = 0; i < new_entry_len; i++) {
        free(new_entries[i].space);
        free(new_entries[i].key);
        free(new_entries[i].value);
        free(new_entries[i].hmac);
        free(new_entries[i].hmac_salt);
        free(new_entries[i].salt);
        free(new_entries[i].iv);
    }
    free(new_entries);
}
