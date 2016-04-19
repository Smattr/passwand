#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test.h"
#include <unistd.h>

TEST("importing the empty list") {

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
    unsigned entry_len;
    int r = passwand_import(tmp, &entries, &entry_len);
    unlink(tmp);
    CU_ASSERT_EQUAL_FATAL(r, 0);

    /* Check we got nothing */
    CU_ASSERT_EQUAL_FATAL(entry_len, 0);
}

TEST("importing an entry with a missing field") {
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
    unsigned entry_len;
    int r = passwand_import(tmp, &entries, &entry_len);
    unlink(tmp);
    CU_ASSERT_NOT_EQUAL_FATAL(r, 0);
}

TEST("basic import functionality") {
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
    unsigned entry_len;
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

TEST("test having a superfluous field is fine") {
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
    unsigned entry_len;
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
