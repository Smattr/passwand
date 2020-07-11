#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "test.h"
#include <unistd.h>

static void cleanup_entry(passwand_entry_t *e) {
    if (e->space != NULL)
        free(e->space);
    if (e->key != NULL)
        free(e->key);
    if (e->value != NULL)
        free(e->value);
    if (e->hmac != NULL)
        free(e->hmac);
    if (e->hmac_salt != NULL)
        free(e->hmac_salt);
    if (e->salt != NULL)
        free(e->salt);
    if (e->iv != NULL)
        free(e->iv);
}

typedef struct {
    size_t index;
    bool failed;
} state_t;

static void body(void *state, const char *space, const char *key, const char *value) {
    state_t *st = state;
    switch (st->index) {

        case 0:
            st->failed |= !(strcmp(space, "foo.com") == 0 &&
                            strcmp(key, "username") == 0 &&
                            strcmp(value, "bob") == 0);
            break;

        case 1:
            st->failed |= !(strcmp(space, "foo.com") == 0 &&
                            strcmp(key, "password") == 0 &&
                            strcmp(value, "bob's password") == 0);
            break;

        case 2:
            st->failed |= !(strcmp(space, "bar.com") == 0 &&
                            strcmp(key, "username") == 0 &&
                            strcmp(value, "alice") == 0);
            break;

        case 3:
            st->failed |= !(strcmp(space, "bar.com") == 0 &&
                            strcmp(key, "password") == 0 &&
                            strcmp(value, "alice's password") == 0);
            break;

        default:
            st->failed = true;
    }
    st->index++;
}

TEST("integration: basic lifecycle") {
    const char *mainpass = "hello world";

    size_t entry_len = 4;
    passwand_entry_t *entries = calloc(entry_len, sizeof(entries[0]));

    const int work_factor = 14;

    {
        const char *space = "foo.com";
        const char *key = "username";
        const char *value = "bob";

        passwand_error_t err = passwand_entry_new(&entries[0], mainpass, space, key, value, work_factor);
        CU_ASSERT_EQUAL_FATAL(err, PW_OK);
    }

    {
        const char *space = "foo.com";
        const char *key = "password";
        const char *value = "bob's password";

        passwand_error_t err = passwand_entry_new(&entries[1], mainpass, space, key, value, work_factor);
        CU_ASSERT_EQUAL_FATAL(err, PW_OK);
    }

    {
        const char *space = "bar.com";
        const char *key = "username";
        const char *value = "alice";

        passwand_error_t err = passwand_entry_new(&entries[2], mainpass, space, key, value, work_factor);
        CU_ASSERT_EQUAL_FATAL(err, PW_OK);
    }

    {
        const char *space = "bar.com";
        const char *key = "password";
        const char *value = "alice's password";

        passwand_error_t err = passwand_entry_new(&entries[3], mainpass, space, key, value, work_factor);
        CU_ASSERT_EQUAL_FATAL(err, PW_OK);
    }

    char tmp[] = "/tmp/tmp.XXXXXX";
    {
        int fd = mkstemp(tmp);
        CU_ASSERT_NOT_EQUAL_FATAL(fd, -1);
        close(fd);

        passwand_error_t err = passwand_export(tmp, entries, entry_len);
        CU_ASSERT_EQUAL_FATAL(err, PW_OK);
    }

    for (size_t i = 0; i < entry_len; i++)
        cleanup_entry(&entries[i]);
    free(entries);

    passwand_error_t err = passwand_import(tmp, &entries, &entry_len);
    CU_ASSERT_EQUAL_FATAL(err, PW_OK);

    CU_ASSERT_EQUAL_FATAL(entry_len, 4);

    for (size_t i = 0; i < entry_len; i++)
        entries[i].work_factor = work_factor;

    state_t st = {
        .index = 0,
        .failed = false,
    };
    for (size_t i = 0; i < entry_len; i++) {
        err = passwand_entry_do(mainpass, &entries[i], body, &st);
        CU_ASSERT_EQUAL_FATAL(err, PW_OK);
        CU_ASSERT_EQUAL_FATAL(st.failed, false);
    }

    unlink(tmp);

    for (size_t i = 0; i < entry_len; i++)
        cleanup_entry(&entries[i]);
    free(entries);
}
