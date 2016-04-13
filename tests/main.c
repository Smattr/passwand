#define _XOPEN_SOURCE 700 /* for open_memstream */

#include <assert.h>
#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test.h"
#include <unistd.h>

#include "../src/encoding.h"

struct test_case *test_cases;

static int run(const char *command, char **output) {
    assert(command != NULL);
    assert(output != NULL);

    FILE *p = popen(command, "r");
    if (p == NULL)
        return -1;


    *output = NULL;
    size_t buffer_len;
    FILE *b = open_memstream(output, &buffer_len);
    if (b == NULL) {
        pclose(p);
        return -1;
    }

    char window[1024];
    size_t read;
    while ((read = fread(window, 1, sizeof(window), p)) != 0) {
        assert(read <= sizeof(window));
        size_t written = fwrite(window, 1, read, b);
        if (read != written) {
            /* out of memory */
            fclose(b);
            free(*output);
            pclose(p);
            return -1;
        }
    }

    if (ferror(p)) {
        fclose(b);
        free(*output);
        pclose(p);
        return -1;
    }

    fclose(b);
    return pclose(p);
}

static void test_erase_null(void) {
    int r = passwand_erase(NULL);
    CU_ASSERT_EQUAL(r, 0);
}

static void test_erase_basic(void) {
    char basic[20];
    strcpy(basic, "hello world");
    int r = passwand_erase(basic);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_STRING_NOT_EQUAL(basic, "hello world");
}

static void test_erase_empty_string(void) {
    char empty[1];
    strcpy(empty, "");
    int r = passwand_erase(empty);
    CU_ASSERT_EQUAL(r, 0);
}

static void test_encode_empty(void) {
    const char *empty = "";
    char *r = encode(empty);
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    CU_ASSERT_STRING_EQUAL(empty, r);
    free(r);
}

static void test_encode_basic(void) {
    const char *basic = "hello world";
    char *r = encode(basic);
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    CU_ASSERT_STRING_EQUAL(r, "aGVsbG8gd29ybGQ=");
    free(r);
}

/* Confirm that encoding does the same as the standard base64 utility. */
static void test_encode_is_base64(void) {
    char *output;
    int r = run("echo -n \"hello world\" | base64", &output);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_STRING_EQUAL(output, "aGVsbG8gd29ybGQ=\n");
    free(output);
}

static void test_decode_empty(void) {
    const char *empty = "";
    char *r = decode(empty);
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    CU_ASSERT_STRING_EQUAL(empty, r);
    free(r);
}

static void test_decode_basic(void) {
    const char *basic = "aGVsbG8gd29ybGQ=";
    char *blah = strdup(basic);
    char *r = decode(blah);
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    CU_ASSERT_STRING_EQUAL(r, "hello world");
    free(r);
}

/* Confirm that decoding does the same as the standard base64 utility. */
static void test_decode_is_base64(void) {
    char *output;
    int r = run("echo -n \"aGVsbG8gd29ybGQ=\" | base64 --decode", &output);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_STRING_EQUAL(output, "hello world");
    free(output);
}

/* Test exporting 0 entries. */
static void test_export_nothing(void) {

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

/* Test basic export. */
static void test_export_basic(void) {

    /* Create a temporary path. */
    char tmp[sizeof("/tmp/tmp.XXXXXX")];
    strcpy(tmp, "/tmp/tmp.XXXXXX");
    int fd = mkstemp(tmp);
    CU_ASSERT_NOT_EQUAL_FATAL(fd, -1);
    close(fd);

    /* Create an entry to export. */
    passwand_entry_t entries[] = {
        {
            .space = "hello world",
            .key = "hello world",
            .value = "hello world",
            .hmac = "hello world",
            .hmac_salt = "hello world",
            .salt = "hello world",
            .iv = "hello world",
            .encrypted = true,
            .work_factor = 0,
        },
    };

    /* Export to this path. */
    int r = passwand_export(tmp, entries, sizeof(entries) / sizeof(entries[0]));
    unlink(tmp);
    CU_ASSERT_EQUAL_FATAL(r, 0);
}

/* Test that exporting an unencrypted entry fails. */
static void test_export_unencrypted(void) {

    /* Create a temporary path. */
    char tmp[sizeof("/tmp/tmp.XXXXXX")];
    strcpy(tmp, "/tmp/tmp.XXXXXX");
    int fd = mkstemp(tmp);
    CU_ASSERT_NOT_EQUAL_FATAL(fd, -1);
    close(fd);

    /* Create an entry to export. */
    passwand_entry_t entries[] = {
        {
            .space = "hello world",
            .key = "hello world",
            .value = "hello world",
            .hmac = "hello world",
            .hmac_salt = "hello world",
            .salt = "hello world",
            .iv = "hello world",
            .encrypted = false, /* <-- note, not encrypted */
            .work_factor = 0,
        },
    };

    /* Export to this path. */
    int r = passwand_export(tmp, entries, sizeof(entries) / sizeof(entries[0]));
    unlink(tmp);
    CU_ASSERT_NOT_EQUAL_FATAL(r, 0);
}

static void test_import_empty_list(void) {

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

static void test_import_missing_field(void) {
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

static void test_import_basic(void) {
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
    CU_ASSERT_STRING_EQUAL(entries[0].space, "hello world");
    CU_ASSERT_STRING_EQUAL(entries[0].key, "hello world");
    CU_ASSERT_STRING_EQUAL(entries[0].value, "hello world");
    CU_ASSERT_STRING_EQUAL(entries[0].hmac, "hello world");
    CU_ASSERT_STRING_EQUAL(entries[0].hmac_salt, "hello world");
    CU_ASSERT_STRING_EQUAL(entries[0].salt, "hello world");
    CU_ASSERT_STRING_EQUAL(entries[0].iv, "hello world");
}

/* Test having a superfluous field is fine. */
static void test_import_extra_field(void) {
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
    CU_ASSERT_STRING_EQUAL(entries[0].space, "hello world");
    CU_ASSERT_STRING_EQUAL(entries[0].key, "hello world");
    CU_ASSERT_STRING_EQUAL(entries[0].value, "hello world");
    CU_ASSERT_STRING_EQUAL(entries[0].hmac, "hello world");
    CU_ASSERT_STRING_EQUAL(entries[0].hmac_salt, "hello world");
    CU_ASSERT_STRING_EQUAL(entries[0].salt, "hello world");
    CU_ASSERT_STRING_EQUAL(entries[0].iv, "hello world");
}

static const struct {
    const char *name;
    void (*fn)(void);
} TESTS[] = {
    { "test_erase_null", test_erase_null, },
    { "test_erase_basic", test_erase_basic, },
    { "test_erase_empty_string", test_erase_empty_string, },
    { "test_encode_empty", test_encode_empty, },
    { "test_encode_basic", test_encode_basic, },
    { "test_encode_is_base64", test_encode_is_base64, },
    { "test_decode_empty", test_decode_empty, },
    { "test_decode_basic", test_decode_basic, },
    { "test_decode_is_base64", test_decode_is_base64, },
    { "test_export_nothing", test_export_nothing, },
    { "test_export_basic", test_export_basic, },
    { "test_export_unencrypted", test_export_unencrypted, },
    { "test_import_empty_list", test_import_empty_list, },
    { "test_import_basic", test_import_basic, },
    { "test_import_missing_field", test_import_missing_field, },
    { "test_import_extra_field", test_import_extra_field, },
};

int main(int argc, char **argv) {

    if (CU_initialize_registry() != CUE_SUCCESS) {
        CU_ErrorCode err = CU_get_error();
        fprintf(stderr, "failed to initialise CUnit registry\n");
        return err;
    }

    CU_pSuite suite = CU_add_suite("passwand", NULL, NULL);
    if (suite == NULL) {
        CU_ErrorCode err = CU_get_error();
        CU_cleanup_registry();
        fprintf(stderr, "failed to add suite\n");
        return err;
    }

    unsigned int total = 0;
    for (unsigned int i = 0; i < sizeof(TESTS) / sizeof(TESTS[0]); i++) {
        if (argc == 1 || strcmp(argv[1], TESTS[i].name) == 0) {
            if (CU_add_test(suite, TESTS[i].name, TESTS[i].fn) == NULL) {
                CU_ErrorCode err = CU_get_error();
                fprintf(stderr, "failed to add test %s\n", TESTS[i].name);
                CU_cleanup_registry();
                return err;
            }
        total++;
        }
    }

    if (total == 0) {
        fprintf(stderr, "no tests found\n");
        return EXIT_FAILURE;
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    unsigned int failed = CU_get_number_of_tests_failed();

    CU_cleanup_registry();

    printf("%u/%u passed\n", total - failed, total);

    return failed > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
