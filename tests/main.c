#define _XOPEN_SOURCE 700 /* for open_memstream */

#include <assert.h>
#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/encoding.h"

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

#define TEST(fn) { #fn, fn }
static const struct {
    const char *name;
    void (*fn)(void);
} TESTS[] = {
    TEST(test_erase_null),
    TEST(test_erase_basic),
    TEST(test_erase_empty_string),
    TEST(test_encode_empty),
    TEST(test_encode_basic),
    TEST(test_encode_is_base64),
    TEST(test_decode_empty),
    TEST(test_decode_basic),
    TEST(test_decode_is_base64),
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
