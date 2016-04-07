#include <assert.h>
#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void test_erase_null(void) {
    int r = passwand_erase(NULL);
    CU_ASSERT_EQUAL(r, 0);
}

static void test_erase_basic(void) {
    char basic[20];
    strcpy(basic, "hello world");
    int r = passwand_erase(basic);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_STRING_NOT_EQUAL(basic, "hello world");
}

static void test_erase_empty_string(void) {
    char empty[1];
    strcpy(empty, "");
    int r = passwand_erase(empty);
    CU_ASSERT_EQUAL(r, 0);
}

#define TEST(fn) { #fn, fn }
static const struct {
    const char *name;
    void (*fn)(void);
} TESTS[] = {
    TEST(test_erase_null),
    TEST(test_erase_basic),
    TEST(test_erase_empty_string),
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
