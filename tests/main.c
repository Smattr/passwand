#include "test.h"
#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

test_case_t *test_cases;

int main(int argc, char **argv) {

  if (argc == 2 &&
      (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
    fprintf(stderr, "usage %s [test prefix]\n\ntest options:\n", argv[0]);
    for (test_case_t *p = test_cases; p != NULL; p = p->next) {
      fprintf(stderr, " %s\n", p->description);
    }
    return EXIT_FAILURE;
  }

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

  unsigned total = 0;
  for (test_case_t *p = test_cases; p != NULL; p = p->next) {
    if (argc == 1 || strncmp(argv[1], p->description, strlen(argv[1])) == 0) {
      if (CU_add_test(suite, p->description, p->function) == NULL) {
        CU_ErrorCode err = CU_get_error();
        fprintf(stderr, "failed to add test \"%s\"\n", p->description);
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

  unsigned failed = CU_get_number_of_tests_failed();

  CU_cleanup_registry();

  printf("%u/%u passed\n", total - failed, total);

  return failed > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
