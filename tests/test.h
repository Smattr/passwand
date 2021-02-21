#pragma once

typedef struct _test_case {
  void (*function)(void);
  const char *description;
  struct _test_case *next;
} test_case_t;

extern test_case_t *test_cases;

#define _JOIN(x, y) x##y
#define JOIN(x, y) _JOIN(x, y)

#define TEST(desc)                                                             \
  static void JOIN(test_, __LINE__)(void);                                     \
  static void __attribute__((constructor)) JOIN(add_test_, __LINE__)(void) {   \
    static test_case_t JOIN(test_case_, __LINE__) = {                          \
        .function = JOIN(test_, __LINE__),                                     \
        .description = desc,                                                   \
    };                                                                         \
    JOIN(test_case_, __LINE__).next = test_cases;                              \
    test_cases = &JOIN(test_case_, __LINE__);                                  \
  }                                                                            \
  static void JOIN(test_, __LINE__)(void)
