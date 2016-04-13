#pragma once

typedef struct _test_case {
    const char *name;
    void (*function)(void);
    const char *description;
    struct _test_case *next;
} test_case_t;

extern test_case_t *test_cases;

#define TEST(n, desc) \
    static void test_##n(void); \
    static void __attribute__((constructor)) add_test_##n(void) { \
        static test_case_t test_case_##n = { \
            .name = #n, \
            .function = test_##n, \
            .description = desc, \
        }; \
        test_case_##n.next = test_cases; \
        test_cases = &test_case_##n; \
    } \
    static void test_##n(void)
