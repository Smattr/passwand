#pragma once

struct test_case {
    const char *name;
    void (*function)(void);
    const char *description;
    struct test_case *next;
};

extern struct test_case *test_cases;

#define TEST(n, desc) \
    static void test_##n(void); \
    static void __attribute__((constructor)) add_test_##n(void) { \
        static struct test_case test_case_##n = { \
            .name = #n, \
            .function = test_##n, \
            .description = desc, \
        }; \
        test_case_##n.next = test_cases; \
        test_cases = &test_case_##n; \
    } \
    static void test_##n(void)
