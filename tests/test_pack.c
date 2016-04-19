#include "../src/encryption.h"
#include "../src/types.h"
#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "test.h"

TEST("basic packing functionality") {

    char _pt[] = "hello world";
    const pt_t p = {
        .data = (uint8_t*)_pt,
        .length = sizeof _pt,
    };
    uint8_t _iv[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16 };
    const iv_t iv = {
        .data = _iv,
        .length = sizeof _iv,
    };

    ppt_t pp;

    passwand_error_t r = pack_data(&p, &iv, &pp);
    CU_ASSERT_EQUAL_FATAL(r, PW_OK);
    CU_ASSERT_EQUAL_FATAL(pp.length > 0, true);

    free(pp.data);
}
