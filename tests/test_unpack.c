#include "../src/encryption.h"
#include <CUnit/CUnit.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "test.h"

TEST(unpack_basic, "test unpacking something we packed") {

    /* First pack something. */

    const char pt[] = "hello world";
    const uint8_t iv[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16 };

    uint8_t *ppt;
    size_t ppt_len;

    int r = pack_data((const uint8_t*)pt, sizeof pt, iv, sizeof iv, &ppt,
        &ppt_len);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(ppt_len > 0, true);

    /* Now try to unpack it. */

    uint8_t *out;
    size_t out_len;

    r = unpack_data(ppt, ppt_len, iv, sizeof iv, &out, &out_len);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(out_len, sizeof pt);
    CU_ASSERT_EQUAL_FATAL(memcmp(pt, out, out_len), 0);

    free(out);
    free(ppt);
}
