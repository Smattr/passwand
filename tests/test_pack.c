#include "../src/internal.h"
#include "../src/types.h"
#include "test.h"
#include <CUnit/CUnit.h>
#include <assert.h>
#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

TEST("pack: basic functionality") {

  char _pt[] = "hello world";
  const pt_t p = {
      .data = (uint8_t *)_pt,
      .length = sizeof(_pt),
  };
  const iv_t iv = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

  ppt_t pp;

  passwand_error_t r = pack_data(&p, iv, &pp);
  CU_ASSERT_EQUAL_FATAL(r, PW_OK);
  CU_ASSERT_EQUAL_FATAL(pp.length > 0, true);

  passwand_secure_free(pp.data, pp.length);
}

TEST("pack: is aligned") {

  char _pt[] = "Deliberately not 16-byte aligned text";
  assert(sizeof(_pt) % 16 != 0);
  pt_t p = {
      .data = (uint8_t *)_pt,
      .length = sizeof(_pt),
  };
  const iv_t iv = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

  ppt_t pp;

  passwand_error_t r = pack_data(&p, iv, &pp);
  CU_ASSERT_EQUAL_FATAL(r, PW_OK);
  CU_ASSERT_EQUAL_FATAL(pp.length > 0, true);
  CU_ASSERT_EQUAL_FATAL(pp.length % 16, 0);

  passwand_secure_free(pp.data, pp.length);
}
