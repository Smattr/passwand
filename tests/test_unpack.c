#include "../src/internal.h"
#include "../src/types.h"
#include "test.h"
#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

TEST("unpack: unpack(pack(x)) == x") {

  // first pack something

  char _pt[] = "hello world";
  pt_t p = {
      .data = (uint8_t *)_pt,
      .length = sizeof(_pt),
  };
  const iv_t iv = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

  ppt_t pp;

  passwand_error_t r = pack_data(&p, iv, &pp);
  CU_ASSERT_EQUAL_FATAL(r, PW_OK);
  CU_ASSERT_EQUAL_FATAL(pp.length > 0, true);

  // now try to unpack it

  pt_t out;

  r = unpack_data(&pp, iv, &out);
  CU_ASSERT_EQUAL_FATAL(r, PW_OK);
  CU_ASSERT_EQUAL_FATAL(out.length, p.length);
  CU_ASSERT_EQUAL_FATAL(memcmp(p.data, out.data, out.length), 0);

  passwand_secure_free(out.data, out.length);
  passwand_secure_free(pp.data, pp.length);
}
