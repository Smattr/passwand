#include "../src/internal.h"
#include "../src/types.h"
#include "test.h"
#include <passwand/passwand.h>
#include <stdint.h>
#include <stdlib.h>

TEST("unpack: unpack(pack(x)) == x") {

  // first pack something

  uint8_t _pt[] = "hello world";
  pt_t p = {
      .data = _pt,
      .length = sizeof(_pt),
  };
  const iv_t iv = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

  ppt_t pp;

  int r = pack_data(&p, iv, &pp);
  ASSERT_EQ(r, PW_OK);
  ASSERT_GT(pp.length, 0ul);

  // now try to unpack it

  pt_t out;

  r = unpack_data(&pp, iv, &out);
  ASSERT_EQ(r, PW_OK);
  ASSERT_EQ(out.length, p.length);
  ASSERT_EQ(memcmp(p.data, out.data, out.length), 0);

  passwand_secure_free(out.data, out.length);
  passwand_secure_free(pp.data, pp.length);
}
