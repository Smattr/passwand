#include <passwand/passwand.h>
#include "test.h"
#include <CUnit/CUnit.h>

TEST("random_bytes: basic functionality") {
  uint8_t buffer[10] = {0};
  int r = passwand_random_bytes(buffer, sizeof(buffer));
  CU_ASSERT_EQUAL_FATAL(r, 0);

  // statistically, we should not get a buffer back full of zeros
  uint8_t buffer2[sizeof(buffer)] = {0};
  CU_ASSERT_NOT_EQUAL_FATAL(memcmp(buffer, buffer2, sizeof(buffer)), 0);
}

TEST("random_bytes: random_bytes(0)") {
  uint8_t buffer[10] = {0};
  int r = passwand_random_bytes(buffer, 0);
  CU_ASSERT_EQUAL_FATAL(r, 0);

  uint8_t buffer2[sizeof(buffer)] = {0};
  CU_ASSERT_EQUAL_FATAL(memcmp(buffer, buffer2, sizeof(buffer)), 0);
}
