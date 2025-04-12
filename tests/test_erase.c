#include "test.h"
#include <passwand/passwand.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

TEST("erase: erase(NULL)") {
  int r = passwand_erase(NULL, 10);
  ASSERT_EQ(r, 0);
}

TEST("erase: basic functionality") {
  char basic[20] = "hello world";
  int r = passwand_erase((uint8_t *)basic, strlen(basic));
  ASSERT_EQ(r, 0);
  ASSERT_STRNE(basic, "hello world");
}

TEST("erase: erase(\"\")") {
  char empty[] = "";
  int r = passwand_erase((uint8_t *)empty, strlen(empty));
  ASSERT_EQ(r, 0);
}
