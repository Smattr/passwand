#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static bool streq(const char *a, const char *b) {
  assert(a != NULL);
  assert(b != NULL);
  return strcmp(a, b) == 0;
}
