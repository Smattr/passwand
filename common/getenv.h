#pragma once

#include <stdlib.h>

// Wrapper around getenv to call secure_getenv when available.
static inline char *getenv_(const char *name) {
#if __GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 17)
  return secure_getenv(name);
#else
  return getenv(name);
#endif
}
