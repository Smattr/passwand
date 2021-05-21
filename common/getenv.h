#pragma once

#include <stdlib.h>

// wrapper around getenv to call secure_getenv when available
static inline char *getenv_(const char *name) {
#ifdef __GLIBC__
#if __GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 17)
  return secure_getenv(name);
#endif
#endif
  return getenv(name);
}
