// Helpers for RAII

#pragma once

#include "internal.h"
#include "types.h"
#include <assert.h>
#include <passwand/passwand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static inline k_t *make_k_t(void) {
  k_t *k;
  if (passwand_secure_malloc((void **)&k, sizeof(*k)) != 0)
    return NULL;
  return k;
}

static inline void unmake_k_t(void *p) {
  assert(p != NULL);
  k_t *k = *(k_t **)p;
  if (k != NULL)
    passwand_secure_free(k, sizeof(*k));
}
#define AUTO_K_T(name)                                                         \
  k_t *name __attribute__((cleanup(unmake_k_t))) = make_k_t()
