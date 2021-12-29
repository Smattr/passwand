// helpers for RAII

#pragma once

#include "internal.h"
#include "types.h"
#include <assert.h>
#include <passwand/passwand.h>
#include <stdlib.h>

static inline k_t *make_k_t(void) {
  k_t *k;
  if (passwand_secure_malloc((void **)&k, sizeof(*k)) != 0)
    return NULL;
  return k;
}
