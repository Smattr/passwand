/* Helpers for RAII */

#pragma once

#include <assert.h>
#include "encryption.h"
#include <passwand/passwand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"

static inline k_t *make_k_t(void) {
    k_t *k;
    if (passwand_secure_malloc((void**)&k, sizeof *k) != 0)
        return NULL;
    if (passwand_secure_malloc((void**)&k->data, AES_KEY_SIZE) != 0) {
        passwand_secure_free(k, sizeof *k);
        return NULL;
    }
    k->length = AES_KEY_SIZE;
    return k;
}

static inline void unmake_k_t(void *p) {
    assert(p != NULL);
    k_t *k = *(k_t**)p;
    if (k != NULL) {
        if (k->data != NULL)
            passwand_secure_free(k->data, k->length);
        passwand_secure_free(k, sizeof *k);
    }
}
#define AUTO_K_T(name) k_t *k __attribute__((cleanup(unmake_k_t))) = make_k_t()

static inline void autoerase(void *p) {
    assert(p != NULL);
    char **s = p;
    if (*s != NULL) {
        passwand_erase(*s, strlen(*s));
        free(*s);
    }
}
#define AUTO_SECURE_STRING(name) __attribute__((cleanup(autoerase))) char *name = NULL
