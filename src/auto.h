/* Helpers for RAII */

#pragma once

#include <assert.h>
#include "encryption.h"
#include <passwand/passwand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"

static inline void autowipek_t(void *p) {
    assert(p != NULL);
    k_t *k = p;
    if (k->data != NULL)
        passwand_erase(k->data, k->length);
}
#define AUTO_K_T(name) \
    uint8_t _##name[AES_KEY_SIZE]; \
    __attribute__((cleanup(autowipek_t))) k_t name = { \
        .data = _##name, \
        .length = sizeof _##name, \
    }

static inline void autoerase(void *p) {
    assert(p != NULL);
    char **s = p;
    if (*s != NULL) {
        passwand_erase((uint8_t*)*s, strlen(*s));
        free(*s);
    }
}
#define AUTO_SECURE_STRING(name) __attribute__((cleanup(autoerase))) char *name = NULL
