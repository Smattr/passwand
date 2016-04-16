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

static inline void autowipeppt_t(void *p) {
    assert(p != NULL);
    ppt_t *pp = p;
    if (pp->data != NULL) {
        passwand_erase(pp->data, pp->length);
        free(pp->data);
    }
}
#define AUTO_PPT_T(name) __attribute__((cleanup(autowipeppt_t))) ppt_t name = { .data = NULL }

static inline void autowipept_t(void *p) {
    assert(p != NULL);
    pt_t *pt = p;
    if (pt->data != NULL) {
        passwand_erase(pt->data, pt->length);
        free(pt->data);
    }
}
#define AUTO_PT_T(name) __attribute__((cleanup(autowipept_t))) pt_t name = { .data = NULL }

static inline void autoerase(void *p) {
    assert(p != NULL);
    char **s = p;
    if (*s != NULL) {
        passwand_erase((uint8_t*)*s, strlen(*s));
        free(*s);
    }
}
#define AUTO_SECURE_STRING(name) __attribute__((cleanup(autoerase))) char *name = NULL
