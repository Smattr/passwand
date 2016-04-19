#pragma once

#include <passwand/passwand.h>
#include <stddef.h>
#include <stdint.h>

passwand_error_t encode(const uint8_t *s, size_t len, char **e)
    __attribute__((visibility("internal")));

passwand_error_t decode(const char *s, uint8_t **d, size_t *len)
    __attribute__((visibility("internal")));
