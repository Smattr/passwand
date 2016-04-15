#pragma once

#include <passwand/passwand.h>

passwand_error_t encode(const char *s, char **e) __attribute__((visibility("internal")));

passwand_error_t decode(const char *s, char **d) __attribute__((visibility("internal")));
