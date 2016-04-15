#pragma once

#include <passwand/passwand.h>

passwand_error_t encode(const char *s, char **e) __attribute__((visibility("internal")));

char *decode(const char *s) __attribute__((visibility("internal")));
