#pragma once

#include <passwand/passwand.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    char *master;
    size_t master_len;
} master_t;

master_t *getpassword(const char *prompt);

void discard_master(master_t *m);

#define DIE(format, args...) \
    do { \
        fprintf(stderr, format "\n", ## args); \
        return EXIT_FAILURE; \
    } while (0)

