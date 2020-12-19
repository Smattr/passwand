#pragma once

#include <stddef.h>

typedef struct {
    char *path;
    unsigned work_factor;
} database_t;

typedef struct {
    database_t db;
    char *space;
    char *key;
    char *value;
    unsigned long jobs;
} options_t;

extern options_t options;

int parse(int argc, char **argv);
