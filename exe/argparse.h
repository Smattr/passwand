#pragma once

typedef struct {
    char *data;
    char *space;
    char *key;
    char *value;
    unsigned work_factor;
} options_t;

int parse(int argc, char **argv, options_t *options);
