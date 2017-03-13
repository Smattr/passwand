#pragma once

typedef struct {
    char *data;
    char *space;
    char *key;
    char *value;
    unsigned work_factor;
    unsigned long jobs;
} options_t;

int parse(int argc, char **argv, options_t *options);
