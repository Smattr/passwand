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
  size_t length;

  // extra indirect databases to go through to get the main password for the
  // primary database above
  database_t *chain;
  size_t chain_len;
} options_t;

extern options_t options;

int parse(int argc, char **argv);
