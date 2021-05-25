#pragma once

#include "cli.h"
#include <stdbool.h>
#include <stddef.h>

extern const command_t set;

int set_initialize(const main_t *mainpass, passwand_entry_t *entries,
                   size_t entry_len) __attribute__((visibility("hidden")));

void set_loop_notify(size_t entry_index) __attribute__((visibility("hidden")));

bool set_loop_condition(void) __attribute__((visibility("hidden")));

void set_loop_body(const char *space, const char *key, const char *value)
    __attribute__((visibility("hidden")));

int set_finalize(void) __attribute__((visibility("hidden")));
