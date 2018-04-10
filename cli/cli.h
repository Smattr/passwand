#pragma once

#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    char *master;
    size_t master_len;
} master_t;

master_t *getpassword(const char *prompt);

void discard_master(master_t *m);

/* A subcommand of this tool. */
typedef struct {
    bool need_space; /* Whether the command uses the --space argument. */
    bool need_key;   /* Whether the command uses the --key argument. */
    bool need_value; /* Whether the command uses the --value argument. */

    /* Constructor. */
    int (*initialize)(const master_t *master, passwand_entry_t *entries, size_t entry_len);

    /* Prepare to run 'loop_body' on an entry. */
    void (*loop_notify)(size_t thread_index, size_t entry_index);

    /* Indicate whether iteration should continue. */
    bool (*loop_condition)(void);

    /* Action of this command. Note, this may be called by multiple threads in parallel. */
    void (*loop_body)(void *state, const char *space, const char *key, const char *value);

    /* Destructor. */
    int (*finalize)(void);
} command_t;
