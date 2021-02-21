#pragma once

#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
  char *main;
  size_t main_len;
} main_t;

main_t *getpassword(const char *prompt);

void discard_main(main_t *m);

// How a command line argument is used.
typedef enum {
  DISALLOWED,
  OPTIONAL,
  REQUIRED,
} arg_required_t;

// A subcommand of this tool.
typedef struct {
  arg_required_t
      need_space;          // Whether the command uses the --space argument.
  arg_required_t need_key; // Whether the command uses the --key argument.
  arg_required_t
      need_value; // Whether the command uses the --value argument.

  // Mode to access the database in:
  //  LOCK_SH - shared (read)
  //  LOCK_EX - exclusive (write)
  int access;

  // Constructor.
  int (*initialize)(const main_t *mainpass, passwand_entry_t *entries,
                    size_t entry_len);

  // Prepare to run 'loop_body' on an entry.
  void (*loop_notify)(size_t entry_index);

  // Indicate whether iteration should continue.
  bool (*loop_condition)(void);

  // Action of this command. Note, this may be called by multiple threads in
  // parallel.
  void (*loop_body)(const char *space, const char *key, const char *value);

  // Destructor.
  int (*finalize)(void);
} command_t;
