#pragma once

#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
  char *main;
  size_t main_len;
  bool confirmed; ///< should any password confirmation prompts be bypassed?
} main_t;

main_t *getpassword(const char *prompt);

void discard_main(main_t *m);

// how a command line argument is used
typedef enum {
  DISALLOWED,
  OPTIONAL,
  REQUIRED,
} arg_required_t;

// a subcommand of this tool
typedef struct {
  arg_required_t need_space;  // whether the command uses the --space argument
  arg_required_t need_key;    // whether the command uses the --key argument
  arg_required_t need_value;  // whether the command uses the --value argument
  arg_required_t need_length; // whether the command uses the --length argument

  // mode to access the database in:
  //  LOCK_SH - shared (read)
  //  LOCK_EX - exclusive (write)
  int access;

  // constructor
  int (*initialize)(const main_t *mainpass, passwand_entry_t *entries,
                    size_t entry_len);

  // prepare to run `loop_body` on an entry
  void (*loop_notify)(size_t entry_index);

  // indicate whether iteration should continue
  bool (*loop_condition)(void);

  // Action of this command. Note, this may be called by multiple threads in
  // parallel.
  void (*loop_body)(const char *space, const char *key, const char *value);

  // destructor
  int (*finalize)(void);
} command_t;
