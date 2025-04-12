#include "get.h"
#include "../common/argparse.h"
#include "../common/streq.h"
#include "cli.h"
#include "print.h"
#include <assert.h>
#include <passwand/passwand.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>

static atomic_bool found;

static int initialize(const main_t *mainpass __attribute__((unused)),
                      passwand_entry_t *entries __attribute__((unused)),
                      size_t entry_len __attribute__((unused))) {

  found = false;
  return 0;
}

static bool loop_condition(void) { return !found; }

static void loop_body(const char *space, const char *key, const char *value) {
  assert(space != NULL);
  assert(key != NULL);
  assert(value != NULL);

  if (streq(options.space, space) && streq(options.key, key)) {
    print("%s\n", value);
    found = true;
  }
}

static int finalize(bool failure_pending __attribute__((unused))) {
  if (!found)
    eprint("not found\n");

  return found ? 0 : -1;
}

const command_t get = {
    .need_space = REQUIRED,
    .need_key = REQUIRED,
    .need_value = DISALLOWED,
    .need_length = DISALLOWED,
    .access = LOCK_SH,
    .initialize = initialize,
    .loop_condition = loop_condition,
    .loop_body = loop_body,
    .finalize = finalize,
};
