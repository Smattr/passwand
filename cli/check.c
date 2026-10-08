#include "check.h"
#include <sys/file.h>
#include "../common/argparse.h"
#include "../common/streq.h"
#include "cli.h"
#include "print.h"
#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static atomic_bool found_weak;

static int initialize(const main_t *mainpass __attribute__((unused)),
                      passwand_entry_t *entries __attribute__((unused)),
                      size_t entry_len __attribute__((unused))) {
  return 0;
}

static bool in_dictionary(const char *s) {

  // open the system dictionary
  FILE *f = fopen("/usr/share/dict/words", "r");
  if (f == NULL) {
    // failed; perhaps the file does not exist
    return false;
  }

  bool result = false;

  char *line = NULL;
  size_t size = 0;
  for (;;) {
    ssize_t r = getline(&line, &size, f);
    if (r < 0) {
      // done or error
      break;
    }

    if (r > 0) {
      // delete the trailing \n
      if (line[strlen(line) - 1] == '\n')
        line[strlen(line) - 1] = '\0';

      if (streq(s, line)) {
        result = true;
        break;
      }
    }
  }

  free(line);
  fclose(f);

  return result;
}

static void loop_body(const char *space, const char *key, const char *value) {
  assert(space != NULL);
  assert(key != NULL);
  assert(value != NULL);

  // if we were given a space, check that this entry is within it
  if (options.space != NULL && !streq(options.space, space))
    return;

  // if we were given a key, check that this entry matches it
  if (options.key != NULL && !streq(options.key, key))
    return;

  if (in_dictionary(value)) {
    print("%s/%s: weak password (dictionary word)\n", space, key);
    found_weak = true;
  }
}

static int finalize(bool failure_pending __attribute__((unused))) {
  return found_weak ? -1 : 0;
}

const command_t check = {
    .need_space = OPTIONAL,
    .need_key = OPTIONAL,
    .need_value = DISALLOWED,
    .need_length = DISALLOWED,
    .access = LOCK_SH,
    .initialize = initialize,
    .loop_body = loop_body,
    .finalize = finalize,
};
