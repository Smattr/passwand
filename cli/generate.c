#include <assert.h>
#include "cli.h"
#include "../common/argparse.h"
#include <ctype.h>
#include "generate.h"
#include <passwand/passwand.h>
#include "print.h"
#include "set.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/file.h>

// default value if --length was not given
static const size_t DEFAULT_LENGTH = 30;

// characters we accept in a password
static bool is_ok(char c) {
  if (c >= 'a' && c <= 'z')
    return true;
  if (c >= 'A' && c <= 'Z')
    return true;
  if (isdigit(c))
    return true;
  if (c == '_')
    return true;
  return false;
}

static int initialize(const main_t *mainpass, passwand_entry_t *entries,
                      size_t entry_len) {

  // piggy-back off `set` constructor
  int r = set.initialize(mainpass, entries, entry_len);
  if (r != 0)
    return r;

  // create space to store a generated password
  size_t length = options.length == 0 ? DEFAULT_LENGTH : options.length;
  assert(options.value == NULL);
  options.value = malloc(sizeof(char) * (length + 1));
  if (options.value == NULL) {
    eprint("out of memory\n");
    return -1;
  }
  options.value[length] = '\0';

  // generate the password
  size_t offset = 0;
  while (length > 0) {
    char buffer[UINT8_MAX];
    uint8_t chunk = length > UINT8_MAX ? UINT8_MAX : (uint8_t)length;
    passwand_error_t err = passwand_random_bytes(buffer, chunk);
    if (err != PW_OK) {
      eprint("failed to generate random bytes: %s\n", passwand_error(err));
      return -1;
    }

    for (uint8_t i = 0; i < chunk; ++i) {
      if (is_ok(buffer[i])) {
        options.value[offset] = buffer[i];
        ++offset;
        --length;
      }
    }
  }

  return 0;
}

const command_t generate = {
  .need_space = REQUIRED,
  .need_key = REQUIRED,
  .need_value = DISALLOWED,
  .need_length = OPTIONAL,
  .access = LOCK_EX,
  .initialize = initialize,
  .loop_notify = set_loop_notify,
  .loop_condition = set_loop_condition,
  .loop_body = set_loop_body,
  .finalize = set_finalize,
};
