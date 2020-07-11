#include "../common/argparse.h"
#include <assert.h>
#include "cli.h"
#include "list.h"
#include <passwand/passwand.h>
#include "print.h"
#include <stdatomic.h>
#include <stddef.h>
#include <sys/file.h>

static int initialize(const main_t *mainpass __attribute__((unused)),
  passwand_entry_t *entries __attribute__((unused)), size_t entry_len __attribute__((unused))) {
    return 0;
}

static void loop_body(const char *space, const char *key,
        const char *value __attribute__((unused))) {
    assert(space != NULL);
    assert(key != NULL);

    print("%s/%s\n", space, key);
}

const command_t list = {
    .need_space = DISALLOWED,
    .need_key = DISALLOWED,
    .need_value = DISALLOWED,
    .access = LOCK_SH,
    .initialize = initialize,
    .loop_body = loop_body,
};
