#include "../common/argparse.h"
#include <assert.h>
#include "cli.h"
#include "get.h"
#include <passwand/passwand.h>
#include "print.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const options_t *options;
    atomic_bool found;
} get_state_t;

static int initialize(void **state, const options_t *opts,
  const master_t *master __attribute__((unused)),
  passwand_entry_t *entries __attribute__((unused)), size_t entry_len __attribute__((unused))) {

    assert(state != NULL);
    assert(opts != NULL);

    get_state_t *st = calloc(1, sizeof(*st));
    if (st == NULL) {
        eprint("out of memory\n");
        return -1;
    }

    st->options = opts;
    st->found = false;

    *state = st;
    return 0;
}

static bool loop_condition(void *state) {
    assert(state != NULL);

    get_state_t *st = state;
    return !st->found;
}

static void loop_body(void *state, const char *space, const char *key, const char *value) {
    assert(state != NULL);
    assert(space != NULL);
    assert(key != NULL);
    assert(value != NULL);

    get_state_t *st = state;
    if (strcmp(st->options->space, space) == 0 && strcmp(st->options->key, key) == 0) {
        print("%s\n", value);
        st->found = true;
    }
}

static int finalize(void *state) {
    assert(state != NULL);

    int ret = -1;

    get_state_t *st = state;
    if (!st->found) {
        eprint("not found\n");
    } else {
        ret = 0;
    }

    free(state);
    return ret;
}

const command_t get = {
    .need_space = true,
    .need_key = true,
    .need_value = false,
    .initialize = initialize,
    .loop_condition = loop_condition,
    .loop_body = loop_body,
    .finalize = finalize,
};
