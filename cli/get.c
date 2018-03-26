#include "../common/argparse.h"
#include <assert.h>
#include "cli.h"
#include "get.h"
#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const options_t *options;
    bool found;
} find_state_t;

static void get_body(void *state, const char *space, const char *key, const char *value) {

    assert(state != NULL);
    assert(space != NULL);
    assert(key != NULL);
    assert(value != NULL);

    find_state_t *st = state;
    if (strcmp(st->options->space, space) == 0 && strcmp(st->options->key, key) == 0) {
        puts(value);
        st->found = true;
    }
}

int get(const options_t *options, const master_t *master, passwand_entry_t *entries,
        size_t entry_len) {

    find_state_t st = {
        .options = options,
        .found = false,
    };
    for (size_t i = 0; !st.found && i < entry_len; i++) {
        if (passwand_entry_do(master->master, &entries[i], get_body, &st) != PW_OK) {
            fprintf(stderr, "failed to handle entry %zu\n", i);
            return -1;
        }
    }

    if (!st.found) {
        fprintf(stderr, "not found\n");
        return -1;
    }

    return 0;
}
