#include "../common/argparse.h"
#include <assert.h>
#include "cli.h"
#include "delete.h"
#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    bool found;
    const char *space;
    const char *key;
} delete_state_t;

static void check(void *state, const char *space, const char *key,
        const char *value __attribute__((unused))) {

    assert(state != NULL);
    assert(space != NULL);
    assert(key != NULL);

    delete_state_t *st = state;
    assert(st->space != NULL);
    assert(st->key != NULL);

    assert(!st->found);
    st->found = strcmp(st->space, space) == 0 && strcmp(st->key, key) == 0;
}

int delete(const options_t *options __attribute__((unused)), master_t *master,
        passwand_entry_t *entries, size_t entry_len) {

    delete_state_t st = {
        .found = false,
        .space = options->space,
        .key = options->key,
    };

    /* Try to find the entry to delete. */
    size_t i;
    for (i = 0; i < entry_len; i++) {
        if (passwand_entry_do(master->master, &entries[i], check, &st) != PW_OK)
            DIE("failed to handle entry %zu", i);
        if (st.found)
            break;
    }

    if (!st.found)
        DIE("failed to find entry");

    /* Shuffle entries following the one to be deleted, to remove the deleted one. */
    for (size_t j = i; j < entry_len - 1; j++)
        entries[j] = entries[j + 1];

    passwand_error_t err = passwand_export(options->data, entries, entry_len - 1);
    if (err != PW_OK)
        DIE("failed to export entries: %s", passwand_error(err));

    return EXIT_SUCCESS;
}