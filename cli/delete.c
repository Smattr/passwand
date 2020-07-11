#include "../common/argparse.h"
#include <assert.h>
#include "cli.h"
#include "delete.h"
#include <passwand/passwand.h>
#include "print.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>

static atomic_bool found;
static atomic_size_t found_index;
static _Thread_local size_t current_index;

static passwand_entry_t *saved_entries;
static size_t saved_entry_len;

static int initialize(const main_t *mainpass __attribute__((unused)), passwand_entry_t *entries,
  size_t entry_len) {

    found = false;
    found_index = 0;
    saved_entries = entries;
    saved_entry_len = entry_len;
    return 0;
}

static void loop_notify(size_t entry_index) {
    current_index = entry_index;
}

static bool loop_condition(void) {
    return !found;
}

static void loop_body(const char *space, const char *key,
        const char *value __attribute__((unused))) {

    assert(space != NULL);
    assert(key != NULL);

    assert(options.space != NULL);
    assert(options.key != NULL);

    if (strcmp(options.space, space) == 0 && strcmp(options.key, key) == 0) {
        bool expected = false;
        if (atomic_compare_exchange_strong(&found, &expected, true))
            found_index = current_index;
    }
}

static int finalize(void) {

    if (!found) {
        eprint("failed to find entry\n");
        return -1;
    }

    /* Shuffle entries following the one to be deleted, to remove the deleted one. */
    passwand_entry_t deleted = saved_entries[found_index];
    for (size_t i = found_index; i < saved_entry_len - 1; i++)
        saved_entries[i] = saved_entries[i + 1];

    /* Put the deleted entry in the last place in the list, unused by us, but will be freed by
     * main().
     */
    saved_entries[saved_entry_len - 1] = deleted;

    passwand_error_t err = passwand_export(options.data, saved_entries, saved_entry_len - 1);
    if (err != PW_OK) {
        eprint("failed to export entries: %s\n", passwand_error(err));
        return -1;
    }

    return 0;
}

const command_t delete = {
    .need_space = REQUIRED,
    .need_key = REQUIRED,
    .need_value = DISALLOWED,
    .access = LOCK_EX,
    .initialize = initialize,
    .loop_notify = loop_notify,
    .loop_condition = loop_condition,
    .loop_body = loop_body,
    .finalize = finalize,
};
