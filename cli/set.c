#include "../common/argparse.h"
#include <assert.h>
#include "cli.h"
#include <limits.h>
#include <passwand/passwand.h>
#include "print.h"
#include "set.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static bool found;
static size_t entry_index;

static void set_body(void *state __attribute__((unused)), const char *space, const char *key,
        const char *value __attribute__((unused))) {

    assert(space != NULL);
    assert(key != NULL);
    assert(value != NULL);

    if (strcmp(options.space, space) == 0 && strcmp(options.key, key) == 0) {
        /* This entry matches the one we just set. Mark it. */
        found = true;
    } else {
        entry_index++;
    }
}

static int set(const master_t *master, passwand_entry_t *entries, size_t entry_len) {

    found = false;
    entry_index = 0;

    master_t *confirm = getpassword("confirm master password: ");
    if (confirm == NULL) {
        eprint("out of memory\n");
        return -1;
    }
    bool r = strcmp(master->master, confirm->master) == 0;
    discard_master(confirm);
    if (!r) {
        eprint("passwords do not match\n");
        return -1;
    }

    passwand_entry_t e;
    if (passwand_entry_new(&e, master->master, options.space, options.key, options.value,
            options.work_factor) != PW_OK) {
        eprint("failed to create new entry\n");
        return -1;
    }

    /* Figure out if the entry we've just created collides with (and overwrites) an existing one.
     */

    for (size_t i = 0; !found && i < entry_len; i++) {
        if (passwand_entry_do(master->master, &entries[i], set_body, NULL) != PW_OK) {
            eprint("failed to handle entry %zu\n", i);
            return -1;
        }
    }

    if (!found && entry_len == SIZE_MAX) {
        eprint("maximum number of entries exceeded\n");
        return -1;
    }

    passwand_entry_t *new_entries = calloc(entry_len + (found ? 0 : 1), sizeof(passwand_entry_t));
    if (new_entries == NULL) {
        eprint("out of memory\n");
        return -1;
    }

    /* Insert the new or updated entry at the start of the list, as we assume
     * we'll be looking it up in the near future.
     */
    size_t count_before = found ? entry_index : entry_len;
    size_t count_after = found ? entry_len - entry_index - 1 : 0;
    new_entries[0] = e;
    memcpy(new_entries + 1, entries, sizeof(passwand_entry_t) * count_before);
    memcpy(new_entries + entry_index + 1, entries + entry_index + 1,
        sizeof(passwand_entry_t) * count_after);
    size_t new_entry_len = found ? entry_len : entry_len + 1;

    passwand_error_t err = passwand_export(options.data, new_entries, new_entry_len);
    free(new_entries);
    if (err != PW_OK) {
        print("failed to export entries: %s\n", passwand_error(err));
        return -1;
    }

    return 0;
}

const command_t set_command = {
    .need_space = true,
    .need_key = true,
    .need_value = true,
    .initialize = set,
};
