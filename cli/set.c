#include "../common/argparse.h"
#include <assert.h>
#include "cli.h"
#include <limits.h>
#include <passwand/passwand.h>
#include "set.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    bool found;
    size_t index;
    const char *space;
    const char *key;
} set_state_t;

static void set_body(void *state, const char *space, const char *key,
        const char *value __attribute__((unused))) {

    assert(state != NULL);
    assert(space != NULL);
    assert(key != NULL);
    assert(value != NULL);

    set_state_t *st = state;
    if (strcmp(st->space, space) == 0 && strcmp(st->key, key) == 0) {
        /* This entry matches the one we just set. Mark it. */
        st->found = true;
    } else {
        st->index++;
    }
}

int set(const options_t *options, master_t *master, passwand_entry_t *entries,
        size_t entry_len) {

    master_t *confirm = getpassword("confirm master password: ");
    if (confirm == NULL)
        DIE("out of memory");
    bool r = strcmp(master->master, confirm->master) == 0;
    discard_master(confirm);
    if (!r)
        DIE("passwords do not match");

    passwand_entry_t e;
    if (passwand_entry_new(&e, master->master, options->space, options->key, options->value,
            options->work_factor) != PW_OK)
        DIE("failed to create new entry");

    /* Figure out if the entry we've just created collides with (and overwrites) an existing one.
     */

    set_state_t st = {
        .found = false,
        .index = 0,
        .space = options->space,
        .key = options->key,
    };
    for (size_t i = 0; !st.found && i < entry_len; i++) {
        if (passwand_entry_do(master->master, &entries[i], set_body, &st) != PW_OK)
            DIE("failed to handle entry %zu", i);
    }

    if (!st.found && entry_len == SIZE_MAX)
        DIE("maximum number of entries exceeded");

    passwand_entry_t *new_entries = calloc(entry_len + (st.found ? 0 : 1), sizeof(passwand_entry_t));
    if (new_entries == NULL)
        DIE("out of memory");

    /* Insert the new or updated entry at the start of the list, as we assume
     * we'll be looking it up in the near future.
     */
    size_t count_before = st.found ? st.index : entry_len;
    size_t count_after = st.found ? entry_len - st.index - 1 : 0;
    new_entries[0] = e;
    memcpy(new_entries + 1, entries, sizeof(passwand_entry_t) * count_before);
    memcpy(new_entries + st.index + 1, entries + st.index + 1,
        sizeof(passwand_entry_t) * count_after);
    size_t new_entry_len = st.found ? entry_len : entry_len + 1;

    passwand_error_t err = passwand_export(options->data, new_entries, new_entry_len);
    if (err != PW_OK)
        DIE("failed to export entries: %s", passwand_error(err));

    discard_master(master);
    return EXIT_SUCCESS;
}
