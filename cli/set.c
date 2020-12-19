#include "../common/argparse.h"
#include <assert.h>
#include "cli.h"
#include <limits.h>
#include <passwand/passwand.h>
#include "print.h"
#include "set.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>

static const main_t *saved_main;
static passwand_entry_t *saved_entries;
static size_t saved_entry_len;
static atomic_bool found;
static _Thread_local size_t candidate_index;

static int initialize(const main_t *mainpass, passwand_entry_t *entries, size_t entry_len) {

    saved_main = mainpass;
    saved_entries = entries;
    saved_entry_len = entry_len;
    found = false;

    main_t *confirm = getpassword("confirm main password: ");
    if (confirm == NULL) {
        eprint("out of memory\n");
        return -1;
    }
    bool r = strcmp(mainpass->main, confirm->main) == 0;
    discard_main(confirm);
    if (!r) {
        eprint("passwords do not match\n");
        return -1;
    }

    return 0;
}

static void loop_notify(size_t entry_index) {
    candidate_index = entry_index;
}

static bool loop_condition(void) {
    return !found;
}

static void loop_body(const char *space, const char *key,
        const char *value __attribute__((unused))) {

    assert(space != NULL);
    assert(key != NULL);

    if (strcmp(options.space, space) == 0 && strcmp(options.key, key) == 0) {
        /* This entry matches the one we are trying to set. This cmpxchg should never fail because
         * there should only ever be a single matching entry (this one) but maybe we're operating
         * on a tampered with or corrupted database.
         */
        bool expected = false;
        (void)atomic_compare_exchange_strong(&found, &expected, true);
    }
}

static int finalize(void) {

    if (found) {
        eprint("an entry for %s/%s already exists\n", options.space, options.key);
        return -1;
    }

    passwand_entry_t e;
    if (passwand_entry_new(&e, saved_main->main, options.space, options.key, options.value,
            options.db.work_factor) != PW_OK) {
        eprint("failed to create new entry\n");
        return -1;
    }

    size_t new_entry_len = saved_entry_len + 1;
    passwand_entry_t *new_entries = calloc(new_entry_len, sizeof(new_entries[0]));
    if (new_entries == NULL) {
        eprint("out of memory\n");
        return -1;
    }

    /* Insert the new or updated entry at the start of the list, as we assume we'll be looking it up
     * in the near future.
     */
    new_entries[0] = e;
    for (size_t index = 0; index < saved_entry_len; index++) {
        assert(index + 1 < new_entry_len);
        new_entries[index + 1] = saved_entries[index];
    }

    passwand_error_t err = passwand_export(options.db.path, new_entries, new_entry_len);
    free(new_entries);
    free(e.space);
    free(e.key);
    free(e.value);
    free(e.hmac);
    free(e.hmac_salt);
    free(e.salt);
    free(e.iv);
    if (err != PW_OK) {
        print("failed to export entries: %s\n", passwand_error(err));
        return -1;
    }

    return 0;
}

const command_t set = {
    .need_space = REQUIRED,
    .need_key = REQUIRED,
    .need_value = REQUIRED,
    .access = LOCK_EX,
    .initialize = initialize,
    .loop_notify = loop_notify,
    .loop_condition = loop_condition,
    .loop_body = loop_body,
    .finalize = finalize,
};
