#include "../common/argparse.h"
#include "change-master.h"
#include "cli.h"
#include <passwand/passwand.h>
#include "print.h"
#include <stdlib.h>
#include <string.h>

static master_t *new_master;
static passwand_entry_t *new_entries;
static size_t entry_index;
static passwand_error_t err;

static void change_master_body(void *state __attribute__((unused)), const char *space, const char *key,
        const char *value) {
    err = passwand_entry_new(&new_entries[entry_index], new_master->master, space, key, value,
        options.work_factor);
    entry_index++;
}

static int change_master(void **state __attribute__((unused)), const master_t *master, passwand_entry_t *entries,
        size_t entry_len) {

    new_master = NULL;
    master_t *confirm_new = NULL;
    new_entries = NULL;
    entry_index = 0;
    err = PW_OK;
    int ret = -1;

    new_master = getpassword("new master password: ");
    if (new_master == NULL) {
        eprint("failed to read new password\n");
        return -1;
    }

    confirm_new = getpassword("confirm new master password: ");
    if (confirm_new == NULL) {
        eprint("failed to read confirmation of new password\n");
        goto done;
    }

    if (strcmp(new_master->master, confirm_new->master) != 0) {
        eprint("passwords do not match\n");
        goto done;
    }

    discard_master(confirm_new);
    confirm_new = NULL;

    new_entries = calloc(entry_len, sizeof(*new_entries));
    if (new_entries == NULL) {
        eprint("out of memory\n");
        goto done;
    }

    for (size_t i = 0; i < entry_len; i++) {
        passwand_error_t e = passwand_entry_do(master->master, &entries[i], change_master_body,
            NULL);
        if (e != PW_OK) {
            eprint("failed to process entry %zu: %s\n", i, passwand_error(e));
            goto done;
        }
        if (err != PW_OK) {
            eprint("failed to process entry %zu: %s\n", i, passwand_error(err));
            goto done;
        }
    }
    discard_master(new_master);
    new_master = NULL;

    passwand_error_t e = passwand_export(options.data, new_entries, entry_len);
    if (e != PW_OK) {
        eprint("failed to export entries\n");
        goto done;
    }

    ret = 0;

done:
    free(new_entries);
    if (confirm_new != NULL)
        discard_master(confirm_new);
    if (new_master != NULL)
        discard_master(new_master);
    return ret;
}

const command_t change_master_command = {
    .need_space = false,
    .need_key = false,
    .need_value = false,
    .initialize = change_master,
};
